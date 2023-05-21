pub mod defs;
// mod regex;
// mod substr;
pub mod table;
pub mod vrm;
pub use defs::*;
// pub use regex::*;
// pub use substr::*;

use halo2_base::halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Assigned, Circuit, Column, ConstraintSystem, Constraints, Error, Expression,
        Instance, Selector, TableColumn,
    },
    poly::Rotation,
};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{bigint_to_fe, biguint_to_fe, fe_to_biguint, modulus, PrimeField},
    AssignedValue, Context, QuantumCell,
};
use std::{
    collections::HashSet,
    fmt::format,
    fs::File,
    io::{BufRead, BufReader},
    marker::PhantomData,
};

use crate::table::RegexTableConfig;
use crate::{AllstrRegexDef, RegexDefs, SubstrRegexDef};
#[derive(Debug, Clone, Default)]
pub struct AssignedRegexResult<'a, F: PrimeField> {
    pub all_enable_flags: Vec<AssignedValue<'a, F>>,
    pub all_characters: Vec<AssignedValue<'a, F>>,
    // pub all_states: Vec<AssignedValue<'a, F>>,
    pub all_substr_ids: Vec<AssignedValue<'a, F>>,
    pub masked_characters: Vec<AssignedValue<'a, F>>,
}

#[derive(Debug, Clone)]
pub struct RegexVerifyConfig<F: PrimeField> {
    characters: Column<Advice>,
    char_enable: Column<Advice>,
    states_array: Vec<Column<Advice>>,
    substr_ids_array: Vec<Column<Advice>>,
    is_start_array: Vec<Column<Advice>>,
    is_end_array: Vec<Column<Advice>>,
    table_array: Vec<RegexTableConfig<F>>,
    q_first: Selector,
    not_q_first: Selector,
    max_chars_size: usize,
    gate: FlexGateConfig<F>,
    pub regex_defs: Vec<RegexDefs>,
}

impl<F: PrimeField> RegexVerifyConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        max_chars_size: usize,
        gate: FlexGateConfig<F>,
        regex_defs: Vec<RegexDefs>,
    ) -> Self {
        let num_regex_def = regex_defs.len();
        let characters = meta.advice_column();
        let char_enable = meta.advice_column();
        let states_array = (0..num_regex_def)
            .map(|_| {
                let column = meta.advice_column();
                meta.enable_equality(column);
                column
            })
            .collect::<Vec<Column<Advice>>>();
        let substr_ids_array = (0..num_regex_def)
            .map(|_| {
                let column = meta.advice_column();
                meta.enable_equality(column);
                column
            })
            .collect::<Vec<Column<Advice>>>();
        let is_start_array = (0..num_regex_def)
            .map(|_| {
                let column = meta.advice_column();
                meta.enable_equality(column);
                column
            })
            .collect::<Vec<Column<Advice>>>();
        let is_end_array = (0..num_regex_def)
            .map(|_| {
                let column = meta.advice_column();
                meta.enable_equality(column);
                column
            })
            .collect::<Vec<Column<Advice>>>();
        let q_first = meta.complex_selector();
        let not_q_first = meta.complex_selector();
        let table_array = (0..num_regex_def)
            .map(|_| RegexTableConfig::configure(meta))
            .collect::<Vec<RegexTableConfig<F>>>();
        meta.enable_equality(characters);
        meta.enable_equality(char_enable);

        meta.create_gate("The state must start from the first state value", |meta| {
            let q_frist = meta.query_selector(q_first);
            let cur_enable = meta.query_advice(char_enable, Rotation::cur());
            let not_cur_enable = Expression::Constant(F::from(1)) - cur_enable.clone();
            let mut constraints =
                vec![q_frist.clone() * cur_enable.clone() * not_cur_enable.clone()];
            for (idx, states) in states_array.iter().enumerate() {
                let cur_state = meta.query_advice(*states, Rotation::cur());
                constraints.push(
                    q_frist.clone()
                        * cur_enable.clone()
                        * (cur_state
                            - Expression::Constant(F::from(
                                regex_defs[idx].allstr.first_state_val,
                            ))),
                );
            }
            constraints
        });

        meta.create_gate("The transition of enable flags", |meta| {
            let not_q_frist = meta.query_selector(not_q_first);
            let cur_enable = meta.query_advice(char_enable, Rotation::cur());
            let not_cur_enable = Expression::Constant(F::from(1)) - cur_enable.clone();
            let prev_enable = meta.query_advice(char_enable, Rotation::prev());
            let enable_change = prev_enable.clone() - cur_enable.clone();
            let not_enable_change = Expression::Constant(F::from(1)) - enable_change.clone();
            vec![
                not_q_frist.clone() * enable_change * not_enable_change,
                not_q_frist * cur_enable * not_cur_enable,
            ]
        });

        for (idx, defs) in regex_defs.iter().enumerate() {
            meta.lookup("lookup characters and their state", |meta| {
                let enable = meta.query_advice(char_enable, Rotation::cur());
                let not_enable = Expression::Constant(F::from(1)) - enable.clone();
                let character = meta.query_advice(characters, Rotation::cur());
                let states = states_array[idx];
                let substr_ids = substr_ids_array[idx];
                let cur_state = meta.query_advice(states, Rotation::cur());
                let next_state = meta.query_advice(states, Rotation::next());
                let substr_id = meta.query_advice(substr_ids, Rotation::cur());
                let dummy_state_val =
                    Expression::Constant(F::from(defs.allstr.largest_state_val + 1));
                vec![
                    (
                        enable.clone() * character.clone(),
                        table_array[idx].characters,
                    ),
                    (
                        enable.clone() * cur_state + not_enable.clone() * dummy_state_val.clone(),
                        table_array[idx].cur_states,
                    ),
                    (
                        enable.clone() * next_state + not_enable.clone() * dummy_state_val.clone(),
                        table_array[idx].next_states,
                    ),
                    (enable.clone() * substr_id, table_array[idx].substr_ids),
                ]
            });

            meta.lookup("lookup start_state of substring", |meta| {
                let enable = meta.query_advice(char_enable, Rotation::cur());
                let states = states_array[idx];
                let substr_ids = substr_ids_array[idx];
                let is_starts = is_start_array[idx];
                let cur_state = meta.query_advice(states, Rotation::cur());
                let substr_id = meta.query_advice(substr_ids, Rotation::cur());
                let is_start = meta.query_advice(is_starts, Rotation::cur());
                let dummy_state_val =
                    Expression::Constant(F::from(defs.allstr.largest_state_val + 1));
                let flag = enable.clone() * is_start.clone();
                let not_flag = Expression::Constant(F::from(1)) - flag.clone();
                vec![
                    (
                        flag.clone() * substr_id,
                        table_array[idx].endpoints_substr_ids,
                    ),
                    (
                        flag * cur_state + not_flag * dummy_state_val.clone(),
                        table_array[idx].start_states,
                    ),
                    (dummy_state_val, table_array[idx].end_states),
                ]
            });

            meta.lookup("lookup end_state of substring", |meta| {
                let enable = meta.query_advice(char_enable, Rotation::cur());
                let states = states_array[idx];
                let substr_ids = substr_ids_array[idx];
                let is_ends = is_end_array[idx];
                let next_state = meta.query_advice(states, Rotation::next());
                let substr_id = meta.query_advice(substr_ids, Rotation::cur());
                let next_is_end = meta.query_advice(is_ends, Rotation::next());
                let dummy_state_val =
                    Expression::Constant(F::from(defs.allstr.largest_state_val + 1));
                let flag = enable * next_is_end;
                let not_flag = Expression::Constant(F::from(1)) - flag.clone();
                vec![
                    (
                        flag.clone() * substr_id,
                        table_array[idx].endpoints_substr_ids,
                    ),
                    (dummy_state_val.clone(), table_array[idx].start_states),
                    (
                        flag * next_state + not_flag * dummy_state_val,
                        table_array[idx].end_states,
                    ),
                ]
            });
        }

        Self {
            characters,
            char_enable,
            states_array,
            substr_ids_array,
            is_start_array,
            is_end_array,
            table_array,
            q_first,
            not_q_first,
            max_chars_size,
            gate,
            regex_defs,
        }
    }

    pub fn match_substrs<'v: 'a, 'a>(
        &self,
        ctx: &mut Context<'v, F>,
        characters: &[u8],
    ) -> Result<AssignedRegexResult<'a, F>, Error> {
        let states = self.derive_states(characters);
        let substr_ids = self.derive_substr_ids(states.as_slice());
        let (is_starts, is_ends) = self.derive_is_start_end(&states, &substr_ids);
        // for idx in 0..characters.len() {
        //     println!(
        //         "char {}, state {}, substr_id {}, is_start {}, is_end {}",
        //         characters[idx] as char,
        //         states[0][idx],
        //         substr_ids[0][idx],
        //         is_starts[0][idx],
        //         is_ends[0][idx]
        //     );
        // }

        self.q_first.enable(&mut ctx.region, 0)?;
        for idx in 1..self.max_chars_size {
            self.not_q_first.enable(&mut ctx.region, idx)?;
        }

        let mut enable_values = vec![];
        let mut character_values = vec![];
        for char in characters.iter() {
            enable_values.push(Value::known(F::from(1)));
            character_values.push(Value::known(F::from(*char as u64)));
        }
        for _ in characters.len()..self.max_chars_size {
            enable_values.push(Value::known(F::from(0)));
            character_values.push(Value::known(F::from(0)));
        }
        let assigned_enables = enable_values
            .into_iter()
            .enumerate()
            .map(|(idx, val)| {
                let assigned = ctx.region.assign_advice(
                    || format!("enable at {}", idx),
                    self.char_enable,
                    idx,
                    || val,
                )?;
                self.assigned_cell2value(ctx, &assigned)
            })
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;
        let assigned_characters = character_values
            .into_iter()
            .enumerate()
            .map(|(idx, val)| {
                let assigned = ctx.region.assign_advice(
                    || format!("character at {}", idx),
                    self.characters,
                    idx,
                    || val,
                )?;
                self.assigned_cell2value(ctx, &assigned)
            })
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;

        let gate = self.gate();
        let mut assigned_substr_ids = (0..self.max_chars_size)
            .map(|_| gate.load_zero(ctx))
            .collect::<Vec<AssignedValue<F>>>();
        let mut assigned_is_start = (0..self.max_chars_size + 1)
            .map(|_| gate.load_zero(ctx))
            .collect::<Vec<AssignedValue<F>>>();
        let mut assigned_is_end = (0..self.max_chars_size + 1)
            .map(|_| gate.load_zero(ctx))
            .collect::<Vec<AssignedValue<F>>>();

        for (d_idx, defs) in self.regex_defs.iter().enumerate() {
            let mut state_values = states[d_idx][0..characters.len()]
                .iter()
                .map(|state| Value::known(F::from(*state)))
                .collect::<Vec<Value<F>>>();
            let mut substr_id_values = substr_ids[d_idx]
                .iter()
                .map(|substr_id| Value::known(F::from(*substr_id as u64)))
                .collect::<Vec<Value<F>>>();
            let mut is_start_values = is_starts[d_idx][0..characters.len()]
                .iter()
                .map(|flag| Value::known(F::from(*flag)))
                .collect::<Vec<Value<F>>>();
            let mut is_end_values = is_ends[d_idx][0..characters.len()]
                .iter()
                .map(|flag| Value::known(F::from(*flag)))
                .collect::<Vec<Value<F>>>();
            for idx in characters.len()..self.max_chars_size {
                substr_id_values.push(Value::known(F::from(0)));
                let (state_val, is_start, is_end) = if idx == characters.len() {
                    (
                        states[d_idx][idx],
                        is_starts[d_idx][idx],
                        is_ends[d_idx][idx],
                    )
                } else {
                    (defs.allstr.largest_state_val + 1, false, false)
                };
                state_values.push(Value::known(F::from(state_val)));
                is_start_values.push(Value::known(F::from(is_start)));
                is_end_values.push(Value::known(F::from(is_end)));
            }
            for (s_idx, state) in state_values.into_iter().enumerate() {
                let assigned_cell = ctx.region.assign_advice(
                    || format!("state at {} of def {}", s_idx, d_idx),
                    self.states_array[d_idx],
                    s_idx,
                    || state,
                )?;
                let assigned_value = self.assigned_cell2value(ctx, &assigned_cell)?;
                let pre_flag = if s_idx == 0 {
                    gate.load_constant(ctx, F::from(1))
                } else {
                    assigned_enables[s_idx - 1].clone()
                };
                let cur_flag = if s_idx == self.max_chars_size {
                    gate.load_constant(ctx, F::from(0))
                } else {
                    assigned_enables[s_idx].clone()
                };
                let flag_change = gate.sub(
                    ctx,
                    QuantumCell::Existing(&pre_flag),
                    QuantumCell::Existing(&cur_flag),
                );
                let is_state_eq = gate.is_equal(
                    ctx,
                    QuantumCell::Existing(&assigned_value),
                    QuantumCell::Constant(F::from(defs.allstr.accepted_state_val)),
                );
                let is_accepted = gate.select(
                    ctx,
                    QuantumCell::Existing(&is_state_eq),
                    QuantumCell::Constant(F::from(1)),
                    QuantumCell::Existing(&flag_change),
                );
                gate.assert_equal(
                    ctx,
                    QuantumCell::Existing(&is_accepted),
                    QuantumCell::Constant(F::from(1)),
                );
            }
            for (s_idx, substr_id) in substr_id_values.into_iter().enumerate() {
                let assigned_cell = ctx.region.assign_advice(
                    || format!("substr_id at {} of def {}", s_idx, d_idx),
                    self.substr_ids_array[d_idx],
                    s_idx,
                    || substr_id,
                )?;
                let assigned_value = self.assigned_cell2value(ctx, &assigned_cell)?;
                assigned_substr_ids[s_idx] = gate.add(
                    ctx,
                    QuantumCell::Existing(&assigned_substr_ids[s_idx]),
                    QuantumCell::Existing(&assigned_value),
                );
            }
            for (idx, (is_start, is_end)) in is_start_values
                .into_iter()
                .zip(is_end_values.into_iter())
                .enumerate()
            {
                {
                    let assigned_cell = ctx.region.assign_advice(
                        || format!("is_start at {} of def {}", idx, d_idx),
                        self.is_start_array[d_idx],
                        idx,
                        || is_start,
                    )?;
                    let assigned_value = self.assigned_cell2value(ctx, &assigned_cell)?;
                    assigned_is_start[idx] = gate.add(
                        ctx,
                        QuantumCell::Existing(&assigned_is_start[idx]),
                        QuantumCell::Existing(&assigned_value),
                    );
                }
                {
                    let assigned_cell = ctx.region.assign_advice(
                        || format!("is_end at {} of def {}", idx, d_idx),
                        self.is_end_array[d_idx],
                        idx,
                        || is_end,
                    )?;
                    let assigned_value = self.assigned_cell2value(ctx, &assigned_cell)?;
                    assigned_is_end[idx] = gate.add(
                        ctx,
                        QuantumCell::Existing(&assigned_is_end[idx]),
                        QuantumCell::Existing(&assigned_value),
                    );
                }
            }
        }
        debug_assert_eq!(assigned_enables.len(), assigned_characters.len());

        let mut masked_characters = vec![];
        let mut masked_substr_ids = vec![];
        let mut start_mask = vec![];
        let mut end_mask = vec![];

        let mut last_start_mask = gate.load_zero(ctx);
        for idx in 0..self.max_chars_size {
            let is_changed = {
                let pre_substr_id = if idx == 0 {
                    gate.load_zero(ctx)
                } else {
                    assigned_substr_ids[idx - 1].clone()
                };
                let is_eq = gate.is_equal(
                    ctx,
                    QuantumCell::Existing(&pre_substr_id),
                    QuantumCell::Existing(&assigned_substr_ids[idx]),
                );
                gate.not(ctx, QuantumCell::Existing(&is_eq))
            };
            let is_set = gate.and(
                ctx,
                QuantumCell::Existing(&assigned_is_start[idx]),
                QuantumCell::Existing(&is_changed),
            );
            let is_reset = {
                let not = gate.not(ctx, QuantumCell::Existing(&assigned_is_start[idx]));
                let and = gate.and(
                    ctx,
                    QuantumCell::Existing(&not),
                    QuantumCell::Existing(&assigned_is_end[idx]),
                );
                gate.and(
                    ctx,
                    QuantumCell::Existing(&and),
                    QuantumCell::Existing(&is_changed),
                )
            };
            let mut new_mask = gate.select(
                ctx,
                QuantumCell::Constant(F::from(1u64)),
                QuantumCell::Existing(&last_start_mask),
                QuantumCell::Existing(&is_set),
            );
            new_mask = gate.select(
                ctx,
                QuantumCell::Constant(F::from(0u64)),
                QuantumCell::Existing(&new_mask),
                QuantumCell::Existing(&is_reset),
            );
            start_mask.push(new_mask.clone());
            last_start_mask = new_mask;
        }
        // for (is_start, is_end) in assigned_is_start.iter().zip(assigned_is_end.iter()) {
        //     let new_mask = {
        //         let not_end = gate.not(ctx, QuantumCell::Existing(&is_end));
        //         let and = gate.and(
        //             ctx,
        //             QuantumCell::Existing(&not_end),
        //             QuantumCell::Existing(&last_start_mask),
        //         );
        //         gate.or(
        //             ctx,
        //             QuantumCell::Existing(&is_start),
        //             QuantumCell::Existing(&and),
        //         )
        //     };
        //     start_mask.push(new_mask.clone());
        //     last_start_mask = new_mask;
        // }
        let mut last_end_mask = gate.load_zero(ctx);
        for idx in 0..self.max_chars_size {
            let is_changed = {
                let pre_substr_id = if idx == 0 {
                    gate.load_zero(ctx)
                } else {
                    assigned_substr_ids[self.max_chars_size - idx].clone()
                };
                let is_eq = gate.is_equal(
                    ctx,
                    QuantumCell::Existing(&pre_substr_id),
                    QuantumCell::Existing(&assigned_substr_ids[self.max_chars_size - 1 - idx]),
                );
                gate.not(ctx, QuantumCell::Existing(&is_eq))
            };
            let is_set = gate.and(
                ctx,
                QuantumCell::Existing(&assigned_is_end[self.max_chars_size - idx]),
                QuantumCell::Existing(&is_changed),
            );
            let is_reset = {
                let not = gate.not(
                    ctx,
                    QuantumCell::Existing(&assigned_is_end[self.max_chars_size - idx]),
                );
                let and = gate.and(
                    ctx,
                    QuantumCell::Existing(&not),
                    QuantumCell::Existing(&assigned_is_start[self.max_chars_size - idx]),
                );
                gate.and(
                    ctx,
                    QuantumCell::Existing(&and),
                    QuantumCell::Existing(&is_changed),
                )
            };
            let mut new_mask = gate.select(
                ctx,
                QuantumCell::Constant(F::from(1u64)),
                QuantumCell::Existing(&last_end_mask),
                QuantumCell::Existing(&is_set),
            );
            new_mask = gate.select(
                ctx,
                QuantumCell::Constant(F::from(0u64)),
                QuantumCell::Existing(&new_mask),
                QuantumCell::Existing(&is_reset),
            );
            end_mask.push(new_mask.clone());
            last_end_mask = new_mask;
        }
        end_mask.reverse();

        // for (is_start, is_end) in assigned_is_start
        //     .iter()
        //     .rev()
        //     .zip(assigned_is_end.iter().rev())
        // {
        //     let new_mask = {
        //         let not_start = gate.not(ctx, QuantumCell::Existing(&is_start));
        //         let and = gate.and(
        //             ctx,
        //             QuantumCell::Existing(&not_start),
        //             QuantumCell::Existing(&last_end_mask),
        //         );
        //         gate.or(
        //             ctx,
        //             QuantumCell::Existing(&is_end),
        //             QuantumCell::Existing(&and),
        //         )
        //     };
        //     end_mask.push(new_mask.clone());
        //     last_end_mask = new_mask;
        // }
        // end_mask.reverse();
        // end_mask = vec![&end_mask[1..], &[gate.load_constant(ctx, F::one())][..]].concat();

        for idx in 0..self.max_chars_size {
            let mask = gate.and(
                ctx,
                QuantumCell::Existing(&start_mask[idx]),
                QuantumCell::Existing(&end_mask[idx]),
            );
            // println!(
            //     "idx {} char {} start_mask {:?} end_mask {:?}",
            //     idx, characters[idx] as char, &start_mask[idx], &end_mask[idx],
            // );
            // let is_zero = gate.is_zero(ctx, &assigned_substr_ids[idx]);
            // let is_not_zero = gate.not(ctx, QuantumCell::Existing(&is_zero));
            let masked_char = gate.mul(
                ctx,
                QuantumCell::Existing(&mask),
                QuantumCell::Existing(&assigned_characters[idx]),
            );
            let masked_substr_id = gate.mul(
                ctx,
                QuantumCell::Existing(&mask),
                QuantumCell::Existing(&assigned_substr_ids[idx]),
            );
            masked_characters.push(masked_char);
            masked_substr_ids.push(masked_substr_id);
        }

        let result = AssignedRegexResult {
            all_characters: assigned_characters,
            all_enable_flags: assigned_enables,
            all_substr_ids: masked_substr_ids,
            masked_characters,
        };
        Ok(result)
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let mut substr_id_offset = 1;
        for (idx, table) in self.table_array.iter().enumerate() {
            substr_id_offset = table.load(layouter, &self.regex_defs[idx], substr_id_offset)?;
        }
        Ok(())
    }

    fn gate(&self) -> &FlexGateConfig<F> {
        &self.gate
    }

    fn assigned_cell2value<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        assigned_cell: &AssignedCell<F, F>,
    ) -> Result<AssignedValue<'v, F>, Error> {
        let gate = self.gate();
        let assigned_value = gate.load_witness(ctx, assigned_cell.value().map(|v| *v));
        ctx.region
            .constrain_equal(assigned_cell.cell(), assigned_value.cell())?;
        Ok(assigned_value)
    }

    pub(crate) fn derive_states(&self, characters: &[u8]) -> Vec<Vec<u64>> {
        let mut states = vec![];
        for (d_idx, defs) in self.regex_defs.iter().enumerate() {
            states.push(vec![defs.allstr.first_state_val]);
            for (c_idx, char) in characters.into_iter().enumerate() {
                let state = states[d_idx][c_idx];
                let next_state = defs.allstr.state_lookup.get(&(*char, state));
                // println!(
                //     "d_idx {} c_idx {} char {} state {}",
                //     d_idx, c_idx, char, state,
                // );
                match next_state {
                    Some((_, s)) => states[d_idx].push(*s),
                    None => panic!("The transition from {} by {} is invalid!", state, *char),
                }
            }
            assert_eq!(states[d_idx].len(), characters.len() + 1);
        }
        states
    }

    pub(crate) fn derive_substr_ids(&self, states: &[Vec<u64>]) -> Vec<Vec<usize>> {
        let mut substr_ids: Vec<Vec<usize>> = vec![];
        let mut substr_id_offset = 1;
        for (d_idx, defs) in self.regex_defs.iter().enumerate() {
            substr_ids.push(vec![0; states[d_idx].len() - 1]);
            for state_idx in 0..(states[d_idx].len() - 1) {
                for (substr_idx, substr_def) in defs.substrs.iter().enumerate() {
                    if substr_def
                        .valid_state_transitions
                        .get(&(states[d_idx][state_idx], states[d_idx][state_idx + 1]))
                        .is_some()
                    {
                        substr_ids[d_idx][state_idx] = substr_id_offset + substr_idx;
                        break;
                    }
                }
            }
            substr_id_offset += defs.substrs.len();
        }
        substr_ids
    }

    pub(crate) fn derive_is_start_end(
        &self,
        states: &[Vec<u64>],
        substr_ids: &[Vec<usize>],
    ) -> (Vec<Vec<bool>>, Vec<Vec<bool>>) {
        let mut is_starts_array = vec![];
        let mut is_ends_array = vec![];
        let mut substr_id_offset = 1usize;
        for (d_idx, defs) in self.regex_defs.iter().enumerate() {
            let state_len = states[d_idx].len();
            let mut is_starts = states[d_idx][0..state_len - 1]
                .iter()
                .zip(substr_ids[d_idx].iter())
                .map(|(state, substr_id)| {
                    if *substr_id == 0 {
                        return false;
                    }
                    let substr_idx = *substr_id - substr_id_offset;
                    let valid_start_states = &defs.substrs[substr_idx].start_states;
                    valid_start_states.contains(state)
                })
                .collect::<Vec<bool>>();
            is_starts.push(false);
            let is_ends = states[d_idx][1..]
                .iter()
                .zip(substr_ids[d_idx].iter())
                .map(|(state, substr_id)| {
                    if *substr_id == 0 {
                        return false;
                    }
                    let substr_idx: usize = *substr_id - substr_id_offset;
                    let valid_end_states = &defs.substrs[substr_idx].end_states;
                    valid_end_states.contains(state)
                })
                .collect::<Vec<bool>>();
            let is_ends = vec![&vec![false][..], &is_ends].concat();
            is_starts_array.push(is_starts);
            is_ends_array.push(is_ends);
            substr_id_offset += defs.substrs.len();
        }
        (is_starts_array, is_ends_array)
    }
}

#[cfg(test)]
mod test {
    use halo2_base::halo2_proofs::{
        dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::{Bn256, Fr, G1Affine, G1},
        plonk::{Any, Circuit},
    };
    use halo2_base::{gates::range::RangeStrategy::Vertical, ContextParams, SKIP_FIRST_PASS};

    use super::*;
    use crate::{
        defs::{AllstrRegexDef, SubstrRegexDef},
        vrm::DecomposedRegexConfig,
    };

    use halo2_base::halo2_proofs::plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, ConstraintSystem,
    };
    use halo2_base::halo2_proofs::poly::commitment::{Params, ParamsProver, ParamsVerifier};
    use halo2_base::halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
    use halo2_base::halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
    use halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
    use halo2_base::halo2_proofs::transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    };
    use rand::rngs::OsRng;
    use std::marker::PhantomData;
    use std::{collections::HashSet, path::Path};

    use super::*;

    use halo2_base::halo2_proofs::{
        circuit::{floor_planner::V1, Cell, SimpleFloorPlanner},
        plonk::{Column, Instance},
    };
    use itertools::Itertools;

    // Checks a regex of string len
    const MAX_STRING_LEN: usize = 1024;
    const K: usize = 13;

    #[derive(Default, Clone, Debug)]
    struct TestCircuit1<F: PrimeField> {
        // Since this is only relevant for the witness, we can opt to make this whatever convenient type we want
        characters: Vec<u8>,
        correct_substrs: Vec<(usize, String)>,
        _marker: PhantomData<F>,
    }

    impl<F: PrimeField> TestCircuit1<F> {
        const NUM_ADVICE: usize = 25;
        const NUM_FIXED: usize = 1;
    }

    impl<F: PrimeField> Circuit<F> for TestCircuit1<F> {
        type Config = RegexVerifyConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        // Circuit without witnesses, called only during key generation
        fn without_witnesses(&self) -> Self {
            Self {
                characters: vec![],
                correct_substrs: vec![],
                _marker: PhantomData,
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let all_regex_def1 =
                AllstrRegexDef::read_from_text("./test_regexes/regex1_test_lookup.txt");
            let substr_def1 =
                SubstrRegexDef::read_from_text("./test_regexes/substr1_test_lookup.txt");
            let all_regex_def2 =
                AllstrRegexDef::read_from_text("./test_regexes/regex2_test_lookup.txt");
            let substr_def2 =
                SubstrRegexDef::read_from_text("./test_regexes/substr2_test_lookup.txt");
            // let substr_def2 =
            //     SubstrRegexDef::read_from_text("./test_regexes/substr2_test_lookup.txt");
            let gate = FlexGateConfig::<F>::configure(
                meta,
                halo2_base::gates::flex_gate::GateStrategy::Vertical,
                &[Self::NUM_ADVICE],
                Self::NUM_FIXED,
                0,
                K,
            );
            let regex_defs = vec![
                RegexDefs {
                    allstr: all_regex_def1,
                    substrs: vec![substr_def1],
                },
                RegexDefs {
                    allstr: all_regex_def2,
                    substrs: vec![substr_def2],
                },
            ];
            let config = RegexVerifyConfig::configure(meta, MAX_STRING_LEN, gate, regex_defs);
            config
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            // test regex: "email was meant for @(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_)+( and (a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+)*."
            config.load(&mut layouter)?;

            // println!("Synthesize being called...");
            let mut first_pass = SKIP_FIRST_PASS;
            let gate = config.gate().clone();
            // let mut substr_positions = self.substr_positions.to_vec();
            // for _ in substr_positions.len()..self.substr_def.max_length {
            //     substr_positions.push(0);
            // }

            layouter.assign_region(
                || "regex",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    let mut aux = Context::new(
                        region,
                        ContextParams {
                            max_rows: gate.max_rows,
                            num_context_ids: 1,
                            fixed_columns: gate.constants.clone(),
                        },
                    );
                    let ctx = &mut aux;
                    let result = config.match_substrs(ctx, &self.characters)?;
                    let mut expected_masked_chars = vec![0; MAX_STRING_LEN];
                    let mut expected_substr_ids = vec![0; MAX_STRING_LEN];

                    for (substr_idx, (start, chars)) in self.correct_substrs.iter().enumerate() {
                        for (idx, char) in chars.as_bytes().iter().enumerate() {
                            expected_masked_chars[start + idx] = *char;
                            expected_substr_ids[start + idx] = substr_idx + 1;
                        }
                    }
                    for idx in 0..MAX_STRING_LEN {
                        result.masked_characters[idx]
                            .value()
                            .map(|v| assert_eq!(*v, F::from(expected_masked_chars[idx] as u64)));
                        result.all_substr_ids[idx]
                            .value()
                            .map(|v| assert_eq!(*v, F::from(expected_substr_ids[idx] as u64)));
                    }
                    Ok(())
                },
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_substr_pass1() {
        let regex1_decomposed: DecomposedRegexConfig =
            serde_json::from_reader(File::open("./test_regexes/regex1_test.json").unwrap())
                .unwrap();
        regex1_decomposed
            .gen_regex_files(
                &Path::new("./test_regexes/regex1_test_lookup.txt").to_path_buf(),
                &[Path::new("./test_regexes/substr1_test_lookup.txt").to_path_buf()],
            )
            .unwrap();
        let regex2_decomposed: DecomposedRegexConfig =
            serde_json::from_reader(File::open("./test_regexes/regex2_test.json").unwrap())
                .unwrap();
        regex2_decomposed
            .gen_regex_files(
                &Path::new("./test_regexes/regex2_test_lookup.txt").to_path_buf(),
                &[Path::new("./test_regexes/substr2_test_lookup.txt").to_path_buf()],
            )
            .unwrap();
        let characters: Vec<u8> = "email was meant for @y. Also for x."
            .chars()
            .map(|c| c as u8)
            .collect();
        // Make a vector of the numbers 1...24
        // let states = (1..=STRING_LEN as u128).collect::<Vec<u128>>();
        // assert_eq!(characters.len(), STRING_LEN);
        // assert_eq!(states.len(), STRING_LEN);

        // Successful cases
        let circuit = TestCircuit1::<Fr> {
            characters,
            correct_substrs: vec![(21, "y".to_string()), (33, "x".to_string())],
            _marker: PhantomData,
        };

        let prover = MockProver::run(K as u32, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
        // CircuitCost::<Eq, RegexCheckCircuit<Fp>>::measure((k as u128).try_into().unwrap(), &circuit)
        println!(
            "{:?}",
            CircuitCost::<G1, TestCircuit1<Fr>>::measure((K as u128).try_into().unwrap(), &circuit)
        );
    }

    #[test]
    fn test_substr_pass2() {
        let regex1_decomposed: DecomposedRegexConfig =
            serde_json::from_reader(File::open("./test_regexes/regex1_test.json").unwrap())
                .unwrap();
        regex1_decomposed
            .gen_regex_files(
                &Path::new("./test_regexes/regex1_test_lookup.txt").to_path_buf(),
                &[Path::new("./test_regexes/substr1_test_lookup.txt").to_path_buf()],
            )
            .unwrap();
        let regex2_decomposed: DecomposedRegexConfig =
            serde_json::from_reader(File::open("./test_regexes/regex2_test.json").unwrap())
                .unwrap();
        regex2_decomposed
            .gen_regex_files(
                &Path::new("./test_regexes/regex2_test_lookup.txt").to_path_buf(),
                &[Path::new("./test_regexes/substr2_test_lookup.txt").to_path_buf()],
            )
            .unwrap();
        let characters: Vec<u8> = "email was meant for @yajk. Also for swq."
            .chars()
            .map(|c| c as u8)
            .collect();
        // Make a vector of the numbers 1...24
        // let states = (1..=STRING_LEN as u128).collect::<Vec<u128>>();
        // assert_eq!(characters.len(), STRING_LEN);
        // assert_eq!(states.len(), STRING_LEN);

        // Successful cases
        let circuit = TestCircuit1::<Fr> {
            characters,
            correct_substrs: vec![(21, "yajk".to_string()), (36, "swq".to_string())],
            _marker: PhantomData,
        };

        let prover = MockProver::run(K as u32, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
        // CircuitCost::<Eq, RegexCheckCircuit<Fp>>::measure((k as u128).try_into().unwrap(), &circuit)
        println!(
            "{:?}",
            CircuitCost::<G1, TestCircuit1<Fr>>::measure((K as u128).try_into().unwrap(), &circuit)
        );
    }

    #[test]
    fn test_substr_fail1() {
        let regex1_decomposed: DecomposedRegexConfig =
            serde_json::from_reader(File::open("./test_regexes/regex1_test.json").unwrap())
                .unwrap();
        regex1_decomposed
            .gen_regex_files(
                &Path::new("./test_regexes/regex1_test_lookup.txt").to_path_buf(),
                &[Path::new("./test_regexes/substr1_test_lookup.txt").to_path_buf()],
            )
            .unwrap();
        let regex2_decomposed: DecomposedRegexConfig =
            serde_json::from_reader(File::open("./test_regexes/regex2_test.json").unwrap())
                .unwrap();
        regex2_decomposed
            .gen_regex_files(
                &Path::new("./test_regexes/regex2_test_lookup.txt").to_path_buf(),
                &[Path::new("./test_regexes/substr2_test_lookup.txt").to_path_buf()],
            )
            .unwrap();
        // 1. The string does not satisfy the regex.
        let characters: Vec<u8> = "email was meant for @@".chars().map(|c| c as u8).collect();

        // Make a vector of the numbers 1...24
        // let states = (1..=STRING_LEN as u128).collect::<Vec<u128>>();
        // assert_eq!(characters.len(), STRING_LEN);
        // assert_eq!(states.len(), STRING_LEN);

        // Successful cases
        let circuit = TestCircuit1::<Fr> {
            characters,
            correct_substrs: vec![],
            _marker: PhantomData,
        };

        let prover = MockProver::run(K as u32, &circuit, vec![]).unwrap();
        match prover.verify() {
            Err(_) => {
                println!("Error successfully achieved!");
            }
            _ => assert!(false, "Should be error."),
        }
        // CircuitCost::<Eq, RegexCheckCircuit<Fp>>::measure((k as u128).try_into().unwrap(), &circuit)
        println!(
            "{:?}",
            CircuitCost::<G1, TestCircuit1<Fr>>::measure((K as u128).try_into().unwrap(), &circuit)
        );
    }

    #[test]
    fn test_substr_pass1_keygen_and_prove() {
        let regex1_decomposed: DecomposedRegexConfig =
            serde_json::from_reader(File::open("./test_regexes/regex1_test.json").unwrap())
                .unwrap();
        regex1_decomposed
            .gen_regex_files(
                &Path::new("./test_regexes/regex1_test_lookup.txt").to_path_buf(),
                &[Path::new("./test_regexes/substr1_test_lookup.txt").to_path_buf()],
            )
            .unwrap();
        let regex2_decomposed: DecomposedRegexConfig =
            serde_json::from_reader(File::open("./test_regexes/regex2_test.json").unwrap())
                .unwrap();
        regex2_decomposed
            .gen_regex_files(
                &Path::new("./test_regexes/regex2_test_lookup.txt").to_path_buf(),
                &[Path::new("./test_regexes/substr2_test_lookup.txt").to_path_buf()],
            )
            .unwrap();
        let characters: Vec<u8> = "email was meant for @y. Also for x."
            .chars()
            .map(|c| c as u8)
            .collect();

        let circuit = TestCircuit1::<Fr> {
            characters,
            correct_substrs: vec![(21, "y".to_string()), (33, "x".to_string())],
            _marker: PhantomData,
        };
        let prover = MockProver::run(K as u32, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        let emp_circuit = circuit.without_witnesses();
        let params = ParamsKZG::<Bn256>::setup(K as u32, OsRng);
        let vk = keygen_vk(&params, &emp_circuit).unwrap();
        let pk = keygen_pk(&params, vk.clone(), &emp_circuit).unwrap();
        let proof = {
            let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
            create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
                &params,
                &pk,
                &[circuit.clone()],
                &[&[]],
                OsRng,
                &mut transcript,
            )
            .unwrap();
            transcript.finalize()
        };
        {
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            let verifier_params = params.verifier_params();
            let strategy = SingleStrategy::new(&verifier_params);
            verify_proof::<_, VerifierGWC<_>, _, _, _>(
                verifier_params,
                &vk,
                strategy,
                &[&[]],
                &mut transcript,
            )
            .unwrap();
        }
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuit2<F: PrimeField> {
        characters: Vec<u8>,
        correct_substrs: Vec<(usize, String)>,
        is_success: bool,
        _marker: PhantomData<F>,
    }

    impl<F: PrimeField> TestCircuit2<F> {
        const NUM_ADVICE: usize = 25;
        const NUM_FIXED: usize = 1;
    }

    impl<F: PrimeField> Circuit<F> for TestCircuit2<F> {
        type Config = RegexVerifyConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        // Circuit without witnesses, called only during key generation
        fn without_witnesses(&self) -> Self {
            Self {
                characters: vec![],
                correct_substrs: vec![],
                is_success: false,
                _marker: PhantomData,
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let all_regex_def =
                AllstrRegexDef::read_from_text("./test_regexes/regex3_test_lookup.txt");
            let substr_def =
                SubstrRegexDef::read_from_text("./test_regexes/substr3_test_lookup.txt");
            let gate = FlexGateConfig::<F>::configure(
                meta,
                halo2_base::gates::flex_gate::GateStrategy::Vertical,
                &[Self::NUM_ADVICE],
                Self::NUM_FIXED,
                0,
                K,
            );
            let regex_defs = vec![RegexDefs {
                allstr: all_regex_def,
                substrs: vec![substr_def],
            }];
            let config = RegexVerifyConfig::configure(meta, MAX_STRING_LEN, gate, regex_defs);
            config
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            // test regex: "email was meant for @(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_)+( and (a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+)*."
            config.load(&mut layouter)?;

            // println!("Synthesize being called...");
            let mut first_pass = SKIP_FIRST_PASS;
            let gate = config.gate().clone();
            // let mut substr_positions = self.substr_positions.to_vec();
            // for _ in substr_positions.len()..self.substr_def.max_length {
            //     substr_positions.push(0);
            // }

            layouter.assign_region(
                || "regex",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    let mut aux = Context::new(
                        region,
                        ContextParams {
                            max_rows: gate.max_rows,
                            num_context_ids: 1,
                            fixed_columns: gate.constants.clone(),
                        },
                    );
                    let ctx = &mut aux;
                    let result = config.match_substrs(ctx, &self.characters)?;
                    let mut expected_masked_chars = vec![0; MAX_STRING_LEN];
                    let mut expected_substr_ids = vec![0; MAX_STRING_LEN];

                    if self.is_success {
                        for (substr_idx, (start, chars)) in self.correct_substrs.iter().enumerate()
                        {
                            for (idx, char) in chars.as_bytes().iter().enumerate() {
                                expected_masked_chars[start + idx] = *char;
                                expected_substr_ids[start + idx] = substr_idx + 1;
                            }
                        }
                        for idx in 0..MAX_STRING_LEN {
                            result.masked_characters[idx].value().map(|v| {
                                assert_eq!(*v, F::from(expected_masked_chars[idx] as u64))
                            });
                            result.all_substr_ids[idx]
                                .value()
                                .map(|v| assert_eq!(*v, F::from(expected_substr_ids[idx] as u64)));
                        }
                    }
                    Ok(())
                },
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_substr_pass3() {
        let regex_decomposed: DecomposedRegexConfig =
            serde_json::from_reader(File::open("./test_regexes/regex3_test.json").unwrap())
                .unwrap();
        regex_decomposed
            .gen_regex_files(
                &Path::new("./test_regexes/regex3_test_lookup.txt").to_path_buf(),
                &[Path::new("./test_regexes/substr3_test_lookup.txt").to_path_buf()],
            )
            .unwrap();
        let characters: Vec<u8> = "from:alice@gmail.com\r\n"
            .chars()
            .map(|c| c as u8)
            .collect();
        // Make a vector of the numbers 1...24
        // let states = (1..=STRING_LEN as u128).collect::<Vec<u128>>();
        // assert_eq!(characters.len(), STRING_LEN);
        // assert_eq!(states.len(), STRING_LEN);

        // Successful cases
        let circuit = TestCircuit2::<Fr> {
            characters,
            correct_substrs: vec![(5, "alice@gmail.com".to_string())],
            is_success: true,
            _marker: PhantomData,
        };

        let prover = MockProver::run(K as u32, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
        // CircuitCost::<Eq, RegexCheckCircuit<Fp>>::measure((k as u128).try_into().unwrap(), &circuit)
        println!(
            "{:?}",
            CircuitCost::<G1, TestCircuit2<Fr>>::measure((K as u128).try_into().unwrap(), &circuit)
        );
    }

    #[test]
    fn test_substr_pass4() {
        let regex_decomposed: DecomposedRegexConfig =
            serde_json::from_reader(File::open("./test_regexes/regex3_test.json").unwrap())
                .unwrap();
        regex_decomposed
            .gen_regex_files(
                &Path::new("./test_regexes/regex3_test_lookup.txt").to_path_buf(),
                &[Path::new("./test_regexes/substr3_test_lookup.txt").to_path_buf()],
            )
            .unwrap();
        let characters: Vec<u8> = "from:alice<alice@gmail.com>\r\n"
            .chars()
            .map(|c| c as u8)
            .collect();
        // Make a vector of the numbers 1...24
        // let states = (1..=STRING_LEN as u128).collect::<Vec<u128>>();
        // assert_eq!(characters.len(), STRING_LEN);
        // assert_eq!(states.len(), STRING_LEN);

        // Successful cases
        let circuit = TestCircuit2::<Fr> {
            characters,
            correct_substrs: vec![(11, "alice@gmail.com".to_string())],
            is_success: true,
            _marker: PhantomData,
        };

        let prover = MockProver::run(K as u32, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
        // CircuitCost::<Eq, RegexCheckCircuit<Fp>>::measure((k as u128).try_into().unwrap(), &circuit)
        println!(
            "{:?}",
            CircuitCost::<G1, TestCircuit2<Fr>>::measure((K as u128).try_into().unwrap(), &circuit)
        );
    }

    #[test]
    fn test_substr_fail2() {
        let regex_decomposed: DecomposedRegexConfig =
            serde_json::from_reader(File::open("./test_regexes/regex3_test.json").unwrap())
                .unwrap();
        regex_decomposed
            .gen_regex_files(
                &Path::new("./test_regexes/regex3_test_lookup.txt").to_path_buf(),
                &[Path::new("./test_regexes/substr3_test_lookup.txt").to_path_buf()],
            )
            .unwrap();
        let characters: Vec<u8> = "from:alice<alicegmail.com>\r\n"
            .chars()
            .map(|c| c as u8)
            .collect();
        // Make a vector of the numbers 1...24
        // let states = (1..=STRING_LEN as u128).collect::<Vec<u128>>();
        // assert_eq!(characters.len(), STRING_LEN);
        // assert_eq!(states.len(), STRING_LEN);

        // Successful cases
        let circuit = TestCircuit2::<Fr> {
            characters,
            correct_substrs: vec![],
            is_success: false,
            _marker: PhantomData,
        };

        let prover = MockProver::run(K as u32, &circuit, vec![]).unwrap();
        match prover.verify() {
            Err(_) => {
                println!("Error successfully achieved!");
            }
            _ => panic!("Should be error."),
        }
        // CircuitCost::<Eq, RegexCheckCircuit<Fp>>::measure((k as u128).try_into().unwrap(), &circuit)
        println!(
            "{:?}",
            CircuitCost::<G1, TestCircuit2<Fr>>::measure((K as u128).try_into().unwrap(), &circuit)
        );
    }

    #[test]
    fn test_substr_fail3() {
        let regex_decomposed: DecomposedRegexConfig =
            serde_json::from_reader(File::open("./test_regexes/regex3_test.json").unwrap())
                .unwrap();
        regex_decomposed
            .gen_regex_files(
                &Path::new("./test_regexes/regex3_test_lookup.txt").to_path_buf(),
                &[Path::new("./test_regexes/substr3_test_lookup.txt").to_path_buf()],
            )
            .unwrap();
        let characters: Vec<u8> = "from:alice<alice@gmail.com>"
            .chars()
            .map(|c| c as u8)
            .collect();
        // Make a vector of the numbers 1...24
        // let states = (1..=STRING_LEN as u128).collect::<Vec<u128>>();
        // assert_eq!(characters.len(), STRING_LEN);
        // assert_eq!(states.len(), STRING_LEN);

        // Successful cases
        let circuit = TestCircuit2::<Fr> {
            characters,
            correct_substrs: vec![],
            is_success: false,
            _marker: PhantomData,
        };

        let prover = MockProver::run(K as u32, &circuit, vec![]).unwrap();
        match prover.verify() {
            Err(_) => {
                println!("Error successfully achieved!");
            }
            _ => panic!("Should be error."),
        }
        // CircuitCost::<Eq, RegexCheckCircuit<Fp>>::measure((k as u128).try_into().unwrap(), &circuit)
        println!(
            "{:?}",
            CircuitCost::<G1, TestCircuit2<Fr>>::measure((K as u128).try_into().unwrap(), &circuit)
        );
    }

    #[test]
    fn test_substr_fail4() {
        let regex_decomposed: DecomposedRegexConfig =
            serde_json::from_reader(File::open("./test_regexes/regex3_test.json").unwrap())
                .unwrap();
        regex_decomposed
            .gen_regex_files(
                &Path::new("./test_regexes/regex3_test_lookup.txt").to_path_buf(),
                &[Path::new("./test_regexes/substr3_test_lookup.txt").to_path_buf()],
            )
            .unwrap();
        let characters: Vec<u8> = "fromalice<alice@gmail.com>\r\n"
            .chars()
            .map(|c| c as u8)
            .collect();
        // Make a vector of the numbers 1...24
        // let states = (1..=STRING_LEN as u128).collect::<Vec<u128>>();
        // assert_eq!(characters.len(), STRING_LEN);
        // assert_eq!(states.len(), STRING_LEN);

        // Successful cases
        let circuit = TestCircuit2::<Fr> {
            characters,
            correct_substrs: vec![],
            is_success: false,
            _marker: PhantomData,
        };

        let prover = MockProver::run(K as u32, &circuit, vec![]).unwrap();
        match prover.verify() {
            Err(_) => {
                println!("Error successfully achieved!");
            }
            _ => panic!("Should be error."),
        }
        // CircuitCost::<Eq, RegexCheckCircuit<Fp>>::measure((k as u128).try_into().unwrap(), &circuit)
        println!(
            "{:?}",
            CircuitCost::<G1, TestCircuit2<Fr>>::measure((K as u128).try_into().unwrap(), &circuit)
        );
    }
}
