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
use std::{collections::HashSet, marker::PhantomData};

use crate::table::TransitionTableConfig;
use crate::{AssignedRegexResult, RegexCheckConfig, RegexDef};

#[derive(Debug, Clone, Default)]
pub struct SubstrDef {
    max_length: usize,
    min_position: u64,
    max_position: u64,
    valid_state_transitions: HashSet<(u64, u64)>,
}

impl SubstrDef {
    pub fn new(
        max_length: usize,
        min_position: u64,
        max_position: u64,
        valid_state_transitions: HashSet<(u64, u64)>,
    ) -> Self {
        Self {
            max_length,
            min_position,
            max_position,
            valid_state_transitions,
        }
    }
}

// #[derive(Debug, Clone)]
// pub struct AssignedAllString<'a, F: PrimeField> {
//     pub enable_flags: Vec<AssignedValue<'a, F>>,
//     pub characters: Vec<AssignedValue<'a, F>>,
//     pub states: Vec<AssignedValue<'a, F>>,
//     pub indexes: Vec<AssignedValue<'a, F>>,
// }

#[derive(Debug, Clone, Default)]
pub struct AssignedSubstrsResult<'a, F: PrimeField> {
    pub all_enable_flags: Vec<AssignedValue<'a, F>>,
    pub all_characters: Vec<AssignedValue<'a, F>>,
    pub all_states: Vec<AssignedValue<'a, F>>,
    pub all_indexes: Vec<AssignedValue<'a, F>>,
    pub substrs_bytes: Vec<Vec<AssignedValue<'a, F>>>,
    pub substrs_length: Vec<AssignedValue<'a, F>>,
}

#[derive(Debug, Clone)]
pub struct SubstrMatchConfig<F: PrimeField> {
    regex_config: RegexCheckConfig<F>,
    range_gate: RangeConfig<F>,
    substr_defs: Vec<SubstrDef>,
    valid_state_transitions: Vec<(TableColumn, TableColumn)>,
    invalid_state_transitions: Vec<(TableColumn, TableColumn)>,
    substr_states: Vec<Column<Advice>>,
    is_valid: Vec<Column<Advice>>,
    selectors: Vec<Selector>,
}

impl<F: PrimeField> SubstrMatchConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        regex_def: RegexDef,
        max_chars_size: usize,
        range_gate: RangeConfig<F>,
        substr_defs: Vec<SubstrDef>,
    ) -> Self {
        let regex_config = RegexCheckConfig::configure(meta, regex_def, max_chars_size);
        let num_substr_defs = substr_defs.len();
        let valid_state_transitions = (0..num_substr_defs)
            .map(|_| (meta.lookup_table_column(), meta.lookup_table_column()))
            .collect::<Vec<(TableColumn, TableColumn)>>();
        let invalid_state_transitions = (0..num_substr_defs)
            .map(|_| (meta.lookup_table_column(), meta.lookup_table_column()))
            .collect::<Vec<(TableColumn, TableColumn)>>();
        let substr_states = (0..num_substr_defs)
            .map(|_| {
                let column = meta.advice_column();
                meta.enable_equality(column);
                column
            })
            .collect::<Vec<Column<Advice>>>();
        let is_valid = (0..num_substr_defs)
            .map(|_| {
                let column = meta.advice_column();
                meta.enable_equality(column);
                column
            })
            .collect::<Vec<Column<Advice>>>();
        let selectors = (0..num_substr_defs)
            .map(|_| meta.complex_selector())
            .collect::<Vec<Selector>>();

        meta.lookup("lookup substring states", |meta| {
            let mut lookup_vecs = Vec::new();
            for idx in 0..num_substr_defs {
                let selector = meta.query_selector(selectors[idx]);
                let substr_state_cur = meta.query_advice(substr_states[idx], Rotation::cur());
                let substr_state_next = meta.query_advice(substr_states[idx], Rotation::next());
                let is_valid_state = meta.query_advice(is_valid[idx], Rotation::cur());
                lookup_vecs.push((
                    selector.clone() * is_valid_state.clone() * substr_state_cur.clone(),
                    valid_state_transitions[idx].0,
                ));
                lookup_vecs.push((
                    selector.clone() * is_valid_state.clone() * substr_state_next.clone(),
                    valid_state_transitions[idx].1,
                ));
                let is_invalid_state = Expression::Constant(F::from(1u64)) - is_valid_state;
                lookup_vecs.push((
                    selector.clone() * is_invalid_state.clone() * substr_state_cur,
                    invalid_state_transitions[idx].0,
                ));
                lookup_vecs.push((
                    selector * is_invalid_state * substr_state_next,
                    invalid_state_transitions[idx].1,
                ));
            }
            lookup_vecs
        });

        Self {
            regex_config,
            range_gate,
            substr_defs,
            valid_state_transitions,
            invalid_state_transitions,
            substr_states,
            is_valid,
            selectors,
        }
    }

    pub fn match_substrs<'v: 'a, 'a>(
        &self,
        ctx: &mut Context<'v, F>,
        characters: &[u8],
    ) -> Result<AssignedSubstrsResult<'a, F>, Error> {
        let regex_result = self
            .regex_config
            .assign_values(&mut ctx.region, characters)?;
        let mut assigned_flags = Vec::new();
        let mut assigned_characters = Vec::new();
        let mut assigned_states = Vec::new();
        let mut assigned_indexes = Vec::new();
        let all_max_len = regex_result.enable_flags.len();
        let gate = self.gate();
        for idx in 0..all_max_len {
            let assigned_f = self.assigned_cell2value(ctx, &regex_result.enable_flags[idx])?;
            assigned_flags.push(assigned_f);
            let assigned_c = self.assigned_cell2value(ctx, &regex_result.characters[idx])?;
            assigned_characters.push(assigned_c);
            let assigned_s = self.assigned_cell2value(ctx, &regex_result.states[idx])?;
            assigned_states.push(assigned_s);
            let assigned_index = gate.load_constant(ctx, F::from(idx as u64));
            assigned_indexes.push(assigned_index);
        }
        let assigned_last_state =
            self.assigned_cell2value(ctx, &regex_result.states[all_max_len])?;
        assigned_states.push(assigned_last_state);

        let states = self.regex_config.derive_states(characters);
        let mut substrs_bytes: Vec<Vec<AssignedValue<'a, F>>> = Vec::new();
        let mut substrs_length: Vec<AssignedValue<'a, F>> = Vec::new();
        for (id_def, substr_def) in self.substr_defs.iter().enumerate() {
            let mut substr_start = None;
            let mut substr_end = all_max_len as u64;
            let mut in_matching = false;
            // let substr_max_len = substr_def.max_length;
            let valid_state_transitions = &substr_def.valid_state_transitions;
            for position in substr_def.min_position..=substr_def.max_position {
                if position >= characters.len() as u64 {
                    break;
                }
                let cur_state = states[position as usize];
                let next_state = states[position as usize + 1];
                match valid_state_transitions.get(&(cur_state, next_state)) {
                    Some(_) => {
                        if !in_matching {
                            in_matching = true;
                            substr_start = Some(position);
                        }
                    }
                    None => {
                        if !in_matching {
                            continue;
                        } else {
                            substr_end = position;
                            break;
                        }
                    }
                }
            }
            let substr_start = match substr_start {
                Some(x) => x,
                None => all_max_len as u64,
            };
            let mut assigned_chars = Vec::new();
            // let mut assigned_len = gate.load_zero(ctx);
            let assigned_start = gate.load_witness(ctx, Value::known(F::from(substr_start)));
            let assigned_end = gate.load_witness(ctx, Value::known(F::from(substr_end)));
            {
                // assigned_start <= assigned_end
                let range = self.range();
                // assigned_start > assigned_end
                let is_less = range.is_less_than(
                    ctx,
                    QuantumCell::Existing(&assigned_end),
                    QuantumCell::Existing(&assigned_start),
                    64,
                );
                gate.assert_is_const(ctx, &is_less, F::from(0u64));
            }
            // substr_positions.append(&mut vec![
            //     all_max_len as u64;
            //     substr_max_len - substr_positions.len()
            // ]);
            let mut offset = 0;
            for position in (substr_def.min_position as usize)..=(substr_def.max_position as usize)
            {
                let assigned_c = &assigned_characters[position];
                let assigned_s = &assigned_states[position];
                let assigned_i = &assigned_indexes[position];
                let is_valid_flag =
                    if position >= (substr_start as usize) && position < (substr_end as usize) {
                        gate.load_witness(ctx, Value::known(F::from(1)))
                    } else {
                        gate.load_witness(ctx, Value::known(F::from(0)))
                    };
                // if position < characters.len() {
                //     println!(
                //         "position {} char {}, cur_state {}, is_valid {}",
                //         position,
                //         characters[position as usize],
                //         states[position as usize],
                //         position >= (substr_start as usize) && position <= (substr_end as usize)
                //     );
                // }
                {
                    // state constraints.
                    let assigned_cell = ctx.region.assign_advice(
                        || format!("substr_states at {}", offset),
                        self.substr_states[id_def],
                        offset,
                        || assigned_s.value().map(|v| *v),
                    )?;
                    ctx.region
                        .constrain_equal(assigned_cell.cell(), assigned_s.cell())?;
                    let assigned_cell = ctx.region.assign_advice(
                        || format!("is_valid_state at {}", offset),
                        self.is_valid[id_def],
                        offset,
                        || is_valid_flag.value().map(|v| *v),
                    )?;
                    ctx.region
                        .constrain_equal(assigned_cell.cell(), is_valid_flag.cell())?;
                }
                {
                    // When is_valid_flag == 1, start <= index < end holds.
                    let range = self.range();
                    let i_less_than_start = range.is_less_than(
                        ctx,
                        QuantumCell::Existing(&assigned_i),
                        QuantumCell::Existing(&assigned_start),
                        64,
                    );
                    let start_check = gate.mul(
                        ctx,
                        QuantumCell::Existing(&is_valid_flag),
                        QuantumCell::Existing(&i_less_than_start),
                    );
                    gate.assert_is_const(ctx, &start_check, F::from(0));
                    let i_less_than_end = range.is_less_than(
                        ctx,
                        QuantumCell::Existing(&assigned_i),
                        QuantumCell::Existing(&assigned_end),
                        64,
                    );
                    let not_i_less_than_end =
                        gate.not(ctx, QuantumCell::Existing(&i_less_than_end));
                    let end_check = gate.mul(
                        ctx,
                        QuantumCell::Existing(&is_valid_flag),
                        QuantumCell::Existing(&not_i_less_than_end),
                    );
                    gate.assert_is_const(ctx, &end_check, F::from(0));
                }
                // {
                //     // The start index check. (0->1)
                //     assigned_start.value().map(|v| println!("start {:?}", v));
                //     is_valid_flag
                //         .value()
                //         .map(|v| println!("is_valid_flag {:?}", v));
                //     last_flag.value().map(|v| println!("last_flag {:?}", v));
                //     let index_sub_start = gate.sub(
                //         ctx,
                //         QuantumCell::Existing(&assigned_i),
                //         QuantumCell::Existing(&assigned_start),
                //     );
                //     let flag_sub_start = gate.sub(
                //         ctx,
                //         QuantumCell::Existing(&is_valid_flag),
                //         QuantumCell::Existing(&last_flag),
                //     );
                //     let muled_start = gate.mul(
                //         ctx,
                //         QuantumCell::Existing(&flag_sub_start),
                //         QuantumCell::Existing(&index_sub_start),
                //     );
                //     muled_start.value().map(|v| println!("muled_start {:?}", v));
                //     gate.assert_is_const(ctx, &muled_start, F::zero());
                // }
                // {
                //     // The end index check. (1->0)
                //     let index_sub_end = gate.sub(
                //         ctx,
                //         QuantumCell::Existing(&assigned_i),
                //         QuantumCell::Existing(&assigned_end),
                //     );
                //     let flag_sub_end = gate.sub(
                //         ctx,
                //         QuantumCell::Existing(&last_flag),
                //         QuantumCell::Existing(&is_valid_flag),
                //     );
                //     let muled_end = gate.mul(
                //         ctx,
                //         QuantumCell::Existing(&flag_sub_end),
                //         QuantumCell::Existing(&index_sub_end),
                //     );
                //     // gate.assert_is_const(ctx, &muled_end, F::zero());
                // }
                {
                    self.selectors[id_def].enable(&mut ctx.region, offset)?;
                }

                // let index_sub = gate.sub(
                //     ctx,
                //     QuantumCell::Existing(&assigned_i),
                //     QuantumCell::Existing(&assigned_target_i),
                // );
                // let selector = gate.is_zero(ctx, &index_sub);
                // // state constraints.
                // {
                //     let sub = gate.sub(
                //         ctx,
                //         QuantumCell::Existing(&assigned_s),
                //         QuantumCell::Constant(F::from(substr_def.correct_state)),
                //     );
                //     let state_constraint = gate.mul(
                //         ctx,
                //         QuantumCell::Existing(&selector),
                //         QuantumCell::Existing(&sub),
                //     );
                //     gate.assert_is_const(ctx, &state_constraint, F::zero());
                // }
                // // The selector constraints: 0->0, 1->0, 1->1 are allowed, but 0->1 is invalid!
                // {
                //     let sub = gate.sub(
                //         ctx,
                //         QuantumCell::Existing(&last_selector),
                //         QuantumCell::Existing(&selector),
                //     );
                //     gate.assert_bit(ctx, &sub);
                // }
                // new_substr_char = gate.mul_add(
                //     ctx,
                //     QuantumCell::Existing(&assigned_c),
                //     QuantumCell::Existing(&selector),
                //     QuantumCell::Existing(&new_substr_char),
                // );
                let substr_char = gate.mul(
                    ctx,
                    QuantumCell::Existing(&is_valid_flag),
                    QuantumCell::Existing(&assigned_c),
                );
                assigned_chars.push(substr_char);
                // assigned_len = gate.add(
                //     ctx,
                //     QuantumCell::Existing(&assigned_len),
                //     QuantumCell::Existing(&is_valid_flag),
                // );
                offset += 1;
            }
            let assigned_chars = self.shift_variable(ctx, &assigned_chars, &assigned_start);
            substrs_bytes.push(assigned_chars[0..substr_def.max_length].to_vec());
            let assigned_len = gate.sub(
                ctx,
                QuantumCell::Existing(&assigned_end),
                QuantumCell::Existing(&assigned_start),
            );
            substrs_length.push(assigned_len);
        }
        let result = AssignedSubstrsResult {
            all_enable_flags: assigned_flags,
            all_characters: assigned_characters,
            all_states: assigned_states,
            all_indexes: assigned_indexes,
            substrs_bytes: substrs_bytes,
            substrs_length: substrs_length,
        };
        Ok(result)
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.regex_config.load(layouter)?;
        layouter.assign_table(
            || "substring valid and invalid states",
            |mut table| {
                // let max_state_id = self.regex_config.regex_def.largest_state_val;
                for (id_def, substr_def) in self.substr_defs.iter().enumerate() {
                    let valid_state_transitions = &substr_def.valid_state_transitions;
                    let mut offset = 0;
                    for ((_, pre_state), next_state) in
                        self.regex_config.regex_def.state_lookup.iter()
                    {
                        match valid_state_transitions.get(&(*pre_state, *next_state)) {
                            Some(_) => {
                                table.assign_cell(
                                    || {
                                        format!(
                                            "{} is a valid previous state for the {}-th substring",
                                            pre_state, id_def
                                        )
                                    },
                                    self.valid_state_transitions[id_def].0,
                                    offset,
                                    || Value::known(F::from(*pre_state)),
                                )?;
                                table.assign_cell(
                                    || {
                                        format!(
                                            "{} is a valid next state for the {}-th substring",
                                            next_state, id_def
                                        )
                                    },
                                    self.valid_state_transitions[id_def].1,
                                    offset,
                                    || Value::known(F::from(*next_state)),
                                )?;
                                table.assign_cell(
                                    || {
                                        format!(
                                            "{} is not an invalid previous state for the {}-th substring",
                                            pre_state, id_def
                                        )
                                    },
                                    self.invalid_state_transitions[id_def].0,
                                    offset,
                                    || Value::known(F::from(0)),
                                )?;
                                table.assign_cell(
                                    || {
                                        format!(
                                            "{} is not an invalid next state for the {}-th substring",
                                            next_state, id_def
                                        )
                                    },
                                    self.invalid_state_transitions[id_def].1,
                                    offset,
                                    || Value::known(F::from(0)),
                                )?;
                            }
                            None => {
                                table.assign_cell(
                                    || {
                                        format!(
                                            "{} is not a valid previous state for the {}-th substring",
                                            pre_state, id_def
                                        )
                                    },
                                    self.valid_state_transitions[id_def].0,
                                    offset,
                                    || Value::known(F::from(0)),
                                )?;
                                table.assign_cell(
                                    || {
                                        format!(
                                            "{} is not a valid next state for the {}-th substring",
                                            next_state, id_def
                                        )
                                    },
                                    self.valid_state_transitions[id_def].1,
                                    offset,
                                    || Value::known(F::from(0)),
                                )?;
                                table.assign_cell(
                                    || {
                                        format!(
                                            "{} is an invalid previous state for the {}-th substring",
                                            pre_state, id_def
                                        )
                                    },
                                    self.invalid_state_transitions[id_def].0,
                                    offset,
                                    || Value::known(F::from(*pre_state)),
                                )?;
                                table.assign_cell(
                                    || {
                                        format!(
                                            "{} is an invalid next state for the {}-th substring",
                                            next_state, id_def
                                        )
                                    },
                                    self.invalid_state_transitions[id_def].1,
                                    offset,
                                    || Value::known(F::from(*next_state)),
                                )?;
                            }
                        };
                        offset += 1;
                    }
                    table.assign_cell(
                        || {
                            format!(
                                "{} is not a valid previous state for the {}-th substring",
                                0, id_def
                            )
                        },
                        self.valid_state_transitions[id_def].0,
                        offset,
                        || Value::known(F::from(0)),
                    )?;
                    table.assign_cell(
                        || {
                            format!(
                                "{} is not a valid next state for the {}-th substring",
                                0, id_def
                            )
                        },
                        self.valid_state_transitions[id_def].1,
                        offset,
                        || Value::known(F::from(0)),
                    )?;
                    table.assign_cell(
                        || {
                            format!(
                                "{} is an invalid previous state for the {}-th substring",
                                0, id_def
                            )
                        },
                        self.invalid_state_transitions[id_def].0,
                        offset,
                        || Value::known(F::from(0)),
                    )?;
                    table.assign_cell(
                        || {
                            format!(
                                "{} is an invalid next state for the {}-th substring",
                                0, id_def
                            )
                        },
                        self.invalid_state_transitions[id_def].1,
                        offset,
                        || Value::known(F::from(0)),
                    )?;
                    offset += 1;
                    for accepted_state in self.regex_config.regex_def.accepted_state_vals.iter() {
                        table.assign_cell(
                            || {
                                format!(
                                    "{} is not a valid previous state for the {}-th substring",
                                    0, id_def
                                )
                            },
                            self.valid_state_transitions[id_def].0,
                            offset,
                            || Value::known(F::from(0)),
                        )?;
                        table.assign_cell(
                            || {
                                format!(
                                    "{} is not a valid next state for the {}-th substring",
                                    0, id_def
                                )
                            },
                            self.valid_state_transitions[id_def].1,
                            offset,
                            || Value::known(F::from(0)),
                        )?;
                        table.assign_cell(
                            || {
                                format!(
                                    "{} is an invalid previous state for the {}-th substring",
                                    accepted_state, id_def
                                )
                            },
                            self.invalid_state_transitions[id_def].0,
                            offset,
                            || Value::known(F::from(*accepted_state)),
                        )?;
                        table.assign_cell(
                            || {
                                format!(
                                    "{} is not an invalid next state for the {}-th substring",
                                    0, id_def
                                )
                            },
                            self.invalid_state_transitions[id_def].1,
                            offset,
                            || Value::known(F::from(0)),
                        )?;
                        offset += 1;
                    }
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    fn range(&self) -> &RangeConfig<F> {
        &self.range_gate
    }

    fn gate(&self) -> &FlexGateConfig<F> {
        self.range().gate()
    }

    fn shift_variable<'v: 'a, 'a>(
        &self,
        ctx: &mut Context<'v, F>,
        inputs: &[AssignedValue<'a, F>],
        shift_value: &AssignedValue<'a, F>,
    ) -> Vec<AssignedValue<'a, F>> {
        const MAX_SHIFT_BITS: usize = 64;
        let gate = self.gate();
        let mut shift_value_bits = gate.num_to_bits(ctx, shift_value, MAX_SHIFT_BITS);
        let mut prev_tmp = inputs.to_vec();
        let max_len = inputs.len();
        let mut new_tmp = (0..max_len)
            .into_iter()
            .map(|_| gate.load_zero(ctx))
            .collect::<Vec<AssignedValue<F>>>();

        for log_offset in 0..MAX_SHIFT_BITS {
            for position in 0..max_len {
                let offset = (position + (1 << log_offset)) % max_len;
                let value_offset = gate.select(
                    ctx,
                    QuantumCell::Existing(&prev_tmp[offset]),
                    QuantumCell::Existing(&prev_tmp[position]),
                    QuantumCell::Existing(&shift_value_bits[log_offset]),
                );
                new_tmp[position] = value_offset;
            }
            prev_tmp = new_tmp.to_vec();
        }
        new_tmp
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
}

#[cfg(test)]
mod test {
    use halo2_base::halo2_proofs::{
        circuit::floor_planner::V1,
        dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::{Fr, G1},
        plonk::{Any, Circuit},
    };
    use halo2_base::{gates::range::RangeStrategy::Vertical, ContextParams, SKIP_FIRST_PASS};

    use super::*;
    use crate::table::RegexDef;

    // Checks a regex of string len
    const MAX_STRING_LEN: usize = 128;
    const K: usize = 13;

    #[derive(Default, Clone, Debug)]
    struct TestSubstrMatchCircuit<F: PrimeField> {
        // Since this is only relevant for the witness, we can opt to make this whatever convenient type we want
        characters: Vec<u8>,
        correct_substrs: Vec<String>,
        _marker: PhantomData<F>,
    }

    impl<F: PrimeField> TestSubstrMatchCircuit<F> {
        const NUM_ADVICE: usize = 50;
        const NUM_FIXED: usize = 1;
        const NUM_LOOKUP_ADVICE: usize = 8;
        const LOOKUP_BITS: usize = 12;
    }

    impl<F: PrimeField> Circuit<F> for TestSubstrMatchCircuit<F> {
        type Config = SubstrMatchConfig<F>;
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
            let lookup_filepath = "./test_regexes/regex_test_lookup.txt";
            let regex_def = RegexDef::read_from_text(lookup_filepath);
            let substr_def1 = SubstrDef {
                max_length: 4,
                min_position: 0,
                max_position: MAX_STRING_LEN as u64 - 1,
                valid_state_transitions: HashSet::from([(29, 1), (1, 1)]),
            };
            let substr_def2 = SubstrDef {
                max_length: 20,
                min_position: 0,
                max_position: MAX_STRING_LEN as u64 - 1,
                valid_state_transitions: HashSet::from([
                    (4, 8),
                    (8, 9),
                    (9, 10),
                    (10, 11),
                    (11, 12),
                    (12, 4),
                    (12, 12),
                ]),
            };
            let range_config = RangeConfig::configure(
                meta,
                Vertical,
                &[Self::NUM_ADVICE],
                &[Self::NUM_LOOKUP_ADVICE],
                Self::NUM_FIXED,
                Self::LOOKUP_BITS,
                0,
                K,
            );
            let config = SubstrMatchConfig::configure(
                meta,
                regex_def,
                MAX_STRING_LEN,
                range_config,
                vec![substr_def1, substr_def2],
            );
            config
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            // test regex: "email was meant for @(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_)+( and (a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+)*."
            config.load(&mut layouter)?;
            config.range_gate.load_lookup_table(&mut layouter)?;
            // let mut states = vec![RegexCheckConfig::<F>::STATE_FIRST];
            // // let mut next_state = START_STATE;

            // // Set the states to transition via the character and state that appear in the array, to the third value in each array tuple
            // for idx in 0..self.characters.len() {
            //     let character = self.characters[idx];
            //     // states[i] = next_state;
            //     let state = states[idx];
            //     // next_state = START_STATE; // Default to start state if no match found
            //     let mut is_found = false;
            //     for j in 0..array.len() {
            //         if array[j][2] == character as u64 && array[j][0] == state {
            //             // next_state = array[j][1] as u64;
            //             states.push(array[j][1]);
            //             is_found = true;
            //             break;
            //         }
            //     }
            //     if !is_found {
            //         states.push(RegexCheckConfig::<F>::STATE_FIRST);
            //     }
            // }
            // assert_eq!(states.len(), self.characters.len() + 1);

            println!("Synthesize being called...");
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
                    for (idx, assigned_len) in result.substrs_length.iter().enumerate() {
                        assigned_len.value().map(|v| assert_eq!(*v,F::from(self.correct_substrs[idx].len() as u64)));
                    }
                    for (idx, assigned_bytes) in result.substrs_bytes.iter().enumerate() {
                        for (j, byte) in self.correct_substrs[idx].as_bytes().into_iter().enumerate() {
                            assigned_bytes[j].value().map(|v| assert_eq!(*v, F::from(*byte as u64)));
                        }
                    }
                    config.range().finalize(ctx);
                    Ok(())
                },
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_substr_pass1() {
        let characters: Vec<u8> = "email was meant for @y.".chars().map(|c| c as u8).collect();
        // Make a vector of the numbers 1...24
        // let states = (1..=STRING_LEN as u128).collect::<Vec<u128>>();
        // assert_eq!(characters.len(), STRING_LEN);
        // assert_eq!(states.len(), STRING_LEN);

        // Successful cases
        let circuit = TestSubstrMatchCircuit::<Fr> {
            characters,
            correct_substrs: vec!["y".to_string(), "".to_string()],
            _marker: PhantomData,
        };

        let prover = MockProver::run(K as u32, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
        // CircuitCost::<Eq, RegexCheckCircuit<Fp>>::measure((k as u128).try_into().unwrap(), &circuit)
        println!(
            "{:?}",
            CircuitCost::<G1, TestSubstrMatchCircuit<Fr>>::measure(
                (K as u128).try_into().unwrap(),
                &circuit
            )
        );
    }

    #[test]
    fn test_substr_pass2() {
        let characters: Vec<u8> = "email was meant for @yajk."
            .chars()
            .map(|c| c as u8)
            .collect();
        // Make a vector of the numbers 1...24
        // let states = (1..=STRING_LEN as u128).collect::<Vec<u128>>();
        // assert_eq!(characters.len(), STRING_LEN);
        // assert_eq!(states.len(), STRING_LEN);

        // Successful cases
        let circuit = TestSubstrMatchCircuit::<Fr> {
            characters,
            correct_substrs: vec!["yajk".to_string(), "".to_string()],
            _marker: PhantomData,
        };

        let prover = MockProver::run(K as u32, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
        // CircuitCost::<Eq, RegexCheckCircuit<Fp>>::measure((k as u128).try_into().unwrap(), &circuit)
        println!(
            "{:?}",
            CircuitCost::<G1, TestSubstrMatchCircuit<Fr>>::measure(
                (K as u128).try_into().unwrap(),
                &circuit
            )
        );
    }

    #[test]
    fn test_substr_pass3() {
        let characters: Vec<u8> = "email was meant for @yajk and kaiew and oiewk."
            .chars()
            .map(|c| c as u8)
            .collect();
        // Make a vector of the numbers 1...24
        // let states = (1..=STRING_LEN as u128).collect::<Vec<u128>>();
        // assert_eq!(characters.len(), STRING_LEN);
        // assert_eq!(states.len(), STRING_LEN);

        // Successful cases
        let circuit = TestSubstrMatchCircuit::<Fr> {
            characters,
            correct_substrs: vec!["yajk".to_string(), "and kaiew and oiewk".to_string()],
            _marker: PhantomData,
        };

        let prover = MockProver::run(K as u32, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
        // CircuitCost::<Eq, RegexCheckCircuit<Fp>>::measure((k as u128).try_into().unwrap(), &circuit)
        println!(
            "{:?}",
            CircuitCost::<G1, TestSubstrMatchCircuit<Fr>>::measure(
                (K as u128).try_into().unwrap(),
                &circuit
            )
        );
    }

    #[test]
    fn test_substr_fail1() {
        // 1. The string does not satisfy the regex.
        let characters: Vec<u8> = "email was meant for @@".chars().map(|c| c as u8).collect();

        // Make a vector of the numbers 1...24
        // let states = (1..=STRING_LEN as u128).collect::<Vec<u128>>();
        // assert_eq!(characters.len(), STRING_LEN);
        // assert_eq!(states.len(), STRING_LEN);

        // Successful cases
        let circuit = TestSubstrMatchCircuit::<Fr> {
            characters,
            correct_substrs: vec!["".to_string(), "".to_string()],
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
            CircuitCost::<G1, TestSubstrMatchCircuit<Fr>>::measure(
                (K as u128).try_into().unwrap(),
                &circuit
            )
        );
    }
}
