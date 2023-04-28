use std::{collections::HashMap, fmt::format, marker::PhantomData};

use halo2_base::halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error, TableColumn},
};
use halo2_base::utils::PrimeField;
use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::defs::{AllstrRegexDef, SubstrRegexDef};

#[derive(Debug, Clone)]
pub struct RegexTableConfig<F: PrimeField> {
    pub(crate) characters: TableColumn,
    pub(crate) cur_states: TableColumn,
    pub(crate) next_states: TableColumn,
    pub(crate) substr_ids: TableColumn,
    // pub(crate) accepted_states: TableColumn,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> RegexTableConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let characters = meta.lookup_table_column();
        let cur_states = meta.lookup_table_column();
        let next_states = meta.lookup_table_column();
        let substr_ids = meta.lookup_table_column();
        // let accepted_states = meta.lookup_table_column();

        Self {
            characters,
            cur_states,
            next_states,
            substr_ids,
            // accepted_states,
            _marker: PhantomData,
        }
    }

    pub fn load(
        &self,
        layouter: &mut impl Layouter<F>,
        all_regex_def: &AllstrRegexDef,
        sub_regex_def: &SubstrRegexDef,
        substr_id: usize,
    ) -> Result<(), Error> {
        let dummy_state = all_regex_def.largest_state_val + 1;
        layouter.assign_table(
            || "load transition table",
            |mut table| {
                let mut offset = 0;
                let mut assign_row =
                    |char: u8, cur_state: u64, next_state: u64, substr_id: usize| {
                        table.assign_cell(
                            || format!("character at {}", offset),
                            self.characters,
                            offset,
                            || Value::known(F::from(char as u64)),
                        )?;
                        table.assign_cell(
                            || format!("cur_state at {}", offset),
                            self.cur_states,
                            offset,
                            || Value::known(F::from(cur_state)),
                        )?;
                        table.assign_cell(
                            || format!("next_state at {}", offset),
                            self.next_states,
                            offset,
                            || Value::known(F::from(next_state)),
                        )?;
                        table.assign_cell(
                            || format!("substr_id at {}", offset),
                            self.substr_ids,
                            offset,
                            || Value::known(F::from(substr_id as u64)),
                        )?;
                        offset += 1;
                        Ok::<(), Error>(())
                    };
                // let mut array = lookups.to_vec();
                // Append a dummy row [0, 0, 0, 0].
                assign_row(0, dummy_state, dummy_state, 0)?;
                // [IMPORTANT] We must sort the keys of `state_lookup`. Otherwise, its order is variable, which derives different verifying key for each setup.
                let mut lookups = all_regex_def
                    .state_lookup
                    .iter()
                    .collect::<Vec<(&(u8, u64), &(usize, u64))>>();
                lookups.sort_by(|a, b| a.1 .0.cmp(&b.1 .0));
                for ((char, cur_state), (idx, next_state)) in lookups.into_iter() {
                    if sub_regex_def
                        .valid_state_transitions
                        .get(&(*cur_state, *next_state))
                        .is_some()
                    {
                        assign_row(*char, *cur_state, *next_state, substr_id)?;
                    } else {
                        assign_row(*char, *cur_state, *next_state, 0)?;
                    }
                }
                Ok(())
            },
        )?;
        // layouter.assign_table(
        //     || "accepted states",
        //     |mut table| {
        //         let mut offset = 0;
        //         let mut accepted_state_vals = all_regex_def.accepted_state_vals.to_vec();
        //         accepted_state_vals.push(dummy_state);
        //         for state in accepted_state_vals.into_iter() {
        //             table.assign_cell(
        //                 || format!("accepted_state at {}", offset),
        //                 self.accepted_states,
        //                 offset,
        //                 || Value::known(F::from(state)),
        //             )?;
        //             offset += 1;
        //         }
        //         Ok(())
        //     },
        // )?;
        Ok(())
    }
}
