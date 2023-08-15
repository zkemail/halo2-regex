use std::{collections::HashMap, fmt::format, marker::PhantomData};

use halo2_base::halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error, TableColumn},
};
use halo2_base::utils::PrimeField;
use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::defs::{AllstrRegexDef, RegexDefs, SubstrRegexDef};
use crate::RegexVerifyConfig;

/// Lookup tables used in [`RegexVerifyConfig`].
#[derive(Debug, Clone)]
pub struct RegexTableConfig<F: PrimeField> {
    pub(crate) characters: TableColumn,
    pub(crate) cur_states: TableColumn,
    pub(crate) next_states: TableColumn,
    pub(crate) substr_ids: TableColumn,
    pub(crate) endpoints_substr_ids: TableColumn,
    pub(crate) start_states: TableColumn,
    pub(crate) end_states: TableColumn,
    dummy_state_val: u64,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> RegexTableConfig<F> {
    /// Configure a new [`RegexTableConfig`].
    /// # Arguments
    /// * `meta` - a constrain system in which contraints are defined.
    pub fn configure(meta: &mut ConstraintSystem<F>, dummy_state_val: u64) -> Self {
        let characters = meta.lookup_table_column();
        let cur_states = meta.lookup_table_column();
        let next_states = meta.lookup_table_column();
        let substr_ids = meta.lookup_table_column();
        let endpoints_substr_ids = meta.lookup_table_column();
        let start_states = meta.lookup_table_column();
        let end_states = meta.lookup_table_column();

        Self {
            characters,
            cur_states,
            next_states,
            substr_ids,
            endpoints_substr_ids,
            start_states,
            end_states,
            dummy_state_val,
            _marker: PhantomData,
        }
    }

    /// Load looup tables used in [`RegexVerifyConfig`].
    ///
    /// # Arguments
    /// * `layouter` - a [`Layouter`] in which the lookup tables are loaded.
    /// * `regex_defs` - a regex definition that the input string must satisfy.
    /// * `substr_id_offset` - a `substr_id` of the first substring of `regex_defs`.
    ///
    /// # Return values
    /// Return `substr_id_offset + regex_defs.substrs.len()`.
    pub fn load(
        &self,
        layouter: &mut impl Layouter<F>,
        regex_defs: &RegexDefs,
        substr_id_offset: usize,
    ) -> Result<usize, Error> {
        let dummy_state = self.dummy_state_val;
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
                assign_row(0, dummy_state, dummy_state, 0)?;
                // [IMPORTANT] We must sort the keys of `state_lookup`. Otherwise, its order is variable, which derives different verifying key for each setup.
                let mut lookups = regex_defs
                    .allstr
                    .state_lookup
                    .iter()
                    .collect::<Vec<(&(u8, u64), &(usize, u64))>>();
                lookups.sort_by(|a, b| a.1 .0.cmp(&b.1 .0));
                for ((char, cur_state), (idx, next_state)) in lookups.into_iter() {
                    let mut substr_id = 0;
                    for (j, substr_def) in regex_defs.substrs.iter().enumerate() {
                        if substr_def
                            .valid_state_transitions
                            .get(&(*cur_state, *next_state))
                            .is_some()
                        {
                            substr_id = substr_id_offset + j;
                            break;
                        }
                    }
                    assign_row(*char, *cur_state, *next_state, substr_id)?;
                }
                Ok(())
            },
        )?;
        layouter.assign_table(
            || "endpoint states",
            |mut table| {
                let mut offset = 0;
                table.assign_cell(
                    || format!("endpoints_substr_ids at {}", offset),
                    self.endpoints_substr_ids,
                    offset,
                    || Value::known(F::from(0 as u64)),
                )?;
                table.assign_cell(
                    || format!("start_states at {}", offset),
                    self.start_states,
                    offset,
                    || Value::known(F::from(dummy_state as u64)),
                )?;
                table.assign_cell(
                    || format!("end_states at {}", offset),
                    self.end_states,
                    offset,
                    || Value::known(F::from(dummy_state as u64)),
                )?;
                offset += 1;
                for (idx, substr_def) in regex_defs.substrs.iter().enumerate() {
                    let substr_id = substr_id_offset + idx;
                    for start in substr_def.start_states.iter() {
                        table.assign_cell(
                            || format!("endpoints_substr_ids at {}", offset),
                            self.endpoints_substr_ids,
                            offset,
                            || Value::known(F::from(substr_id as u64)),
                        )?;
                        table.assign_cell(
                            || format!("start_states at {}", offset),
                            self.start_states,
                            offset,
                            || Value::known(F::from(*start as u64)),
                        )?;
                        table.assign_cell(
                            || format!("end_states at {}", offset),
                            self.end_states,
                            offset,
                            || Value::known(F::from(dummy_state)),
                        )?;
                        offset += 1;
                    }
                    for end in substr_def.end_states.iter() {
                        table.assign_cell(
                            || format!("endpoints_substr_ids at {}", offset),
                            self.endpoints_substr_ids,
                            offset,
                            || Value::known(F::from(substr_id as u64)),
                        )?;
                        table.assign_cell(
                            || format!("start_states at {}", offset),
                            self.start_states,
                            offset,
                            || Value::known(F::from(dummy_state as u64)),
                        )?;
                        table.assign_cell(
                            || format!("end_states at {}", offset),
                            self.end_states,
                            offset,
                            || Value::known(F::from(*end)),
                        )?;
                        offset += 1;
                    }
                }
                Ok(())
            },
        )?;
        Ok(substr_id_offset + regex_defs.substrs.len())
    }
}
