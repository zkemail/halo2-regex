use std::{collections::HashMap, fmt::format, marker::PhantomData};

use halo2_base::halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error, TableColumn},
};
use halo2_base::utils::PrimeField;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::str::FromStr;

// struct Sizes {
//     RANGE: usize,
//     NUM_BITS: usize,
//     LOOKUP_RANGE: usize,
// }

/// A lookup table of values from 0..RANGE.
#[derive(Debug, Clone)]
pub struct TransitionTableConfig<F: PrimeField> {
    pub(crate) prev_state: TableColumn,
    pub(crate) next_state: TableColumn,
    pub(crate) character: TableColumn,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> TransitionTableConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let prev_state = meta.lookup_table_column();
        let next_state = meta.lookup_table_column();
        let character = meta.lookup_table_column();

        Self {
            prev_state,
            next_state,
            character,
            _marker: PhantomData,
        }
    }

    pub fn load(
        &self,
        layouter: &mut impl Layouter<F>,
        state_lookup: &HashMap<(u8, u64), u64>,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "load transition table",
            |mut table| {
                let mut offset = 0;
                let mut assign_row = |prev_state: u64, next_state: u64, char: u8| {
                    table.assign_cell(
                        || "prev_state",
                        self.prev_state,
                        offset,
                        || Value::known(F::from(prev_state)),
                    )?;
                    table.assign_cell(
                        || "next_state",
                        self.next_state,
                        offset,
                        || Value::known(F::from(next_state)),
                    )?;
                    table.assign_cell(
                        || "character",
                        self.character,
                        offset,
                        || Value::known(F::from(char as u64)),
                    )?;
                    offset += 1;
                    Ok::<(), Error>(())
                };
                // let mut array = lookups.to_vec();
                // Append a dummy row [0, 0, 0].
                assign_row(0, 0, 0);
                for ((char, prev_state), next_state) in state_lookup
                    .keys()
                    .into_iter()
                    .zip(state_lookup.values().into_iter())
                {
                    assign_row(*prev_state, *next_state, *char)?;
                }

                // let dummy_lookup = vec![0, 0, 0];
                // array.push(&dummy_lookup);
                // // print!("Array: {:?}", array);
                // let mut offset = 0;
                // for row in array {
                //     print!("Row: {:?} {:?}", row, offset);
                //     table.assign_cell(
                //         || "prev_state",
                //         self.prev_state,
                //         offset,
                //         || Value::known(F::from(row[0])),
                //     )?;
                //     table.assign_cell(
                //         || "next_state",
                //         self.next_state,
                //         offset,
                //         || Value::known(F::from(row[1])),
                //     )?;
                //     table.assign_cell(
                //         || "character",
                //         self.character,
                //         offset,
                //         || Value::known(F::from(row[2])),
                //     )?;
                //     offset += 1;
                // }
                Ok(())
            },
        )
    }
}

pub fn read_regex_lookups(file_path: &str) -> HashMap<(u8, u64), u64> {
    let file = File::open(file_path).unwrap();
    let reader = BufReader::new(file);
    let mut state_lookup = HashMap::<(u8, u64), u64>::new();
    // let mut array = Vec::new();

    for (idx, line) in reader.lines().enumerate() {
        let line = line.expect(&format!("fail to get {}-th line.", idx));
        let elements: Vec<u64> = line
            .split_whitespace()
            .map(|s| {
                s.parse()
                    .expect(&format!("fail to parse string {} at {}-th line.", s, idx))
            })
            .collect();
        state_lookup.insert((elements[2] as u8, elements[0]), elements[1]);
        // array.push(elements);
    }

    // array
    state_lookup
}
