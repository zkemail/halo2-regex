use std::marker::PhantomData;

use halo2_base::halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error, TableColumn},
};
use halo2_base::utils::PrimeField;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::str::FromStr;

struct Sizes {
    RANGE: usize,
    NUM_BITS: usize,
    LOOKUP_RANGE: usize,
}

/// A lookup table of values from 0..RANGE.
#[derive(Debug, Clone)]
pub(super) struct TransitionTableConfig<F: PrimeField> {
    pub(super) prev_state: TableColumn,
    pub(super) next_state: TableColumn,
    pub(super) character: TableColumn,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> TransitionTableConfig<F> {
    pub(super) fn read_2d_array<T>(&self, file_path: &str) -> Vec<Vec<T>>
    where
        T: FromStr,
        <T as FromStr>::Err: std::fmt::Debug,
    {
        let file = File::open(file_path).unwrap();
        let reader = BufReader::new(file);
        let mut array = Vec::new();

        for line in reader.lines() {
            let line = line.unwrap();
            let elements: Vec<T> = line
                .split_whitespace()
                .map(|s| s.parse().unwrap())
                .collect();
            array.push(elements);
        }

        array
    }

    pub(super) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
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

    pub(super) fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "load transition table",
            |mut table| {
                let mut array = self.read_2d_array::<i32>("./src/halo2_regex_lookup_body.txt");
                // Append [0, 0, 0] to array
                array.push(vec![0, 0, 0]);
                // print!("Array: {:?}", array);
                let mut offset = 0;
                for row in array {
                    print!("Row: {:?} {:?}", row, offset);
                    table.assign_cell(
                        || "prev_state",
                        self.prev_state,
                        offset,
                        || Value::known(F::from_u128(row[0] as u128)),
                    )?;
                    table.assign_cell(
                        || "next_state",
                        self.next_state,
                        offset,
                        || Value::known(F::from_u128(row[1] as u128)),
                    )?;
                    table.assign_cell(
                        || "character",
                        self.character,
                        offset,
                        || Value::known(F::from_u128(row[2] as u128)),
                    )?;
                    offset += 1;
                }
                Ok(())
            },
        )
    }
}
