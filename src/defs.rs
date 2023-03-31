use std::{
    collections::{HashMap, HashSet},
    fmt::format,
    marker::PhantomData,
};

use halo2_base::halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error, TableColumn},
};
use halo2_base::utils::PrimeField;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Debug, Clone, Default)]
pub struct AllstrRegexDef {
    pub state_lookup: HashMap<(u8, u64), u64>,
    pub first_state_val: u64,
    pub accepted_state_vals: Vec<u64>,
    pub largest_state_val: u64,
}

impl AllstrRegexDef {
    pub fn read_from_text(file_path: &str) -> Self {
        let file = File::open(file_path).unwrap();
        let reader = BufReader::new(file);
        let mut state_lookup = HashMap::<(u8, u64), u64>::new();
        // let mut array = Vec::new();
        let mut first_state_val = 0;
        let mut accepted_state_vals = Vec::new();
        let mut largest_state_val = 0;

        for (idx, line) in reader.lines().enumerate() {
            let line = line.expect(&format!("fail to get {}-th line.", idx));
            let elements: Vec<u64> = line
                .split_whitespace()
                .map(|s| {
                    s.parse()
                        .expect(&format!("fail to parse string {} at {}-th line.", s, idx))
                })
                .collect();
            if idx == 0 {
                first_state_val = elements[0];
            } else if idx == 1 {
                accepted_state_vals = elements;
            } else if idx == 2 {
                largest_state_val = elements[0];
            } else {
                state_lookup.insert((elements[2] as u8, elements[0]), elements[1]);
            }
            // array.push(elements);
        }
        Self {
            state_lookup,
            first_state_val,
            accepted_state_vals,
            largest_state_val,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SubstrRegexDef {
    pub max_length: usize,
    pub min_position: u64,
    pub max_position: u64,
    pub valid_state_transitions: HashSet<(u64, u64)>,
}

impl SubstrRegexDef {
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

    pub fn read_from_text(file_path: &str) -> Self {
        let file = File::open(file_path).unwrap();
        let reader = BufReader::new(file);
        let mut valid_state_transitions = HashSet::<(u64, u64)>::new();
        let mut max_length = 0;
        let mut min_position = 0;
        let mut max_position = 0;

        for (idx, line) in reader.lines().enumerate() {
            let line = line.expect(&format!("fail to get {}-th line.", idx));
            let elements: Vec<u64> = line
                .split_whitespace()
                .map(|s| {
                    s.parse()
                        .expect(&format!("fail to parse string {} at {}-th line.", s, idx))
                })
                .collect();
            if idx == 0 {
                max_length = elements[0] as usize;
            } else if idx == 1 {
                min_position = elements[0];
            } else if idx == 2 {
                max_position = elements[0];
            } else {
                valid_state_transitions.insert((elements[0], elements[1]));
            };
        }
        Self {
            max_length,
            min_position,
            max_position,
            valid_state_transitions,
        }
    }
}
