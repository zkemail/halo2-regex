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

/// Regex definition.
#[derive(Debug, Clone, Default)]
pub struct RegexDefs {
    /// Regex that whole of the input string must satisfy.
    pub allstr: AllstrRegexDef,
    /// A vector of regexes that each substring must satisfy.
    pub substrs: Vec<SubstrRegexDef>,
}

/// Regex that whole of the input string must satisfy.
#[derive(Debug, Clone, Default)]
pub struct AllstrRegexDef {
    /// A map from (character, current state id in DFA) to (index of the state transitions, next state id in DFA).
    pub state_lookup: HashMap<(u8, u64), (usize, u64)>,
    /// The first state id.
    pub first_state_val: u64,
    /// The id of the accepted state.
    /// It supports only one accepted state.
    pub accepted_state_val: u64,
    /// The largest state id.
    pub largest_state_val: u64,
}

impl AllstrRegexDef {
    /// Construct [`AllstrRegexDef`] from a text file of state transitions.
    ///
    /// First line: initial state id.
    ///
    /// Second line: accepted state id.
    ///
    /// Third line: the largest largest state id.
    ///
    /// The following lines: "(current state id in DFA) (next state id) (character)" for each line.
    ///
    /// # Arguments
    /// * `file_path` - a file path of the text file.
    ///
    /// # Return values
    /// Return a new [`AllstrRegexDef`].
    pub fn read_from_text(file_path: &str) -> Self {
        let file = File::open(file_path).unwrap();
        let reader = BufReader::new(file);
        Self::read_from_reader(reader)
    }

    /// Construct [`AllstrRegexDef`] from a text file of state transitions.
    ///
    /// First line: initial state id.
    ///
    /// Second line: accepted state id.
    ///
    /// Third line: the largest largest state id.
    ///
    /// The following lines: "(current state id in DFA) (next state id) (character)" for each line.
    ///
    /// # Arguments
    /// * `reader` - a reader of the text file.
    ///
    /// # Return values
    /// Return a new [`AllstrRegexDef`].
    pub fn read_from_reader<R: std::io::Read>(reader: BufReader<R>) -> Self {
        // let file = File::open(file_path).unwrap();
        // let reader = BufReader::new(file);
        let mut state_lookup = HashMap::<(u8, u64), (usize, u64)>::new();
        // let mut array = Vec::new();
        let mut first_state_val = 0;
        let mut accepted_state_val = 0;
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
                accepted_state_val = elements[0];
            } else if idx == 2 {
                largest_state_val = elements[0];
            } else {
                state_lookup.insert((elements[2] as u8, elements[0]), (idx, elements[1]));
            }
            // array.push(elements);
        }
        Self {
            state_lookup,
            first_state_val,
            accepted_state_val,
            largest_state_val,
        }
    }
}

/// Regex that each substring must satisfy.
#[derive(Debug, Clone, Default)]
pub struct SubstrRegexDef {
    /// Maximum length of the substring.
    pub max_length: usize,
    /// A minimum position of the first character in the substring.
    /// # Notes
    /// Our current implementation of [`RegexVerifyConfig`] does not use `min_position`.
    pub min_position: u64,
    /// A maximum position of the first character in the substring.
    /// # Notes
    /// Our current implementation of [`RegexVerifyConfig`] does not use `max_position`.
    pub max_position: u64,
    /// A set of state transitions, i.e., `(current_state_id, next_state_id)`, that the substring satisfies.
    pub valid_state_transitions: HashSet<(u64, u64)>,
    /// A vector of state ids from which the state ids of the substring start.
    pub start_states: Vec<u64>,
    /// A vector of state ids to which the state ids of the substring end.
    pub end_states: Vec<u64>,
}

impl SubstrRegexDef {
    /// Construct a new [`SubstrRegexDef`].
    ///
    /// # Arguments
    /// * `max_length` - maximum length of the substring.
    /// * `min_position` - a minimum position of the first character in the substring.
    /// * `max_position` - a maximum position of the first character in the substring.
    /// * `valid_state_transitions` - a set of state transitions that the substring satisfies.
    /// * `start_states` - a vector of state ids from which the state ids of the substring start.
    /// * `end_states` - a vector of state ids to which the state ids of the substring end.
    ///
    /// # Return values
    /// Returns a new [`SubstrRegexDef`].
    pub fn new(
        max_length: usize,
        min_position: u64,
        max_position: u64,
        valid_state_transitions: HashSet<(u64, u64)>,
        start_states: Vec<u64>,
        end_states: Vec<u64>,
    ) -> Self {
        Self {
            max_length,
            min_position,
            max_position,
            valid_state_transitions,
            start_states,
            end_states,
        }
    }

    /// Construct [`SubstrRegexDef`] from a text file to define the substring.
    ///
    /// First line: maximum length of the substring.
    ///
    /// Second line: a minimum position of the first character in the substring.
    ///
    /// Third line: a maximum position of the first character in the substring.
    ///
    /// Fourth line: a vector of state ids from which the state ids of the substring start. The ids within a line are separated by spaces.
    ///
    /// Fifth line: a vector of state ids to which the state ids of the substring end. The ids within a line are separated by spaces.
    ///
    /// The following lines: `(current_state_id, next_state_id)` for each line. The ids within a line are separated by spaces.
    ///
    /// # Arguments
    /// * `file_path` - a file path of the text file.
    ///
    /// # Return values
    /// Returns a new [`SubstrRegexDef`].
    pub fn read_from_text(file_path: &str) -> Self {
        let file = File::open(file_path).unwrap();
        let reader = BufReader::new(file);
        Self::read_from_reader(reader)
    }

    /// Construct [`SubstrRegexDef`] from a text file to define the substring.
    ///
    /// First line: maximum length of the substring.
    ///
    /// Second line: a minimum position of the first character in the substring.
    ///
    /// Third line: a maximum position of the first character in the substring.
    ///
    /// Fourth line: a vector of state ids from which the state ids of the substring start. The ids within a line are separated by spaces.
    ///
    /// Fifth line: a vector of state ids to which the state ids of the substring end. The ids within a line are separated by spaces.
    ///
    /// The following lines: `(current_state_id, next_state_id)` for each line. The ids within a line are separated by spaces.
    ///
    /// # Arguments
    /// * `reader` - a reader of the text file.
    ///
    /// # Return values
    /// Returns a new [`SubstrRegexDef`].
    pub fn read_from_reader<R: std::io::Read>(reader: BufReader<R>) -> Self {
        let mut valid_state_transitions = HashSet::<(u64, u64)>::new();
        // let mut one_state_path = HashMap::<u64, u64>::new();
        let mut max_length = 0;
        let mut min_position = 0;
        let mut max_position = 0;
        let mut start_states = vec![];
        let mut end_states = vec![];

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
            } else if idx == 3 {
                start_states = elements;
            } else if idx == 4 {
                end_states = elements;
            } else {
                valid_state_transitions.insert((elements[0], elements[1]));
                // if elements[0] < start_state {
                //     start_state = elements[0];
                // }
                // if one_state_path.get(&elements[0]).is_none() && elements[0] != elements[1] {
                //     one_state_path.insert(elements[0], elements[1]);
                // }
            };
        }
        // let mut end_state = start_state;
        // while let Some(next_state) = one_state_path.get(&end_state) {
        //     println!("end_state {} next_state {}", end_state, next_state);
        //     end_state = *next_state;
        // }
        // println!(
        //     "start_state {} end_state {} valid transition {:?}",
        //     start_state, end_state, valid_state_transitions
        // );

        Self {
            max_length,
            min_position,
            max_position,
            valid_state_transitions,
            start_states,
            end_states,
        }
    }
}
