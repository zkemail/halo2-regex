use halo2_base::halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Assigned, Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Fixed,
        Instance, Selector, TableColumn,
    },
    poly::Rotation,
};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{bigint_to_fe, biguint_to_fe, fe_to_biguint, modulus, PrimeField},
    AssignedValue, Context, QuantumCell,
};
use std::marker::PhantomData;

pub use crate::table::{read_2d_array, TransitionTableConfig};
#[derive(Debug, Clone)]
struct RangeConstrained<F: PrimeField>(AssignedCell<F, F>);

#[derive(Debug, Clone)]
pub struct AssignedRegexResult<F: PrimeField> {
    pub enable_flags: Vec<AssignedCell<F, F>>,
    pub characters: Vec<AssignedCell<F, F>>,
    pub states: Vec<AssignedCell<F, F>>,
}

// Here we decompose a transition into 3-value lookups.

#[derive(Debug, Clone)]
pub struct RegexCheckConfig<F: PrimeField> {
    characters: Column<Advice>,
    state: Column<Advice>,
    transition_table: TransitionTableConfig<F>,
    char_enable: Column<Advice>,
    q_first: Selector,
    not_q_first: Selector,
    accepted_states: TableColumn,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> RegexCheckConfig<F> {
    pub(super) const STATE_FIRST: u64 = 1;
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let characters = meta.advice_column();
        let state = meta.advice_column();
        let char_enable = meta.advice_column();
        let q_first = meta.complex_selector();
        let not_q_first = meta.complex_selector();
        let transition_table = TransitionTableConfig::configure(meta);
        let accepted_states = meta.lookup_table_column();

        meta.enable_equality(characters);
        meta.enable_equality(state);
        meta.enable_equality(char_enable);

        meta.create_gate("The state must start from 1", |meta| {
            let q_frist = meta.query_selector(q_first);
            let cur_state = meta.query_advice(state, Rotation::cur());
            let cur_enable = meta.query_advice(char_enable, Rotation::cur());
            let not_cur_enable = Expression::Constant(F::from(1)) - cur_enable.clone();
            vec![
                q_frist.clone()
                    * cur_enable.clone()
                    * (cur_state - Expression::Constant(F::from(Self::STATE_FIRST))),
                q_frist * cur_enable * not_cur_enable,
            ]
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

        // Lookup each transition value individually, not paying attention to bit count
        meta.lookup("lookup characters and their state", |meta| {
            let enable = meta.query_advice(char_enable, Rotation::cur());
            let cur_state = meta.query_advice(state, Rotation::cur());
            let next_state = meta.query_advice(state, Rotation::next());
            let character = meta.query_advice(characters, Rotation::cur());

            // One minus q
            let one_minus_enable = Expression::Constant(F::from(1)) - enable.clone();
            let zero = Expression::Constant(F::from(0));

            /*
                | q | state | characters | table.prev_state | table.next_state  | table.character
                | 1 | s_cur |    char    |       s_cur      |     s_next        |     char
                |   | s_next|
            */

            vec![
                (
                    enable.clone() * cur_state + one_minus_enable.clone() * zero.clone(),
                    transition_table.prev_state,
                ),
                (
                    enable.clone() * next_state + one_minus_enable.clone() * zero.clone(),
                    transition_table.next_state,
                ),
                (
                    enable.clone() * character + one_minus_enable.clone() * zero.clone(),
                    transition_table.character,
                ),
            ]
        });

        meta.lookup("The final state must be accepted", |meta| {
            let cur_state = meta.query_advice(state, Rotation::cur());
            let cur_enable = meta.query_advice(char_enable, Rotation::cur());
            let next_enable = meta.query_advice(char_enable, Rotation::next());
            let enable_change = cur_enable.clone() - next_enable.clone();
            let not_enable_change = Expression::Constant(F::from(1)) - enable_change.clone();
            let zero = Expression::Constant(F::from(0));
            vec![(
                enable_change * cur_state + not_enable_change * zero,
                accepted_states,
            )]
        });

        Self {
            characters,
            state,
            char_enable,
            q_first,
            not_q_first,
            transition_table,
            accepted_states,
            _marker: PhantomData,
        }
    }

    pub fn load(
        &self,
        layouter: &mut impl Layouter<F>,
        lookups: &[&[u64]],
        accepted_states: &[u64],
    ) -> Result<(), Error> {
        self.transition_table.load(layouter, lookups)?;
        let mut accepted_states = accepted_states.to_vec();
        accepted_states.push(0);
        layouter.assign_table(
            || "accepted_states",
            |mut table| {
                for (idx, state) in accepted_states.iter().enumerate() {
                    table.assign_cell(
                        || format!("accepted state at {}", idx),
                        self.accepted_states,
                        idx,
                        || Value::known(F::from(*state)),
                    )?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    // Note that the two types of region.assign_advice calls happen together so that it is the same region
    pub fn assign_values(
        &self,
        region: &mut Region<F>,
        characters: &[u8],
        states: &[u64],
        max_chars_size: usize,
    ) -> Result<AssignedRegexResult<F>, Error> {
        let mut assigned_enables = Vec::new();
        let mut assigned_characters = Vec::new();
        let mut assigned_states = Vec::new();
        debug_assert_eq!(characters.len() + 1, states.len());

        self.q_first.enable(region, 0)?;
        for idx in 1..max_chars_size {
            self.not_q_first.enable(region, idx)?;
        }

        for (idx, (char, state)) in characters
            .iter()
            .zip(states[0..characters.len()].iter())
            .enumerate()
        {
            let assigned_enable = region.assign_advice(
                || format!("char_enable at {}", idx),
                self.char_enable,
                idx,
                || Value::known(F::from(1)),
            )?;
            assigned_enables.push(assigned_enable);
            let assigned_c = region.assign_advice(
                || format!("character at {}", idx),
                self.characters,
                idx,
                || Value::known(F::from(*char as u64)),
            )?;
            assigned_characters.push(assigned_c);
            let assigned_s = region.assign_advice(
                || format!("state at {}", idx),
                self.state,
                idx,
                || Value::known(F::from(*state)),
            )?;
            assigned_states.push(assigned_s);
        }
        for idx in characters.len()..max_chars_size {
            let assigned_enable = region.assign_advice(
                || format!("char_enable at {}", idx),
                self.char_enable,
                idx,
                || Value::known(F::from(0)),
            )?;
            assigned_enables.push(assigned_enable);
            let assigned_c = region.assign_advice(
                || format!("character at {}", idx),
                self.characters,
                idx,
                || Value::known(F::from(0)),
            )?;
            assigned_characters.push(assigned_c);
        }
        for idx in characters.len()..max_chars_size + 1 {
            let state_val = if idx == characters.len() {
                states[idx]
            } else {
                0
            };
            let assigned_s = region.assign_advice(
                || format!("state at {}", idx),
                self.state,
                idx,
                || Value::known(F::from(state_val)),
            )?;
            assigned_states.push(assigned_s);
        }
        debug_assert_eq!(assigned_enables.len(), assigned_characters.len());
        debug_assert_eq!(assigned_characters.len() + 1, assigned_states.len());

        // Enable q_decomposed
        // for i in 0..STRING_LEN {
        //     println!("{:?}, {:?}", characters[i], states[i]);
        //     // offset = i;
        //     if i < STRING_LEN - 1 {
        //         self.q_lookup_state_selector.enable(region, i)?;
        //     }
        //     let assigned_c = region.assign_advice(
        //         || format!("character"),
        //         self.characters,
        //         i,
        //         || Value::known(F::from(characters[i] as u64)),
        //     )?;
        //     assigned_characters.push(assigned_c);
        //     let assigned_s = region.assign_advice(
        //         || format!("state"),
        //         self.state,
        //         i,
        //         || Value::known(F::from(states[i])),
        //     )?;
        //     assigned_states.push(assigned_s);
        // }
        Ok(AssignedRegexResult {
            enable_flags: assigned_enables,
            characters: assigned_characters,
            states: assigned_states,
        })
    }
}

#[cfg(test)]
mod tests {
    use halo2_base::halo2_proofs::{
        circuit::floor_planner::V1,
        dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::{Fr, G1},
        plonk::{Any, Circuit},
    };

    use super::*;

    // Checks a regex of string len
    const MAX_STRING_LEN: usize = 32;
    const ACCEPT_STATE: u64 = 22;

    #[derive(Default, Clone, Debug)]
    struct TestRegexCheckCircuit<F: PrimeField> {
        // Since this is only relevant for the witness, we can opt to make this whatever convenient type we want
        pub characters: Vec<u8>,
        _marker: PhantomData<F>,
    }

    impl<F: PrimeField> Circuit<F> for TestRegexCheckCircuit<F> {
        type Config = RegexCheckConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        // Circuit without witnesses, called only during key generation
        fn without_witnesses(&self) -> Self {
            Self {
                characters: vec![],
                _marker: PhantomData,
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let config = RegexCheckConfig::configure(meta);
            config
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            // test regex: "email was meant for @(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_)+"
            // accepted state: 22
            let lookup_filepath = "./test_regexes/regex_test_lookup.txt";
            let array: Vec<Vec<u64>> = read_2d_array::<u64>(lookup_filepath);
            let lookups = array
                .iter()
                .map(|lookup| &lookup[..])
                .collect::<Vec<&[u64]>>();
            config.load(&mut layouter, &lookups, &[ACCEPT_STATE])?;
            // Starting state is 1 always
            let mut states = vec![Self::Config::STATE_FIRST];
            // let mut next_state = START_STATE;

            // Set the states to transition via the character and state that appear in the array, to the third value in each array tuple
            for idx in 0..self.characters.len() {
                let character = self.characters[idx];
                // states[i] = next_state;
                let state = states[idx];
                // next_state = START_STATE; // Default to start state if no match found
                let mut is_found = false;
                for j in 0..array.len() {
                    if array[j][2] == character as u64 && array[j][0] == state {
                        // next_state = array[j][1] as u64;
                        states.push(array[j][1]);
                        is_found = true;
                        break;
                    }
                }
                if !is_found {
                    states.push(Self::Config::STATE_FIRST);
                }
            }
            assert_eq!(states.len(), self.characters.len() + 1);

            print!("Synthesize being called...");
            layouter.assign_region(
                || "regex",
                |mut region| {
                    config.assign_values(&mut region, &self.characters, &states, MAX_STRING_LEN)?;
                    Ok(())
                },
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_regex_pass() {
        let k = 7; // 8, 128, etc

        // Convert query string to u128s
        let characters: Vec<u8> = "email was meant for @y".chars().map(|c| c as u8).collect();

        // Make a vector of the numbers 1...24
        // let states = (1..=STRING_LEN as u128).collect::<Vec<u128>>();
        // assert_eq!(characters.len(), STRING_LEN);
        // assert_eq!(states.len(), STRING_LEN);

        // Successful cases
        let circuit = TestRegexCheckCircuit::<Fr> {
            characters,
            _marker: PhantomData,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
        // CircuitCost::<Eq, RegexCheckCircuit<Fp>>::measure((k as u128).try_into().unwrap(), &circuit)
        println!(
            "{:?}",
            CircuitCost::<G1, TestRegexCheckCircuit<Fr>>::measure(
                (k as u128).try_into().unwrap(),
                &circuit
            )
        );
    }

    #[test]
    fn test_regex_fail() {
        let k = 10;

        // Convert query string to u128s
        let characters: Vec<u8> = "email isnt meant for u".chars().map(|c| c as u8).collect();

        // assert_eq!(characters.len(), STRING_LEN);

        // Out-of-range `value = 8`
        let circuit = TestRegexCheckCircuit::<Fr> {
            characters: characters,
            // states: states,
            _marker: PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        match prover.verify() {
            Err(e) => {
                println!("Error successfully achieved!");
            }
            _ => assert_eq!(1, 0),
        }
    }

    // $ cargo test --release --all-features print_range_check_1
    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_range_check_1() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("range-check-decomposed-layout.png", (1024, 3096))
            .into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Range Check 1 Layout", ("sans-serif", 60))
            .unwrap();

        let circuit = RegexCheckCircuit::<Fp> {
            value: 2 as u128,
            _marker: PhantomData,
        };
        halo2_proofs::dev::CircuitLayout::default()
            .render(3, &circuit, &root)
            .unwrap();
    }
}
