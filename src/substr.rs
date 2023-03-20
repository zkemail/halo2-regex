use halo2_base::halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Assigned, Circuit, Column, ConstraintSystem, Constraints, Error, Expression,
        Instance, Selector,
    },
    poly::Rotation,
};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{bigint_to_fe, biguint_to_fe, fe_to_biguint, modulus, PrimeField},
    AssignedValue, Context, QuantumCell,
};
use std::marker::PhantomData;

use crate::table::TransitionTableConfig;
use crate::{AssignedRegexResult, RegexCheckConfig};

#[derive(Debug, Clone, Default)]
pub struct SubstrDef {
    max_length: usize,
    min_position: u64,
    max_position: u64,
    correct_state: u64,
}

impl SubstrDef {
    pub fn new(
        max_length: usize,
        min_position: u64,
        max_position: u64,
        correct_state: u64,
    ) -> Self {
        Self {
            max_length,
            min_position,
            max_position,
            correct_state,
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
    main_gate: FlexGateConfig<F>,
    substr_defs: Vec<SubstrDef>,
}

impl<F: PrimeField> SubstrMatchConfig<F> {
    pub fn construct(
        regex_config: RegexCheckConfig<F>,
        main_gate: FlexGateConfig<F>,
        substr_defs: Vec<SubstrDef>,
    ) -> Self {
        Self {
            regex_config,
            main_gate,
            substr_defs,
        }
    }

    // pub fn assign_all_string<'v: 'a, 'a>(
    //     &self,
    //     ctx: &mut Context<'v, F>,
    //     characters: &[u8],
    // ) -> Result<AssignedAllString<'a, F>, Error> {
    //     let regex_result = self
    //         .regex_config
    //         .assign_values(&mut ctx.region, characters)?;
    //     let mut assigned_flags = Vec::new();
    //     let mut assigned_characters = Vec::new();
    //     let mut assigned_states = Vec::new();
    //     let mut assigned_indexes = Vec::new();
    //     for idx in 0..regex_result.enable_flags.len() {
    //         let assigned_f = self.assigned_cell2value(ctx, &regex_result.enable_flags[idx])?;
    //         assigned_flags.push(assigned_f);
    //         let assigned_c = self.assigned_cell2value(ctx, &regex_result.characters[idx])?;
    //         assigned_characters.push(assigned_c);
    //         let assigned_s = self.assigned_cell2value(ctx, &regex_result.states[idx])?;
    //         assigned_states.push(assigned_s);
    //         let assigned_index = self.gate().load_constant(ctx, F::from(idx as u64));
    //         assigned_indexes.push(assigned_index);
    //     }
    //     let assigned_last_state =
    //         self.assigned_cell2value(ctx, &regex_result.states[regex_result.enable_flags.len()])?;
    //     assigned_states.push(assigned_last_state);
    //     // for (idx, (assigned_char, assigned_state)) in regex_result.enable_flags.into_iter().zip(regex_result
    //     //     .characters
    //     //     .into_iter())

    //     //     .zip(regex_result.states.into_iter())
    //     //     .enumerate()
    //     // {
    //     //     let assigned_f = self.assigned_cell2value(ctx, assigned_cell)
    //     //     let assigned_c = self.assigned_cell2value(ctx, &assigned_char)?;
    //     //     assigned_characters.push(assigned_c);
    //     //     let assigned_s = self.assigned_cell2value(ctx, &assigned_state)?;
    //     //     assigned_states.push(assigned_s);
    //     //     let assigned_index = self.gate().load_constant(ctx, F::from(idx as u64));
    //     //     assigned_indexes.push(assigned_index);
    //     // }
    //     let result = AssignedAllString {
    //         enable_flags: assigned_flags,
    //         characters: assigned_characters,
    //         states: assigned_states,
    //         indexes: assigned_indexes,
    //     };
    //     Ok(result)
    // }

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
        for substr_def in self.substr_defs.iter() {
            let mut substr_positions = Vec::new();
            let mut in_matching = false;
            let substr_max_len = substr_def.max_length;
            for position in
                substr_def.min_position..=(substr_def.max_position + substr_max_len as u64)
            {
                let cur_state = states[position as usize];
                if cur_state != substr_def.correct_state {
                    if !in_matching {
                        continue;
                    } else {
                        in_matching = false;
                        break;
                    }
                } else {
                    substr_positions.push(position);
                    if !in_matching {
                        in_matching = true;
                    }
                }
            }
            let mut assigned_substr = Vec::new();
            let mut assigned_len = gate.load_zero(ctx);
            let mut last_selector = gate.load_constant(ctx, F::one());
            let mut substr_positions = substr_positions.to_vec();

            substr_positions.append(&mut vec![
                all_max_len as u64;
                substr_max_len - substr_positions.len()
            ]);
            for idx in 0..substr_max_len {
                let assigned_target_i =
                    gate.load_witness(ctx, Value::known(F::from(substr_positions[idx])));
                let mut new_substr_char = gate.load_zero(ctx);
                for position in (substr_def.min_position as usize + idx)
                    ..=(substr_def.max_position as usize + idx)
                {
                    let assigned_c = &assigned_characters[position];
                    let assigned_s = &assigned_states[position];
                    let assigned_i = &assigned_indexes[position];
                    let index_sub = gate.sub(
                        ctx,
                        QuantumCell::Existing(&assigned_i),
                        QuantumCell::Existing(&assigned_target_i),
                    );
                    let selector = gate.is_zero(ctx, &index_sub);
                    // state constraints.
                    {
                        let sub = gate.sub(
                            ctx,
                            QuantumCell::Existing(&assigned_s),
                            QuantumCell::Constant(F::from(substr_def.correct_state)),
                        );
                        let state_constraint = gate.mul(
                            ctx,
                            QuantumCell::Existing(&selector),
                            QuantumCell::Existing(&sub),
                        );
                        gate.assert_is_const(ctx, &state_constraint, F::zero());
                    }
                    // The selector constraints: 0->0, 1->0, 1->1 are allowed, but 0->1 is invalid!
                    {
                        let sub = gate.sub(
                            ctx,
                            QuantumCell::Existing(&last_selector),
                            QuantumCell::Existing(&selector),
                        );
                        gate.assert_bit(ctx, &sub);
                    }
                    new_substr_char = gate.mul_add(
                        ctx,
                        QuantumCell::Existing(&assigned_c),
                        QuantumCell::Existing(&selector),
                        QuantumCell::Existing(&new_substr_char),
                    );
                    assigned_len = gate.add(
                        ctx,
                        QuantumCell::Existing(&assigned_len),
                        QuantumCell::Existing(&selector),
                    );
                    last_selector = selector;
                }
                assigned_substr.push(new_substr_char);
            }
            substrs_bytes.push(assigned_substr);
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
        self.regex_config.load(layouter)
    }

    fn gate(&self) -> &FlexGateConfig<F> {
        &self.main_gate
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
    use crate::table::read_regex_lookups;

    // Checks a regex of string len
    const MAX_STRING_LEN: usize = 32;
    const ACCEPT_STATE: u64 = 23;
    const K: usize = 7;

    #[derive(Default, Clone, Debug)]
    struct TestSubstrMatchCircuit<F: PrimeField> {
        // Since this is only relevant for the witness, we can opt to make this whatever convenient type we want
        characters: Vec<u8>,
        _marker: PhantomData<F>,
    }

    impl<F: PrimeField> TestSubstrMatchCircuit<F> {
        const NUM_ADVICE: usize = 50;
        const NUM_FIXED: usize = 1;
    }

    impl<F: PrimeField> Circuit<F> for TestSubstrMatchCircuit<F> {
        type Config = SubstrMatchConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        // Circuit without witnesses, called only during key generation
        fn without_witnesses(&self) -> Self {
            Self {
                characters: vec![],
                _marker: PhantomData,
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let lookup_filepath = "./test_regexes/regex_test_lookup.txt";
            let state_lookup = read_regex_lookups(lookup_filepath);
            let regex_config =
                RegexCheckConfig::configure(meta, state_lookup, &[ACCEPT_STATE], MAX_STRING_LEN);
            let main_gate = FlexGateConfig::configure(
                meta,
                halo2_base::gates::flex_gate::GateStrategy::Vertical,
                &[Self::NUM_ADVICE],
                Self::NUM_FIXED,
                0,
                K,
            );
            let substr_def = SubstrDef {
                max_length: 4,
                min_position: 21,
                max_position: MAX_STRING_LEN as u64 - 4,
                correct_state: 22,
            };
            let config = SubstrMatchConfig::construct(regex_config, main_gate, vec![substr_def]);
            config
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            // test regex: "email was meant for @(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_)+"
            // accepted state: 22
            config.load(&mut layouter)?;
            // Starting state is 1 always
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

            print!("Synthesize being called...");
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
                    config.match_substrs(ctx, &self.characters)?;
                    Ok(())
                },
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_substr_pass1() {
        let characters: Vec<u8> = "email was meant for @y".chars().map(|c| c as u8).collect();
        // Make a vector of the numbers 1...24
        // let states = (1..=STRING_LEN as u128).collect::<Vec<u128>>();
        // assert_eq!(characters.len(), STRING_LEN);
        // assert_eq!(states.len(), STRING_LEN);

        // Successful cases
        let circuit = TestSubstrMatchCircuit::<Fr> {
            characters,
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

    #[ignore]
    #[test]
    fn test_substr_pass2() {
        let characters: Vec<u8> = "email was meant for @yajk"
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
