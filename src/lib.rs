pub mod defs;
// mod regex;
// mod substr;
pub mod table;
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
use crate::{AllstrRegexDef, SubstrRegexDef};
#[derive(Debug, Clone, Default)]
pub struct AssignedRegexResult<'a, F: PrimeField> {
    pub all_enable_flags: Vec<AssignedValue<'a, F>>,
    pub all_characters: Vec<AssignedValue<'a, F>>,
    pub all_states: Vec<AssignedValue<'a, F>>,
    pub all_substr_ids: Vec<AssignedValue<'a, F>>,
    pub masked_characters: Vec<AssignedValue<'a, F>>,
}

#[derive(Debug, Clone)]
pub struct RegexVerifyConfig<F: PrimeField> {
    characters: Column<Advice>,
    states: Column<Advice>,
    substr_ids: Column<Advice>,
    char_enable: Column<Advice>,
    table: RegexTableConfig<F>,
    q_first: Selector,
    not_q_first: Selector,
    max_chars_size: usize,
    gate: FlexGateConfig<F>,
    pub all_regex_def: AllstrRegexDef,
    pub sub_regex_defs: Vec<SubstrRegexDef>,
}

impl<F: PrimeField> RegexVerifyConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        max_chars_size: usize,
        gate: FlexGateConfig<F>,
        all_regex_def: AllstrRegexDef,
        sub_regex_defs: Vec<SubstrRegexDef>,
    ) -> Self {
        let characters = meta.advice_column();
        let states = meta.advice_column();
        let char_enable = meta.advice_column();
        let substr_ids = meta.advice_column();
        let q_first = meta.complex_selector();
        let not_q_first = meta.complex_selector();
        let table = RegexTableConfig::configure(meta);
        meta.enable_equality(characters);
        meta.enable_equality(states);
        meta.enable_equality(char_enable);
        meta.enable_equality(substr_ids);

        meta.create_gate("The state must start from the first state value", |meta| {
            let q_frist = meta.query_selector(q_first);
            let cur_state = meta.query_advice(states, Rotation::cur());
            let cur_enable = meta.query_advice(char_enable, Rotation::cur());
            let not_cur_enable = Expression::Constant(F::from(1)) - cur_enable.clone();
            vec![
                q_frist.clone()
                    * cur_enable.clone()
                    * (cur_state - Expression::Constant(F::from(all_regex_def.first_state_val))),
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

        meta.lookup("The final state must be accepted", |meta| {
            let not_q_frist = meta.query_selector(not_q_first);
            let cur_state = meta.query_advice(states, Rotation::cur());
            let cur_enable = meta.query_advice(char_enable, Rotation::cur());
            let prev_enable = meta.query_advice(char_enable, Rotation::prev());
            let enable_change = not_q_frist.clone() * (prev_enable.clone() - cur_enable.clone());
            vec![(enable_change * cur_state, table.accepted_states)]
        });

        meta.lookup("lookup characters and their state", |meta| {
            let enable = meta.query_advice(char_enable, Rotation::cur());
            let character = meta.query_advice(characters, Rotation::cur());
            let cur_state = meta.query_advice(states, Rotation::cur());
            let next_state = meta.query_advice(states, Rotation::next());
            let substr_id = meta.query_advice(substr_ids, Rotation::cur());
            vec![
                (enable.clone() * character, table.characters),
                (enable.clone() * cur_state, table.cur_states),
                (enable.clone() * next_state, table.next_states),
                (enable.clone() * substr_id, table.substr_ids),
            ]
        });

        Self {
            characters,
            states,
            substr_ids,
            char_enable,
            table,
            q_first,
            not_q_first,
            max_chars_size,
            gate,
            all_regex_def,
            sub_regex_defs,
        }
    }

    pub fn match_substrs<'v: 'a, 'a>(
        &self,
        ctx: &mut Context<'v, F>,
        characters: &[u8],
    ) -> Result<AssignedRegexResult<'a, F>, Error> {
        let mut assigned_enables = Vec::new();
        let mut assigned_characters = Vec::new();
        let mut assigned_states = Vec::new();
        let mut assigned_substr_ids = Vec::new();
        let states = self.derive_states(characters);
        let substr_ids = self.derive_substr_ids(&states);

        self.q_first.enable(&mut ctx.region, 0)?;
        for idx in 1..self.max_chars_size {
            self.not_q_first.enable(&mut ctx.region, idx)?;
        }

        for (idx, ((char, state), substr_id)) in characters
            .iter()
            .zip(states[0..characters.len()].iter())
            .zip(substr_ids.iter())
            .enumerate()
        {
            let assigned_enable = ctx.region.assign_advice(
                || format!("char_enable at {}", idx),
                self.char_enable,
                idx,
                || Value::known(F::from(1)),
            )?;
            assigned_enables.push(self.assigned_cell2value(ctx, &assigned_enable)?);
            let assigned_c = ctx.region.assign_advice(
                || format!("character at {}", idx),
                self.characters,
                idx,
                || Value::known(F::from(*char as u64)),
            )?;
            assigned_characters.push(self.assigned_cell2value(ctx, &assigned_c)?);
            let assigned_s = ctx.region.assign_advice(
                || format!("state at {}", idx),
                self.states,
                idx,
                || Value::known(F::from(*state)),
            )?;
            assigned_states.push(self.assigned_cell2value(ctx, &assigned_s)?);
            let assigned_substr_id = ctx.region.assign_advice(
                || format!("substr id at {}", idx),
                self.substr_ids,
                idx,
                || Value::known(F::from(*substr_id as u64)),
            )?;
            assigned_substr_ids.push(self.assigned_cell2value(ctx, &assigned_substr_id)?);
        }
        for idx in characters.len()..self.max_chars_size {
            let assigned_enable = ctx.region.assign_advice(
                || format!("char_enable at {}", idx),
                self.char_enable,
                idx,
                || Value::known(F::from(0)),
            )?;
            assigned_enables.push(self.assigned_cell2value(ctx, &assigned_enable)?);
            let assigned_c = ctx.region.assign_advice(
                || format!("character at {}", idx),
                self.characters,
                idx,
                || Value::known(F::from(0)),
            )?;
            assigned_characters.push(self.assigned_cell2value(ctx, &assigned_c)?);
            let assigned_substr_id = ctx.region.assign_advice(
                || format!("substr id at {}", idx),
                self.substr_ids,
                idx,
                || Value::known(F::from(0)),
            )?;
            assigned_substr_ids.push(self.assigned_cell2value(ctx, &assigned_substr_id)?);
        }
        for idx in characters.len()..self.max_chars_size + 1 {
            let state_val = if idx == characters.len() {
                states[idx]
            } else {
                0
            };
            let assigned_s = ctx.region.assign_advice(
                || format!("state at {}", idx),
                self.states,
                idx,
                || Value::known(F::from(state_val)),
            )?;
            assigned_states.push(self.assigned_cell2value(ctx, &assigned_s)?);
        }
        debug_assert_eq!(assigned_enables.len(), assigned_characters.len());
        debug_assert_eq!(assigned_characters.len() + 1, assigned_states.len());
        debug_assert_eq!(assigned_characters.len(), assigned_substr_ids.len());

        let mut masked_characters = Vec::new();
        let gate = self.gate();
        for idx in 0..self.max_chars_size {
            let is_zero = gate.is_zero(ctx, &assigned_substr_ids[idx]);
            let is_not_zero = gate.not(ctx, QuantumCell::Existing(&is_zero));
            let muled = gate.mul(
                ctx,
                QuantumCell::Existing(&is_not_zero),
                QuantumCell::Existing(&assigned_characters[idx]),
            );
            masked_characters.push(muled);
        }
        let result = AssignedRegexResult {
            all_characters: assigned_characters,
            all_enable_flags: assigned_enables,
            all_states: assigned_states,
            all_substr_ids: assigned_substr_ids,
            masked_characters,
        };
        Ok(result)
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.table
            .load(layouter, &self.all_regex_def, &self.sub_regex_defs[..])
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

    pub(crate) fn derive_states(&self, characters: &[u8]) -> Vec<u64> {
        let mut states = vec![self.all_regex_def.first_state_val];
        for (idx, char) in characters.into_iter().enumerate() {
            let state = states[idx];
            let next_state = self.all_regex_def.state_lookup.get(&(*char, state));
            match next_state {
                Some((_, s)) => states.push(*s),
                None => states.push(self.all_regex_def.first_state_val),
            };
        }
        assert_eq!(states.len(), characters.len() + 1);
        states
    }

    pub(crate) fn derive_substr_ids(&self, states: &[u64]) -> Vec<usize> {
        let mut substr_ids = vec![0; states.len() - 1];
        for (idx, state) in states.into_iter().enumerate() {
            if idx == states.len() - 1 {
                break;
            }
            for (substr_idx, substr_def) in self.sub_regex_defs.iter().enumerate() {
                if substr_def
                    .valid_state_transitions
                    .get(&(*state, states[idx + 1]))
                    .is_some()
                {
                    substr_ids[idx] = substr_idx + 1;
                    break;
                }
            }
        }
        substr_ids
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
    use crate::defs::{AllstrRegexDef, SubstrRegexDef};

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
    use std::collections::HashSet;
    use std::marker::PhantomData;

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
    struct TestSubstrMatchCircuit<F: PrimeField> {
        // Since this is only relevant for the witness, we can opt to make this whatever convenient type we want
        characters: Vec<u8>,
        correct_substrs: Vec<(usize, String)>,
        _marker: PhantomData<F>,
    }

    impl<F: PrimeField> TestSubstrMatchCircuit<F> {
        const NUM_ADVICE: usize = 3;
        const NUM_FIXED: usize = 1;
    }

    impl<F: PrimeField> Circuit<F> for TestSubstrMatchCircuit<F> {
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
            let all_regex_def =
                AllstrRegexDef::read_from_text("./test_regexes/regex_test_lookup.txt");
            let substr_def1 =
                SubstrRegexDef::read_from_text("./test_regexes/substr1_test_lookup.txt");
            let substr_def2 =
                SubstrRegexDef::read_from_text("./test_regexes/substr2_test_lookup.txt");
            let gate = FlexGateConfig::<F>::configure(
                meta,
                halo2_base::gates::flex_gate::GateStrategy::Vertical,
                &[Self::NUM_ADVICE],
                Self::NUM_FIXED,
                0,
                K,
            );
            let config = RegexVerifyConfig::configure(
                meta,
                MAX_STRING_LEN,
                gate,
                all_regex_def,
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
        let characters: Vec<u8> = "email was meant for @y.".chars().map(|c| c as u8).collect();
        // Make a vector of the numbers 1...24
        // let states = (1..=STRING_LEN as u128).collect::<Vec<u128>>();
        // assert_eq!(characters.len(), STRING_LEN);
        // assert_eq!(states.len(), STRING_LEN);

        // Successful cases
        let circuit = TestSubstrMatchCircuit::<Fr> {
            characters,
            correct_substrs: vec![(21, "y".to_string())],
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
            correct_substrs: vec![(21, "yajk".to_string())],
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
            correct_substrs: vec![
                (21, "yajk".to_string()),
                (26, "and kaiew and oiewk".to_string()),
            ],
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
            CircuitCost::<G1, TestSubstrMatchCircuit<Fr>>::measure(
                (K as u128).try_into().unwrap(),
                &circuit
            )
        );
    }

    #[test]
    fn test_substr_pass1_keygen_and_prove() {
        let characters: Vec<u8> = "email was meant for @y.".chars().map(|c| c as u8).collect();
        // Make a vector of the numbers 1...24
        // let states = (1..=STRING_LEN as u128).collect::<Vec<u128>>();
        // assert_eq!(characters.len(), STRING_LEN);
        // assert_eq!(states.len(), STRING_LEN);

        // Successful cases
        let circuit = TestSubstrMatchCircuit::<Fr> {
            characters,
            correct_substrs: vec![(21, "y".to_string())],
            _marker: PhantomData,
        };
        let prover = MockProver::run(K as u32, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        // CircuitCost::<Eq, RegexCheckCircuit<Fp>>::measure((k as u128).try_into().unwrap(), &circuit)
        let params = ParamsKZG::<Bn256>::setup(K as u32, OsRng);
        let vk = keygen_vk(&params, &circuit).unwrap();
        let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();
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
}
