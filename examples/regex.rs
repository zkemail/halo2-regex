use halo2_base::gates::flex_gate::FlexGateConfig;
use halo2_base::halo2_proofs::circuit::Layouter;
///! A circuit in this example verifies that the input string satisfies the regex of "email was meant for @(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+." and exposes the substring matching with "(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)" to instances (public inputs).
use halo2_base::halo2_proofs::plonk::{ConstraintSystem, Error};
use halo2_base::halo2_proofs::{
    circuit::SimpleFloorPlanner,
    plonk::{Column, Instance},
};
use halo2_base::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit};
use halo2_base::Context;
use halo2_base::{utils::PrimeField, ContextParams, SKIP_FIRST_PASS};
use halo2_regex::{
    defs::{AllstrRegexDef, RegexDefs, SubstrRegexDef},
    vrm::DecomposedRegexConfig,
    RegexVerifyConfig,
};
use std::marker::PhantomData;
use std::path::Path;

const MAX_STRING_LEN: usize = 128;
const K: usize = 17;

/// 1. Define a configure of our example circuit.
#[derive(Clone, Debug)]
struct ExampleConfig<F: PrimeField> {
    inner: RegexVerifyConfig<F>,
    instances: Column<Instance>,
}

/// 2. Define an example circuit.
#[derive(Default, Clone, Debug)]
struct ExampleCircuit<F: PrimeField> {
    // The bytes of the input string.
    characters: Vec<u8>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> ExampleCircuit<F> {
    /// The number of advice columns in [`FlexGateConfig`].
    const NUM_ADVICE: usize = 2;
    /// The number of fix columns in [`FlexGateConfig`].
    const NUM_FIXED: usize = 1;
}

impl<F: PrimeField> Circuit<F> for ExampleCircuit<F> {
    type Config = ExampleConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    // Circuit without witnesses, called only during key generation
    fn without_witnesses(&self) -> Self {
        Self {
            characters: vec![],
            // correct_substrs: vec![],
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let all_regex_def1 = AllstrRegexDef::read_from_text("./examples/ex_allstr.txt");
        let substr_def1 = SubstrRegexDef::read_from_text("./examples/ex_substr_id1.txt");
        let gate = FlexGateConfig::<F>::configure(
            meta,
            halo2_base::gates::flex_gate::GateStrategy::Vertical,
            &[Self::NUM_ADVICE],
            Self::NUM_FIXED,
            0,
            K,
        );
        let regex_defs = vec![RegexDefs {
            allstr: all_regex_def1,
            substrs: vec![substr_def1],
        }];
        let inner = RegexVerifyConfig::configure(meta, MAX_STRING_LEN, gate, regex_defs);
        let instances = meta.instance_column();
        meta.enable_equality(instances);
        Self::Config { inner, instances }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // test regex: "email was meant for @(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_)+( and (a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+)*."
        config.inner.load(&mut layouter)?;

        // println!("Synthesize being called...");
        let mut first_pass = SKIP_FIRST_PASS;
        let gate = config.inner.gate().clone();
        // let mut substr_positions = self.substr_positions.to_vec();
        // for _ in substr_positions.len()..self.substr_def.max_length {
        //     substr_positions.push(0);
        // }
        let mut masked_char_cells = vec![];
        let mut masked_substr_id_cells = vec![];
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
                let result = config.inner.match_substrs(ctx, &self.characters)?;

                for (assigned_char, assigned_substr_id) in result
                    .masked_characters
                    .iter()
                    .zip(result.all_substr_ids.iter())
                {
                    masked_char_cells.push(assigned_char.cell());
                    masked_substr_id_cells.push(assigned_substr_id.cell());
                }

                // for (substr_idx, (start, chars)) in self.correct_substrs.iter().enumerate() {
                //     for (idx, char) in chars.as_bytes().iter().enumerate() {
                //         expected_masked_chars[start + idx] = *char;
                //         expected_substr_ids[start + idx] = substr_idx + 1;
                //     }
                // }
                // for idx in 0..MAX_STRING_LEN {
                //     result.masked_characters[idx]
                //         .value()
                //         .map(|v| assert_eq!(*v, F::from(expected_masked_chars[idx] as u64)));
                //     result.all_substr_ids[idx]
                //         .value()
                //         .map(|v| assert_eq!(*v, F::from(expected_substr_ids[idx] as u64)));
                // }
                Ok(())
            },
        )?;
        for (idx, cell) in masked_char_cells.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.instances, idx)?;
        }
        for (idx, cell) in masked_substr_id_cells.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.instances, MAX_STRING_LEN + idx)?;
        }
        Ok(())
    }
}

fn main() {
    let regex1_decomposed: DecomposedRegexConfig = serde_json::from_str(
        r#"
        {
            "max_byte_size": 128,
            "parts":[
                {
                    "is_public": false,
                    "regex_def": "email was meant for @",
                    "max_size": 21
                },
                {
                    "is_public": true,
                    "regex_def": "(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+",
                    "max_size": 7,
                    "solidity": {
                        "type": "String"
                    }
                },
                {
                    "is_public": false,
                    "regex_def": ".",
                    "max_size": 1
                }
            ]
        }
    "#,
    )
    .unwrap();
    regex1_decomposed
        .gen_regex_files(
            &Path::new("./examples/ex_allstr.txt").to_path_buf(),
            &[Path::new("./examples/ex_substr_id1.txt").to_path_buf()],
        )
        .unwrap();
    let characters: Vec<u8> = "email was meant for @vitalik."
        .chars()
        .map(|c| c as u8)
        .collect();
    let circuit = ExampleCircuit::<Fr> {
        characters,
        _marker: PhantomData,
    };
    let mut masked_chars = [Fr::from(0); MAX_STRING_LEN];
    let mut masked_substr_ids = [Fr::from(0); MAX_STRING_LEN];
    let offset = 21;
    for (idx, char) in "vitalik".as_bytes().into_iter().enumerate() {
        masked_chars[offset + idx] = Fr::from(*char as u64);
        masked_substr_ids[offset + idx] = Fr::from(1);
    }
    let prover = MockProver::run(
        K as u32,
        &circuit,
        vec![vec![masked_chars, masked_substr_ids].concat()],
    )
    .unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
