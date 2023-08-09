// use halo2_base::halo2_proofs::{
//     circuit::Layouter,
//     dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
//     halo2curves::bn256::{Bn256, Fr, G1Affine, G1},
//     plonk::{Any, Circuit, Error},
// };
// use halo2_base::{
//     gates::{flex_gate::FlexGateConfig, range::RangeStrategy::Vertical},
//     utils::{bigint_to_fe, biguint_to_fe, fe_to_biguint, modulus, PrimeField},
//     Context, ContextParams, SKIP_FIRST_PASS,
// };

// use fancy_regex::Regex;
// use halo2_base::halo2_proofs::plonk::{
//     create_proof, keygen_pk, keygen_vk, verify_proof, ConstraintSystem,
// };
// use halo2_base::halo2_proofs::poly::commitment::{Params, ParamsProver, ParamsVerifier};
// use halo2_base::halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
// use halo2_base::halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
// use halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
// use halo2_base::halo2_proofs::transcript::{
//     Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
// };
// use halo2_base::halo2_proofs::{
//     circuit::{floor_planner::V1, Cell, SimpleFloorPlanner},
//     plonk::{Column, Instance},
// };
// use halo2_regex::*;
// use halo2_regex::{defs::*, vrm::*};
// use itertools::Itertools;
// use rand::rngs::OsRng;
// use snark_verifier_sdk::CircuitExt;
// use std::{collections::HashSet, path::Path};
// use std::{fs::File, marker::PhantomData};

// // Checks a regex of string len
// const MAX_STRING_LEN: usize = 1024;
// const K: usize = 17;

// #[derive(Default, Clone, Debug)]
// struct TestCircuit1<F: PrimeField> {
//     // Since this is only relevant for the witness, we can opt to make this whatever convenient type we want
//     characters: Vec<u8>,
//     correct_substrs: Vec<(usize, String)>,
//     _marker: PhantomData<F>,
// }

// impl<F: PrimeField> TestCircuit1<F> {
//     const NUM_ADVICE: usize = 2;
//     const NUM_FIXED: usize = 1;
// }

// impl<F: PrimeField> Circuit<F> for TestCircuit1<F> {
//     type Config = RegexVerifyConfig<F>;
//     type FloorPlanner = SimpleFloorPlanner;

//     // Circuit without witnesses, called only during key generation
//     fn without_witnesses(&self) -> Self {
//         Self {
//             characters: vec![],
//             correct_substrs: vec![],
//             _marker: PhantomData,
//         }
//     }

//     fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
//         // let all_regex_def1 = AllstrRegexDef::read_from_text("./benches/regex1_test_lookup.txt");
//         // let substr_def1 = SubstrRegexDef::read_from_text("./test_regexes/substr1_test_lookup.txt");
//         // let all_regex_def2 =
//         //     AllstrRegexDef::read_from_text("./test_regexes/regex2_test_lookup.txt");
//         // let substr_def2 = SubstrRegexDef::read_from_text("./test_regexes/substr2_test_lookup.txt");
//         let from_regex = RegexDefs {
//             allstr: AllstrRegexDef::read_from_text("./test_data/from_allstr.txt"),
//             substrs: vec![SubstrRegexDef::read_from_text(
//                 "./test_data/from_substr_0.txt",
//             )],
//         };
//         let to_regex = RegexDefs {
//             allstr: AllstrRegexDef::read_from_text("./test_data/to_allstr.txt"),
//             substrs: vec![SubstrRegexDef::read_from_text(
//                 "./test_data/to_substr_0.txt",
//             )],
//         };
//         let subject_regex = RegexDefs {
//             allstr: AllstrRegexDef::read_from_text("./test_data/subject_allstr.txt"),
//             substrs: vec![
//                 SubstrRegexDef::read_from_text("./test_data/subject_substr_0.txt"),
//                 SubstrRegexDef::read_from_text("./test_data/subject_substr_1.txt"),
//                 SubstrRegexDef::read_from_text("./test_data/subject_substr_2.txt"),
//             ],
//         };
//         // let substr_def2 =
//         //     SubstrRegexDef::read_from_text("./test_regexes/substr2_test_lookup.txt");
//         let gate = FlexGateConfig::<F>::configure(
//             meta,
//             halo2_base::gates::flex_gate::GateStrategy::Vertical,
//             &[Self::NUM_ADVICE],
//             Self::NUM_FIXED,
//             0,
//             K,
//         );
//         let regex_defs = vec![from_regex, to_regex, subject_regex];
//         let config = RegexVerifyConfig::configure(meta, MAX_STRING_LEN, gate, regex_defs);
//         config
//     }

//     fn synthesize(
//         &self,
//         config: Self::Config,
//         mut layouter: impl Layouter<F>,
//     ) -> Result<(), Error> {
//         // test regex: "email was meant for @(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_)+( and (a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+)*."
//         config.load(&mut layouter)?;

//         // println!("Synthesize being called...");
//         let mut first_pass = SKIP_FIRST_PASS;
//         let gate = config.gate().clone();
//         // let mut substr_positions = self.substr_positions.to_vec();
//         // for _ in substr_positions.len()..self.substr_def.max_length {
//         //     substr_positions.push(0);
//         // }

//         layouter.assign_region(
//             || "regex",
//             |region| {
//                 if first_pass {
//                     first_pass = false;
//                     return Ok(());
//                 }
//                 let mut aux = Context::new(
//                     region,
//                     ContextParams {
//                         max_rows: gate.max_rows,
//                         num_context_ids: 1,
//                         fixed_columns: gate.constants.clone(),
//                     },
//                 );
//                 let ctx = &mut aux;
//                 let result = config.match_substrs(ctx, &self.characters)?;
//                 let mut expected_masked_chars = vec![0; MAX_STRING_LEN];
//                 let mut expected_substr_ids = vec![0; MAX_STRING_LEN];

//                 for (substr_idx, (start, chars)) in self.correct_substrs.iter().enumerate() {
//                     for (idx, char) in chars.as_bytes().iter().enumerate() {
//                         expected_masked_chars[start + idx] = *char;
//                         expected_substr_ids[start + idx] = substr_idx + 1;
//                     }
//                 }
//                 for idx in 0..MAX_STRING_LEN {
//                     result.masked_characters[idx]
//                         .value()
//                         .map(|v| assert_eq!(*v, F::from(expected_masked_chars[idx] as u64)));
//                     result.all_substr_ids[idx]
//                         .value()
//                         .map(|v| assert_eq!(*v, F::from(expected_substr_ids[idx] as u64)));
//                 }
//                 Ok(())
//             },
//         )?;
//         Ok(())
//     }
// }

// fn get_substr(input_str: &str, regexes: &[String]) -> Option<(usize, String)> {
//     let regexes = regexes
//         .into_iter()
//         .map(|raw| Regex::new(&raw).unwrap())
//         .collect_vec();
//     let mut start = 0;
//     let mut substr = input_str;
//     // println!("first regex {}", regexes[0]);
//     for regex in regexes.into_iter() {
//         // println!(r"regex {}", regex);
//         match regex.find(substr).unwrap() {
//             Some(m) => {
//                 start += m.start();
//                 substr = m.as_str();
//             }
//             None => {
//                 return None;
//             }
//         };
//     }
//     // println!("substr {}", substr);
//     // println!("start {}", start);
//     Some((start, substr.to_string()))
// }

// fn main() {
//     let regex_from_decomposed: DecomposedRegexConfig =
//         serde_json::from_reader(File::open("./test_data/from_defs.json").unwrap()).unwrap();
//     regex_from_decomposed
//         .gen_regex_files(
//             &Path::new("./test_data/from_allstr.txt").to_path_buf(),
//             &[Path::new("./test_data/from_substr_0.txt").to_path_buf()],
//         )
//         .unwrap();
//     let regex_to_decomposed: DecomposedRegexConfig =
//         serde_json::from_reader(File::open("./test_data/to_defs.json").unwrap()).unwrap();
//     regex_to_decomposed
//         .gen_regex_files(
//             &Path::new("./test_data/to_allstr.txt").to_path_buf(),
//             &[Path::new("./test_data/to_substr_0.txt").to_path_buf()],
//         )
//         .unwrap();
//     let regex_subject_decomposed: DecomposedRegexConfig =
//         serde_json::from_reader(File::open("./test_data/subject_defs.json").unwrap()).unwrap();
//     regex_subject_decomposed
//         .gen_regex_files(
//             &Path::new("./test_data/subject_allstr.txt").to_path_buf(),
//             &[
//                 Path::new("./test_data/subject_substr_0.txt").to_path_buf(),
//                 Path::new("./test_data/subject_substr_1.txt").to_path_buf(),
//                 Path::new("./test_data/subject_substr_2.txt").to_path_buf(),
//             ],
//         )
//         .unwrap();
//     let email_bytes = {
//         let mut f = File::open("./test_data/test_email2.eml").unwrap();
//         let mut buf = Vec::new();
//         f.read_to_end(&mut buf).unwrap();
//         buf
//     };
//     let (input, _, _) = canonicalize_signed_email(&email_bytes).unwrap();
//     let input_str = String::from_utf8(input.clone()).unwrap();
//     let mut expected_masked_chars = vec![Fr::from(0); TestRegexSha2Circuit2::<Fr>::MAX_BYTES_SIZE];
//     let mut expected_substr_ids = vec![Fr::from(0); TestRegexSha2Circuit2::<Fr>::MAX_BYTES_SIZE];
//     let correct_substrs = vec![
//             get_substr(
//                 &input_str,
//                 &[
//                     r"(?<=bh=)(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|\+|/|=)+(?=;)"
//                         .to_string(),
//                 ],
//             )
//             .unwrap(),
//             get_substr(&input_str, &[r"(?<=from:).*@.*(?=\r)".to_string()]).unwrap(),
//             get_substr(&input_str, &[r"(?<=to:).*@.*(?=\r)".to_string()]).unwrap(),
//             get_substr(&input_str, &[r"(?<=subject:).*(?=\r)".to_string()]).unwrap(),
//         ];
//     for (substr_idx, (start, chars)) in correct_substrs.iter().enumerate() {
//         for (idx, char) in chars.as_bytes().iter().enumerate() {
//             expected_masked_chars[start + idx] = Fr::from(*char as u64);
//             expected_substr_ids[start + idx] = Fr::from(substr_idx as u64 + 1);
//         }
//     }
//     let circuit = TestRegexSha2Circuit2::<Fr> {
//         input,
//         _f: PhantomData,
//     };
//     let expected_output = Sha256::digest(&circuit.input);
//     let hash_fs = expected_output
//         .iter()
//         .map(|byte| Fr::from(*byte as u64))
//         .collect::<Vec<Fr>>();
//     let prover = MockProver::run(
//         TestRegexSha2Circuit2::<Fr>::K,
//         &circuit,
//         vec![hash_fs, expected_masked_chars, expected_substr_ids],
//     )
//     .unwrap();
//     assert_eq!(prover.verify(), Ok(()));
// }
fn main() {}
