mod regex;
mod substr;
pub mod table;
pub use regex::*;
pub use substr::*;

// Axiom Snark-Verifier

// use std::{
//     fs::{self, File},
//     io::Write,
//     iter,
//     path::Path,
//     time::Instant,
// };

// use std::env::{set_var, var};

// use halo2_base::{
//     halo2_proofs::{
//         circuit::Value,
//         dev::MockProver,
//         halo2curves::{
//             bn256::{Bn256, Fr},
//             group::ff::PrimeField,
//             FieldExt,
//         },
//         plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, Error as PlonkError},
//         poly::{
//             commitment::{Params, ParamsProver},
//             kzg::{
//                 commitment::ParamsKZG,
//                 multiopen::{ProverSHPLONK, VerifierGWC, VerifierSHPLONK},
//                 strategy::SingleStrategy,
//             },
//         },
//         transcript::{
//             Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
//         },
//     },
//     utils::{fs::gen_srs, value_to_option},
// };

// use rand::{rngs::OsRng, SeedableRng};
// use rand_chacha::ChaCha20Rng;
// use snark_verifier_sdk::{
//     evm::{
//         encode_calldata, evm_verify, gen_evm_proof_gwc, gen_evm_proof_shplonk,
//         gen_evm_verifier_gwc, gen_evm_verifier_shplonk,
//     },
//     halo2::{
//         aggregation::PublicAggregationCircuit, gen_proof_gwc, gen_proof_shplonk, gen_snark,
//         gen_snark_gwc, gen_snark_shplonk, PoseidonTranscript,
//     },
//     CircuitExt, NativeLoader,
// };

// //use snark_verifier_sdk::halo2::gen_snark;

// fn main() -> Result<(), PlonkError> {
//     const PREFIX: &str = "";
//     set_var("VERIFY_CONFIG", "./configs/verify_circuit.config");
//     let mut rng = ChaCha20Rng::from_entropy();

//     // Convert query string to u128s
//     let characters: Vec<u8> = "email was meant for @y".chars().map(|c| c as u8).collect();

//     // Make a vector of the numbers 1...24
//     // let states = (1..=STRING_LEN as u128).collect::<Vec<u128>>();
//     assert_eq!(characters.len(), STRING_LEN);
//     // assert_eq!(states.len(), STRING_LEN);

//     // Successful cases
//     let circuit = RegexCheckCircuit::<Fr> {
//         characters,
//         _marker: PhantomData,
//     };

//     let mock = {
//         let prover = MockProver::run(20, &circuit, input_instance).unwrap();
//         let input_instance = vec![vec![Fr::one(), Fr::one()]];

//         // OUTPUT.get().unwrap().iter().map(|output| {
//         //     output.map(|x| felt_to_i64(x))
//         // }).enumerate().for_each(|(index, output_calc)| {
//         //     println!("output calc for index {} is {:?}", index, output_calc);
//         // });
//     };

//     let output: Vec<_> = OUTPUT
//         .get()
//         .unwrap()
//         .iter()
//         .map(|output| felt_to_i64(value_to_option(*output).unwrap()))
//         .collect();

//     let mut f = File::create("./proof_dir/calc_output.json")?;

//     json::from(output).write(&mut f)?;

//     let input_hash = value_to_option(*HASH_INPUT.get().unwrap()).unwrap();
//     let output_hash = value_to_option(*HASH_OUTPUT.get().unwrap()).unwrap();

//     println!("output hash is {:?}", output_hash);

//     // let now = Instant::now();

//     // MockProver::run(20, &circuit, vec![vec![input_hash, output_hash]]).unwrap().assert_satisfied();

//     // println!("mock prover satisfied in {}", now.elapsed().as_secs_f32());

//     circuit.input_hash = Some(input_hash);
//     circuit.output_hash = Some(output_hash);

//     let params_max: ParamsKZG<Bn256> = gen_srs(24);

//     let snark = {
//         let now = Instant::now();

//         let params = {
//             let mut params = params_max.clone();
//             params.downsize(20);
//             params
//         };

//         println!("params generated in {}", now.elapsed().as_secs_f32());

//         let now = Instant::now();

//         let vk = keygen_vk(&params, &circuit).unwrap();

//         println!("vk generated in {}", now.elapsed().as_secs_f32());

//         let now = Instant::now();

//         let pk = keygen_pk(&params, vk, &circuit).unwrap();

//         println!("pk generated in {}", now.elapsed().as_secs_f32());

//         let now = Instant::now();

//         let out = gen_snark_shplonk(&params, &pk, circuit, &mut rng, None::<Box<Path>>);
//         println!("inner snark generated in {}", now.elapsed().as_secs_f32());
//         out
//     };

//     let agg_circuit = PublicAggregationCircuit::new(&params_max, vec![snark], false, &mut rng);

//     let now = Instant::now();

//     let vk_agg = keygen_vk(&params_max, &agg_circuit).unwrap();

//     println!("vk_agg generated in {}", now.elapsed().as_secs_f32());

//     let now = Instant::now();

//     let pk_agg = keygen_pk(&params_max, vk_agg, &agg_circuit).unwrap();

//     println!("pk_agg generated in {}", now.elapsed().as_secs_f32());

//     let now = Instant::now();

//     let proof = gen_evm_proof_shplonk(
//         &params_max,
//         &pk_agg,
//         agg_circuit.clone(),
//         agg_circuit.instances(),
//         &mut rng,
//     );

//     let mut f = File::create("./proof_dir/proof")?;

//     f.write_all(proof.as_slice()).unwrap();

//     println!("outer proof generated in {}", now.elapsed().as_secs_f32());

//     let verifier_contract = gen_evm_verifier_shplonk::<PublicAggregationCircuit>(
//         &params_max,
//         pk_agg.get_vk(),
//         agg_circuit.num_instance(),
//         None,
//     );

//     let mut f = File::create("./proof_dir/verifier_contract_bytecode")?;

//     f.write_all(verifier_contract.as_slice()).unwrap();

//     println!("contract len: {:?}", verifier_contract.len());

//     println!(
//         "instances are {:?}, instance_len is {:?}, proof len is {:?}",
//         agg_circuit.instances(),
//         agg_circuit.num_instance(),
//         proof.len()
//     );

//     let calldata = encode_calldata(&agg_circuit.instances(), &proof);

//     let mut f = File::create("./proof_dir/official_calldata")?;

//     f.write_all(calldata.as_slice()).unwrap();

//     evm_verify(verifier_contract, agg_circuit.instances(), proof);

//     let instances = &agg_circuit.instances()[0][0..12];

//     let instances_output: Vec<_> = instances
//         .iter()
//         .flat_map(|value| {
//             value
//                 .to_repr()
//                 .as_ref()
//                 .iter()
//                 .rev()
//                 .cloned()
//                 .collect::<Vec<_>>()
//         })
//         .collect();

//     let mut f = File::create("./proof_dir/limbs_instance")?;

//     f.write_all(instances_output.as_slice()).unwrap();

//     println!("Done!");
//     Ok(())
// }
