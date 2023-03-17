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

// Checks a regex of string len
const STRING_LEN: usize = 22;

#[derive(Debug, Clone)]
struct RangeConstrained<F: PrimeField>(AssignedCell<F, F>);

pub struct AssignedRegexResult<'a, F: PrimeField> {
    characters: Vec<AssignedValue<'a, F>>,
    state: Vec<AssignedValue<'a, F>>,
}

// Here we decompose a transition into 3-value lookups.

#[derive(Debug, Clone)]
struct RegexCheckConfig<F: PrimeField> {
    characters: Column<Advice>,
    // characters_advice: Column<Instance>,
    state: Column<Advice>,
    transition_table: TransitionTableConfig<F>,
    q_lookup_state_selector: Selector,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> RegexCheckConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let characters = meta.advice_column();
        let state = meta.advice_column();
        let q_lookup_state_selector = meta.complex_selector();
        let transition_table = TransitionTableConfig::configure(meta);

        // Lookup each transition value individually, not paying attention to bit count
        meta.lookup("lookup characters and their state", |meta| {
            let q = meta.query_selector(q_lookup_state_selector);
            let prev_state = meta.query_advice(state, Rotation::cur());
            let next_state = meta.query_advice(state, Rotation::next());
            let character = meta.query_advice(characters, Rotation::cur());

            // One minus q
            let one_minus_q = Expression::Constant(F::from(1)) - q.clone();
            let zero = Expression::Constant(F::from(0));

            /*
                | q | state | characters | table.prev_state | table.next_state  | table.character
                | 1 | s_cur |    char    |       s_cur      |     s_next        |     char
                |   | s_next|
            */

            vec![
                (
                    q.clone() * prev_state + one_minus_q.clone() * zero.clone(),
                    transition_table.prev_state,
                ),
                (
                    q.clone() * next_state + one_minus_q.clone() * zero.clone(),
                    transition_table.next_state,
                ),
                (
                    q.clone() * character + one_minus_q.clone() * zero.clone(),
                    transition_table.character,
                ),
            ]
        });

        Self {
            characters,
            state,
            q_lookup_state_selector,
            transition_table,
            _marker: PhantomData,
        }
    }

    // Note that the two types of region.assign_advice calls happen together so that it is the same region
    pub fn assign_values(
        &self,
        mut layouter: impl Layouter<F>,
        characters: Vec<u128>,
        states: Vec<u128>,
    ) -> Result<bool, Error> {
        layouter.assign_region(
            || "Assign values",
            |mut region| {
                // let offset = 0;

                // Enable q_decomposed
                for i in 0..STRING_LEN {
                    println!("{:?}, {:?}", characters[i], states[i]);
                    // offset = i;
                    if i < STRING_LEN - 1 {
                        self.q_lookup_state_selector.enable(&mut region, i)?;
                    }
                    region.assign_advice(
                        || format!("character"),
                        self.characters,
                        i,
                        || Value::known(F::from_u128(characters[i])),
                    )?;
                    region.assign_advice(
                        || format!("state"),
                        self.state,
                        i,
                        || Value::known(F::from_u128(states[i])),
                    )?;
                }
                Ok(true)
            },
        )
    }
}
#[derive(Default, Clone)]
struct RegexCheckCircuit<F: PrimeField> {
    // Since this is only relevant for the witness, we can opt to make this whatever convenient type we want
    pub characters: Vec<u128>,
    pub states: Vec<u128>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Circuit<F> for RegexCheckCircuit<F> {
    type Config = RegexCheckConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    // Circuit without witnesses, called only during key generation
    fn without_witnesses(&self) -> Self {
        Self {
            characters: vec![],
            states: vec![],
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
        config.transition_table.load(&mut layouter)?;
        print!("Synthesize being called...");
        let mut value = config.assign_values(
            layouter.namespace(|| "Assign all values"),
            self.characters.clone(),
            self.states.clone(),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_base::halo2_proofs::{
        circuit::floor_planner::V1,
        dev::{FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::Fr,
        plonk::{Any, Circuit},
    };

    use super::*;

    #[test]
    fn test_regex_pass() {
        let k = 7; // 8, 128, etc

        // Convert query string to u128s
        let characters: Vec<u128> = "email was meant for @y"
            .chars()
            .map(|c| c as u32 as u128)
            .collect();

        // Make a vector of the numbers 1...24
        let states = (1..=STRING_LEN as u128).collect::<Vec<u128>>();
        assert_eq!(characters.len(), STRING_LEN);
        assert_eq!(states.len(), STRING_LEN);

        // Successful cases
        let circuit = RegexCheckCircuit::<Fr> {
            characters,
            states,
            _marker: PhantomData,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_regex_fail() {
        let k = 10;

        // Convert query string to u128s
        let characters: Vec<u128> = "email isnt meant for u"
            .chars()
            .map(|c| c as u32 as u128)
            .collect();

        // Make a vector of the numbers 1...24
        let states = (1..=STRING_LEN as u128).collect::<Vec<u128>>();

        assert_eq!(characters.len(), STRING_LEN);
        assert_eq!(states.len(), STRING_LEN);

        // Out-of-range `value = 8`
        let circuit = RegexCheckCircuit::<Fr> {
            characters: characters,
            states: states,
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
