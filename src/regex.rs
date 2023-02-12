use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Assigned, Circuit, Column, ConstraintSystem, Constraints, Error, Expression,
        Selector,
    },
    poly::Rotation,
};
use std::marker::PhantomData;

use crate::table::RangeTableConfig;

// Checks a regex of string len
const STRING_LEN: usize = 8;

#[derive(Debug, Clone)]
struct RangeConstrained<F: PrimeField>(AssignedCell<F, F>);

// Here we decompose a transition into 3-value lookups.

#[derive(Debug, Clone)]
struct RegexCheckConfig<F: PrimeField> {
    characters: Column<Instance>,
    state: Column<Advice>,
    transition_table: TransitionTable<F>,
    q_lookup_state_selector: Column<Selector>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> RegexCheckConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let characters = meta.instance_column();
        let state = meta.advice_column();
        let q_lookup_state_selector = meta.selector_column();
        let transition_table = TransitionTableConfig::configure(meta);

        // Lookup each transition value individually, not paying attention to bit count
        meta.lookup(|meta| {
            let q = meta.query_selector(q_lookup_state_selector);
            let prev_state = meta.query_advice(state, Rotation::cur());
            let next_state = meta.query_advice(state, Rotation::next());
            let character = meta.query_advice(character, Rotation::cur());

            let one_minus_q = Expression::Constant(F::one()) - q.clone();
            let negative_1 = Expression::Constant(F::from_u64(-1));

            vec![
                (
                    q.clone() * prev_state + one_minus_q.clone() * Expression::Constant(negative_1),
                    table.prev_state,
                ),
                (
                    q.clone() * next_state + one_minus_q.clone() * Expression::Constant(negative_1),
                    table.next_state,
                ),
                (
                    q.clone() * character + one_minus_q.clone() * Expression::Constant(negative_1),
                    table.character,
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
        characters: str,
        states: [F; STRING_LEN],
    ) -> Result<bool, Error> {
        layouter.assign_region(
            || "Assign values",
            |mut region| {
                let offset = 0;

                // Enable q_decomposed
                for i in 0..STRING_LEN {
                    // offset = i;
                    self.q_lookup_state_selector.enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("character", i),
                        characters[i],
                        i,
                        || Value::known(F::from_u128(characters[i])),
                    )?;
                    region.assign_advice(
                        || format!("state", i),
                        states[i],
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
    pub characters: str,
    pub states: [u128; STRING_LEN],
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Circuit<F> for RegexCheckCircuit<F> {
    type Config = RegexCheckConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    // Circuit without witnesses, called only during key generation
    fn without_witnesses(&self) -> Self {
        Self {
            characters: "",
            states: [0 as u128; STRING_LEN],
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
        config.table.load(&mut layouter)?;
        print!("Synthesize being called...");
        let mut value = config.assign_values(
            layouter.namespace(|| "Assign all values"),
            self.characters,
            self.states,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::floor_planner::V1,
        dev::{FailureLocation, MockProver, VerifyFailure},
        pasta::Fp,
        plonk::{Any, Circuit},
    };

    use super::*;

    #[test]
    fn test_range_check_pass() {
        let k = 10; // 8, 128, etc

        // Successful cases
        for i in 0..RANGE {
            let i = 0;
            let circuit = RegexCheckCircuit::<Fp> {
                value: i as u128,
                _marker: PhantomData,
            };

            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            prover.assert_satisfied();
        }
    }

    #[test]
    fn test_range_check_fail() {
        let k = 10;
        // Out-of-range `value = 8`
        let circuit = RegexCheckCircuit::<Fp> {
            value: RANGE as u128,
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
