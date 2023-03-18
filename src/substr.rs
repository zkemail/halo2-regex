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

#[derive(Debug, Clone)]
pub struct SubstrDef {
    max_length: usize,
    min_position: u64,
    max_position: u64,
    correct_state: u64,
}

#[derive(Debug, Clone)]
pub struct AssignedSubstrResult<'a, F: PrimeField> {
    pub assigned_bytes: Vec<AssignedValue<'a, F>>,
    pub assigned_length: AssignedValue<'a, F>,
}

#[derive(Debug, Clone)]
pub struct SubstrMatchConfig<'a, F: PrimeField> {
    regex_config: RegexCheckConfig<F>,
    main_gate: FlexGateConfig<F>,
    assigned_characters: Vec<AssignedValue<'a, F>>,
    assigned_states: Vec<AssignedValue<'a, F>>,
    assigned_indexes: Vec<AssignedValue<'a, F>>,
}

impl<'a, F: PrimeField> SubstrMatchConfig<'a, F> {
    pub fn construct(regex_config: RegexCheckConfig<F>, main_gate: FlexGateConfig<F>) -> Self {
        Self {
            regex_config,
            main_gate,
            assigned_characters: Vec::new(),
            assigned_states: Vec::new(),
            assigned_indexes: Vec::new(),
        }
    }

    pub fn set_string<'v>(
        &mut self,
        ctx: &mut Context<'v, F>,
        characters: &[u8],
        states: &[u64],
    ) -> Result<(), Error> {
        debug_assert_eq!(characters.len(), states.len());
        debug_assert_eq!(self.assigned_characters.len(), 0);
        let regex_result = self
            .regex_config
            .assign_values(&mut ctx.region, characters, states)?;
        let mut assigned_characters = Vec::new();
        let mut assigned_states = Vec::new();
        let mut assigned_indexes = Vec::new();
        for (idx, (assigned_char, assigned_state)) in regex_result
            .characters
            .into_iter()
            .zip(regex_result.states.into_iter())
            .enumerate()
        {
            let assigned_c = self.assigned_cell2value(ctx, &assigned_char)?;
            assigned_characters.push(assigned_c);
            let assigned_s = self.assigned_cell2value(ctx, &assigned_state)?;
            assigned_states.push(assigned_s);
            let assigned_index = self.gate().load_constant(ctx, F::from(idx as u64));
            assigned_indexes.push(assigned_index);
        }
        Ok(())
    }

    pub fn match_substr(
        &self,
        ctx: &mut Context<'a, F>,
        substr_def: &SubstrDef,
        substr_positions: &[u64],
    ) -> Result<AssignedSubstrResult<'a, F>, Error> {
        let all_max_len = self.assigned_characters.len();
        let substr_max_len = substr_def.max_length;
        debug_assert!(substr_max_len <= all_max_len);
        debug_assert!(substr_def.max_position as usize <= all_max_len);
        debug_assert_eq!(substr_max_len, substr_positions.len());

        let gate = self.gate();
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
            for position in
                (substr_def.min_position as usize + idx)..=(substr_def.max_position as usize + idx)
            {
                let assigned_c = &self.assigned_characters[position];
                let assigned_s = &self.assigned_states[position];
                let assigned_i = &self.assigned_indexes[position];
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
                let last_substr = &assigned_substr[assigned_substr.len() - 1];
                let new_substr = gate.mul_add(
                    ctx,
                    QuantumCell::Existing(&assigned_c),
                    QuantumCell::Existing(&selector),
                    QuantumCell::Existing(&last_substr),
                );
                assigned_substr.push(new_substr);
                assigned_len = gate.add(
                    ctx,
                    QuantumCell::Existing(&assigned_len),
                    QuantumCell::Existing(&selector),
                );
                last_selector = selector;
            }
        }
        let result = AssignedSubstrResult {
            assigned_bytes: assigned_substr,
            assigned_length: assigned_len,
        };
        Ok(result)
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
