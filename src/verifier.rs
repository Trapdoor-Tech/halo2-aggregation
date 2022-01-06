use crate::lookup::{CommittedVar, EvaluatedVar, LookupChip};
use crate::permutation::PermutationChip;
use crate::transcript::{TranscriptChip, TranscriptInstruction};
use crate::vanishing::VanishingChip;
use crate::{Beta, Gamma, Theta, X, Y};
use blake2b_simd::Params as Blake2bParams;
use halo2::arithmetic::FieldExt;
use halo2::arithmetic::{CurveAffine, Field};
use halo2::circuit::Region;
use halo2::plonk::Error::TranscriptError;
use halo2::plonk::{Any, Column, Error, Expression, PinnedVerificationKey, VerifyingKey};
use halo2::transcript::{EncodedChallenge, TranscriptRead};
use halo2wrong::circuit::ecc::base_field_ecc::{BaseFieldEccChip, BaseFieldEccInstruction};
use halo2wrong::circuit::main_gate::{
    CombinationOption, MainGate, MainGateColumn, MainGateInstructions, Term,
};
use halo2wrong::circuit::{Assigned, AssignedCondition, AssignedValue};
use std::fmt::format;
use std::marker::PhantomData;
use std::ops::MulAssign;

pub struct VerifierChip<'a, C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>> {
    ecc_chip: BaseFieldEccChip<C>,
    lookup: LookupChip<C>,
    perm: PermutationChip<C>,
    vanishing: VanishingChip<C>,
    transcript: Option<&'a mut T>,
    transcript_chip: TranscriptChip<C>,
    _marker: PhantomData<E>,
}

pub(crate) fn compute_expr<C: CurveAffine>(
    main_gate: &MainGate<C::ScalarExt>,
    region: &mut Region<'_, C::ScalarExt>,
    offset: &mut usize,
    expression: &Expression<C::ScalarExt>,
    advice_evals: &[AssignedValue<C::ScalarExt>],
    fixed_evals: &[AssignedValue<C::ScalarExt>],
    instance_evals: &[AssignedValue<C::ScalarExt>],
) -> AssignedValue<C::ScalarExt> {
    match expression {
        Expression::Constant(scalar) => main_gate
            .assign_constant(
                region,
                &(Some(scalar.clone()).into()),
                MainGateColumn::A,
                offset,
            )
            .unwrap(),
        Expression::Selector(_) => {
            panic!("virtual selectors are removed during optimization")
        }
        Expression::Fixed { query_index, .. } => fixed_evals[*query_index].clone(),
        Expression::Advice { query_index, .. } => advice_evals[*query_index].clone(),
        Expression::Instance { query_index, .. } => instance_evals[*query_index].clone(),
        Expression::Negated(a) => {
            let a = compute_expr::<C>(
                main_gate,
                region,
                offset,
                a,
                advice_evals,
                fixed_evals,
                instance_evals,
            );
            main_gate.neg(region, a, offset).unwrap()
        }
        Expression::Sum(a, b) => {
            let a = compute_expr::<C>(
                main_gate,
                region,
                offset,
                a,
                advice_evals,
                fixed_evals,
                instance_evals,
            );
            let b = compute_expr::<C>(
                main_gate,
                region,
                offset,
                b,
                advice_evals,
                fixed_evals,
                instance_evals,
            );
            main_gate.add(region, a, b, offset).unwrap()
        }
        Expression::Product(a, b) => {
            let a = compute_expr::<C>(
                main_gate,
                region,
                offset,
                a,
                advice_evals,
                fixed_evals,
                instance_evals,
            );
            let b = compute_expr::<C>(
                main_gate,
                region,
                offset,
                b,
                advice_evals,
                fixed_evals,
                instance_evals,
            );
            main_gate.mul(region, a, b, offset).unwrap()
        }
        Expression::Scaled(a, scalar) => {
            let a = compute_expr::<C>(
                main_gate,
                region,
                offset,
                a,
                advice_evals,
                fixed_evals,
                instance_evals,
            );
            main_gate
                .mul_by_constant(region, a, *scalar, offset)
                .unwrap()
        }
    }
}

impl<'a, C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>>
    VerifierChip<'a, C, E, T>
{
    pub fn new(ecc_chip: BaseFieldEccChip<C>, transcript: Option<&'a mut T>) -> Self {
        Self {
            ecc_chip: ecc_chip.clone(),
            lookup: LookupChip::new(ecc_chip.clone()),
            perm: PermutationChip::new(ecc_chip.clone()),
            vanishing: VanishingChip::new(ecc_chip.clone()),
            transcript,
            transcript_chip: TranscriptChip::new(),
            _marker: Default::default(),
        }
    }

    pub fn verify_proof(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        vk: &VerifyingKey<C>,
        log_n: usize,
        blinding_factors: usize,
        num_adv_columns: usize,
        num_fixed_columns: usize,
        num_lookups: usize,
        perm_num_columns: usize,
        perm_chunk_len: usize,
        omega: C::ScalarExt,
        input_expressions: Vec<Expression<C::ScalarExt>>,
        table_expressions: Vec<Expression<C::ScalarExt>>,
        gates: Vec<Expression<C::ScalarExt>>,
        perm_columns: &Vec<(Column<Any>, usize)>,
        instance_commitments: &Vec<Option<C>>,
        offset: &mut usize,
    ) -> Result<AssignedCondition<C::ScalarExt>, Error> {
        let mut inst_comms = vec![];
        for inst_comm in instance_commitments.into_iter() {
            let comm = self.ecc_chip.assign_point(region, *inst_comm, offset)?;
            inst_comms.push(comm);
        }

        let transcript_chip = &mut self.transcript_chip;
        let main_gate = self.ecc_chip.main_gate();

        // hash vk into transcript
        {
            let mut hasher = Blake2bParams::new()
                .hash_length(64)
                .personal(b"Halo2-Verify-Key")
                .to_state();
            let s = format!("{:?}", vk.pinned());

            hasher.update(&(s.len() as u64).to_le_bytes());
            hasher.update(s.as_bytes());

            let hash_result = main_gate.assign_value(
                region,
                &Some(C::Scalar::from_bytes_wide(hasher.finalize().as_array())).into(),
                MainGateColumn::A,
                offset,
            )?;
            transcript_chip.common_scalar(region, hash_result, offset);
        }

        // hash the instance commitments into transcript
        for inst_comm in inst_comms.iter() {
            transcript_chip.common_point(region, inst_comm.clone(), offset);
        }

        let mut adv_comms = vec![];
        for i in (0..num_adv_columns).into_iter() {
            let comm = {
                match self.transcript.as_mut() {
                    None => None,
                    Some(t) => Some(t.read_point().map_err(|_| TranscriptError)?),
                }
            };
            let comm = self.ecc_chip.assign_point(region, comm, offset)?;
            adv_comms.push(comm.clone());
            transcript_chip.common_point(region, comm, offset);
        }

        let theta = transcript_chip.squeeze_challenge_scalar::<Theta>(region, offset);

        // hash each lookup permuted commitments into transcript
        let mut lookups_permuted = vec![];
        for i in (0..num_lookups).into_iter() {
            let pcv =
                self.lookup
                    .alloc_pcv(&mut self.transcript, transcript_chip, region, offset)?;
            lookups_permuted.push(pcv);
        }

        // sample beta challenge
        let beta = transcript_chip.squeeze_challenge_scalar::<Beta>(region, offset);

        // sample gamma challenge
        let gamma = transcript_chip.squeeze_challenge_scalar::<Gamma>(region, offset);

        // { zp_i }
        let permutations_committed = self.perm.alloc_cv(
            &mut self.transcript,
            transcript_chip,
            region,
            perm_num_columns,
            perm_chunk_len,
            offset,
        )?;

        let lookups_committed = lookups_permuted
            .into_iter()
            .map(|lookup_permuted| -> Result<CommittedVar<C>, Error> {
                self.lookup
                    .alloc_cv(&mut self.transcript, region, lookup_permuted, offset)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let vanishing =
            self.vanishing
                .alloc_before_y(&mut self.transcript, transcript_chip, region, offset)?;

        let y = transcript_chip.squeeze_challenge_scalar::<Y>(region, offset);

        let vanishing = self.vanishing.alloc_after_y(
            &mut self.transcript,
            transcript_chip,
            vanishing,
            vk.get_domain().get_quotient_poly_degree(),
            region,
            offset,
        )?;

        let x = transcript_chip.squeeze_challenge_scalar::<X>(region, offset);

        let mut inst_evals = vec![];
        for _ in 0..inst_comms.len() {
            let eval = {
                match self.transcript.as_mut() {
                    None => None,
                    Some(t) => Some(t.read_scalar().map_err(|_| TranscriptError)?),
                }
            };
            let eval = main_gate.assign_value(region, &eval.into(), MainGateColumn::A, offset)?;
            inst_evals.push(eval.clone());
            transcript_chip.common_scalar(region, eval, offset);
        }

        let mut adv_evals = vec![];
        for _ in (0..num_adv_columns).into_iter() {
            let eval = {
                match self.transcript.as_mut() {
                    None => None,
                    Some(t) => Some(t.read_scalar().map_err(|_| TranscriptError)?),
                }
            };
            let eval = main_gate.assign_value(region, &eval.into(), MainGateColumn::A, offset)?;
            adv_evals.push(eval.clone());
            transcript_chip.common_scalar(region, eval, offset);
        }

        let mut fixed_evals = vec![];
        for _ in (0..num_fixed_columns).into_iter() {
            let eval = {
                match self.transcript.as_mut() {
                    None => None,
                    Some(t) => Some(t.read_scalar().map_err(|_| TranscriptError)?),
                }
            };
            let eval = main_gate.assign_value(region, &eval.into(), MainGateColumn::A, offset)?;
            fixed_evals.push(eval.clone());
            transcript_chip.common_scalar(region, eval, offset);
        }
        let vanishing = self.vanishing.alloc_after_x(
            &mut self.transcript,
            transcript_chip,
            vanishing,
            region,
            offset,
        )?;
        let permutations_common = self.perm.alloc_cev(
            &mut self.transcript,
            transcript_chip,
            region,
            offset,
            perm_num_columns,
        )?;

        let lookups_evaluated = lookups_committed
            .into_iter()
            .map(|lookup_committed| -> Result<EvaluatedVar<C>, Error> {
                self.lookup.alloc_eval(
                    &mut self.transcript,
                    transcript_chip,
                    region,
                    lookup_committed,
                    offset,
                )
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let permutations_evaluated = self.perm.alloc_ev(
            &mut self.transcript,
            transcript_chip,
            region,
            offset,
            permutations_committed,
        )?;

        let vanishing = {
            let mut xn = x.value();
            for _ in 0..log_n {
                xn = main_gate.mul(region, &xn, &xn, offset)?;
            }
            // l_evals
            let mut l_evals: Vec<AssignedValue<C::ScalarExt>> = vec![];
            let mut omega_powers = C::ScalarExt::one();
            fn sub_by_constant<F: FieldExt>(
                main_gate: &MainGate<F>,
                region: &mut Region<F>,
                x: impl Assigned<F>,
                constant: F,
                offset: &mut usize,
            ) -> Result<AssignedValue<F>, Error> {
                let one = F::one();
                let neg_one = one.neg();

                let x_sub_c_val = match x.value() {
                    Some(x) => Some(x - &constant),
                    None => None,
                };

                let (_, x_sub_c, _, _) = main_gate.combine(
                    region,
                    Term::Assigned(&x, one),
                    Term::Unassigned(x_sub_c_val.clone(), neg_one.clone()),
                    Term::Zero,
                    Term::Zero,
                    neg_one,
                    offset,
                    CombinationOption::SingleLinerAdd,
                )?;

                Ok(AssignedValue::new(x_sub_c, x_sub_c_val))
            }

            let xn_sub_one =
                sub_by_constant(&main_gate, region, xn.clone(), C::ScalarExt::one(), offset)?;
            for _ in 0..(2 + blinding_factors) {
                // l_evals[i] = (x^n - 1) / (n*(x - w^i)) * w^i
                // let omega_i = main_gate.assign_constant(
                //     region,
                //     &Some(omega_powers.clone()).into(),
                //     MainGateColumn::A,
                //     offset,
                // )?;

                // w^i*(x^n-1)
                let numerator =
                    main_gate.mul_by_constant(region, &xn_sub_one, omega_powers, offset)?;
                // n*(x - w^i)
                let denominator = {
                    let term =
                        sub_by_constant(&main_gate, region, &x.value(), omega_powers, offset)?;
                    main_gate.mul_by_constant(
                        region,
                        &term,
                        C::ScalarExt::from_u128(1 << log_n),
                        offset,
                    )?
                };

                let (li, _) = main_gate.div(region, &numerator, &denominator, offset)?;
                l_evals.push(li);
                omega_powers.mul_assign(omega);
            }
            assert_eq!(l_evals.len(), 2 + blinding_factors);
            let l_last = l_evals[0].clone();
            let mut l_blind = l_evals[1].clone();
            for i in 2..(1 + blinding_factors) {
                l_blind = main_gate.add(region, &l_blind, &l_evals[i], offset)?;
            }
            let l_0 = l_evals[1 + blinding_factors].clone();

            let mut expressions = vec![];

            for gate in gates.into_iter() {
                expressions.push(compute_expr::<C>(
                    &main_gate,
                    region,
                    offset,
                    &gate,
                    &adv_evals,
                    &fixed_evals,
                    &inst_evals,
                ));
            }
            for lookup_eval in lookups_evaluated.into_iter() {
                let expr = self.lookup.expressions(
                    region,
                    lookup_eval,
                    l_0.clone(),
                    l_last.clone(),
                    l_blind.clone(),
                    &input_expressions,
                    &table_expressions,
                    theta.clone(),
                    beta.clone(),
                    gamma.clone(),
                    &adv_evals,
                    &fixed_evals,
                    &inst_evals,
                    offset,
                )?;
                expressions.extend(expr);
            }

            expressions.extend(self.perm.expressions(
                region,
                &permutations_common,
                &permutations_evaluated,
                perm_columns,
                &adv_evals,
                &fixed_evals,
                &inst_evals,
                l_0.clone(),
                l_last.clone(),
                l_blind.clone(),
                beta.clone(),
                gamma.clone(),
                x.clone(),
                perm_chunk_len,
                offset,
            )?);
            self.vanishing.verify(
                region,
                vanishing,
                &expressions,
                y.clone(),
                xn.clone(),
                offset,
            )?
        };

        let ret =
            self.ecc_chip
                .main_gate()
                .assign_bit(region, Some(C::ScalarExt::zero()), offset)?;

        Ok(ret)
    }
}
