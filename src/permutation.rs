use crate::multiopen::VerifierQuery;
use crate::transcript::TranscriptChip;
use crate::transcript::TranscriptInstructions;
use crate::{ChallengeBeta, ChallengeGamma, ChallengeX};
use halo2::arithmetic::{CurveAffine, Field, FieldExt};
use halo2::circuit::Region;
use halo2::plonk::Error::Transcript as TranscriptError;
use halo2::plonk::{Any, Column, ConstraintSystem, Error, VerifyingKey};
use halo2::poly::Rotation;
use halo2::transcript::{EncodedChallenge, Transcript, TranscriptRead};
use halo2wrong::circuit::ecc::base_field_ecc::{BaseFieldEccChip, BaseFieldEccInstruction};
use halo2wrong::circuit::ecc::AssignedPoint;
use halo2wrong::circuit::main_gate::{MainGateColumn, MainGateInstructions};
use halo2wrong::circuit::{Assigned, AssignedValue};
use std::marker::PhantomData;
use std::ops::MulAssign;
use std::{io, iter};

#[derive(Clone, Debug)]
pub struct CommittedVar<C: CurveAffine> {
    // commitment of grand product polynomials of permutation argument
    pub permutation_product_commitments: Vec<AssignedPoint<C::ScalarExt>>,
}

pub struct EvaluatedSetVar<C: CurveAffine> {
    permutation_product_commitment: AssignedPoint<C::ScalarExt>,
    permutation_product_eval: AssignedValue<C::ScalarExt>, // Zp(z)
    permutation_product_next_eval: AssignedValue<C::ScalarExt>, // Zp(z*omega)
    permutation_product_last_eval: Option<AssignedValue<C::ScalarExt>>,
}

pub struct EvaluatedVar<C: CurveAffine> {
    sets: Vec<EvaluatedSetVar<C>>,
}

pub struct CommonEvaluatedVar<C: CurveAffine> {
    pub permutation_evals: Vec<AssignedValue<C::ScalarExt>>, // { sigma_i(z) }
}

pub struct PermutationChip<C: CurveAffine> {
    ecc_chip: BaseFieldEccChip<C>,
}

impl<C: CurveAffine> PermutationChip<C> {
    pub fn new(ecc_chip: BaseFieldEccChip<C>) -> Self {
        Self { ecc_chip }
    }
    pub fn alloc_cv<E, T>(
        &mut self,
        transcript: &mut Option<&mut T>,
        transcript_chip: &mut TranscriptChip<C>,
        region: &mut Region<'_, C::ScalarExt>,
        num_columns: usize,
        chunk_len: usize, // vk.cs.degree() - 2
        offset: &mut usize,
    ) -> Result<CommittedVar<C>, Error>
    where
        E: EncodedChallenge<C>,
        T: TranscriptRead<C, E>,
    {
        let num_chunks = (num_columns + chunk_len - 1) / chunk_len;
        let comms = (0..num_chunks)
            .into_iter()
            .map(|_| -> Result<AssignedPoint<C::ScalarExt>, Error> {
                let point = match transcript.as_mut() {
                    None => None,
                    Some(t) => Some(t.read_point().map_err(|e| TranscriptError(e))?),
                };
                self.ecc_chip.assign_point(region, point, offset)
            })
            .collect::<Result<Vec<AssignedPoint<C::ScalarExt>>, Error>>()?;

        for comm in comms.iter() {
            transcript_chip.common_point(region, comm.clone(), offset);
        }
        Ok(CommittedVar {
            permutation_product_commitments: comms,
        })
    }

    pub fn alloc_ev<E, T>(
        &mut self,
        transcript: &mut Option<&mut T>,
        transcript_chip: &mut TranscriptChip<C>,
        region: &mut Region<C::ScalarExt>,
        offset: &mut usize,
        cv: CommittedVar<C>,
    ) -> Result<EvaluatedVar<C>, Error>
    where
        E: EncodedChallenge<C>,
        T: TranscriptRead<C, E>,
    {
        let mut sets = vec![];

        let mut iter = cv.permutation_product_commitments.into_iter();
        while let Some(zp_commitment) = iter.next() {
            let (zp, zp_next) = match transcript.as_mut() {
                None => (None, None),
                Some(t) => (
                    Some(t.read_scalar().map_err(|e| TranscriptError(e))?),
                    Some(t.read_scalar().map_err(|e| TranscriptError(e))?),
                ),
            };
            let zp_last_eval = if iter.len() > 0 {
                let scalar = match transcript.as_mut() {
                    None => None,
                    Some(t) => Some(t.read_scalar().map_err(|e| TranscriptError(e))?),
                };
                Some(self.ecc_chip.main_gate().assign_value(
                    region,
                    &scalar.into(),
                    MainGateColumn::A,
                    offset,
                )?)
            } else {
                None
            };

            let zp_eval = self.ecc_chip.main_gate().assign_value(
                region,
                &zp.into(),
                MainGateColumn::A,
                offset,
            )?;
            let zp_next_eval = self.ecc_chip.main_gate().assign_value(
                region,
                &zp_next.into(),
                MainGateColumn::A,
                offset,
            )?;
            sets.push(EvaluatedSetVar {
                permutation_product_commitment: zp_commitment,
                permutation_product_eval: zp_eval,
                permutation_product_next_eval: zp_next_eval,
                permutation_product_last_eval: zp_last_eval,
            });
        }
        Ok(EvaluatedVar { sets })
    }

    pub fn alloc_cev<E, T>(
        &mut self,
        transcript: &mut Option<&mut T>,
        transcript_chip: &mut TranscriptChip<C>,
        region: &mut Region<C::ScalarExt>,
        offset: &mut usize,
        num_columns: usize,
    ) -> Result<CommonEvaluatedVar<C>, Error>
    where
        E: EncodedChallenge<C>,
        T: TranscriptRead<C, E>,
    {
        let sigma_evals = (0..num_columns)
            .into_iter()
            .map(|_| -> Result<AssignedValue<C::ScalarExt>, Error> {
                let scalar = match transcript.as_mut() {
                    None => None,
                    Some(t) => Some(t.read_scalar().map_err(|e| TranscriptError(e))?),
                };
                let scalar = self.ecc_chip.main_gate().assign_value(
                    region,
                    &scalar.into(),
                    MainGateColumn::A,
                    offset,
                )?;
                transcript_chip.common_scalar(region, scalar.clone(), offset);
                Ok(scalar)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(CommonEvaluatedVar {
            permutation_evals: sigma_evals,
        })
    }

    pub fn alloc_vk(
        &self,
        region: &mut Region<C::ScalarExt>,
        offset: &mut usize,
        vk: halo2::plonk::VerifyingKey<C>, // TODO: use permutation::VerifyingKey instead
    ) -> Result<VerifyingKeyVar<C>, Error> {
        unimplemented!()
    }

    pub fn expressions(
        &mut self,
        mut region: &mut Region<'_, C::ScalarExt>,
        common: &CommonEvaluatedVar<C>,
        ev: &EvaluatedVar<C>,
        columns: &Vec<(Column<Any>, usize)>,
        advice_evals: &[AssignedValue<C::ScalarExt>],
        fixed_evals: &[AssignedValue<C::ScalarExt>],
        instance_evals: &[AssignedValue<C::ScalarExt>],
        l_0: AssignedValue<C::ScalarExt>,
        l_last: AssignedValue<C::ScalarExt>,
        l_blind: AssignedValue<C::ScalarExt>,
        beta: ChallengeBeta<C>,
        gamma: ChallengeGamma<C>,
        x: ChallengeX<C>,
        chunk_len: usize,
        offset: &mut usize,
    ) -> Result<Vec<AssignedValue<C::ScalarExt>>, Error> {
        assert_eq!(common.permutation_evals.len(), columns.len());

        let mut exprs = vec![];
        // 1. l_0(x) * (1 - ZP_0(x)) = 0
        let main_gate = self.ecc_chip.main_gate();
        let one = Some(C::ScalarExt::one());
        let one = main_gate.assign_constant(region, &one.into(), MainGateColumn::A, offset)?;

        let expr1 = {
            let one_sub_zp0 =
                main_gate.sub(region, &one, &ev.sets[0].permutation_product_eval, offset)?;
            main_gate.mul(region, &l_0, &one_sub_zp0, offset)?
        };
        exprs.push(expr1);

        // 2. l_last(X) * (ZP_l(x)^2 - ZP_l(x)) = 0
        let expr2 = {
            assert!(ev.sets.len() >= 1);
            let zp_last = ev
                .sets
                .last()
                .map(|zp| zp.permutation_product_eval.clone())
                .unwrap();
            let zp_last_sqr = main_gate.mul(region, &zp_last, &zp_last, offset)?;
            let term = main_gate.sub(region, &zp_last_sqr, &zp_last, offset)?;
            main_gate.mul(region, &l_last, &term, offset)?
        };
        exprs.push(expr2);

        // 3. l_0(X) * (ZP_i(x) - ZP_{i-1}(omega^(last)*x)) = 0
        for i in (1..ev.sets.len()).into_iter() {
            let term = main_gate.sub(
                region,
                &ev.sets[i].permutation_product_eval,
                &ev.sets[i - 1]
                    .permutation_product_last_eval
                    .clone()
                    .unwrap(),
                offset,
            )?;
            let expr3 = main_gate.mul(region, &l_0, &term, offset)?;
            exprs.push(expr3);
        }

        // 4. (1 - (l_last(x) + l_blind(x))) * (
        //       ZP_i(omega*x) \prod_k (p(x) + beta*sigma_k(x) + gamma)
        //     - ZP_i(x) \prod_k (p(x) + beta * delta^k * x + gamma))
        // )
        let perm_polys_len = common.permutation_evals.len();
        // delta^i
        let one = C::ScalarExt::one();
        let delta = C::ScalarExt::DELTA;
        let mut deltas = vec![];

        let mut acc = one;
        for i in (0..perm_polys_len).into_iter() {
            acc.mul_assign(delta);
            deltas.push(acc);
        }

        for (chunk_idx, ((set, columns), perm_evals)) in ev
            .sets
            .iter()
            .zip(columns.chunks(chunk_len))
            .zip(common.permutation_evals.chunks(chunk_len))
            .enumerate()
        {
            // left = ZP_i(omega*x) \prod_k (p(x) + beta*sigma_k(x) + gamma)
            let mut left = set.permutation_product_next_eval.clone();
            for (eval, perm_eval) in columns
                .iter()
                .map(|(column, idx)| match column.column_type() {
                    Any::Advice => advice_evals[*idx].clone(),
                    Any::Fixed => fixed_evals[*idx].clone(),
                    Any::Instance => instance_evals[*idx].clone(),
                })
                .zip(perm_evals.iter())
            {
                let term1 = main_gate.mul(region, &beta.value(), perm_eval, offset)?;
                let term2 = main_gate.add(region, &term1, &eval, offset)?;
                let term3 = main_gate.add(region, &term2, &gamma.value(), offset)?;

                left = main_gate.mul(region, &left, &term3, offset)?;
            }
            // right = ZP_i(x) \prod_k (p(x) + beta * delta^(chunk_len*i+k) * x + gamma))
            let mut right = set.permutation_product_eval.clone();
            for (i, eval) in columns
                .iter()
                .map(|(column, idx)| match column.column_type() {
                    Any::Advice => advice_evals[*idx].clone(),
                    Any::Fixed => fixed_evals[*idx].clone(),
                    Any::Instance => instance_evals[*idx].clone(),
                })
                .enumerate()
            {
                let idx = chunk_len * chunk_idx + i;
                let term = main_gate.mul_by_constant(region, &beta.value(), deltas[idx], offset)?;
                let term = main_gate.mul(region, &term, &x.value(), offset)?;
                let term = main_gate.add(region, &term, &eval, offset)?;
                let term = main_gate.add(region, &term, &gamma.value(), offset)?;

                right = main_gate.mul(region, &right, &term, offset)?;
            }

            // expr = (1 - (l_last(x) + l_blind(x))) * (left - right)
            let l_last_sum_blind = main_gate.add(region, &l_last, &l_blind, offset)?;
            let one =
                main_gate.assign_constant(region, &Some(one).into(), MainGateColumn::A, offset)?;
            let one_sub_last_sum_blind = main_gate.sub(region, &one, &l_last_sum_blind, offset)?;
            let expr = main_gate.sub(region, &left, &right, offset)?;
            let expr = main_gate.mul(region, &expr, &one_sub_last_sum_blind, offset)?;

            exprs.push(expr);
        }

        Ok(exprs)
    }
}

pub struct VerifyingKeyVar<C: CurveAffine> {
    // commitment of sigma polynomials
    commitments: Vec<AssignedPoint<C::ScalarExt>>,
}

impl<C: CurveAffine> EvaluatedVar<C> {
    pub fn queries(&self, blinding_factors: isize) -> Vec<VerifierQuery<C>> {
        let last_rot = Rotation((-blinding_factors + 1) as i32);

        iter::empty()
            .chain(self.sets.iter().flat_map(move |set| {
                iter::empty()
                    .chain(Some(VerifierQuery::new(
                        set.permutation_product_commitment.clone(),
                        Rotation::cur(),
                        set.permutation_product_eval.clone(),
                    )))
                    .chain(Some(VerifierQuery::new(
                        set.permutation_product_commitment.clone(),
                        Rotation::next(),
                        set.permutation_product_next_eval.clone(),
                    )))
            }))
            .chain(self.sets.iter().rev().skip(1).flat_map(move |set| {
                Some(VerifierQuery::new(
                    set.permutation_product_commitment.clone(),
                    last_rot,
                    set.permutation_product_last_eval.clone().unwrap(),
                ))
            }))
            .collect()
    }
}
