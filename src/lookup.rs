use crate::multiopen::VerifierQuery;
use crate::{ChallengeBeta, ChallengeGamma, ChallengeTheta};
use halo2::arithmetic::{CurveAffine, Field};
use halo2::circuit::{Chip, Region};
use halo2::plonk::{Error, Expression};
use halo2::plonk::Error::TranscriptError;
use halo2::poly::Rotation;
use halo2::transcript::{EncodedChallenge, Transcript, TranscriptRead};
use halo2wrong::circuit::ecc::base_field_ecc::{BaseFieldEccChip, BaseFieldEccInstruction};
use halo2wrong::circuit::ecc::AssignedPoint;
use halo2wrong::circuit::{AssignedValue, UnassignedValue};
use halo2wrong::circuit::main_gate::{MainGateColumn, MainGateInstructions};
use std::iter;
use std::marker::PhantomData;

pub struct PermutationCommitmentsVar<C: CurveAffine> {
    permuted_input_commitment: AssignedPoint<C::ScalarExt>, // A'
    permuted_table_commitment: AssignedPoint<C::ScalarExt>, // S'
}

pub struct CommittedVar<C: CurveAffine> {
    permuted: PermutationCommitmentsVar<C>,
    product_commitment: AssignedPoint<C::ScalarExt>, // Z
}

pub struct EvaluatedVar<C: CurveAffine> {
    committed: CommittedVar<C>,
    product_eval: AssignedValue<C::ScalarExt>,      // Z(z)
    product_next_eval: AssignedValue<C::ScalarExt>, // Z(z*omega)
    permuted_input_eval: AssignedValue<C::ScalarExt>, // A'(z)
    permuted_input_inv_eval: AssignedValue<C::ScalarExt>, // A'(omega^(-1)*z)
    permuted_table_eval: AssignedValue<C::ScalarExt>, // S'(z)
}

pub struct LookupChip<'a, C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>> {
    ecc_chip: BaseFieldEccChip<C>,
    transcript: Option<&'a mut T>,
    _marker: PhantomData<E>,
}

impl<C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>> LookupChip<'_, C, E, T> {
    pub fn alloc_pcv(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<PermutationCommitmentsVar<C>, Error> {
        let (a_prime, s_prime) = {
            match self.transcript.as_mut() {
                None => (None, None),
                Some(t) => (
                    Some(t.read_point().map_err(|_| TranscriptError)?),
                    Some(t.read_point().map_err(|_| TranscriptError)?),
                ),
            }
        };
        let a_prime = self.ecc_chip.assign_point(region, a_prime, offset)?;
        let s_prime = self.ecc_chip.assign_point(region, s_prime, offset)?;

        Ok(PermutationCommitmentsVar {
            permuted_input_commitment: a_prime,
            permuted_table_commitment: s_prime,
        })
    }

    pub fn alloc_cv(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        perm_comms: PermutationCommitmentsVar<C>,
        offset: &mut usize,
    ) -> Result<CommittedVar<C>, Error> {
        let z_lookup = {
            match self.transcript.as_mut() {
                None => None,
                Some(t) => (Some(t.read_point().map_err(|_| TranscriptError)?)),
            }
        };
        let z_lookup = self.ecc_chip.assign_point(region, z_lookup, offset)?;

        Ok(CommittedVar {
            permuted: perm_comms,
            product_commitment: z_lookup,
        })
    }

    pub fn alloc_eval(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        cv: CommittedVar<C>,
        offset: &mut usize,
    ) -> Result<EvaluatedVar<C>, Error> {
        let (z, z_w, a, a_prev, s) = {
            match self.transcript.as_mut() {
                None => (None, None, None, None, None),
                Some(t) => {
                    (
                        Some(t.read_scalar().map_err(|_| TranscriptError)?),
                        Some(t.read_scalar().map_err(|_| TranscriptError)?),
                        Some(t.read_scalar().map_err(|_| TranscriptError)?),
                        Some(t.read_scalar().map_err(|_| TranscriptError)?),
                        Some(t.read_scalar().map_err(|_| TranscriptError)?),
                    )
                }
            }
        };
        let z = self.ecc_chip.main_gate().assign_value(region, &z.into(), MainGateColumn::A, offset)?;
        let z_w = self.ecc_chip.main_gate().assign_value(region, &z_w.into(), MainGateColumn::A, offset)?;
        let a = self.ecc_chip.main_gate().assign_value(region, &a.into(), MainGateColumn::A, offset)?;
        let a_prev = self.ecc_chip.main_gate().assign_value(region, &a_prev.into(), MainGateColumn::A, offset)?;
        let s = self.ecc_chip.main_gate().assign_value(region, &s.into(), MainGateColumn::A, offset)?;

        Ok(EvaluatedVar {
            committed: cv,
            product_eval: z,
            product_next_eval: z_w,
            permuted_input_eval: a,
            permuted_input_inv_eval: a_prev,
            permuted_table_eval: s,
        })
    }

    pub fn expressions(
        &mut self,
        mut region: &mut Region<'_, C::ScalarExt>,
        ev: EvaluatedVar<C>,
        l_0: AssignedValue<C::ScalarExt>,
        l_last: AssignedValue<C::ScalarExt>,
        l_blind: AssignedValue<C::ScalarExt>,
        input_expressions: Vec<Expression<C::ScalarExt>>,
        table_expressions: Vec<Expression<C::ScalarExt>>,
        theta: ChallengeTheta<C>,
        beta: ChallengeBeta<C>,
        gamma: ChallengeGamma<C>,
        advice_evals: &[AssignedValue<C::ScalarExt>],
        fixed_evals: &[AssignedValue<C::ScalarExt>],
        instance_evals: &[AssignedValue<C::ScalarExt>],
        offset: &mut usize,
    ) -> Result<Vec<AssignedValue<C::ScalarExt>>, Error> {
        // 1. l_0(X) * (1 - Z(X)) = 0
        let main_gate = self.ecc_chip.main_gate();
        let one = Some(C::ScalarExt::one());
        let one = main_gate.assign_constant(region, &one.into(), MainGateColumn::A, offset)?;

        let expr1 = {
            let one_sub_z = main_gate.sub(region, &one, &ev.product_eval, offset)?;
            main_gate.mul(region, &l_0, &one_sub_z, offset)?
        };

        // 2. l_last(x) * (Z(x)^2 - Z(x)) = 0
        let expr2 = {
            let z_sqr = main_gate.mul(region, &ev.product_eval, &ev.product_eval, offset)?;
            let z_sqr_sub_z = main_gate.sub(region, &z_sqr, &ev.product_eval, offset)?;
            main_gate.mul(region, &l_last, &z_sqr_sub_z, offset)?
        };

        let l_last_sum_blind = main_gate.add(region, &l_last, &l_blind, offset)?;
        let one_sub_last_sum_blind = main_gate.sub(region, &one, &l_last_sum_blind, offset)?;
        // 3. (1 - (l_last(x) + l_blind(x))) * (
        //   Z(omega * x) * (A'(x) + beta) * (S'(x) + gamma)
        //   - Z(x) * (theta^{m-1} a_0(x) + ... + a_{m-1}(x) + beta)
        //      * (theta^{m-1} s_0(x) + ... + s_{m-1}(x) + gamma)) = 0
        let expr3 = {
            let compress_expressions = |expressions: &[Expression<C::ScalarExt>]| {
                expressions
                    .iter()
                    .map(|expression| {
                        expression.evaluate_mut(
                            &mut |scalar| {
                                // this should never fail
                                main_gate.assign_constant(region, &Some(scalar).into(), MainGateColumn::A, offset).unwrap()
                            },
                            &mut |_| panic!("virtual selectors are removed during optimization"),
                            &mut |index, _, _| fixed_evals[index].clone(),
                            &mut |index, _, _| advice_evals[index].clone(),
                            &mut |index, _, _| instance_evals[index].clone(),
                            &mut |a| main_gate.neg(region, a, offset).unwrap(),
                            &mut |a, b| main_gate.add(region, a, b, offset).unwrap(),
                            &mut |a, b| main_gate.mul(region, a, b, offset).unwrap(),
                            &mut |a, scalar| main_gate.mul_by_constant(region, a, scalar, offset).unwrap(),
                        )
                    })
                    .fold(None, |acc, eval| {
                        match acc {
                            Some(acc) => {
                                let term1 = main_gate.mul(region, &acc, &theta.value(), offset).unwrap();
                                Some(main_gate.add(region, term1, &eval, offset).unwrap())
                            }
                            None => Some(eval)
                        }
                    }).unwrap()
            };
            let left = {
                // a' + beta
                let factor1 = main_gate.add(region, &ev.permuted_input_eval, &beta.value(), offset)?;
                // s' + gamma
                let factor2 = main_gate.add(region, &ev.permuted_table_eval, &gamma.value(), offset)?;
                // z_w * (a' + beta) * (s' + gamma)
                let term1 = main_gate.mul(region, &factor1, &factor2, offset)?;
                main_gate.mul(region, &term1, &ev.product_next_eval, offset)?
            };

            let right = {
                let factor1 = main_gate.add(region, &compress_expressions(&input_expressions), &beta.value(), offset)?;
                let factor2 = main_gate.add(region, &compress_expressions(&table_expressions), &gamma.value(), offset)?;
                let term1 = main_gate.mul(region, &factor1, &factor2, offset)?;
                main_gate.mul(region, &term1, &ev.product_eval, offset)?
            };

            let expr = main_gate.sub(region, &left, &right, offset)?;
            main_gate.mul(region, &l_last_sum_blind, &expr, offset)?
        };

        // 4. l_0(x) * (A'(x) - S'(x)) = 0
        let a_prime_sub_s_prime = main_gate.sub(region, &ev.permuted_input_eval, &ev.permuted_table_eval, offset)?;
        let expr4 = main_gate.mul(region, &l_0, &a_prime_sub_s_prime, offset)?;

        // 5. (1 - (l_last(x) + l_blind(x))) * (A'(x) - S'(x)) * (A'(x) - A'(omega^{-1} x)) = 0
        let expr5 = {
            let a_sub_a_prev = main_gate.sub(region, &ev.permuted_input_eval, &ev.permuted_input_inv_eval, offset)?;
            let term1 = main_gate.mul(region, &a_prime_sub_s_prime, &a_sub_a_prev, offset)?;
            main_gate.mul(region, &one_sub_last_sum_blind, &term1, offset)?
        };

        Ok(vec![expr1, expr2, expr3, expr4, expr5])
    }
}

impl<C: CurveAffine> EvaluatedVar<C> {
    pub fn expressions(
        &self,
    ) -> Result<Vec<AssignedValue<C::ScalarExt>>, Error> {
        unimplemented!()

    }

    pub fn queries(&self) -> impl Iterator<Item = VerifierQuery<C>> + Clone {
        iter::empty()
            // Z_lookup(x)
            .chain(Some(VerifierQuery::new(
                self.committed.product_commitment.clone(),
                Rotation::cur(),
                self.product_eval.clone(),
            )))
            // A'(x)
            .chain(Some(VerifierQuery::new(
                self.committed.permuted.permuted_input_commitment.clone(),
                Rotation::cur(),
                self.permuted_input_eval.clone(),
            )))
            // S'(x)
            .chain(Some(VerifierQuery::new(
                self.committed.permuted.permuted_table_commitment.clone(),
                Rotation::cur(),
                self.permuted_table_eval.clone(),
            )))
            // A'(omega^{-1}*x)
            .chain(Some(VerifierQuery::new(
                self.committed.permuted.permuted_input_commitment.clone(),
                Rotation::prev(),
                self.permuted_input_inv_eval.clone(),
            )))
            // Z_lookup(x*omega)
            .chain(Some(VerifierQuery::new(
                self.committed.product_commitment.clone(),
                Rotation::next(),
                self.product_next_eval.clone(),
            )))
    }
}
