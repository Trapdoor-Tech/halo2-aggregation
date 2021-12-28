use crate::multiopen::VerifierQuery;
use crate::{ChallengeBeta, ChallengeGamma, ChallengeX};
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::circuit::Region;
use halo2::plonk::Error::TranscriptError;
use halo2::plonk::{ConstraintSystem, Error, VerifyingKey};
use halo2::poly::Rotation;
use halo2::transcript::{EncodedChallenge, Transcript, TranscriptRead};
use halo2wrong::circuit::ecc::base_field_ecc::{BaseFieldEccChip, BaseFieldEccInstruction};
use halo2wrong::circuit::ecc::AssignedPoint;
use halo2wrong::circuit::main_gate::{MainGateColumn, MainGateInstructions};
use halo2wrong::circuit::AssignedValue;
use std::marker::PhantomData;
use std::{io, iter};

pub struct CommittedVar<C: CurveAffine> {
    // commitment of grand product polynomials of permutation argument
    permutation_product_commitments: Vec<AssignedPoint<C::ScalarExt>>,
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
    permutation_evals: Vec<AssignedValue<C::ScalarExt>>, // { sigma_i(z) }
}

pub struct PermutationChip<'a, C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>> {
    ecc_chip: BaseFieldEccChip<C>,
    transcript: Option<&'a mut T>,
    _marker: PhantomData<E>,
}

impl<C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>> PermutationChip<'_, C, E, T> {
    pub fn alloc_cv(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        num_columns: usize,
        chunk_len: usize, // vk.cs.degree() - 2
        offset: &mut usize,
    ) -> Result<CommittedVar<C>, Error> {
        let num_chunks = (num_columns + chunk_len - 1) / chunk_len;
        let comms = (0..num_chunks)
            .into_iter()
            .map(|_| -> Result<AssignedPoint<C::ScalarExt>, Error> {
                let point = match self.transcript.as_mut() {
                    None => None,
                    Some(t) => Some(t.read_point().map_err(|_| TranscriptError)?),
                };
                self.ecc_chip.assign_point(region, point, offset)
            })
            .collect::<Result<Vec<AssignedPoint<C::ScalarExt>>, Error>>()?;

        Ok(CommittedVar {
            permutation_product_commitments: comms,
        })
    }

    pub fn alloc_ev(
        &mut self,
        region: &mut Region<C::ScalarExt>,
        offset: &mut usize,
        cv: CommittedVar<C>,
    ) -> Result<EvaluatedVar<C>, Error> {
        let mut sets = vec![];

        let mut iter = cv.permutation_product_commitments.into_iter();
        while let Some(zp_commitment) = iter.next() {
            let (zp, zp_next) = match self.transcript.as_mut() {
                None => (None, None),
                Some(t) => (
                    Some(t.read_scalar().map_err(|_| TranscriptError)?),
                    Some(t.read_scalar().map_err(|_| TranscriptError)?),
                ),
            };
            let zp_last_eval = if iter.len() > 0 {
                let scalar = match self.transcript.as_mut() {
                    None => None,
                    Some(t) => Some(t.read_scalar().map_err(|_| TranscriptError)?),
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

    pub fn alloc_cev(
        &mut self,
        region: &mut Region<C::ScalarExt>,
        offset: &mut usize,
        num_columns: usize,
    ) -> Result<CommonEvaluatedVar<C>, Error> {
        let sigma_evals = (0..num_columns)
            .into_iter()
            .map(|_| -> Result<AssignedValue<C::ScalarExt>, Error> {
                let scalar = match self.transcript.as_mut() {
                    None => None,
                    Some(t) => Some(t.read_scalar().map_err(|_| TranscriptError)?),
                };
                self.ecc_chip.main_gate().assign_value(
                    region,
                    &scalar.into(),
                    MainGateColumn::A,
                    offset,
                )
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
        advice_evals: &[AssignedValue<C::ScalarExt>],
        fixed_evals: &[AssignedValue<C::ScalarExt>],
        instance_evals: &[AssignedValue<C::ScalarExt>],
        l_0: AssignedValue<C::ScalarExt>,
        l_last: AssignedValue<C::ScalarExt>,
        l_blind: AssignedValue<C::ScalarExt>,
        beta: ChallengeBeta<C>,
        gamma: ChallengeGamma<C>,
        x: ChallengeX<C>,
        offset: &mut usize,
    ) -> Result<Vec<AssignedValue<C::ScalarExt>>, Error> {
        unimplemented!()

        // 1. l_0(x) * (1 - ZP_0(x)) = 0

        // 2. l_last(X) * (ZP_l(x)^2 - ZP_l(x)) = 0

        // 3. l_0(X) * (ZP_i(x) - ZP_{i-1}(omega^(last)*x)) = 0

        // 4. (1 - (l_last(x) + l_blind(x))) * (
        //       ZP_i(omega*x) \prod_k (p(x) + beta*sigma_k(x) + gamma)
        //     - ZP_i(x) \prod_k (p(x) + beta * delta^k * x + gamma)
        // )
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
