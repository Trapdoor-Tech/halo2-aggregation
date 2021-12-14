use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::circuit::Region;
use halo2::plonk::{ConstraintSystem, Error, VerifyingKey};
use halo2::transcript::{EncodedChallenge, Transcript, TranscriptRead};
use halo2wrong::circuit::ecc::AssignedPoint;
use halo2wrong::circuit::AssignedValue;
use std::{io, iter};
use halo2::poly::Rotation;
use crate::{ChallengeBeta, ChallengeGamma, ChallengeX};
use crate::multiopen::VerifierQuery;

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

impl<C: CurveAffine> CommittedVar<C> {
    pub fn alloc<R: io::Read>(
        region: &mut Region<'_, C::ScalarExt>,
        reader: &mut R,
        num_columns: usize,
        chunk_len: usize, // vk.cs.degree() - 2
        offset: &mut usize,
    ) -> Result<CommittedVar<C>, Error> {
        unimplemented!()
    }

    pub fn evaluate<E: EncodedChallenge<C>, T: TranscriptRead<C, E>>(
        &self,
        transcript: &mut T,
        offset: &mut usize,
    ) -> Result<EvaluatedVar<C>, Error> {
        unimplemented!()
    }
}

pub struct CommonEvaluatedVar<C: CurveAffine> {
    permutation_evals: Vec<AssignedValue<C::ScalarExt>>, // { sigma_i(z) }
}

pub struct VerifyingKeyVar<C: CurveAffine> {
    // commitment of sigma polynomials
    commitments: Vec<AssignedPoint<C::ScalarExt>>,
}

impl<C: CurveAffine> VerifyingKeyVar<C> {
    pub fn alloc<R: io::Read>(
        region: &mut Region<'_, C::ScalarExt>,
        reader: &mut R,
        num_columns: usize,
    ) -> Result<Self, Error> {
        unimplemented!()
    }

    pub fn evaluate<E: EncodedChallenge<C>, T: TranscriptRead<C, E>>(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        transcript: &mut T,
        offset: &mut usize,
    ) -> Result<CommonEvaluatedVar<C>, Error> {
        unimplemented!()
    }
}

impl<C: CurveAffine> EvaluatedVar<C> {
    pub fn expressions<'a>(
        &'a self,
        common: &'a CommonEvaluatedVar<C>,
        advice_evals: &'a [AssignedValue<C>],
        fixed_evals: &'a [AssignedValue<C>],
        instance_evals: &'a [AssignedValue<C>],
        l_0: AssignedValue<C>,
        l_last: AssignedValue<C>,
        l_blind: AssignedValue<C>,
        beta: ChallengeBeta<C>,
        gamma: ChallengeGamma<C>,
        x: ChallengeX<C>,
    ) -> Result<Vec<AssignedValue<C>>, Error> {
        unimplemented!()

        // 1. l_0(x) * (1 - ZP_0(x)) = 0

        // 2. l_last(X) * (ZP_l(x)^2 - ZP_l(x)) = 0

        // 3. l_0(X) * (ZP_i(x) - ZP_{i-1}(omega^(last)*x)) = 0

        // 4. (1 - (l_last(x) + l_blind(x))) * (
        //       ZP_i(omega*x) \prod_k (p(x) + beta*sigma_k(x) + gamma)
        //     - ZP_i(x) \prod_k (p(x) + beta * delta^k * x + gamma)
        // )
    }

    pub fn queries(
        &self,
        blinding_factors: usize,
    ) -> impl Iterator<Item = VerifierQuery<C>> + Clone {
        let last_rot = Rotation((-blinding_factors+1) as i32);

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
    }
}