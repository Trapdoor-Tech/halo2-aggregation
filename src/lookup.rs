use crate::multiopen::VerifierQuery;
use crate::{ChallengeBeta, ChallengeGamma, ChallengeTheta};
use halo2::arithmetic::CurveAffine;
use halo2::circuit::Region;
use halo2::plonk::Error;
use halo2::poly::Rotation;
use halo2::transcript::{EncodedChallenge, TranscriptRead};
use halo2wrong::circuit::ecc::AssignedPoint;
use halo2wrong::circuit::AssignedValue;
use std::iter;

pub struct PermutationCommitmentsVar<C: CurveAffine> {
    permuted_input_commitment: AssignedPoint<C>, // A'
    permuted_table_commitment: AssignedPoint<C>, // S'
}

pub struct CommittedVar<C: CurveAffine> {
    permuted: PermutationCommitmentsVar<C>,
    product_commitment: AssignedPoint<C>, // Z
}

pub struct EvaluatedVar<C: CurveAffine> {
    committed: CommittedVar<C>,
    product_eval: AssignedValue<C::ScalarExt>,      // Z(z)
    product_next_eval: AssignedValue<C::ScalarExt>, // Z(z*omega)
    permuted_input_eval: AssignedValue<C::ScalarExt>, // A'(z)
    permuted_input_inv_eval: AssignedValue<C::ScalarExt>, // A'(omega^(-1)*z)
    permuted_table_eval: AssignedValue<C::ScalarExt>, // S'(z)
}

impl<C: CurveAffine> PermutationCommitmentsVar<C> {
    pub fn alloc<E: EncodedChallenge<C>, T: TranscriptRead<C, E>>(
        region: &mut Region<'_, C::ScalarExt>,
        transcript: &mut T,
        offset: &mut usize,
    ) -> Result<PermutationCommitmentsVar<C>, Error> {
        unimplemented!()
    }
}

impl<C: CurveAffine> CommittedVar<C> {
    pub fn alloc<E: EncodedChallenge<C>, T: TranscriptRead<C, E>>(
        region: &mut Region<'_, C::ScalarExt>,
        perm_comms: PermutationCommitmentsVar<C>,
        transcript: &mut T,
        offset: &mut usize,
    ) -> Result<CommittedVar<C>, Error> {
        unimplemented!()
    }

    pub fn evaluate<E: EncodedChallenge<C>, T: TranscriptRead<C, E>>(
        self,
        region: &mut Region<'_, C::ScalarExt>,
        transcript: &mut T,
        offset: &mut usize,
    ) -> Result<EvaluatedVar<C>, Error> {
        unimplemented!()
    }
}

impl<C: CurveAffine> EvaluatedVar<C> {
    pub fn expressions(
        &self,
        l_0: AssignedValue<C::ScalarExt>,
        l_last: AssignedValue<C::ScalarExt>,
        l_blind: AssignedValue<C::ScalarExt>,
        theta: ChallengeTheta<C>,
        beta: ChallengeBeta<C>,
        gamma: ChallengeGamma<C>,
        advice_evals: &[AssignedValue<C>],
        fixed_evals: &[AssignedValue<C>],
        instance_evals: &[AssignedValue<C>],
    ) -> Result<Vec<AssignedValue<C>>, Error> {
        unimplemented!()

        // 1. l_0(x) * (1 - Z(x)) = 0

        // 2. l_last(x) * (Z(x)^2 - Z(x)) = 0

        // 3. (1 - (l_last(x) + l_blind(x))) * (
        //   Z(omega * x) * (A'(x) + beta) * (S'(x) + gamma)
        //   - Z(x) * (theta^{m-1} a_0(x) + ... + a_{m-1}(x) + beta)
        //      * (theta^{m-1} s_0(x) + ... + s_{m-1}(x) + gamma)) = 0

        // 4. l_0(x) * (A'(x) - S'(x)) = 0

        // 5. (1 - (l_last(x) + l_blind(x))) * (A'(x) - S'(x)) * (A'(x) - A'(omega^{-1} x)) = 0
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
