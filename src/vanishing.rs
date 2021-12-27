use crate::multiopen::VerifierQuery;
use crate::ChallengeY;
use halo2::arithmetic::CurveAffine;
use halo2::circuit::Region;
use halo2::plonk::Error;
use halo2::poly::Rotation;
use halo2::transcript::{EncodedChallenge, TranscriptRead};
use halo2wrong::circuit::ecc::AssignedPoint;
use halo2wrong::circuit::AssignedValue;
use std::iter;

pub struct CommittedVar<C: CurveAffine> {
    random_poly_commitment: AssignedPoint<C::ScalarExt>,
}

pub struct ConstructedVar<C: CurveAffine> {
    h_commitments: Vec<AssignedPoint<C::ScalarExt>>, // commitment of quotient polynomials
    random_poly_commitment: AssignedPoint<C::ScalarExt>,
}

pub struct PartiallyEvaluatedVar<C: CurveAffine> {
    h_commitments: Vec<AssignedPoint<C::ScalarExt>>,
    random_poly_commitment: AssignedPoint<C::ScalarExt>,
    random_eval: AssignedValue<C::ScalarExt>,
}

pub struct EvaluatedVar<C: CurveAffine> {
    h_commitment: AssignedPoint<C::ScalarExt>,           // h(X)
    random_poly_commitment: AssignedPoint<C::ScalarExt>, // r(X)
    random_eval: AssignedValue<C::ScalarExt>,            // r(x)
    // quotient poly eval h(x)
    // we have h(x) = \sum_i hi(x)*x^{i*n} = (\sum_k expr_k * y^k) / (x^n - 1)
    h_eval: AssignedValue<C::ScalarExt>,
}

impl<C: CurveAffine> CommittedVar<C> {
    pub fn alloc_before_y<E: EncodedChallenge<C>, T: TranscriptRead<C, E>>(
        region: &mut Region<'_, C::ScalarExt>,
        transcript: &mut T,
        offset: &mut usize,
    ) -> Result<Self, Error> {
        unimplemented!()
    }
}

impl<C: CurveAffine> ConstructedVar<C> {
    pub fn alloc_after_y<E: EncodedChallenge<C>, T: TranscriptRead<C, E>>(
        region: &mut Region<'_, C::ScalarExt>,
        committed: CommittedVar<C>,
        transcript: &mut T,
        offset: &mut usize,
    ) -> Result<ConstructedVar<C>, Error> {
        unimplemented!()
    }

    pub fn evaluate_after_x<E: EncodedChallenge<C>, T: TranscriptRead<C, E>>(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        transcript: &mut T,
        offset: &mut usize,
    ) -> Result<PartiallyEvaluatedVar<C>, Error> {
        unimplemented!()
    }
}

impl<C: CurveAffine> PartiallyEvaluatedVar<C> {
    pub fn verify(
        self,
        expressions: impl Iterator<Item = AssignedValue<C::ScalarExt>>,
        y: ChallengeY<C>,
        xn: AssignedValue<C::ScalarExt>,
    ) -> Result<EvaluatedVar<C>, Error> {
        // exected_h_eval = \sum_k expressions_k * y^k

        // h(X)

        unimplemented!()
    }
}

impl<C: CurveAffine> EvaluatedVar<C> {
    pub fn queries(&self) -> impl Iterator<Item = VerifierQuery<C>> + Clone {
        iter::empty()
            .chain(Some(VerifierQuery::new(
                self.h_commitment.clone(),
                Rotation::cur(),
                self.h_eval.clone(),
            )))
            .chain(Some(VerifierQuery::new(
                self.random_poly_commitment.clone(),
                Rotation::cur(),
                self.random_eval.clone(),
            )))
    }
}
