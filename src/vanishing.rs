use halo2::arithmetic::CurveAffine;
use halo2::circuit::Region;
use halo2::plonk::Error;
use halo2::transcript::{EncodedChallenge, TranscriptRead};
use halo2wrong::circuit::ecc::AssignedPoint;
use halo2wrong::circuit::AssignedValue;

pub struct CommittedVar<C: CurveAffine> {
    random_poly_commitment: AssignedPoint<C>,
}

pub struct ConstructedVar<C: CurveAffine> {
    h_commitments: Vec<AssignedPoint<C>>,
    random_poly_commitment: AssignedPoint<C>,
}

pub struct PartiallyEvaluatedVar<C: CurveAffine> {
    h_commitments: Vec<AssignedPoint<C>>,
    random_poly_commitment: AssignedPoint<C>,
    random_eval: AssignedValue<C::ScalarExt>,
}

// pub struct EvaluatedVar<C: CurveAffine> {
//     h_commitment:
// }

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
