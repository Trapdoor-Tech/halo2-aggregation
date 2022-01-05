use halo2::arithmetic::CurveAffine;
use halo2::circuit::Region;
use halo2wrong::circuit::ecc::AssignedPoint;
use halo2wrong::circuit::AssignedValue;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct ChallengeScalarVar<C: CurveAffine, T> {
    inner: AssignedValue<C::ScalarExt>,
    _marker: PhantomData<T>,
}

impl<C: CurveAffine, T> ChallengeScalarVar<C, T> {
    pub fn value(&self) -> AssignedValue<C::ScalarExt> {
        self.inner.clone()
    }
}

pub trait TranscriptInstruction<C: CurveAffine> {
    fn squeeze_challenge_scalar<T>(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> ChallengeScalarVar<C, T>;

    fn common_point(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        point: AssignedPoint<C::ScalarExt>,
        offset: &mut usize,
    );

    fn common_scalar(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        scalar: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    );
}

#[derive(Clone)]
pub struct TranscriptChip<C: CurveAffine> {
    _marker: PhantomData<C>,
}

impl<C: CurveAffine> TranscriptChip<C> {
    pub fn new() -> Self {
        Self {
            _marker: Default::default(),
        }
    }
}

impl<C: CurveAffine> TranscriptInstruction<C> for TranscriptChip<C> {
    fn squeeze_challenge_scalar<T>(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> ChallengeScalarVar<C, T> {
        todo!()
    }

    fn common_point(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        point: AssignedPoint<C::ScalarExt>,
        offset: &mut usize,
    ) {
        todo!()
    }

    fn common_scalar(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        scalar: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    ) {
        todo!()
    }
}
