use halo2::arithmetic::CurveAffine;
use halo2::circuit::Region;
use halo2wrong::circuit::ecc::AssignedPoint;
use halo2wrong::circuit::AssignedValue;
use std::marker::PhantomData;

#[derive(Copy, CLone, Debug)]
pub struct ChallengeScalarVar<C: CurveAffine, T> {
    inner: AssignedValue<C::ScalarExt>,
    _marker: PhantomData<T>,
}

pub trait TranscriptChip<C: CurveAffine> {
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
