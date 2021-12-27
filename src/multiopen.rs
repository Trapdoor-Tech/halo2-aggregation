use halo2::arithmetic::CurveAffine;
use halo2::poly::Rotation;
use halo2wrong::circuit::ecc::AssignedPoint;
use halo2wrong::circuit::AssignedValue;

#[derive(Debug, Clone)]
pub struct VerifierQuery<C: CurveAffine> {
    commitment: AssignedPoint<C::ScalarExt>,
    rotation: Rotation,
    eval: AssignedValue<C::ScalarExt>,
}

impl<C: CurveAffine> VerifierQuery<C> {
    pub fn new(
        commitment: AssignedPoint<C::ScalarExt>,
        rotation: Rotation,
        eval: AssignedValue<C::ScalarExt>,
    ) -> Self {
        VerifierQuery {
            commitment,
            rotation,
            eval,
        }
    }
}
