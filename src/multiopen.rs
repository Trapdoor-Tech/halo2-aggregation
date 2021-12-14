use halo2::arithmetic::CurveAffine;
use halo2::poly::Rotation;
use halo2wrong::circuit::ecc::AssignedPoint;
use halo2wrong::circuit::AssignedValue;

#[derive(Debug, Clone, Copy)]
pub struct VerifierQuery<C: CurveAffine> {
    commitment: AssignedPoint<C>,
    rotation: Rotation,
    eval: AssignedValue<C>,
}

impl<C: CurveAffine> VerifierQuery<C> {
    pub fn new(commitment: AssignedPoint<C>, rotation: Rotation, eval: AssignedValue<C>) -> Self {
        VerifierQuery {
            commitment,
            rotation,
            eval,
        }
    }
}
