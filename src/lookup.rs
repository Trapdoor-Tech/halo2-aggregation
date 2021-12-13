use halo2::arithmetic::CurveAffine;
use halo2::circuit::Region;
use halo2::plonk::Error;
use halo2::transcript::{EncodedChallenge, TranscriptRead};
use halo2wrong::circuit::ecc::AssignedPoint;
use halo2wrong::circuit::AssignedValue;

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
