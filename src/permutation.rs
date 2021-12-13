use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::circuit::Region;
use halo2::plonk::{ConstraintSystem, Error, VerifyingKey};
use halo2::transcript::{EncodedChallenge, Transcript, TranscriptRead};
use halo2wrong::circuit::ecc::AssignedPoint;
use halo2wrong::circuit::AssignedInteger;
use std::io;

pub struct CommittedVar<C: CurveAffine> {
    // commitment of grand product polynomials of permutation argument
    permutation_product_commitments: Vec<AssignedPoint<C::ScalarExt>>,
}

pub struct EvaluatedSetVar<C: CurveAffine> {
    permutation_product_commitment: AssignedPoint<C::ScalarExt>,
    permutation_product_eval: AssignedInteger<C::ScalarExt>, // Zp(z)
    permutation_product_next_eval: AssignedInteger<C::ScalarExt>, // Zp(z*omega)
    permutation_product_last_eval: Option<AssignedInteger<C::ScalarExt>>,
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
    permutation_evals: Vec<AssignedInteger<C::ScalarExt>>, // { sigma_i(z) }
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
