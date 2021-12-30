use crate::multiopen::VerifierQuery;
use crate::ChallengeY;
use halo2::arithmetic::CurveAffine;
use halo2::circuit::Region;
use halo2::plonk::Error;
use halo2::plonk::Error::TranscriptError;
use halo2::poly::Rotation;
use halo2::transcript::{EncodedChallenge, TranscriptRead};
use halo2wrong::circuit::ecc::base_field_ecc::{BaseFieldEccChip, BaseFieldEccInstruction};
use halo2wrong::circuit::ecc::AssignedPoint;
use halo2wrong::circuit::main_gate::{MainGateColumn, MainGateInstructions};
use halo2wrong::circuit::AssignedValue;
use std::iter;
use std::marker::PhantomData;

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
    h_commitment: AssignedPoint<C::ScalarExt>, // h(X) = \sum hi(X)*X^{i*n}
    random_poly_commitment: AssignedPoint<C::ScalarExt>, // r(X)
    random_eval: AssignedValue<C::ScalarExt>,  // r(x)
    // quotient poly eval h(x)
    // we have h(x) = \sum_i hi(x)*x^{i*n} = (\sum_k expr_k * y^k) / (x^n - 1)
    h_eval: AssignedValue<C::ScalarExt>,
}

pub struct VanishingChip<C: CurveAffine> {
    ecc_chip: BaseFieldEccChip<C>,
}

impl<C: CurveAffine> VanishingChip<C> {
    pub fn new(ecc_chip: BaseFieldEccChip<C>) -> Self {
        Self {
            ecc_chip,
        }
    }
    pub fn alloc_before_y<E, T>(
        &mut self,
        mut transcript: Option<&mut T>,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<CommittedVar<C>, Error>
    where
        E: EncodedChallenge<C>,
        T: TranscriptRead<C, E>,
    {
        let r = match transcript.as_mut() {
            None => None,
            Some(t) => Some(t.read_point().map_err(|_| TranscriptError)?),
        };

        let r = self.ecc_chip.assign_point(region, r, offset)?;
        Ok(CommittedVar {
            random_poly_commitment: r,
        })
    }

    pub fn alloc_after_y<E, T>(
        &mut self,
        mut transcript: Option<&mut T>,
        cv: CommittedVar<C>,
        n: usize, // equals to vk.domain.get_quotient_poly_degree()
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<ConstructedVar<C>, Error>
    where
        E: EncodedChallenge<C>,
        T: TranscriptRead<C, E>,
    {
        let mut h_commitments = vec![];
        for i in (0..n).into_iter() {
            let h = match transcript.as_mut() {
                None => None,
                Some(t) => Some(t.read_point().map_err(|_| TranscriptError)?),
            };

            h_commitments.push(self.ecc_chip.assign_point(region, h, offset)?);
        }

        Ok(ConstructedVar {
            h_commitments,
            random_poly_commitment: cv.random_poly_commitment,
        })
    }

    pub fn alloc_after_x<E, T>(
        &mut self,
        mut transcript: Option<&mut T>,
        cv: ConstructedVar<C>,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<PartiallyEvaluatedVar<C>, Error>
    where
        E: EncodedChallenge<C>,
        T: TranscriptRead<C, E>,
    {
        let r_eval = match transcript.as_mut() {
            None => None,
            Some(t) => Some(t.read_scalar().map_err(|_| TranscriptError)?),
        };

        let main_gate = self.ecc_chip.main_gate();
        let r_eval = main_gate.assign_value(region, &r_eval.into(), MainGateColumn::A, offset)?;

        Ok(PartiallyEvaluatedVar {
            h_commitments: cv.h_commitments,
            random_poly_commitment: cv.random_poly_commitment,
            random_eval: r_eval,
        })
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
