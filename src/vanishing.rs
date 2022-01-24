use crate::multiopen::VerifierQuery;
use crate::transcript::{TranscriptChip, TranscriptInstructions};
use crate::ChallengeY;
use halo2::arithmetic::{CurveAffine, Field};
use halo2::circuit::Region;
use halo2::plonk::Assigned::Zero;
use halo2::plonk::Error;
use halo2::plonk::Error::Transcript as TranscriptError;
use halo2::poly::Rotation;
use halo2::transcript::{EncodedChallenge, TranscriptRead};
use halo2wrong::circuit::ecc::base_field_ecc::{BaseFieldEccChip, BaseFieldEccInstruction};
use halo2wrong::circuit::ecc::AssignedPoint;
use halo2wrong::circuit::main_gate::Term::Unassigned;
use halo2wrong::circuit::main_gate::{
    CombinationOption, MainGateColumn, MainGateInstructions, Term,
};
use halo2wrong::circuit::{Assigned, AssignedValue};
use std::iter;
use std::marker::PhantomData;
use std::ops::Neg;

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
        Self { ecc_chip }
    }
    pub fn alloc_before_y<E, T>(
        &mut self,
        transcript: &mut Option<&mut T>,
        transcript_chip: &mut TranscriptChip<C>,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<CommittedVar<C>, Error>
    where
        E: EncodedChallenge<C>,
        T: TranscriptRead<C, E>,
    {
        let r = match transcript.as_mut() {
            None => None,
            Some(t) => Some(t.read_point().map_err(|e| TranscriptError(e))?),
        };

        let r = self.ecc_chip.assign_point(region, r, offset)?;
        transcript_chip.common_point(region, r.clone(), offset);
        Ok(CommittedVar {
            random_poly_commitment: r,
        })
    }

    pub fn alloc_after_y<E, T>(
        &mut self,
        transcript: &mut Option<&mut T>,
        transcript_chip: &mut TranscriptChip<C>,
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
                Some(t) => Some(t.read_point().map_err(|e| TranscriptError(e))?),
            };

            let point = self.ecc_chip.assign_point(region, h, offset)?;
            transcript_chip.common_point(region, point.clone(), offset);
            h_commitments.push(point);
        }

        Ok(ConstructedVar {
            h_commitments,
            random_poly_commitment: cv.random_poly_commitment,
        })
    }

    pub fn alloc_after_x<E, T>(
        &mut self,
        transcript: &mut Option<&mut T>,
        transcript_chip: &mut TranscriptChip<C>,
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
            Some(t) => Some(t.read_scalar().map_err(|e| TranscriptError(e))?),
        };

        let main_gate = self.ecc_chip.main_gate();
        let r_eval = main_gate.assign_value(region, &r_eval.into(), MainGateColumn::A, offset)?;
        transcript_chip.common_scalar(region, r_eval.clone(), offset);

        Ok(PartiallyEvaluatedVar {
            h_commitments: cv.h_commitments,
            random_poly_commitment: cv.random_poly_commitment,
            random_eval: r_eval,
        })
    }

    pub fn verify(
        &self,
        region: &mut Region<C::ScalarExt>,
        pev: PartiallyEvaluatedVar<C>,
        expressions: &[AssignedValue<C::ScalarExt>],
        y: ChallengeY<C>,
        xn: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<EvaluatedVar<C>, Error> {
        // expected_h_eval = \sum_k expressions_k * y^k
        let main_gate = self.ecc_chip.main_gate();
        assert!(expressions.len() >= 1);
        let mut expected_h_eval = expressions[0].clone();
        let mut y_acc = y.value();

        for expr in expressions.iter().skip(1) {
            let term = main_gate.mul(region, expected_h_eval, &y.value(), offset)?;
            expected_h_eval = main_gate.add(region, expr, &term, offset)?;
            // y_acc = main_gate.mul(region, &y_acc, &y.value(), offset)?;
        }
        let one = C::ScalarExt::one();
        let neg_one = one.neg();

        let xn_sub_one_val = match xn.value() {
            Some(xn) => Some(xn - &one),
            None => None,
        };
        let (_, xn_sub_one, _, _) = main_gate.combine(
            region,
            Term::Assigned(&xn, one),
            Unassigned(xn_sub_one_val.clone(), neg_one.clone()),
            Term::Zero,
            Term::Zero,
            neg_one,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;
        let xn_sub_one = AssignedValue::new(xn_sub_one, xn_sub_one_val);

        let (expected_h_eval, _) = main_gate.div(region, &expected_h_eval, &xn_sub_one, offset)?;

        // h(X)
        let mut H = pev.h_commitments[0].clone();
        let mut xn_power = xn.clone();
        assert!(pev.h_commitments.len() >= 1);

        for h_comm in pev.h_commitments.iter().skip(1) {
            let term = self
                .ecc_chip
                .mul_var(region, h_comm.clone(), xn_power.clone(), offset)?;
            xn_power = main_gate.mul(region, &xn_power, &xn, offset)?;
            H = self.ecc_chip.add(region, &H, &term, offset)?;
        }
        #[cfg(debug)]
        {
            println!("[circuit] expected h eval: {:?}", expected_h_eval);
            println!("[circuit] H: {:?}", H);
        }

        Ok(EvaluatedVar {
            h_commitment: H,
            random_poly_commitment: pev.random_poly_commitment,
            random_eval: pev.random_eval,
            h_eval: expected_h_eval,
        })
    }
}

impl<C: CurveAffine> PartiallyEvaluatedVar<C> {}

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
