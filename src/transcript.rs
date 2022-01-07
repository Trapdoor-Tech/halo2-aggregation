use halo2::arithmetic::{CurveAffine, Field, FieldExt};
use halo2::circuit::Region;
use halo2::plonk::Advice;
use halo2::plonk::{Column, ConstraintSystem, Error, TableColumn};
use halo2wrong::circuit::ecc::AssignedPoint;
use halo2wrong::circuit::Assigned;
use halo2wrong::circuit::AssignedValue;
use halo2wrong::rns::big_to_fe;
use halo2wrong::rns::Common;
use std::io::Write;
use std::marker::PhantomData;

use halo2::transcript::{
    Blake2bWrite, Challenge255, EncodedChallenge, Transcript, TranscriptWrite,
};

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

pub trait TranscriptInstructions<C: CurveAffine> {
    fn squeeze_challenge_scalar<T>(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<ChallengeScalarVar<C, T>, Error>;

    fn common_point(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        point: AssignedPoint<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<(), Error>;

    fn common_scalar(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        scalar: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<(), Error>;
}

pub struct TranscriptConfig {
    c: Column<Advice>,
}

pub struct TranscriptChip<C: CurveAffine> {
    config: TranscriptConfig,
    transcript: Blake2bWrite<Vec<u8>, C, Challenge255<C>>,
    // _marker: PhantomData<E>,
}

/// USE THIS CHIP WITH CAUTION!
///
/// This chip is not finished. In order to comply with other parts of the verifier, this chip calls `blake2b` and assigns
/// the result into a challengeVar. No constraint is made.
impl<C: CurveAffine> TranscriptInstructions<C> for TranscriptChip<C> {
    fn squeeze_challenge_scalar<T>(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<ChallengeScalarVar<C, T>, Error> {
        let c = self.transcript.squeeze_challenge().get_scalar();

        let circuit_c = region.assign_advice(|| "challenge", self.config.c, *offset, || Ok(c))?;

        let assigned_c = AssignedValue::new(circuit_c, Some(c));

        let result = ChallengeScalarVar {
            inner: assigned_c,
            _marker: PhantomData,
        };

        Ok(result)
    }

    fn common_point(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        point: AssignedPoint<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<(), Error> {
        let p = point.x().integer().zip(point.y().integer()).map(|(x, y)| {
            let (x, y) = (
                big_to_fe::<C::Base>(x.value()),
                big_to_fe::<C::Base>(y.value()),
            );
            let p: Option<_> = C::from_xy(x, y).into();
            p
        });

        if p.is_some() {
            // do computation only when proving
            let p = p.unwrap().ok_or(Error::Synthesis)?;
            self.transcript
                .write_point(p)
                .map_err(|e| Error::Transcript(e))?;
        }

        Ok(())
    }

    fn common_scalar(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        scalar: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<(), Error> {
        let v = scalar.value();
        if v.is_some() {
            let v = v.unwrap();
            self.transcript
                .write_scalar(v)
                .map_err(|e| Error::Transcript(e))?;
        }

        Ok(())
    }
}

impl<C: CurveAffine> TranscriptChip<C> {
    pub fn new(config: TranscriptConfig) -> Self {
        let mut transcript = Blake2bWrite::<_, C, Challenge255<C>>::init(vec![]);

        Self {
            config,
            transcript,
            // _marker: PhantomData,
        }
    }

    /// CAUTION: NO CONSTRAINT YET!
    pub fn configure(meta: &mut ConstraintSystem<C::ScalarExt>) -> TranscriptConfig {
        let c = meta.advice_column();

        TranscriptConfig { c }
    }
}
