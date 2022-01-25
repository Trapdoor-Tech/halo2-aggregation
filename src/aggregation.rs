use crate::{VerifierConfig, VerifierChip};
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::transcript::{EncodedChallenge, TranscriptRead};
use std::marker::PhantomData;
use halo2::plonk::{ConstraintSystem, Column, Error, Instance, VerifyingKey};
use halo2::circuit::Layouter;
use halo2wrong::circuit::AssignedCondition;
use halo2wrong::circuit::range::RangeInstructions;


#[derive(Clone, Debug)]
pub struct AggregationConfig<C: CurveAffine> {
    verifier_config: VerifierConfig<C>,
}

pub struct AggregationChip<C: CurveAffine, E: EncodedChallenge<C>, T: Clone + TranscriptRead<C, E>> {
    config: AggregationConfig<C>,
    _marker: PhantomData<(E, T)>,
}

impl<'a, C: CurveAffine, E: EncodedChallenge<C>, T: Clone + TranscriptRead<C, E>>
    AggregationChip<C, E, T>
{
    pub fn new(config: AggregationConfig<C>) -> Self {
        AggregationChip {
            config,
            _marker: Default::default(),
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<C::ScalarExt>,
        instance_column: Column<Instance>,
        bit_len_limb: usize,
    ) -> AggregationConfig<C> {
        let verifier_config =
            VerifierChip::<C, E, T>::configure(meta, instance_column, bit_len_limb);
        AggregationConfig {
            verifier_config,
        }
    }

    pub fn verify_single_proof_instruction(
        &self,
        mut layouter:  impl Layouter<C::ScalarExt>,
        vk: &VerifyingKey<C>,
        log_n: usize,
        proof_id: usize,
        transcript: Option<T>
    ) -> Result<AssignedCondition<C::ScalarExt>, Error> {
        let mut transcript = transcript.clone();
        // TODO: transcript will be replace when it is finished
        let mut verifier_chip =
            VerifierChip::<C, E, T>::new(self.config.verifier_config.clone(), transcript.as_mut());

        verifier_chip
            .ecc_chip
            .integer_chip()
            .range_chip()
            .load_limb_range_table(&mut layouter)?;
        verifier_chip
            .ecc_chip
            .integer_chip()
            .range_chip()
            .load_overflow_range_tables(&mut layouter)?;

        let verifier_config = self.config.verifier_config.clone();
        let name = "verify_single_".to_string() + &proof_id.to_string();
        println!("proof id {}", proof_id);
        layouter.assign_region(
            || name.as_str(),
            |mut region| {
                println!("hhh {}", name);
                let mut transcript = transcript.clone();
                // TODO: transcript will be replace when it is finished
                let mut verifier_chip =
                    VerifierChip::<C, E, T>::new(verifier_config.clone(), transcript.as_mut());

                verifier_chip.verify_proof(&mut region, vk, log_n)
            },
        )
    }
}