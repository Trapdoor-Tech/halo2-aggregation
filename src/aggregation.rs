use crate::{VerifierConfig, VerifierChip, ChallengeAlpha};
use halo2::arithmetic::{CurveAffine, FieldExt, Field};
use halo2::transcript::{EncodedChallenge, TranscriptRead, ChallengeScalar};
use std::marker::PhantomData;
use halo2::plonk::{ConstraintSystem, Column, Error, Instance, VerifyingKey};
use halo2::circuit::{Layouter, Region};
use halo2wrong::circuit::{AssignedCondition, AssignedValue};
use halo2wrong::circuit::range::RangeInstructions;
use halo2wrong::circuit::ecc::{AssignedPoint, EccConfig};
use halo2wrong::rns::{Rns, big_to_fe, Common};
use crate::transcript::{TranscriptConfig, TranscriptChip, TranscriptInstructions, ChallengeScalarVar};
use halo2wrong::circuit::main_gate::{MainGate, MainGateInstructions, MainGateColumn};
use halo2wrong::circuit::ecc::base_field_ecc::{BaseFieldEccChip, BaseFieldEccInstruction};
use halo2wrong::circuit::integer::IntegerInstructions;
use log::debug;


#[derive(Clone, Debug)]
pub struct AggregationConfig<C: CurveAffine> {
    instance_columns: [Column<Instance>; 2],
    base_ecc_config: EccConfig,
    transcript_config: TranscriptConfig,
    verifier_config: VerifierConfig<C>,
    rns: Rns<C::Base, C::ScalarExt>,
}

pub struct AggregationChip<C: CurveAffine, E: EncodedChallenge<C>, T: Clone + TranscriptRead<C, E>> {
    config: AggregationConfig<C>,
    ecc_chip: BaseFieldEccChip<C>,
    _marker: PhantomData<(E, T)>,
}

impl<'a, C: CurveAffine, E: EncodedChallenge<C>, T: Clone + TranscriptRead<C, E>>
    AggregationChip<C, E, T>
{
    pub fn new(config: AggregationConfig<C>) -> Self {
        let ecc_chip =
            BaseFieldEccChip::new(config.base_ecc_config.clone(), config.rns.clone()).unwrap();
        AggregationChip {
            config: config.clone(),
            ecc_chip,
            _marker: Default::default(),
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<C::ScalarExt>,
        instance_columns: [Column<Instance>; 2],
        bit_len_limb: usize,
    ) -> AggregationConfig<C> {
        let main_gate_config = MainGate::configure(meta);
        let rns = Rns::<C::Base, C::ScalarExt>::construct(bit_len_limb);
        let base_ecc_config = BaseFieldEccChip::<C>::configure(
            meta,
            main_gate_config.clone(),
            rns.overflow_lengths(),
            rns.clone(),
        );
        let transcript_config = TranscriptChip::<C>::configure(meta);
        let verifier_config =
            VerifierChip::<C, E, T>::configure_from_common(meta, instance_columns, base_ecc_config.clone(), transcript_config.clone(), rns.clone());
        AggregationConfig {
            instance_columns,
            base_ecc_config,
            transcript_config,
            verifier_config,
            rns,
        }
    }

    fn assign_point_from_instance(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        instance_column: Column<Instance>,
        instance_row: &mut usize,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        let integer_chip = self.ecc_chip.integer_chip();
        let px = integer_chip.assign_integer_from_instance(
            region,
            instance_column,
            *instance_row,
            offset,
        )?;
        *instance_row += 4;
        let py = integer_chip.assign_integer_from_instance(
            region,
            instance_column,
            *instance_row,
            offset,
        )?;
        *instance_row += 4;
        let pz = px.integer().map(|_| C::ScalarExt::zero());
        let pz = self.ecc_chip.main_gate().assign_bit(region, pz, offset)?;

        Ok(AssignedPoint::new(px, py, pz))
    }

    pub fn load_range_table_instruction(
        &self,
        mut layouter:  impl Layouter<C::ScalarExt>,
    ) -> Result<(), Error> {
        // TODO: transcript will be replace when it is finished
        let mut verifier_chip =
            VerifierChip::<C, E, T>::new(self.config.verifier_config.clone(), None);

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
        Ok(())
    }

    pub fn verify_single_proof_instruction(
        &self,
        mut layouter:  impl Layouter<C::ScalarExt>,
        vk: &VerifyingKey<C>,
        log_n: usize,
        proof_id: usize,
        vk_offset: usize,
        single_input_offset: usize,
        transcript: Option<T>
    ) -> Result<(AssignedPoint<C::ScalarExt>, AssignedPoint<C::ScalarExt>, AssignedPoint<C::ScalarExt>, AssignedPoint<C::ScalarExt>), Error> {
        let verifier_config = self.config.verifier_config.clone();
        let name = "verify_single_".to_string() + &proof_id.to_string();
        layouter.assign_region(
            || name.as_str(),
            |mut region| {
                let mut transcript = transcript.clone();
                // TODO: transcript will be replace when it is finished
                let mut verifier_chip =
                    VerifierChip::<C, E, T>::new(verifier_config.clone(), transcript.as_mut());

                verifier_chip.verify_proof(&mut region, vk, log_n, vk_offset, single_input_offset)
            },
        )
    }

    pub fn generate_g1_linear_combinations(
        &mut self,
        mut layouter:  impl Layouter<C::ScalarExt>,
        all_e: Vec<AssignedPoint<C::ScalarExt>>,
        all_f: Vec<AssignedPoint<C::ScalarExt>>,
        all_w: Vec<AssignedPoint<C::ScalarExt>>,
        all_zw: Vec<AssignedPoint<C::ScalarExt>>,
        proof_to_check: usize,
        instance_row: usize,
    ) -> Result<(), Error> {
        assert_eq!(proof_to_check, all_e.len());
        assert_eq!(proof_to_check, all_f.len());
        assert_eq!(proof_to_check, all_w.len());
        assert_eq!(proof_to_check, all_zw.len());

        // Do the linear combination
        layouter.assign_region(
            || "G1_linear_combination",
            |mut region| {
                let mut transcript_chip = TranscriptChip::<C>::new(self.config.transcript_config.clone());
                let mut instance_row = instance_row;
                // Calc the challenge
                let mut origin_offset = 0usize;
                let mut offset = &mut origin_offset;
                let mut region = &mut region;
                // Absorb all the (e, f, w, zw) tuple
                for (((e, f), w), zw) in all_e.iter().zip(all_f.iter()).zip(all_w.iter()).zip(all_zw.iter()) {
                    transcript_chip.common_point(region, e.clone(), offset)?;
                    transcript_chip.common_point(region, f.clone(), offset)?;
                    transcript_chip.common_point(region, w.clone(), offset)?;
                    transcript_chip.common_point(region, zw.clone(), offset)?;
                }
                let challenge: ChallengeAlpha<_> = transcript_chip.squeeze_challenge_scalar(&mut region, offset)?;
                // Calc linear combinations
                /// TODO: Identity should be used here, replace the generator when add identity fixed.
                /// Here use generator as the initial value is a trick. In fact, we should use C::Identity(),
                /// but till now, maybe ecc_chip.add has some bugs, the related results are incorrect.
                /// So here use generator, then sub the generator in the final result.
                let mut sum_e = self.ecc_chip.assign_point(
                    region,
                    Some(C::generator()),
                    offset,
                )?;
                let mut sum_f = self.ecc_chip.assign_point(
                    region,
                    Some(C::generator()),
                    offset,
                )?;
                let mut sum_w = self.ecc_chip.assign_point(
                    region,
                    Some(C::generator()),
                    offset,
                )?;
                let mut sum_zw = self.ecc_chip.assign_point(
                    region,
                    Some(C::generator()),
                    offset,
                )?;
                let mut current = self.ecc_chip.main_gate().assign_value(
                    region,
                    &Some(C::ScalarExt::one()).into(),
                    MainGateColumn::A,
                    offset,
                )?;

                let neg_one = self.ecc_chip.main_gate().neg(region, current.clone(), offset)?;
                let neg_g = self.ecc_chip.mul_var(region, sum_e.clone(), neg_one, offset)?;

                // a * iterm[0] + a^2 * iterm[1] + a^3 * iterm[2] + ...
                for (((e, f), w), zw) in all_e.iter().zip(all_f.iter()).zip(all_w.iter()).zip(all_zw.iter()) {
                    current = self.ecc_chip.main_gate().mul(region, current.clone(), challenge.value(), offset)?;
                    let current_e = self.ecc_chip.mul_var(region, e.clone(), current.clone(), offset)?;
                    let current_f = self.ecc_chip.mul_var(region, f.clone(), current.clone(), offset)?;
                    let current_w = self.ecc_chip.mul_var(region, w.clone(), current.clone(), offset)?;
                    let current_zw = self.ecc_chip.mul_var(region, zw.clone(), current.clone(), offset)?;
                    sum_e = self.ecc_chip.add(region, &sum_e, &current_e, offset)?;
                    sum_f = self.ecc_chip.add(region, &sum_f, &current_f, offset)?;
                    sum_w = self.ecc_chip.add(region, &sum_w, &current_w, offset)?;
                    sum_zw = self.ecc_chip.add(region, &sum_zw, &current_zw, offset)?;
                    debug!("circuit_a: {:?}", current.clone());
                }

                // sub generator. This is tricky
                sum_e = self.ecc_chip.add(region, &sum_e, &neg_g, offset)?;
                sum_f = self.ecc_chip.add(region, &sum_f, &neg_g, offset)?;
                sum_w = self.ecc_chip.add(region, &sum_w, &neg_g, offset)?;
                sum_zw = self.ecc_chip.add(region, &sum_zw, &neg_g, offset)?;
                debug!("sum_e: {:?}", sum_e.clone());
                debug!("sum_f: {:?}", sum_f.clone());
                debug!("sum_w: {:?}", sum_w.clone());
                debug!("sum_zw: {:?}", sum_zw.clone());
                // constrain equal to public input
                let e_input = self.assign_point_from_instance(region, self.config.instance_columns[1], &mut instance_row, offset)?;
                let f_input = self.assign_point_from_instance(region, self.config.instance_columns[1], &mut instance_row, offset)?;
                let w_input = self.assign_point_from_instance(region, self.config.instance_columns[1], &mut instance_row, offset)?;
                let zw_input = self.assign_point_from_instance(region, self.config.instance_columns[1], &mut instance_row, offset)?;
                debug!("e_input: {:?}", e_input.clone());
                debug!("f_input: {:?}", f_input.clone());
                debug!("w_input: {:?}", w_input.clone());
                debug!("zw_input: {:?}", zw_input.clone());

                self.ecc_chip.assert_equal(region, &sum_e, &e_input, offset)?;
                self.ecc_chip.assert_equal(region, &sum_f, &f_input, offset)?;
                self.ecc_chip.assert_equal(region, &sum_w, &w_input, offset)?;
                self.ecc_chip.assert_equal(region, &sum_zw, &zw_input, offset)?;

                Ok(())
            },
        )
    }
}