use std::fmt::format;
use crate::lookup::{CommittedVar, LookupChip};
use crate::permutation::PermutationChip;
use crate::vanishing::VanishingChip;
use halo2::arithmetic::{CurveAffine, Field};
use halo2::circuit::Region;
use halo2::plonk::{Error, PinnedVerificationKey, VerifyingKey};
use halo2::transcript::{EncodedChallenge, TranscriptRead};
use halo2wrong::circuit::ecc::base_field_ecc::{BaseFieldEccChip, BaseFieldEccInstruction};
use halo2wrong::circuit::AssignedCondition;
use std::marker::PhantomData;
use halo2wrong::circuit::main_gate::{MainGateColumn, MainGateInstructions};
use crate::transcript::{TranscriptChip, TranscriptInstruction};
use halo2::arithmetic::FieldExt;
use blake2b_simd::Params as Blake2bParams;
use halo2::plonk::Error::TranscriptError;
use crate::{Beta, Gamma, Theta};

pub struct VerifierChip<'a, C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>> {
    ecc_chip: BaseFieldEccChip<C>,
    lookup: LookupChip<C>,
    perm: PermutationChip<C>,
    vanishing: VanishingChip<C>,
    transcript: Option<&'a mut T>,
    transcript_chip: TranscriptChip<C>,
    _marker: PhantomData<E>,
}

impl<'a, C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>>
    VerifierChip<'a, C, E, T>
{
    pub fn new(ecc_chip: BaseFieldEccChip<C>, transcript: Option<&'a mut T>) -> Self {
        Self {
            ecc_chip: ecc_chip.clone(),
            lookup: LookupChip::new(ecc_chip.clone()),
            perm: PermutationChip::new(ecc_chip.clone()),
            vanishing: VanishingChip::new(ecc_chip.clone()),
            transcript,
            transcript_chip: TranscriptChip::new(),
            _marker: Default::default(),
        }
    }

    pub fn verify_proof(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        vk: &VerifyingKey<C>,
        num_adv_columns: usize,
        num_lookups: usize,
        perm_num_columns: usize,
        perm_chunk_len: usize,
        instance_commitments: &Vec<Option<C>>,
        instance_evals: &Vec<Option<C::ScalarExt>>,
        offset: &mut usize,
    ) -> Result<AssignedCondition<C::ScalarExt>, Error> {
        assert_eq!(instance_commitments.len(), instance_evals.len());
        // instance commitments and evals are public inputs to this chip
        let mut inst_comms = vec![];
        for inst_comm in instance_commitments.into_iter() {
            let comm = self.ecc_chip.assign_point(region, *inst_comm, offset)?;
            inst_comms.push(comm);
        }

        let mut inst_evals = vec![];
        for inst_eval in instance_evals.into_iter() {
            // TODO: they are public inputs
            let eval = self.ecc_chip.main_gate().assign_value(region, &(*inst_eval).into(), MainGateColumn::A, offset)?;
            // region.assign_advice_from_instance()
            inst_evals.push(eval);
        }

        let transcript_chip = &mut self.transcript_chip;
        let main_gate = self.ecc_chip.main_gate();

        // hash vk into transcript
        {
            let mut hasher = Blake2bParams::new()
                .hash_length(64)
                .personal(b"Halo2-Verify-Key")
                .to_state();
            let s = format!("{:?}", vk.pinned());

            hasher.update(&(s.len() as u64).to_le_bytes());
            hasher.update(s.as_bytes());

            let hash_result = main_gate.assign_value(
                region, &Some(C::Scalar::from_bytes_wide(hasher.finalize().as_array())).into(), MainGateColumn::A, offset)?;
            transcript_chip.common_scalar(region, hash_result, offset);
        }

        // hash the instance commitments into transcript
        for inst_comm in inst_comms.iter() {
            transcript_chip.common_point(region, inst_comm.clone(), offset);
        }

        let mut adv_comms = vec![];
        for i in (0..num_adv_columns).into_iter() {
            let comm = {
                match self.transcript.as_mut() {
                    None => None,
                    Some(t) => Some(t.read_point().map_err(|_| TranscriptError)?),
                }
            };
            let comm = self.ecc_chip.assign_point(region, comm, offset)?;
            adv_comms.push(comm.clone());
            transcript_chip.common_point(region, comm, offset);
        }

        let theta = transcript_chip.squeeze_challenge_scalar::<Theta>(region, offset);

        // hash each lookup permuted commitments into transcript
        let mut lookups_permuted = vec![];
        for i in (0..num_lookups).into_iter() {
            let pcv = self.lookup.alloc_pcv(&mut self.transcript, transcript_chip, region, offset)?;
            lookups_permuted.push(pcv);
        }

        // sample beta challenge
        let beta = transcript_chip.squeeze_challenge_scalar::<Beta>(region, offset);

        // sample gamma challenge
        let gamma = transcript_chip.squeeze_challenge_scalar::<Gamma>(region, offset);

        // { zp_i }
        let permutations_committed = self.perm.alloc_cv(&mut self.transcript, transcript_chip, region, perm_num_columns, perm_chunk_len, offset)?;

        let lookups_committed = lookups_permuted.into_iter()
            .map(|lookup_permuted| -> Result<CommittedVar<C>, Error> {
                self.lookup.alloc_cv(&mut self.transcript, region, lookup_permuted, offset)
            })
            .collect::<Result<Vec<_>, Error>>()?;


        let ret = self.ecc_chip.main_gate().assign_bit(
            region, Some(C::ScalarExt::zero()), offset)?;

        Ok(ret)
    }
}
