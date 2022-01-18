use crate::lookup::{CommittedVar, EvaluatedVar, LookupChip};
use crate::multiopen::{MultiopenChip, MultiopenConfig, MultiopenInstructions, VerifierQuery};
use crate::permutation::PermutationChip;
use crate::transcript::{TranscriptChip, TranscriptConfig, TranscriptInstructions};
use crate::vanishing::VanishingChip;
use crate::{Beta, Gamma, Theta, U, V, X, Y};
use blake2b_simd::Params as Blake2bParams;
use halo2::arithmetic::FieldExt;
use halo2::arithmetic::{BaseExt, MultiMillerLoop};
use halo2::arithmetic::{CurveAffine, Field};
use halo2::circuit::Region;
use halo2::pairing;
use halo2::plonk::Error::Transcript as TranscriptError;
use halo2::plonk::{
    Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed, Instance,
    PinnedVerificationKey, VerifyingKey,
};
use halo2::poly::Rotation;
use halo2::transcript::{EncodedChallenge, TranscriptRead};
use halo2wrong::circuit::ecc::base_field_ecc::{BaseFieldEccChip, BaseFieldEccInstruction};
use halo2wrong::circuit::ecc::{AssignedPoint, EccConfig};
use halo2wrong::circuit::integer::IntegerInstructions;
use halo2wrong::circuit::main_gate::{
    CombinationOption, MainGate, MainGateColumn, MainGateConfig, MainGateInstructions, Term,
};
use halo2wrong::circuit::range::RangeInstructions;
use halo2wrong::circuit::{
    Assigned, AssignedCondition, AssignedInteger, AssignedLimb, AssignedValue,
};
use halo2wrong::rns::{Common, Rns};
use std::fmt::format;
use std::marker::PhantomData;
use std::ops::MulAssign;

#[derive(Clone, Debug)]
pub struct VerifierConfig<C: CurveAffine> {
    // used to hold public inputs,
    // e.g., instance_commitments, (w, zw, f, e)
    instance_column: Column<Instance>,
    transcript_config: TranscriptConfig,
    multiopen_config: MultiopenConfig,
    base_ecc_config: EccConfig,
    rns: Rns<C::Base, C::ScalarExt>,
}

pub struct VerifierChip<'a, C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>> {
    config: VerifierConfig<C>,
    pub ecc_chip: BaseFieldEccChip<C>,
    lookup: LookupChip<C>,
    perm: PermutationChip<C>,
    vanishing: VanishingChip<C>,
    transcript: Option<&'a mut T>,
    transcript_chip: TranscriptChip<C>,
    multiopen_chip: MultiopenChip<C>,
    _marker: PhantomData<E>,
}

pub(crate) fn compute_expr<C: CurveAffine>(
    main_gate: &MainGate<C::ScalarExt>,
    region: &mut Region<'_, C::ScalarExt>,
    offset: &mut usize,
    expression: &Expression<C::ScalarExt>,
    advice_evals: &[AssignedValue<C::ScalarExt>],
    fixed_evals: &[AssignedValue<C::ScalarExt>],
    instance_evals: &[AssignedValue<C::ScalarExt>],
) -> AssignedValue<C::ScalarExt> {
    match expression {
        Expression::Constant(scalar) => main_gate
            .assign_constant(
                region,
                &(Some(scalar.clone()).into()),
                MainGateColumn::A,
                offset,
            )
            .unwrap(),
        Expression::Selector(_) => {
            panic!("virtual selectors are removed during optimization")
        }
        Expression::Fixed { query_index, .. } => fixed_evals[*query_index].clone(),
        Expression::Advice { query_index, .. } => advice_evals[*query_index].clone(),
        Expression::Instance { query_index, .. } => instance_evals[*query_index].clone(),
        Expression::Negated(a) => {
            let a = compute_expr::<C>(
                main_gate,
                region,
                offset,
                a,
                advice_evals,
                fixed_evals,
                instance_evals,
            );
            main_gate.neg(region, a, offset).unwrap()
        }
        Expression::Sum(a, b) => {
            let a = compute_expr::<C>(
                main_gate,
                region,
                offset,
                a,
                advice_evals,
                fixed_evals,
                instance_evals,
            );
            let b = compute_expr::<C>(
                main_gate,
                region,
                offset,
                b,
                advice_evals,
                fixed_evals,
                instance_evals,
            );
            main_gate.add(region, a, b, offset).unwrap()
        }
        Expression::Product(a, b) => {
            let a = compute_expr::<C>(
                main_gate,
                region,
                offset,
                a,
                advice_evals,
                fixed_evals,
                instance_evals,
            );
            let b = compute_expr::<C>(
                main_gate,
                region,
                offset,
                b,
                advice_evals,
                fixed_evals,
                instance_evals,
            );
            main_gate.mul(region, a, b, offset).unwrap()
        }
        Expression::Scaled(a, scalar) => {
            let a = compute_expr::<C>(
                main_gate,
                region,
                offset,
                a,
                advice_evals,
                fixed_evals,
                instance_evals,
            );
            main_gate
                .mul_by_constant(region, a, *scalar, offset)
                .unwrap()
        }
    }
}

impl<'a, C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>>
    VerifierChip<'a, C, E, T>
{
    pub fn new(config: VerifierConfig<C>, transcript: Option<&'a mut T>) -> Self {
        let ecc_chip =
            BaseFieldEccChip::new(config.base_ecc_config.clone(), config.rns.clone()).unwrap();
        Self {
            config: config.clone(),
            ecc_chip: ecc_chip.clone(),
            lookup: LookupChip::new(ecc_chip.clone()),
            perm: PermutationChip::new(ecc_chip.clone()),
            vanishing: VanishingChip::new(ecc_chip.clone()),
            transcript,
            transcript_chip: TranscriptChip::new(config.transcript_config),
            multiopen_chip: MultiopenChip::new(
                config.multiopen_config,
                config.base_ecc_config,
                config.rns,
            ),
            _marker: Default::default(),
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<C::ScalarExt>,
        instance_column: Column<Instance>,
        bit_len_limb: usize,
    ) -> VerifierConfig<C> {
        let main_gate_config = MainGate::configure(meta);
        let multiopen_config = MultiopenChip::<C>::configure(meta);
        let rns = Rns::<C::Base, C::ScalarExt>::construct(bit_len_limb);
        let base_ecc_config = BaseFieldEccChip::<C>::configure(
            meta,
            main_gate_config.clone(),
            rns.overflow_lengths(),
            rns.clone(),
        );
        let transcript_config = TranscriptChip::<C>::configure(meta);
        VerifierConfig {
            instance_column,
            transcript_config,
            multiopen_config,
            base_ecc_config,
            rns,
        }
    }

    fn assign_point_from_instance(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        instance_row: &mut usize,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        let integer_chip = self.ecc_chip.integer_chip();
        let px = integer_chip.assign_integer_from_instance(
            region,
            self.config.instance_column,
            *instance_row,
            offset,
        )?;
        *instance_row += 4;
        let py = integer_chip.assign_integer_from_instance(
            region,
            self.config.instance_column,
            *instance_row,
            offset,
        )?;
        *instance_row += 4;
        let pz = px.integer().map(|_| C::ScalarExt::zero());
        let pz = self.ecc_chip.main_gate().assign_bit(region, pz, offset)?;

        Ok(AssignedPoint::new(px, py, pz))
    }

    pub fn verify_proof(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        vk: &VerifyingKey<C>,
        log_n: usize,
    ) -> Result<AssignedCondition<C::ScalarExt>, Error> {
        let cs = vk.cs();
        let lookups = cs.lookups();
        let num_lookups = lookups.len();
        let perm_chunk_len = cs.degree() - 2;
        let perm_num_columns = vk.permutation().get_perm_column_num();
        let mut input_expressions = vec![];
        let mut table_expressions = vec![];
        let mut offset = 0usize;
        let mut instance_row = 0usize;
        let mut fixed_row = 0usize;

        for argument in lookups.into_iter() {
            for input_expression in argument.input_expressions.iter() {
                input_expressions.push(input_expression.clone());
            }
            for table_expression in argument.table_expressions.iter() {
                table_expressions.push(table_expression.clone());
            }
        }
        let omega = vk.get_domain().get_omega();
        let g1 = C::generator();
        let gates = vk.gates();
        let perm_columns = &vk.permutation_columns();
        let fixed_commitments = &vk.fixed_commitments();
        let instance_queries = vk.instance_queries();
        let fixed_queries = vk.fixed_queries();
        let advice_queries = vk.advice_queries();
        self._verify_proof(
            region,
            vk,
            log_n,
            cs.blinding_factors(),
            cs.num_advice_columns(),
            cs.num_fixed_columns(),
            num_lookups,
            perm_num_columns,
            perm_chunk_len,
            omega,
            g1,
            input_expressions,
            table_expressions,
            gates,
            perm_columns,
            fixed_commitments,
            cs.num_instance_columns(),
            instance_queries,
            advice_queries,
            fixed_queries,
            &mut offset,
            &mut instance_row,
            &mut fixed_row,
        )
    }
    fn _verify_proof(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        vk: &VerifyingKey<C>,
        log_n: usize,
        blinding_factors: usize,
        num_adv_columns: usize,
        num_fixed_columns: usize,
        num_lookups: usize,
        perm_num_columns: usize,
        perm_chunk_len: usize,
        omega: C::ScalarExt,
        g1: C,
        input_expressions: Vec<Expression<C::ScalarExt>>,
        table_expressions: Vec<Expression<C::ScalarExt>>,
        gates: Vec<Expression<C::ScalarExt>>,
        perm_columns: &Vec<(Column<Any>, usize)>,
        fixed_commitments: &Vec<C>,
        num_instance_commitments: usize,
        instance_queries: Vec<(Column<Instance>, Rotation)>,
        advice_queries: Vec<(Column<Advice>, Rotation)>,
        fixed_queries: Vec<(Column<Fixed>, Rotation)>,
        offset: &mut usize,
        instance_row: &mut usize,
        fixed_row: &mut usize,
    ) -> Result<AssignedCondition<C::ScalarExt>, Error> {
        let mut inst_comms = vec![];
        for _ in (0..num_instance_commitments).into_iter() {
            let comm = self.assign_point_from_instance(region, instance_row, offset)?;
            inst_comms.push(comm);
        }

        let transcript_chip = &mut self.transcript_chip;
        let main_gate = self.ecc_chip.main_gate();

        let mut fixed_comms = vec![];
        for fixed_comm in fixed_commitments {
            // TODO: alloc point from constant
            let p = fixed_comm.coordinates().unwrap();
            let point = self
                .ecc_chip
                .assign_point(region, Some(*fixed_comm), offset)?;
            fixed_comms.push(point);
        }
        // hash vk into transcript
        // TODO: maybe put this instance_column?
        {
            let mut hasher = Blake2bParams::new()
                .hash_length(64)
                .personal(b"Halo2-Verify-Key")
                .to_state();
            let s = format!("{:?}", vk.pinned());

            hasher.update(&(s.len() as u64).to_le_bytes());
            hasher.update(s.as_bytes());

            let hash_result = main_gate.assign_value(
                region,
                &Some(C::Scalar::from_bytes_wide(hasher.finalize().as_array())).into(),
                MainGateColumn::A,
                offset,
            )?;
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
                    Some(t) => Some(t.read_point().map_err(|e| TranscriptError(e))?),
                }
            };
            let comm = self.ecc_chip.assign_point(region, comm, offset)?;
            adv_comms.push(comm.clone());
            transcript_chip.common_point(region, comm, offset);
        }

        let theta = transcript_chip.squeeze_challenge_scalar::<Theta>(region, offset)?;

        // hash each lookup permuted commitments into transcript
        let mut lookups_permuted = vec![];
        for i in (0..num_lookups).into_iter() {
            let pcv =
                self.lookup
                    .alloc_pcv(&mut self.transcript, transcript_chip, region, offset)?;
            lookups_permuted.push(pcv);
        }

        // sample beta challenge
        let beta = transcript_chip.squeeze_challenge_scalar::<Beta>(region, offset)?;

        // sample gamma challenge
        let gamma = transcript_chip.squeeze_challenge_scalar::<Gamma>(region, offset)?;

        // { zp_i }
        let permutations_committed = self.perm.alloc_cv(
            &mut self.transcript,
            transcript_chip,
            region,
            perm_num_columns,
            perm_chunk_len,
            offset,
        )?;

        let lookups_committed = lookups_permuted
            .into_iter()
            .map(|lookup_permuted| -> Result<CommittedVar<C>, Error> {
                self.lookup
                    .alloc_cv(&mut self.transcript, region, lookup_permuted, offset)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let vanishing =
            self.vanishing
                .alloc_before_y(&mut self.transcript, transcript_chip, region, offset)?;

        let y = transcript_chip.squeeze_challenge_scalar::<Y>(region, offset)?;

        let vanishing = self.vanishing.alloc_after_y(
            &mut self.transcript,
            transcript_chip,
            vanishing,
            vk.get_domain().get_quotient_poly_degree(),
            region,
            offset,
        )?;

        let x = transcript_chip.squeeze_challenge_scalar::<X>(region, offset)?;

        let mut inst_evals = vec![];
        for _ in 0..instance_queries.len() {
            let eval = {
                match self.transcript.as_mut() {
                    None => None,
                    Some(t) => Some(t.read_scalar().map_err(|e| TranscriptError(e))?),
                }
            };
            let eval = main_gate.assign_value(region, &eval.into(), MainGateColumn::A, offset)?;
            inst_evals.push(eval.clone());
            transcript_chip.common_scalar(region, eval, offset);
        }

        let mut adv_evals = vec![];
        for _ in (0..advice_queries.len()).into_iter() {
            let eval = {
                match self.transcript.as_mut() {
                    None => None,
                    Some(t) => Some(t.read_scalar().map_err(|e| TranscriptError(e))?),
                }
            };
            let eval = main_gate.assign_value(region, &eval.into(), MainGateColumn::A, offset)?;
            adv_evals.push(eval.clone());
            transcript_chip.common_scalar(region, eval, offset);
        }

        let mut fixed_evals = vec![];
        for _ in (0..fixed_queries.len()).into_iter() {
            let eval = {
                match self.transcript.as_mut() {
                    None => None,
                    Some(t) => Some(t.read_scalar().map_err(|e| TranscriptError(e))?),
                }
            };
            let eval = main_gate.assign_value(region, &eval.into(), MainGateColumn::A, offset)?;
            fixed_evals.push(eval.clone());
            transcript_chip.common_scalar(region, eval, offset);
        }
        let vanishing = self.vanishing.alloc_after_x(
            &mut self.transcript,
            transcript_chip,
            vanishing,
            region,
            offset,
        )?;
        let permutations_common = self.perm.alloc_cev(
            &mut self.transcript,
            transcript_chip,
            region,
            offset,
            perm_num_columns,
        )?;

        let lookups_evaluated = lookups_committed
            .into_iter()
            .map(|lookup_committed| -> Result<EvaluatedVar<C>, Error> {
                self.lookup.alloc_eval(
                    &mut self.transcript,
                    transcript_chip,
                    region,
                    lookup_committed,
                    offset,
                )
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let permutations_evaluated = self.perm.alloc_ev(
            &mut self.transcript,
            transcript_chip,
            region,
            offset,
            permutations_committed.clone(),
        )?;

        let vanishing = {
            let mut xn = x.value();
            for _ in 0..log_n {
                xn = main_gate.mul(region, &xn, &xn, offset)?;
            }
            // l_evals
            let mut l_evals: Vec<AssignedValue<C::ScalarExt>> = vec![];
            let mut omega_powers = C::ScalarExt::one();

            // y = x - c
            // <=> x - y - c = 0
            fn sub_by_constant<F: FieldExt>(
                main_gate: &MainGate<F>,
                region: &mut Region<F>,
                x: impl Assigned<F>,
                constant: F,
                offset: &mut usize,
            ) -> Result<AssignedValue<F>, Error> {
                let one = F::one();
                let neg_one = one.neg();
                let neg_constant = constant.neg();

                let x_sub_c_val = match x.value() {
                    Some(x) => Some(x - &constant),
                    None => None,
                };

                let (_, x_sub_c, _, _) = main_gate.combine(
                    region,
                    Term::Assigned(&x, one),
                    Term::Unassigned(x_sub_c_val.clone(), neg_one.clone()),
                    Term::Zero,
                    Term::Zero,
                    neg_constant,
                    offset,
                    CombinationOption::SingleLinerAdd,
                )?;

                Ok(AssignedValue::new(x_sub_c, x_sub_c_val))
            }

            let xn_sub_one =
                sub_by_constant(&main_gate, region, xn.clone(), C::ScalarExt::one(), offset)?;
            let omega_inv = omega.invert().unwrap();
            for _ in 0..(2 + blinding_factors) {
                // l_evals[i] = (x^n - 1) / (n*(x - w^i)) * w^i
                // let omega_i = main_gate.assign_constant(
                //     region,
                //     &Some(omega_powers.clone()).into(),
                //     MainGateColumn::A,
                //     offset,
                // )?;

                // w^i*(x^n-1)
                let numerator =
                    main_gate.mul_by_constant(region, &xn_sub_one, omega_powers, offset)?;
                // n*(x - w^i)
                let denominator = {
                    let term =
                        sub_by_constant(&main_gate, region, &x.value(), omega_powers, offset)?;
                    main_gate.mul_by_constant(
                        region,
                        &term,
                        C::ScalarExt::from_u128(1 << log_n),
                        offset,
                    )?
                };

                let (li, _) = main_gate.div(region, &numerator, &denominator, offset)?;
                l_evals.push(li);
                omega_powers.mul_assign(omega_inv);
            }
            l_evals.reverse();
            assert_eq!(l_evals.len(), 2 + blinding_factors);
            let l_last = l_evals[0].clone();
            let mut l_blind = l_evals[1].clone();
            for i in 2..(1 + blinding_factors) {
                l_blind = main_gate.add(region, &l_blind, &l_evals[i], offset)?;
            }
            let l_0 = l_evals[1 + blinding_factors].clone();

            let mut expressions = vec![];

            for gate in gates.into_iter() {
                expressions.push(compute_expr::<C>(
                    &main_gate,
                    region,
                    offset,
                    &gate,
                    &adv_evals,
                    &fixed_evals,
                    &inst_evals,
                ));
            }
            for lookup_eval in lookups_evaluated.iter() {
                let expr = self.lookup.expressions(
                    region,
                    lookup_eval.clone(),
                    l_0.clone(),
                    l_last.clone(),
                    l_blind.clone(),
                    &input_expressions,
                    &table_expressions,
                    theta.clone(),
                    beta.clone(),
                    gamma.clone(),
                    &adv_evals,
                    &fixed_evals,
                    &inst_evals,
                    offset,
                )?;
                expressions.extend(expr);
            }

            expressions.extend(self.perm.expressions(
                region,
                &permutations_common,
                &permutations_evaluated,
                perm_columns,
                &adv_evals,
                &fixed_evals,
                &inst_evals,
                l_0.clone(),
                l_last.clone(),
                l_blind.clone(),
                beta.clone(),
                gamma.clone(),
                x.clone(),
                perm_chunk_len,
                offset,
            )?);
            self.vanishing.verify(
                region,
                vanishing,
                &expressions,
                y.clone(),
                xn.clone(),
                offset,
            )?
        };

        let queries = {
            let inst_queries = instance_queries
                .iter()
                .enumerate()
                .map(|(query_index, &(column, at))| {
                    VerifierQuery::<C>::new(
                        inst_comms[column.index()].clone(),
                        at,
                        inst_evals[query_index].clone(),
                    )
                })
                .collect::<Vec<_>>();

            let adv_queries = advice_queries
                .iter()
                .enumerate()
                .map(|(query_index, &(column, at))| {
                    VerifierQuery::<C>::new(
                        adv_comms[column.index()].clone(),
                        at,
                        adv_evals[query_index].clone(),
                    )
                })
                .collect::<Vec<_>>();

            let fixed_queries = fixed_queries
                .iter()
                .enumerate()
                .map(|(query_index, &(column, at))| {
                    VerifierQuery::<C>::new(
                        fixed_comms[column.index()].clone(),
                        at,
                        fixed_evals[query_index].clone(),
                    )
                })
                .collect::<Vec<_>>();

            let perm_queries = permutations_evaluated.queries(blinding_factors as isize);
            let lookup_queries = lookups_evaluated
                .iter()
                .flat_map(|p| p.queries())
                .collect::<Vec<_>>();
            let perm_common_queries = permutations_committed
                .permutation_product_commitments
                .iter()
                .zip(permutations_common.permutation_evals.iter())
                .map(|(comm, eval)| {
                    VerifierQuery::<C>::new(comm.clone(), Rotation::cur(), eval.clone())
                })
                .collect::<Vec<_>>();
            let vanishing_queries = vanishing.queries().collect::<Vec<_>>();

            let mut queries = vec![];
            queries.extend(inst_queries);
            queries.extend(adv_queries);
            queries.extend(perm_queries);
            queries.extend(lookup_queries);
            queries.extend(fixed_queries);
            queries.extend(perm_common_queries);
            queries.extend(vanishing_queries);

            queries
        };

        // TODO: use MultiOpenChip to verify these queries
        let v = transcript_chip.squeeze_challenge_scalar::<V>(region, offset)?;
        let u = transcript_chip.squeeze_challenge_scalar::<U>(region, offset)?;

        let omega_inv = omega.invert().unwrap();
        let multiopen_var = self.multiopen_chip.calc_witness(
            &mut self.transcript,
            region,
            &queries,
            &omega,
            &omega_inv,
            &g1,
            x,
            u,
            v,
            offset,
        )?;
        let w = multiopen_var.w;
        let zw = multiopen_var.zw;
        let f = multiopen_var.f;
        let e = multiopen_var.e;
        // TODO: assert (w, zw, f, e) equal to their public input counterparts.
        let e_input = self.assign_point_from_instance(region, instance_row, offset)?;
        let f_input = self.assign_point_from_instance(region, instance_row, offset)?;
        let w_input = self.assign_point_from_instance(region, instance_row, offset)?;
        let zw_input = self.assign_point_from_instance(region, instance_row, offset)?;

        self.ecc_chip.assert_equal(region, &w, &w_input, offset)?;
        self.ecc_chip.assert_equal(region, &zw, &zw_input, offset)?;
        self.ecc_chip.assert_equal(region, &e, &e_input, offset)?;
        self.ecc_chip.assert_equal(region, &f, &f_input, offset)?;

        let ret =
            self.ecc_chip
                .main_gate()
                .assign_bit(region, Some(C::ScalarExt::zero()), offset)?;

        Ok(ret)
    }
}
