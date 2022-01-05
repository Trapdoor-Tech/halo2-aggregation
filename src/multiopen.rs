use halo2::arithmetic::CurveAffine;
use halo2::poly::Rotation;
use halo2wrong::circuit::ecc::AssignedPoint;
use halo2wrong::circuit::AssignedValue;

#[derive(Debug, Clone)]
pub struct VerifierQuery<C: CurveAffine> {
    commitment: AssignedPoint<C::ScalarExt>,
    rotation: Rotation,
    eval: AssignedValue<C::ScalarExt>,
}

impl<C: CurveAffine> VerifierQuery<C> {
    pub fn new(
        commitment: AssignedPoint<C::ScalarExt>,
        rotation: Rotation,
        eval: AssignedValue<C::ScalarExt>,
    ) -> Self {
        VerifierQuery {
            commitment,
            rotation,
            eval,
        }
    }

    pub fn get_rotation(&self) -> Rotation {
        self.rotation
    }

    pub fn get_comm(&self) -> AssginedPoint<C::ScalarExt> {
        self.commitment
    }

    pub fn get_eval(&self) -> AssginedValue<C::ScalarExt> {
        self.eval
    }
}

pub struct VerifierQueriesByRotation<C: CurveAffine> {
    queries: Vec<VerifierQuery<C>>,
    rotation: Rotation,
}

#[derive(Debug, Clone)]
pub struct MultiopenResult<C: CurveAffine> {
    w: AssignedPoint<C::ScalarExt>,
    zw_lc: AssignedPoint<C::ScalarExt>,
    e_multi: AssignedValue<C::ScalarExt>,
}

impl<C: CurveAffine> MultiopenResult<C> {
    pub fn get_w(&self) -> AssignedPoint<C::ScalarExt> {
        self.w
    }

    pub fn get_zw(&self) -> AssignedPoint<C::ScalarExt> {
        self.zw_lc
    }

    pub fn get_e(&self) -> AssignedPoint<C::ScalarExt> {
        self.e_multi
    }
}

/// MultiopenConfig contains all the columns needed, along with two chips which provide ecc/scalar arithmetic
/// This Multiopen chip use the following column layout
///
/// | witness | witness_aux | comm_multi | eval_multi | u | u_sel | v_sel | comms | evals | z   | wi   |
/// | ---     | ---         | ---        | ---        | - | ---   | ---   | ---   | ---   | -   | --   |
/// | wit_0   | wit_aux_0   | comm_mul_0 | eval_mul_0 | u | 1     | v     | c_1_0 | e_1_0 | z_1 | wi_1 |   // for point set 1
/// | wit_1   | wit_aux_1   | comm_mul_1 | eval_mul_1 | u | 0     | v^2   | c_1_1 | e_1_1 | z_1 | wi_1 |
/// | wit_2   | wit_aux_2   | comm_mul_2 | eval_mul_2 | u | 0     | v^3   | c_1_2 | e_1_2 | z_1 | wi_1 |
/// | wit_3   | wit_aux_3   | comm_mul_3 | eval_mul_3 | u | 1     | v     | c_2_0 | e_2_0 | z_2 | wi_2 |   // for point set 2
/// | wit_4   | wit_aux_4   | comm_mul_4 | eval_mul_4 | u | 1     | v     | c_3_0 | e_3_0 | z_3 | wi_3 |   // for point set 3
/// | wit_5   | wit_aux_5   | comm_mul_5 | eval_mul_5 | u | 0     | v^2   | c_3_1 | e_3_1 | z_1 | wi_1 |
///
/// Constraints (advice columns):
/// witness_i           = witness_{i-1} * u_sel_i * u           + witness_{i-1} * (1 - u_sel_i)         + z_i * wi_i * u_sel_i
/// witness_aux_i       = witness_aux_{i-1} * u_sel_i * u       + witness_aux_{i-1} * (1 - u_sel_i)     + wi_i * u_sel_i
/// comm_mul_i          = comm_mul_{i-1} * u_sel_i * u          + comm_mul_{i-1} * (1 - u_sel_i)        + comms_i * v_sel_i
/// eval_mul_i          = eval_mul_{i-1} * u_sel_i * u          + eval_mul_{i-1} * (1 - u_sel_i)        + eval_i * v_sel_i
/// v_sel_i             = v * u_sel_i                           + v_sel_{i-1} * (1 - u_sel_i) * v
///
/// TODO: u_i                 = u
///
/// u_sel is a fixed column
///
/// TODO: comms, evals, z, wi are instance columns ??? (or read from transcript?)
/// TODO: did not constrain u/v from transcript
pub struct MultiopenConfig {
    // witness: Column<Advice>,
    // witness_aux: Column<Advice>,
    // comm_multi: Column<Advice>,
    // eval_multi: Column<Advice>,
    // v_sel: Column<Advice>,
    // u: Column<Advice>,
    // v: Column<Advice>,

    // u_sel: Column<Fixed>,
    // comms: Column<Instance>,
    // evals: Column<Instance>,
    // z: Column<Instance>,
    // wi: Column<Instance>,
    rot: Column<Advice>,
    omega_evals: Column<Advice>,

    t_rot: TableColumn,
    t_omega_evals: TableColumn,

    // chip to do mul/add arithmetics on commitments/evals
    ecc_chip: EccConfig,
}

/// Instructions should be able to compute and fill in witnesses
/// in order to do linear combination of commitments, we use `BaseFieldEccInstruction` from `halo2wrong`
pub trait MultiopenInstructions<C: CurveAffine> {
    type Comm;
    type Eval;

    // fn assign_comm(
    //     &self,
    //     region: &mut Region<'_, C::ScalarExt>,
    //     comm: Option<Point<C::ScalarExt>>,
    //     offset: &mut usize,
    // ) -> Result<Self::Comm, Error>;

    // fn assign_eval(
    //     &self,
    //     region: &mut Region<'_, C::ScalarExt>,
    //     eval: Option<C::ScalarExt>,
    //     offset: &mut usize,
    // ) -> Result<Self::Eval, Error>;

    // fn calc_witness(
    //     &self,
    //     region: &mut Region<'_, C::ScalarExt>,
    //     zi: &[C],
    //     wi: &[C],
    //     u_sel: &[C],
    //     u: &C,
    // ) -> Result<(), Error>;
}

pub struct MultiopenChip<'a, C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>> {
    config: MultiopenConfig,
    transcript: Option<&'a mut T>,

    base_ecc_config: EccConfig,
    rns: Rns<C::Base, C::ScalarExt>,
    _marker: PhantomData<E>,
}

impl<'a, C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>> MultiopenInstruction<C>
    for MultiopenChip<C, E, T>
{
    type Comm = AssignedPoint<C::ScalarExt>;
    type Eval = AssignedValue<C::ScalarExt>;

    // fn assign_comm(
    //     &self,
    //     region: &mut Region<'_, C::ScalarExt>,
    //     comm: Option<C>,
    //     offset: &mut usize,
    // ) -> Result<Self::Comm, Error> {
    //     let base_ecc_chip = self.base_ecc_chip();

    //     // `assign_point` will convert `comm` into an rns point
    //     base_ecc_chip.assign_point(region, comm?, offset)
    // }

    // fn assign_eval(
    //     &self,
    //     region: &mut Region<'_, C::ScalarExt>,
    //     eval: Option<C::ScalarExt>,
    //     offset: &mut usize,
    // ) -> Result<Self::Eval, Error> {
    //     let e = region.assign_advice(
    //         || "evals",
    //         self.config.evals,
    //         offset,
    //         || Ok(eval.ok_or(Error::SynthesisError)?.0),
    //     )?;

    //     Ok(e)
    // }

    fn read_comm(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<Self::Comm, Error> {
        let point = match self.transcript.as_mut() {
            None => return TranscriptError,
            Some(t) => t.read_point().map_err(|_| TranscriptError)?,
        };
        self.ecc_chip.assign_point(region, point, offset)?;
        Ok(point)
    }

    fn read_eval(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<Self::Eval, Error> {
        let eval = match self.transcript.as_mut() {
            None => return TranscriptError,
            Some(t) => t.read_scalar().map_err(|_| TranscriptError)?,
        };
        self.ecc_chip
            .main_gate()
            .assign_value(region, eval, MainGateColumn::A, offset)?;
        Ok(eval)
    }

    fn lookup_table_pows(
        &self,
        layouter: &mut impl Layouter<C::ScalarExt>,
        omega_evals: &[(Rotation, Self::Eval)],
        offset: &mut usize,
    ) -> Result<Self::Eval, Error> {
        layouter.assign_table(
            || "Rotation table",
            |mut table| {
                for (index, &value) in omega_evals.iter().enumerate() {
                    let (rot, _) = value;
                    table.assign_cell(|| "table col", self.config.rot, index, || Ok(rot))?;
                }
                Ok(())
            },
        )?;

        layouter.assign_table(
            || "Omega_eval table",
            |mut table| {
                for (index, &value) in omega_evals.iter().enumerate() {
                    let (_, eval) = value;
                    table.assign_cell(
                        || "table col",
                        self.config.omega_evals,
                        index,
                        || Ok(eval),
                    )?;
                }
                Ok(())
            },
        )?;

        Ok(())
    }

    fn construct_intermediate_sets<C: CurveAffine, I, Q: VerifierQuery<C>>(
        queries: I,
    ) -> Vec<VerifierQueriesByRotation<Q>>
    where
        I: IntoIterator<Item = Q> + Clone,
    {
        let mut point_query_map: BTreeMap<Q::Scalar, Vec<Q>> = BTreeMap::new();
        for query in queries.clone() {
            if let Some(queries) = point_query_map.get_mut(&query.get_rotation()) {
                queries.push(query);
            } else {
                point_query_map.insert(query.get_rotation(), vec![query]);
            }
        }

        point_query_map
            .keys()
            .map(|rot| {
                let queries = point_query_map.get(rot).unwrap();
                VerifierQueriesByRotation {
                    queries: queries.clone(),
                    rotation: rot.clone(),
                    _marker: PhantomData,
                }
            })
            .collect()
    }

    /// witness_i = witness_{i-1} * u_sel_i * u + witness_{i-1} * (1 - u_sel_i) + z_i * wi_i * u_sel_i
    /// witness_aux_i = witness_aux_{i-1} * u_sel_i * u + witness_aux_{i-1} * (1 - u_sel_i) + wi_i * u_sel_i
    /// comm_mul_i = comm_mul_{i-1} * u_sel_i * u + comm_mul_{i-1} * (1 - u_sel_i) + comms_i * v_sel_i
    /// eval_mul_i = eval_mul_{i-1} * u_sel_i * u + eval_mul_{i-1} * (1 - u_sel_i) + eval_i * v_sel_i
    pub fn calc_witness(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        queries: &[VerifierQuery<C>],
        omega: &C::ScalarExt,     // TODO: omega should be a constant
        omega_inv: &C::ScalarExt, // TODO: omega should be a constant
        x: ChallengeX<C>,
        u: ChallengeU<C>,
        v: ChallengeV<C>,
    ) -> Result<Self::Comm, Error> {
        let config = self.config();
        let ecc_chip = self.base_ecc_chip();

        let mut rot_offset = 0;
        let mut omega_eval_offset = 0;

        // rearrange the verifier queries
        let queries_by_rotation = self.construct_intermediate_sets(queries);

        let one = Some(C::ScalarExt::one());
        let one = main_gate.assign_constant(region, &one.into(), MainGateColumn::A, offset)?;

        let omega = ecc_chip.main_gate().assign_constant(
            region,
            &omega.into(),
            MainGateColumn::A,
            offset,
        )?;

        let omega_inv = ecc_chip.main_gate().assign_constant(
            region,
            &omega_inv.into(),
            MainGateColumn::A,
            offset,
        )?;

        let omega_x_omega_inv = ecc_chip.main_gate().mul(region, omega, omega_inv, offset)?;
        ecc_chip
            .main_gate()
            .assert_equal(region, one, omega_x_omega_inv, offset)?;

        let mut witness = ecc_chip.assign_point(region, C::zero(), offset)?;
        let mut witness_with_aux = ecc_chip.assign_point(region, C::zero(), offset)?;
        let mut commitment_multi = ecc_chip.assign_point(region, C::zero(), offset)?;
        let mut eval_multi =
            ecc_chip
                .main_gate()
                .assign_value(region, C::ScalarExt::zero(), offset)?;

        let circuit_x = ecc_chip.main_gate().assign_value(
            region,
            &x.value().into(),
            MainGateColumn::A,
            offset,
        )?;
        let circuit_u = ecc_chip.main_gate().assign_value(
            region,
            &u.value().into(),
            MainGateColumn::A,
            offset,
        )?;
        let circuit_v = ecc_chip.main_gate().assign_value(
            region,
            &v.value().into(),
            MainGateColumn::A,
            offset,
        )?;

        // use cur_p to store the linear comb of zi/wi
        for queries_at_a_rotation in queries_by_rotation.iter() {
            let r = queries_at_a_rotation.get_rotation();

            let r_geq_zero = if r >= 0 {
                UnassignedValue::new(Some(F::one()))
            } else {
                UnassignedValue::new(Some(F::zero()))
            };
            let r_geq_zero = ecc_chip.main_gate().assign_value(
                region,
                &r_geq_zero,
                MainGateColumn::A,
                offset,
            )?;
            let real_omega = ecc_chip
                .main_gate()
                .cond_select(region, omega, omega_inv, r_geq_zero, offset)?;

            // we should calculate real_omega ^ r
            let (rot, omega_eval) = if r >= 0 {
                (C::ScalarExt::from_u64(r), omega.pow(&[r]))
            } else {
                (-C::ScalarExt::from_u64(-r), omega_inv.pow(&[-r]))
            };

            let r = region.assign_advice(|| "rotation", self.config.rot, rot_offset, || Ok(rot))?;
            let pow_real_omega = region.assign_advice(
                || "omega eval",
                self.config.omega_evals,
                omega_eval_offset,
                || Ok(omega_eval),
            )?;

            let z = ecc_chip
                .main_gate()
                .mul(region, pow_real_omega, circuit_x, offset)?;
            let wi = self.read_comm(region, offset)?;
            let z_wi = ecc_chip.mul_var(region, wi, z, offset)?;

            witness = ecc_chip.mul_var(region, witness, circuit_u, offset)?;
            witness = ecc_chip.add(region, witness, wi, offset)?;

            witness_with_aux = ecc_chip.mul_var(region, witness_with_aux, circuit_u, offset)?;
            witness_with_aux = ecc_chip.add(region, witness_with_aux, z_wi, offset)?;

            commitment_multi = ecc_chip.mul_var(region, commitment_multi, circuit_u, offset)?;
            eval_multi = ecc_chip
                .main_gate()
                .mul(region, eval_multi, circuit_u, offset)?;

            let mut commitment_batch = ecc_chip.assign_point(region, C::zero(), offset)?;
            let mut eval_batch =
                ecc_chip
                    .main_gate()
                    .assign_value(region, C::ScalarExt::zero(), offset)?;

            for query in queries_at_a_rotation.queries.iter() {
                ecc_chip
                    .main_gate()
                    .assert_equal(region, z, query.get_comm(), offset)?;

                commitment_batch = ecc_chip.mul_var(region, commitment_batch, circuit_v, offset)?;

                eval_batch = ecc_chip
                    .main_gate()
                    .mul(region, eval_batch, circuit_v, offset)?;

                let comm = query.get_comm();
                let eval = query.get_eval();

                commitment_batch = ecc_chip.add(region, commitment_batch, comm, offset)?;
                eval_batch = ecc_chip.main_gate().add(region, eval_batch, eval, offset)?;
            }

            commitment_multi = ecc_chip.add(region, commitment_multi, commitment_batch, offset)?;
            eval_multi = ecc_chip
                .main_gate()
                .add(region, eval_multi, eval_batch, offset)?;
        }

        Ok(())
    }

    // /// witness_i = witness_{i-1} * u_sel_i * u + witness_{i-1} * (1 - u_sel_i) + z_i * wi_i * u_sel_i
    // fn calc_witness(
    //     &self,
    //     region: &mut Region<'_, C::ScalarExt>,
    //     zi: &[C],
    //     wi: &[C],
    //     u_sel: &[C],
    //     u: &C,
    //     // u: ChallengeU<C>,
    // ) -> Result<Self::Comm, Error> {
    //     let config = self.config();
    //     let ecc_chip = self.base_ecc_chip();

    //     assert!(zi_len() == wi.len(), "zi/wi have different length!");
    //     assert!(zi_len() == u_sel.len(), "zi/u_sel have different length!");
    //     assert!(zi.len() > 0, "no zi found!");

    //     // use cur_p to store the linear comb of zi/wi
    //     let mut cur_p = C::zero();

    //     let mut circuit_p = ecc_chip.assign_point(region, Some(cur_p), offset)?;
    //     let circuit_inf_point = ecc_chip.assign_point(region, Some(C::zero()), offset)?;
    //     let circuit_z = region.assign_advice(
    //         || "u",
    //         self.config.u,
    //         offset,
    //         || Ok(u.ok_or(Error::SynthesisError)?.0),
    //     )?;

    //     for ((z, w), u_s) in zi
    //         .iter()
    //         .zip(wi.iter())
    //         .zip(u_sel.iter())
    //     {
    //         // === circuit computation ===
    //         let circuit_z = region.assign_advice(
    //             || "zi",
    //             self.config.zi,
    //             offset,
    //             || Ok(z.ok_or(Error::SynthesisError)?.0),
    //         )?;

    //         let circuit_w = ecc_chip.mul_var(region, circuit_w, circuit_z, offset)?;

    //         let circuit_u_sel = region.assign_advice(
    //             || "u_sel",
    //             self.config.u_sel,
    //             offset,
    //             || Ok(u_s.ok_or(Error::SynthesisError)?.0),
    //         )?;

    //         let circuit_p_prev_selected =
    //             ecc_chip.mul_var(region, circuit_p_prev, circuit_z, offset)?;

    //         // convert `u_sel` from `AssignedValue` to `AssignedCondition`
    //         let circuit_p_prev = ecc_chip.select(
    //             region,
    //             u_sel.into(),
    //             circuit_p_prev_selected,
    //             circuit_p_prev,
    //         )?;
    //         let circuit_w = ecc_chip.select(region, u_sel.into(), circuit_w, circuit_inf_point)?;

    //         circuit_p = ecc_chip.add(region, &circuit_w, &circuit_p_prev, offset)?;

    //         // === non circuit computation ===
    //         cur_p =
    //             w.mul(z * u_s) + &(cur_p.mul(u_s * u) + &cur_p.mul(C::ScalarExt::one() - u_s));
    //     }

    //     let circuit_cur_p = ecc.assign_point(region, cur_p, offset)?;

    //     ecc_chip.assert_equal(region, &circuit_p, &circuit_cur_p, offset)?;

    //     Ok(())
    // }

    // /// witness_aux_i = witness_aux_{i-1} * u_sel_i * u + witness_aux_{i-1} * (1 - u_sel_i) + wi_i * u_sel_i
    // fn calc_witness_aux(
    //     &self,
    //     region: &mut Region<'_, C::ScalarExt>,
    //     wi: &[C],
    //     u_sel: &[C],
    //     u: &C,
    // ) -> Result<(), Error> {
    //     let config = self.config();
    //     let ecc_chip = self.base_ecc_chip();

    //     assert!(wi.len() == u_sel.len(), "wi/u_sel have different length!");
    //     assert!(wi.len() > 0, "no wi found!");

    //     let mut p_prev = C::zero();

    //     for (w, u_s) in wi.iter().skip(1).zip(u_sel.iter().skip(1)) {
    //         let cur_p = w.mul(u_s) + &(p_prev.mul(u_s * u) + p_prev.mul(C::ScalarExt::one() - u_s));

    //         ecc_chip.assign_point(region, cur_p, offset);
    //     }

    //     Ok(())
    // }

    // /// comm_mul_i = comm_mul_{i-1} * u_sel_i * u + comm_mul_{i-1} * (1 - u_sel_i) + comms_i * v_sel_i
    // fn calc_comms_multi(
    //     &self,
    //     region: &mut Region<'_, C::ScalarExt>,
    //     comms: &[C],
    //     u_sel: &[C],
    //     v_sel: &[C],
    //     u: &C,
    // ) -> Result<(), Error> {
    //     let config = self.config();
    //     let ecc_chip = self.base_ecc_chip();

    //     assert!(
    //         comms.len() == u_sel.len(),
    //         "comms/u_sel have different length!"
    //     );
    //     assert!(
    //         comms.len() == v_sel.len(),
    //         "comms/v_sel have different length!"
    //     );
    //     assert!(comms.len() > 0, "no comms found!");

    //     let mut p_prev = comms[0].clone();
    //     ecc_chip.assign_point(region, p_prev, offset);

    //     for ((comm, u_s), v_s) in comms
    //         .iter()
    //         .skip(1)
    //         .zip(u_sel.iter().skip(1))
    //         .zip(v_sel.iter().skip(1))
    //     {
    //         let cur_p =
    //             comm.mul(v_s) + &(p_prev.mul(u_s * u) + p_prev.mul(C::ScalarExt::one() - u_s));

    //         ecc_chip.assign_point(region, cur_p, offset);
    //     }

    //     Ok(())
    // }

    // /// eval_mul_i = eval_mul_{i-1} * u_sel_i * u + eval_mul_{i-1} * (1 - u_sel_i) + eval_i * v_sel_i
    // fn calc_evals_multi(
    //     &self,
    //     region: &mut Region<'_, C::ScalarExt>,
    //     evals: &[C::ScalarExt],
    //     u_sel: &[C],
    //     v_sel: &[C],
    //     u: &C,
    // ) -> Result<(), Error> {
    //     let config = self.config();
    //     let ecc_chip = self.base_ecc_chip();

    //     assert!(
    //         evals.len() == u_sel.len(),
    //         "evals/u_sel have different length!"
    //     );
    //     assert!(
    //         evals.len() == v_sel.len(),
    //         "evals/v_sel have different length!"
    //     );
    //     assert!(comms.len() > 0, "no comms found!");

    //     let mut e_prev = evals[0].clone();
    //     ecc_chip.assign_point(region, e_prev, offset);

    //     for ((eval, u_s), v_s) in eval
    //         .iter()
    //         .skip(1)
    //         .zip(u_sel.iter().skip(1))
    //         .zip(v_sel.iter().skip(1))
    //     {
    //         let cur_e =
    //             eval * v_s + &(&(e_prev * &(u_s * u)) + (e_prev * &(C::ScalarExt::one() - u_s)));

    //         region.assign_advice(|| "evals", config.eval_multi, offset, || cur_e)?;
    //     }

    //     Ok(())
    // }
}

impl<'a, C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>> Chip<C::ScalarExt>
    for MultiopenChip<'a, C, E>
{
    type Config = MultiopenConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

/// To simplify MSM computation, we calculate every commitment/eval while accumulating
impl<'a, C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>> MultiopenChip<'a, C, E> {
    fn new(
        config: MultiopenConfig,
        ecc_config: EccConfig,
        rns: Rns<C::Base, C::ScalarExt>,
    ) -> Self {
        Self {
            config,
            transcript: None,
            ecc_config,
            rns,
        }
    }

    fn base_ecc_chip(&self) -> Result<BaseFieldEccConfig, Error> {
        let base_ecc_config = self.base_ecc_config.clone();
        let rns = self.rns.clone();
        BaseFieldEccChip::<C>::new(base_ecc_config, rns)
    }

    fn configure(meta: &mut ConstraintSystem<C>) -> MultiopenConfig {
        let rot = meta.advice_column();
        let omega_evals = meta.advice_column();
        let t_rot = meta.lookup_table_column();
        let t_omega_evals = meta.lookup_table_column();

        meta.lookup(|meta| {
            let a = meta.query_any(rot.into(), Rotation::cur());
            vec![(a, t_rot)]
        });

        meta.lookup(|meta| {
            let b = meta.query_any(omega_evals.into(), Rotation::cur());
            vec![(b, t_omega_evals)]
        });

        MultiopenConfig {
            rot,
            omega_evals,
            t_rot,
            t_omega_evals,
            ecc_chip,
        }
    }

    // fn configure(
    //     meta: &mut ConstraintSystem<F>,
    //     advice: [Column<Advice>; 7],
    //     fixed: [Column<Fixed>; 1],
    //     instace: [Column<Instance>; 4],
    // ) -> PlonkConfig {
    //     let witness = advice[0];
    //     let witness_aux = advice[1];
    //     let comm_multi = advice[2];
    //     let eval_multi = advice[3];
    //     let v_sel = advice[4];
    //     let u = advice[5];
    //     let v = advice[6];

    //     let u_sel = fixed[0];

    //     let comms = instance[0];
    //     let evals = instance[1];
    //     let z = instance[2];
    //     let wi = instance[3];

    //     meta.create_gate("multiopen custom gate", |meta| {
    //         let witness = meta.query_advice(witness, Rotation::cur());
    //         let witness_prev = meta.query_advice(witness, Rotation::prev());
    //         let witness_aux = meta.query_advice(witness_aux, Rotation::cur());
    //         let witness_aux_prev = meta.query_advice(witness_aux, Rotation::prev());

    //         let comm_multi = meta.query_advice(comm_multi, Rotation::cur());
    //         let comm_multi_prev = meta.query_advice(comm_multi, Rotation::prev());
    //         let eval_multi = meta.query_advice(eval_multi, Rotation::cur());
    //         let eval_multi_prev = meta.query_advice(eval_multi, Rotation::prev());
    //         let v_sel = meta.query_advice(v_sel, Rotation::cur());

    //         // TODO: is this correct?
    //         let u = meta.query_advice(u, Rotation::cur());
    //         // TODO: is this correct?
    //         let v = meta.query_advice(u, Rotation::cur());

    //         let u_sel = meta.query_fixed(u_sel, Rotation::cur());
    //         let u_sel_prev = meta.query_fixed(u_sel, Rotation::prev());

    //         let comms = meta.query_instance(comms, Rotation::cur());
    //         let comms_prev = meta.query_instance(comms, Rotation::prev());
    //         let evals = meta.query_instance(evals, Rotation::cur());
    //         let evals_prev = meta.query_instance(evals, Rotation::prev());
    //         let z = meta.query_instance(z, Rotation::cur());
    //         let wi = meta.query_instance(wi, Rotation::cur());

    //         // 5 constraints as described previously
    //         // TODO: is this correct?
    //         vec![
    //             witness_prev * u_sel * u
    //                 + witness_prev * (F::one() - u_sel)
    //                 + z * wi * u_sel
    //                 + (witness * (-F::one())),
    //             witness_aux_prev * u_sel * u
    //                 + witness_aux_prev * (F::one() - u_sel)
    //                 + wi * u_sel
    //                 + (witness_aux * (-F::one())),
    //             comm_mul_prev * u_sel * u
    //                 + comm_mul_prev * (F::one() - u_sel)
    //                 + comms * v_sel
    //                 + (comms_mul * (-F::one())),
    //             eval_mul_prev * u_sel * u
    //                 + eval_mul_prev * (F::one() - u_sel)
    //                 + evals * v_sel
    //                 + (eval_mul * (-F::one())),
    //             v_sel + v * u_sel,
    //         ]
    //     });

    //     MultiopenConfig {
    //         witness,
    //         witness_aux,
    //         comm_multi,
    //         eval_multi,
    //         v_sel,
    //         u,
    //         v,
    //         u_sel,
    //         comms,
    //         evals,
    //         z,
    //         wi,
    //     }
    // }
}
