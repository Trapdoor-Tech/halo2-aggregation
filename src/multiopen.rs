use crate::{ChallengeU, ChallengeV, ChallengeX};
use halo2::arithmetic::{CurveAffine, Field, FieldExt};
use halo2::circuit::{Chip, Region};
use halo2::plonk::Advice;
use halo2::plonk::Error::TranscriptError;
use halo2::plonk::{Column, ConstraintSystem, Error, TableColumn};
use halo2::poly::Rotation;
use halo2::circuit::Layouter;
use halo2::transcript::{EncodedChallenge, TranscriptRead};
use halo2wrong::circuit::ecc::base_field_ecc::{BaseFieldEccChip, BaseFieldEccInstruction};
use halo2wrong::circuit::ecc::AssignedPoint;
use halo2wrong::circuit::ecc::EccConfig;
use halo2wrong::circuit::main_gate::{MainGateColumn, MainGateInstructions};
use halo2wrong::circuit::{Assigned, AssignedValue, UnassignedValue};
use halo2wrong::rns::Rns;
use std::collections::BTreeMap;
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct VerifierQuery<C: CurveAffine> {
    commitment: AssignedPoint<C::ScalarExt>,
    rotation: Rotation,
    eval: AssignedValue<C::ScalarExt>,
}

trait Query<F>: Sized + Copy {
    type Commitment: PartialEq + Copy;
    type Scalar: Clone + Default + Ord + Copy;

    fn get_rotation(&self) -> Rotation;
    fn get_eval(&self) -> Self::Scalar;
    fn get_comm(&self) -> Self::Commitment;
}

impl<C: CurveAffine> Query<C::ScalarExt> for VerifierQuery<C> {
    type Commitment = AssignedPoint<C::ScalarExt>;
    type Scalar = AssignedValue<C::ScalarExt>;

    fn get_rotation(&self) -> Rotation {
        self.rotation
    }

    fn get_comm(&self) -> AssignedPoint<C::ScalarExt> {
        self.commitment
    }

    fn get_eval(&self) -> AssignedValue<C::ScalarExt> {
        self.eval
    }
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
    rot: Column<Advice>,
    omega_evals: Column<Advice>,

    t_rot: TableColumn,
    t_omega_evals: TableColumn,
}

/// Instructions should be able to compute and fill in witnesses
/// in order to do linear combination of commitments, we use `BaseFieldEccInstruction` from `halo2wrong`
pub trait MultiopenInstructions<C: CurveAffine> {
    type Comm;
    type Eval;

    fn read_comm(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<Self::Comm, Error>;

    fn read_eval(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<Self::Eval, Error>;

    fn lookup_table_pows(
        &self,
        layouter: &mut impl Layouter<C::ScalarExt>,
        omega_evals: &[(Rotation, Self::Eval)],
        offset: &mut usize,
    ) -> Result<Self::Eval, Error>;

    fn construct_intermediate_sets<I, Q: Query<C::ScalarExt>>(
        queries: I,
    ) -> Vec<VerifierQueriesByRotation<C>>
    where
        I: IntoIterator<Item = Q> + Clone;

    fn calc_witness(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        queries: &[VerifierQuery<C>],
        omega: &C::ScalarExt,
        omega_inv: &C::ScalarExt,
        x: ChallengeX<C>,
        u: ChallengeU<C>,
        v: ChallengeV<C>,
        offset: &mut usize,
    ) -> Result<Self::Comm, Error>;
}

pub struct MultiopenChip<'a, C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>> {
    config: MultiopenConfig,
    transcript: Option<&'a mut T>,

    // chip to do mul/add arithmetics on commitments/evals
    base_ecc_config: EccConfig,
    rns: Rns<C::Base, C::ScalarExt>,
    _marker: PhantomData<E>,
}

impl<'a, C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>> MultiopenInstructions<C>
    for MultiopenChip<'a, C, E, T>
{
    type Comm = AssignedPoint<C::ScalarExt>;
    type Eval = AssignedValue<C::ScalarExt>;

    fn read_comm(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<Self::Comm, Error> {
        let point = match self.transcript.as_mut() {
            None => return TranscriptError,
            Some(t) => t.read_point().map_err(|_| TranscriptError)?,
        };

        let ecc_chip = self.base_ecc_chip()?;

        ecc_chip.assign_point(region, point, offset)?;

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

        let ecc_chip = self.base_ecc_chip()?;

        ecc_chip
            .main_gate()
            .assign_value(region, eval, MainGateColumn::A, offset)?;

        Ok(eval)
    }

    /// use two lookup tabels for calculating `omega ^ rotation`
    /// these two tables are loaded from circuit
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

    fn construct_intermediate_sets<I, Q: Query<C::ScalarExt>>(
        queries: I,
    ) -> Vec<VerifierQueriesByRotation<C>>
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
    fn calc_witness(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        queries: &[VerifierQuery<C>],
        omega: &C::ScalarExt,
        omega_inv: &C::ScalarExt,
        x: ChallengeX<C>,
        u: ChallengeU<C>,
        v: ChallengeV<C>,
        offset: &mut usize,
    ) -> Result<Self::Comm, Error> {
        let ecc_chip = self.base_ecc_chip();

        let mut rot_offset = 0;
        let mut omega_eval_offset = 0;

        // rearrange the verifier queries
        let queries_by_rotation = self.construct_intermediate_sets(queries);

        let one = Some(C::ScalarExt::one());
        let one = ecc_chip.main_gate.assign_constant(region, &one.into(), MainGateColumn::A, offset)?;

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
                UnassignedValue::new(Some(C::ScalarExt::one()))
            } else {
                UnassignedValue::new(Some(C::ScalarExt::zero()))
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
}

impl<'a, C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>> Chip<C::ScalarExt>
    for MultiopenChip<'a, C, E, T>
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
impl<'a, C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>> MultiopenChip<'a, C, E, T> {
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

    fn base_ecc_chip(&self) -> Result<BaseFieldEccChip<C>, Error> {
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
        }
    }
}
