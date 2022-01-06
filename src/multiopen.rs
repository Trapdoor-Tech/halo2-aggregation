use crate::{ChallengeU, ChallengeV, ChallengeX};
use halo2::arithmetic::{CurveAffine, Field, FieldExt};
use halo2::circuit::Layouter;
use halo2::circuit::{Chip, Region};
use halo2::plonk::Advice;
use halo2::plonk::{Column, ConstraintSystem, Error, TableColumn};
use halo2::poly::Rotation;
use halo2::transcript::{EncodedChallenge, TranscriptRead};
use halo2wrong::circuit::ecc::base_field_ecc::{BaseFieldEccChip, BaseFieldEccInstruction};
use halo2wrong::circuit::ecc::AssignedPoint;
use halo2wrong::circuit::ecc::EccConfig;
use halo2wrong::circuit::main_gate::{MainGateColumn, MainGateInstructions};
use halo2wrong::circuit::{Assigned, AssignedValue, UnassignedValue};
use halo2wrong::rns::Rns;
use std::collections::BTreeMap;
use std::marker::PhantomData;

pub fn construct_intermediate_sets<C: CurveAffine, Q>(
    queries: &[Q],
) -> Vec<VerifierQueriesByRotation<C, Q>>
where
    Q: Query<C::ScalarExt>,
{
    let mut point_query_map: BTreeMap<Rotation, Vec<Q>> = BTreeMap::new();
    for query in queries.iter() {
        if let Some(queries) = point_query_map.get_mut(&query.get_rotation()) {
            queries.push(query.clone());
        } else {
            point_query_map.insert(query.get_rotation(), vec![query.clone()]);
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

#[derive(Debug, Clone)]
pub struct MultiopenVar<C: CurveAffine> {
    witness: AssignedPoint<C::ScalarExt>,
    witness_with_aux: AssignedPoint<C::ScalarExt>,
    commitment_multi: AssignedPoint<C::ScalarExt>,
    eval_multi: AssignedValue<C::ScalarExt>,
}

#[derive(Debug, Clone)]
pub struct VerifierQuery<C: CurveAffine> {
    commitment: AssignedPoint<C::ScalarExt>,
    eval: AssignedValue<C::ScalarExt>,
    rotation: Rotation,
}

pub trait Query<F>: Sized + Clone {
    type Commitment: Clone;
    type Scalar: Clone;

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
        self.commitment.clone()
    }

    fn get_eval(&self) -> AssignedValue<C::ScalarExt> {
        self.eval.clone()
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

pub struct VerifierQueriesByRotation<C: CurveAffine, Q: Query<C::ScalarExt>> {
    queries: Vec<Q>,
    rotation: Rotation,
    _marker: PhantomData<C>,
}

impl<C: CurveAffine, Q: Query<C::ScalarExt>> VerifierQueriesByRotation<C, Q> {
    pub fn get_rotation(&self) -> Rotation {
        self.rotation
    }
}

// /// MultiopenConfig contains all the columns needed, along with two chips which provide ecc/scalar arithmetic
// /// This Multiopen chip use the following column layout
// ///
// /// | witness | witness_aux | comm_multi | eval_multi | u | u_sel | v_sel | comms | evals | z   | wi   |
// /// | ---     | ---         | ---        | ---        | - | ---   | ---   | ---   | ---   | -   | --   |
// /// | wit_0   | wit_aux_0   | comm_mul_0 | eval_mul_0 | u | 1     | v     | c_1_0 | e_1_0 | z_1 | wi_1 |   // for point set 1
// /// | wit_1   | wit_aux_1   | comm_mul_1 | eval_mul_1 | u | 0     | v^2   | c_1_1 | e_1_1 | z_1 | wi_1 |
// /// | wit_2   | wit_aux_2   | comm_mul_2 | eval_mul_2 | u | 0     | v^3   | c_1_2 | e_1_2 | z_1 | wi_1 |
// /// | wit_3   | wit_aux_3   | comm_mul_3 | eval_mul_3 | u | 1     | v     | c_2_0 | e_2_0 | z_2 | wi_2 |   // for point set 2
// /// | wit_4   | wit_aux_4   | comm_mul_4 | eval_mul_4 | u | 1     | v     | c_3_0 | e_3_0 | z_3 | wi_3 |   // for point set 3
// /// | wit_5   | wit_aux_5   | comm_mul_5 | eval_mul_5 | u | 0     | v^2   | c_3_1 | e_3_1 | z_1 | wi_1 |
// ///
// /// Constraints (advice columns):
// /// witness_i           = witness_{i-1} * u_sel_i * u           + witness_{i-1} * (1 - u_sel_i)         + z_i * wi_i * u_sel_i
// /// witness_aux_i       = witness_aux_{i-1} * u_sel_i * u       + witness_aux_{i-1} * (1 - u_sel_i)     + wi_i * u_sel_i
// /// comm_mul_i          = comm_mul_{i-1} * u_sel_i * u          + comm_mul_{i-1} * (1 - u_sel_i)        + comms_i * v_sel_i
// /// eval_mul_i          = eval_mul_{i-1} * u_sel_i * u          + eval_mul_{i-1} * (1 - u_sel_i)        + eval_i * v_sel_i
// /// v_sel_i             = v * u_sel_i                           + v_sel_{i-1} * (1 - u_sel_i) * v
// ///
// /// TODO: u_i                 = u
// ///
// /// u_sel is a fixed column
// ///
// /// TODO: comms, evals, z, wi are instance columns ??? (or read from transcript?)
// /// TODO: did not constrain u/v from transcript

/// MultiopenChip need to compute linear combinations of commitments/evaluations at different rotations
/// the `x * omega/omega_inv ^ rotation` must be computed as the challenge point
/// in order to do this, we utilize two lookup tables, one for rotation, one for omega/omega_inv at the rotation
/// then we constrain the calculated rot/omega_evals, as two advice columns, should exist in the lookup tables
#[derive(Debug, Clone)]
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
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<Self::Comm, Error>;

    fn lookup_table_pows(
        &self,
        layouter: &mut impl Layouter<C::ScalarExt>,
        omega_evals: &[(Rotation, C::ScalarExt)],
    ) -> Result<(), Error>;

    fn calc_witness(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        queries: &[VerifierQuery<C>],
        omega: &C::ScalarExt,
        omega_inv: &C::ScalarExt,
        x: ChallengeX<C>,
        u: ChallengeU<C>,
        v: ChallengeV<C>,
        offset: &mut usize,
    ) -> Result<MultiopenVar<C>, Error>;
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
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<Self::Comm, Error> {
        let point = match self.transcript.as_mut() {
            None => return Err(Error::TranscriptError),
            Some(t) => t.read_point().map_err(|_| Error::TranscriptError)?,
        };

        let ecc_chip = self.base_ecc_chip()?;

        let p = ecc_chip.assign_point(region, Some(point), offset)?;

        Ok(p)
    }

    /// use two lookup tabels for calculating `omega ^ rotation`
    /// these two tables should be initialized before calling `calc_witness()`
    fn lookup_table_pows(
        &self,
        layouter: &mut impl Layouter<C::ScalarExt>,
        omega_evals: &[(Rotation, C::ScalarExt)],
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "Rotation table",
            |mut table| {
                for (index, &value) in omega_evals.iter().enumerate() {
                    let (r, _) = value;

                    let rot = if r.0 >= 0 {
                        let r = r.0 as u64;
                        C::ScalarExt::from_u64(r)
                    } else {
                        let r_inv = -r.0 as u64;
                        -C::ScalarExt::from_u64(r_inv)
                    };

                    table.assign_cell(|| "table col", self.config.t_rot, index, || Ok(rot))?;
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
                        self.config.t_omega_evals,
                        index,
                        || Ok(eval),
                    )?;
                }
                Ok(())
            },
        )?;

        Ok(())
    }

    /// witness_i = witness_{i-1} * u_sel_i * u + witness_{i-1} * (1 - u_sel_i) + z_i * wi_i * u_sel_i
    /// witness_aux_i = witness_aux_{i-1} * u_sel_i * u + witness_aux_{i-1} * (1 - u_sel_i) + wi_i * u_sel_i
    /// comm_mul_i = comm_mul_{i-1} * u_sel_i * u + comm_mul_{i-1} * (1 - u_sel_i) + comms_i * v_sel_i
    /// eval_mul_i = eval_mul_{i-1} * u_sel_i * u + eval_mul_{i-1} * (1 - u_sel_i) + eval_i * v_sel_i
    fn calc_witness(
        &mut self,
        region: &mut Region<'_, C::ScalarExt>,
        queries: &[VerifierQuery<C>],
        omega: &C::ScalarExt,
        omega_inv: &C::ScalarExt,
        x: ChallengeX<C>,
        u: ChallengeU<C>,
        v: ChallengeV<C>,
        offset: &mut usize,
    ) -> Result<MultiopenVar<C>, Error> {
        let ecc_chip = self.base_ecc_chip()?;

        let rot_offset = 0;
        let omega_eval_offset = 0;

        // rearrange the verifier queries
        let queries_by_rotation = construct_intermediate_sets::<C, _>(queries);

        let one = Some(C::ScalarExt::one());
        let one =
            ecc_chip
                .main_gate()
                .assign_constant(region, &one.into(), MainGateColumn::A, offset)?;

        let circuit_omega = ecc_chip.main_gate().assign_constant(
            region,
            &Some(*omega).into(),
            MainGateColumn::A,
            offset,
        )?;

        let circuit_omega_inv = ecc_chip.main_gate().assign_constant(
            region,
            &Some(*omega_inv).into(),
            MainGateColumn::A,
            offset,
        )?;

        let omega_x_omega_inv = ecc_chip.main_gate().mul(
            region,
            circuit_omega.clone(),
            circuit_omega_inv.clone(),
            offset,
        )?;

        // make sure that omega * omega_inv is 1
        ecc_chip
            .main_gate()
            .assert_equal(region, one, omega_x_omega_inv, offset)?;

        let mut witness = ecc_chip.assign_point(region, Some(C::identity()), offset)?;
        let mut witness_with_aux = ecc_chip.assign_point(region, Some(C::identity()), offset)?;
        let mut commitment_multi = ecc_chip.assign_point(region, Some(C::identity()), offset)?;
        let mut eval_multi = ecc_chip.main_gate().assign_value(
            region,
            &Some(C::ScalarExt::zero()).into(),
            MainGateColumn::A,
            offset,
        )?;

        let circuit_x = x.value().clone();
        let circuit_u = u.value().clone();
        let circuit_v = v.value().clone();

        for queries_at_a_rotation in queries_by_rotation.iter() {
            let r = queries_at_a_rotation.get_rotation();

            // omega_eval = omega ^ |r| or omega_inv ^ |r|, depends on rotation
            let (rot, omega_eval) = if r.0 >= 0 {
                (
                    C::ScalarExt::from_u64(r.0 as u64),
                    omega.pow(&[r.0 as u64, 0, 0, 0]),
                )
            } else {
                let r_abs = -r.0 as u64;
                (
                    -C::ScalarExt::from_u64(r_abs),
                    omega_inv.pow(&[r_abs, 0, 0, 0]),
                )
            };

            region.assign_advice(|| "rotation", self.config.rot, rot_offset, || Ok(rot))?;
            region.assign_advice(
                || "omega eval",
                self.config.omega_evals,
                omega_eval_offset,
                || Ok(omega_eval),
            )?;

            let r = ecc_chip.main_gate().assign_value(
                region,
                &Some(rot).into(),
                MainGateColumn::A,
                offset,
            )?;

            // we should calculate omega_eval ^ rot
            let pow_real_omega = ecc_chip.main_gate().assign_value(
                region,
                &Some(omega_eval).into(),
                MainGateColumn::A,
                offset,
            )?;

            // the challenge point `z`: x * real_omega ^ rot
            let z = ecc_chip.main_gate().mul(
                region,
                pow_real_omega.clone(),
                circuit_x.clone(),
                offset,
            )?;

            let wi = self.read_comm(region, offset)?;

            let z_wi = ecc_chip.mul_var(region, wi.clone(), z.clone(), offset)?;

            witness = ecc_chip.mul_var(region, witness, circuit_u.clone(), offset)?;
            witness = ecc_chip.add(region, &witness, &wi, offset)?;

            witness_with_aux =
                ecc_chip.mul_var(region, witness_with_aux.clone(), circuit_u.clone(), offset)?;
            witness_with_aux = ecc_chip.add(region, &witness_with_aux, &z_wi, offset)?;

            commitment_multi =
                ecc_chip.mul_var(region, commitment_multi.clone(), circuit_u.clone(), offset)?;
            eval_multi =
                ecc_chip
                    .main_gate()
                    .mul(region, eval_multi.clone(), circuit_u.clone(), offset)?;

            let mut commitment_batch =
                ecc_chip.assign_point(region, Some(C::identity()), offset)?;
            let mut eval_batch = ecc_chip.main_gate().assign_value(
                region,
                &Some(C::ScalarExt::zero()).into(),
                MainGateColumn::A,
                offset,
            )?;

            for query in queries_at_a_rotation.queries.iter() {
                let query_rot = query.get_rotation().0;
                let query_rot = if query_rot >= 0 {
                    C::ScalarExt::from_u64(query_rot as u64)
                } else {
                    let query_rot_inv = -query_rot as u64;
                    -C::ScalarExt::from_u64(query_rot_inv)
                };

                let query_rot = ecc_chip.main_gate().assign_value(
                    region,
                    &Some(query_rot).into(),
                    MainGateColumn::A,
                    offset,
                )?;

                // make sure the rotation are the same
                ecc_chip
                    .main_gate()
                    .assert_equal(region, r.clone(), query_rot, offset)?;

                commitment_batch = ecc_chip.mul_var(
                    region,
                    commitment_batch.clone(),
                    circuit_v.clone(),
                    offset,
                )?;

                eval_batch = ecc_chip.main_gate().mul(
                    region,
                    eval_batch.clone(),
                    circuit_v.clone(),
                    offset,
                )?;

                let comm = query.get_comm();
                let eval = query.get_eval();

                commitment_batch = ecc_chip.add(region, &commitment_batch, &comm, offset)?;
                eval_batch = ecc_chip.main_gate().add(region, eval_batch, eval, offset)?;
            }

            commitment_multi =
                ecc_chip.add(region, &commitment_multi, &commitment_batch, offset)?;
            eval_multi = ecc_chip
                .main_gate()
                .add(region, eval_multi, eval_batch, offset)?;
        }

        let result = MultiopenVar {
            witness,
            witness_with_aux,
            commitment_multi,
            eval_multi,
        };

        Ok(result)
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
impl<'a, C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>>
    MultiopenChip<'a, C, E, T>
{
    fn new(
        config: MultiopenConfig,
        base_ecc_config: EccConfig,
        rns: Rns<C::Base, C::ScalarExt>,
    ) -> Self {
        Self {
            config,
            transcript: None,
            base_ecc_config,
            rns,
            _marker: PhantomData,
        }
    }

    fn base_ecc_chip(&self) -> Result<BaseFieldEccChip<C>, Error> {
        let base_ecc_config = self.base_ecc_config.clone();
        let rns = self.rns.clone();
        BaseFieldEccChip::<C>::new(base_ecc_config, rns)
    }

    fn configure(meta: &mut ConstraintSystem<C::ScalarExt>) -> MultiopenConfig {
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
