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
}

pub struct MultiopenConfig {
    witness: Column<Advice>,
    witness_aux: Column<Advice>,
    comm_multi: Column<Advice>,
    eval_multi: Column<Advice>,
    v_sel: Column<Advice>,
    u: Column<Advice>,
    v: Column<Advice>,

    u_sel: Column<Fixed>,

    comms: Column<Instance>,
    evals: Column<Instance>,
    z: Column<Instance>,
    wi: Column<Instance>,
}

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
pub struct MultiopenChip<'a, C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>> {
    integer_chip: IntegerChip<C::Base, C::ScalarExt>,
    ecc_chip: BaseFieldEccChip<C>,
    transcript: Option<&'a mut T>,
    _marker: PhantomData<E>,
}

/// To simplify MSM computation, we calculate every commitment/eval while accumulating
impl<'a, C: CurveAffine, E: EncodedChallenge<C>, T: TranscriptRead<C, E>> Circuit<C> MultiopenChip<'a, C, E> {
    type Config = MultiopenConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            transcript: None,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> PlonkConfig {
        let witness = meta.advice_column();
        let witness_aux = meta.advice_column();
        let comm_multi = meta.advice_column();
        let eval_multi = meta.advice_column();
        let v_sel = meta.advice_column();
        let u = meta.advice_column();

        let u_sel = meta.fixed_column();

        let comms = meta.instance_column();
        let evals = meta.instance_column();
        let z = meta.instance_column();
        let wi = meta.instance_column();

        meta.create_gate("multiopen custom gate", |meta| {
            let witness = meta.query_advice(witness, Rotation::cur());
            let witness_prev = meta.query_advice(witness, Rotation::prev());
            let witness_aux = meta.query_advice(witness_aux, Rotation::cur());
            let witness_aux_prev = meta.query_advice(witness_aux, Rotation::prev());

            let comm_multi = meta.query_advice(comm_multi, Rotation::cur());
            let comm_multi_prev = meta.query_advice(comm_multi, Rotation::prev());
            let eval_multi = meta.query_advice(eval_multi, Rotation::cur());
            let eval_multi_prev = meta.query_advice(eval_multi, Rotation::prev());
            let v_sel = meta.query_advice(v_sel, Rotation::cur());

            // TODO: is this correct?
            let u = meta.query_advice(u, Rotation::cur());
            // TODO: is this correct?
            let v = meta.query_advice(u, Rotation::cur());

            let u_sel = meta.query_fixed(u_sel, Rotation::cur());
            let u_sel_prev = meta.query_fixed(u_sel, Rotation::prev());

            let comms = meta.query_instance(comms, Rotation::cur());
            let comms_prev = meta.query_instance(comms, Rotation::prev());
            let evals = meta.query_instance(evals, Rotation::cur());
            let evals_prev = meta.query_instance(evals, Rotation::prev());
            let z = meta.query_instance(z, Rotation::cur());
            let wi = meta.query_instance(wi, Rotation::cur());

            // 5 constraints as described previously
            vec![
                witness_prev.clone() * u_sel.clone() * u + witness_prev.clone() * (F::one() - u_sel.clone()) + z.clone() * wi.clone() * u_sel.clone() + (witness.clone() * (-F::one())),
                witness_aux_prev.clone() * u_sel.clone() * u + witness_aux_prev.clone() * (F::one() - u_sel.clone()) + wi.clone() * u_sel.clone() + (witness_aux.clone() * (-F::one())),
                comm_mul_prev.clone() * u_sel.clone() * u + comm_mul_prev.clone() * (F::one() - u_sel.clone()) + comms.clone() * v_sel.clone() + (comms_mul.clone() * (-F::one())),
                eval_mul_prev.clone() * u_sel.clone() * u + eval_mul_prev.clone() * (F::one() - u_sel.clone()) + evals.clone() * v_sel.clone() + (eval_mul.clone() * (-F::one())),
                v_sel.clone() + v * u_sel.clone(),
            ]
        });

        MultiopenConfig {
            witness,
            witness_aux,
            comm_multi,
            eval_multi,
            v_sel,
            u,
            v,
            u_sel,
            comms,
            evals,
            z,
            wi,
        }
    }

    fn synthesize(&self, config: MultiopenConfig, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let cs = MultiopenChip::new(config);

        for _ in 0..(1 << (self.k - 1) - 3) {
            let mut a_squared = None;
            let (a0, _, c0) = cs.raw_multiply(&mut layouter, || {
                a_squared = self.a.map(|a| a.square());
                Ok((
                    self.a.ok_or(Error::Synthesis)?,
                    self.a.ok_or(Error::Synthesis)?,
                    a_squared.ok_or(Error::Synthesis)?,
                ))
            })?;
            let (a1, b1, _) = cs.raw_add(&mut layouter, || {
                let fin = a_squared.and_then(|a2| self.a.map(|a| a + a2));
                Ok((
                    self.a.ok_or(Error::Synthesis)?,
                    a_squared.ok_or(Error::Synthesis)?,
                    fin.ok_or(Error::Synthesis)?,
                ))
            })?;
            cs.copy(&mut layouter, a0, a1)?;
            cs.copy(&mut layouter, b1, c0)?;
        }

        Ok(())
    }


}
