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

/// MultiopenConfig contains all the columns needed, along with two chips which provide ecc/scalar arithmetic
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

    // chip to do mul/add arithmetics on commitments
    ecc_chip: EccConfig,
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
    config: MultiopenConfig,
    transcript: Option<&'a mut T>,

    ecc_chip: BaseFieldEccChip<C>,
    _marker: PhantomData<E>,
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
    fn new(config: MultiopenConfig) -> Self {
        Self {
            config,
            transcript: None,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 7],
        fixed: [Column<Fixed>; 1],
        instace: [Column<Instance>; 4],
    ) -> PlonkConfig {
        let witness = advice[0];
        let witness_aux = advice[1];
        let comm_multi = advice[2];
        let eval_multi = advice[3];
        let v_sel = advice[4];
        let u = advice[5];
        let v = advice[6];

        let u_sel = fixed[0];

        let comms = instance[0];
        let evals = instance[1];
        let z = instance[2];
        let wi = instance[3];

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
                witness_prev * u_sel * u
                    + witness_prev * (F::one() - u_sel)
                    + z * wi * u_sel
                    + (witness * (-F::one())),
                witness_aux_prev * u_sel * u
                    + witness_aux_prev * (F::one() - u_sel)
                    + wi * u_sel
                    + (witness_aux * (-F::one())),
                comm_mul_prev * u_sel * u
                    + comm_mul_prev * (F::one() - u_sel)
                    + comms * v_sel
                    + (comms_mul * (-F::one())),
                eval_mul_prev * u_sel * u
                    + eval_mul_prev * (F::one() - u_sel)
                    + evals * v_sel
                    + (eval_mul * (-F::one())),
                v_sel + v * u_sel,
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

    fn synthesize(
        &self,
        config: MultiopenConfig,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let cs = MultiopenChip::new(config);

        Ok(())
    }
}
