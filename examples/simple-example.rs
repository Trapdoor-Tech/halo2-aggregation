use std::marker::PhantomData;

use halo2::arithmetic::CurveAffine;
use halo2::pairing::bn256::Bn256;
use halo2::pairing::group::Curve;
use halo2::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, VerifyingKey};
use halo2::poly::commitment::{Params, Setup};
use halo2::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, EncodedChallenge, TranscriptRead,
};
use halo2::{
    arithmetic::FieldExt,
    circuit::{Cell, Chip, Layouter, Region, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};
use halo2_aggregation::{VerifierChip, VerifierConfig};
use halo2wrong::circuit::ecc::base_field_ecc::BaseFieldEccChip;
use halo2wrong::circuit::ecc::EccConfig;
use halo2wrong::circuit::main_gate::{MainGate, MainGateConfig};
use halo2wrong::circuit::range::{RangeChip, RangeInstructions};
use halo2wrong::rns::{decompose, decompose_fe, fe_to_big, Rns};
use rand::thread_rng;
use std::io::Read;

// ANCHOR: instructions
trait NumericInstructions<F: FieldExt>: Chip<F> {
    /// Variable representing a number.
    type Num;

    /// Loads a number into the circuit as a private input.
    fn load_private(&self, layouter: impl Layouter<F>, a: Option<F>) -> Result<Self::Num, Error>;

    /// Loads a number into the circuit as a fixed constant.
    fn load_constant(&self, layouter: impl Layouter<F>, constant: F) -> Result<Self::Num, Error>;

    /// Returns `c = a * b`.
    fn mul(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error>;

    /// Exposes a number as a public input to the circuit.
    fn expose_public(
        &self,
        layouter: impl Layouter<F>,
        num: Self::Num,
        row: usize,
    ) -> Result<(), Error>;
}
// ANCHOR_END: instructions

// ANCHOR: chip
/// The chip that will implement our instructions! Chips store their own
/// config, as well as type markers if necessary.
struct FieldChip<F: FieldExt> {
    config: FieldConfig,
    _marker: PhantomData<F>,
}
// ANCHOR_END: chip

// ANCHOR: chip-config
/// Chip state is stored in a config struct. This is generated by the chip
/// during configuration, and then stored inside the chip.
#[derive(Clone, Debug)]
struct FieldConfig {
    /// For this chip, we will use two advice columns to implement our instructions.
    /// These are also the columns through which we communicate with other parts of
    /// the circuit.
    advice: [Column<Advice>; 2],

    /// This is the public input (instance) column.
    instance: Column<Instance>,

    // We need a selector to enable the multiplication gate, so that we aren't placing
    // any constraints on cells where `NumericInstructions::mul` is not being used.
    // This is important when building larger circuits, where columns are used by
    // multiple sets of instructions.
    s_mul: Selector,

    /// The fixed column used to load constants.
    constant: Column<Fixed>,
}

impl<F: FieldExt> FieldChip<F> {
    fn construct(config: <Self as Chip<F>>::Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
        instance: Column<Instance>,
        constant: Column<Fixed>,
    ) -> <Self as Chip<F>>::Config {
        meta.enable_equality(instance.into());
        meta.enable_constant(constant);
        for column in &advice {
            meta.enable_equality((*column).into());
        }
        let s_mul = meta.selector();

        // Define our multiplication gate!
        meta.create_gate("mul", |meta| {
            // To implement multiplication, we need three advice cells and a selector
            // cell. We arrange them like so:
            //
            // | a0  | a1  | s_mul |
            // |-----|-----|-------|
            // | lhs | rhs | s_mul |
            // | out |     |       |
            //
            // Gates may refer to any relative offsets we want, but each distinct
            // offset adds a cost to the proof. The most common offsets are 0 (the
            // current row), 1 (the next row), and -1 (the previous row), for which
            // `Rotation` has specific constructors.
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let s_mul = meta.query_selector(s_mul);

            // Finally, we return the polynomial expressions that constrain this gate.
            // For our multiplication gate, we only need a single polynomial constraint.
            //
            // The polynomial expressions returned from `create_gate` will be
            // constrained by the proving system to equal zero. Our expression
            // has the following properties:
            // - When s_mul = 0, any value is allowed in lhs, rhs, and out.
            // - When s_mul != 0, this constrains lhs * rhs = out.
            vec![s_mul * (lhs * rhs - out)]
        });

        FieldConfig {
            advice,
            instance,
            s_mul,
            constant,
        }
    }
}
// ANCHOR_END: chip-config

// ANCHOR: chip-impl
impl<F: FieldExt> Chip<F> for FieldChip<F> {
    type Config = FieldConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
// ANCHOR_END: chip-impl

// ANCHOR: instructions-impl
/// A variable representing a number.
#[derive(Clone)]
struct Number<F: FieldExt> {
    cell: Cell,
    value: Option<F>,
}

impl<F: FieldExt> NumericInstructions<F> for FieldChip<F> {
    type Num = Number<F>;

    fn load_private(
        &self,
        mut layouter: impl Layouter<F>,
        value: Option<F>,
    ) -> Result<Self::Num, Error> {
        let config = self.config();

        let mut num = None;
        layouter.assign_region(
            || "load private",
            |mut region| {
                let cell = region.assign_advice(
                    || "private input",
                    config.advice[0],
                    0,
                    || value.ok_or(Error::Synthesis),
                )?;
                num = Some(Number { cell, value });
                Ok(())
            },
        )?;
        Ok(num.unwrap())
    }

    fn load_constant(
        &self,
        mut layouter: impl Layouter<F>,
        constant: F,
    ) -> Result<Self::Num, Error> {
        let config = self.config();

        let mut num = None;
        layouter.assign_region(
            || "load constant",
            |mut region| {
                let cell = region.assign_advice_from_constant(
                    || "constant value",
                    config.advice[0],
                    0,
                    constant,
                )?;
                num = Some(Number {
                    cell,
                    value: Some(constant),
                });
                Ok(())
            },
        )?;
        Ok(num.unwrap())
    }

    fn mul(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error> {
        let config = self.config();

        let mut out = None;
        layouter.assign_region(
            || "mul",
            |mut region: Region<'_, F>| {
                // We only want to use a single multiplication gate in this region,
                // so we enable it at region offset 0; this means it will constrain
                // cells at offsets 0 and 1.
                config.s_mul.enable(&mut region, 0)?;

                // The inputs we've been given could be located anywhere in the circuit,
                // but we can only rely on relative offsets inside this region. So we
                // assign new cells inside the region and constrain them to have the
                // same values as the inputs.
                let lhs = region.assign_advice(
                    || "lhs",
                    config.advice[0],
                    0,
                    || a.value.ok_or(Error::Synthesis),
                )?;
                let rhs = region.assign_advice(
                    || "rhs",
                    config.advice[1],
                    0,
                    || b.value.ok_or(Error::Synthesis),
                )?;
                region.constrain_equal(a.cell, lhs)?;
                region.constrain_equal(b.cell, rhs)?;

                // Now we can assign the multiplication result into the output position.
                let value = a.value.and_then(|a| b.value.map(|b| a * b));
                let cell = region.assign_advice(
                    || "lhs * rhs",
                    config.advice[0],
                    1,
                    || value.ok_or(Error::Synthesis),
                )?;

                // Finally, we return a variable representing the output,
                // to be used in another part of the circuit.
                out = Some(Number { cell, value });
                Ok(())
            },
        )?;

        Ok(out.unwrap())
    }

    fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        num: Self::Num,
        row: usize,
    ) -> Result<(), Error> {
        let config = self.config();

        layouter.constrain_instance(num.cell, config.instance, row)
    }
}
// ANCHOR_END: instructions-impl

// ANCHOR: circuit
/// The full circuit implementation.
///
/// In this struct we store the private input variables. We use `Option<F>` because
/// they won't have any value during key generation. During proving, if any of these
/// were `None` we would get an error.
#[derive(Default, Clone)]
struct MyCircuit<F: FieldExt> {
    constant: F,
    a: Option<F>,
    b: Option<F>,
}

impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
    // Since we are using a single chip for everything, we can just reuse its config.
    type Config = FieldConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // We create the two advice columns that FieldChip uses for I/O.
        let advice = [meta.advice_column(), meta.advice_column()];

        // We also need an instance column to store public inputs.
        let instance = meta.instance_column();

        // Create a fixed column to load constants.
        let constant = meta.fixed_column();

        FieldChip::configure(meta, advice, instance, constant)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let field_chip = FieldChip::<F>::construct(config);

        // Load our private values into the circuit.
        let a = field_chip.load_private(layouter.namespace(|| "load a"), self.a)?;
        let b = field_chip.load_private(layouter.namespace(|| "load b"), self.b)?;

        // Load the constant factor into the circuit.
        let constant =
            field_chip.load_constant(layouter.namespace(|| "load constant"), self.constant)?;

        // We only have access to plain multiplication.
        // We could implement our circuit as:
        //     asq  = a*a
        //     bsq  = b*b
        //     absq = asq*bsq
        //     c    = constant*asq*bsq
        //
        // but it's more efficient to implement it as:
        //     ab   = a*b
        //     absq = ab^2
        //     c    = constant*absq
        let ab = field_chip.mul(layouter.namespace(|| "a * b"), a, b)?;
        let absq = field_chip.mul(layouter.namespace(|| "ab * ab"), ab.clone(), ab)?;
        let c = field_chip.mul(layouter.namespace(|| "constant * absq"), constant, absq)?;

        // Expose the result as a public input to the circuit.
        field_chip.expose_public(layouter.namespace(|| "expose c"), c, 0)
    }
}
// ANCHOR_END: circuit

/// The following is the single proof circuit

const BIT_LEN_LIMB: usize = 68;
const NUMBER_OF_LOOKUP_LIMBS: usize = 4;

#[derive(Clone, Debug)]
struct SingleProofConfig<C: CurveAffine> {
    verifier_config: VerifierConfig<C>,
}

// fn rns<C: CurveAffine, N: FieldExt>() -> (Rns<C::Base, N>, Rns<C::ScalarExt, N>) {
//     let rns_base = Rns::<C::Base, N>::construct(BIT_LEN_LIMB);
//     let rns_scalar = Rns::<C::Scalar, N>::construct(BIT_LEN_LIMB);
//     (rns_base, rns_scalar)
// }

fn setup<C: CurveAffine, N: FieldExt>(
    k_override: u32,
    // ) -> (Rns<C::Base, N>, Rns<C::ScalarExt, N>, u32) {
) -> u32 {
    // let (rns_base, rns_scalar) = rns::<C, N>();
    let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
    #[cfg(not(feature = "no_lookup"))]
    let mut k: u32 = (bit_len_lookup + 1) as u32;
    #[cfg(feature = "no_lookup")]
    let mut k: u32 = 8;
    if k_override != 0 {
        k = k_override;
    }
    // (rns_base, rns_scalar, k)
    k
}

// impl SingleProofConfig {
// fn new<C: CurveAffine, N: FieldExt>(meta: &mut ConstraintSystem<N>) -> Self {
//     let main_gate_config = MainGate::<N>::configure(meta);
//
//     let (rns_base, rns_scalar) = rns::<C, N>();
//
//     let mut overflow_bit_lengths: Vec<usize> = vec![];
//     overflow_bit_lengths.extend(rns_base.overflow_lengths());
//     overflow_bit_lengths.extend(rns_scalar.overflow_lengths());
//
//     let range_config = RangeChip::<N>::configure(meta, &main_gate_config, overflow_bit_lengths);
//
//     Self {
//         ecc_config: EccConfig::new(main_gate_config, range_config),
//     }
// }
// }

#[derive(Clone, Debug)]
struct SingleProofCircuit<
    'a,
    C: CurveAffine,
    E: EncodedChallenge<C>,
    T: TranscriptRead<C, E> + Clone,
> {
    log_n: usize,
    num_proofs: usize,
    vk: &'a VerifyingKey<C>,
    // rns_base: Rns<C::Base, N>,
    // rns_scalar: Rns<C::ScalarExt, N>,
    transcript: Option<T>,

    num_instance_commitments: usize,
    _marker: PhantomData<E>,
}

impl<'a, C: CurveAffine, E: EncodedChallenge<C>, T: 'a + Clone + TranscriptRead<C, E>>
    Circuit<C::ScalarExt> for SingleProofCircuit<'a, C, E, T>
{
    type Config = SingleProofConfig<C>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            log_n: self.log_n,
            num_proofs: self.num_proofs,
            num_instance_commitments: self.num_instance_commitments,
            vk: self.vk.clone(),
            // rns_base: self.rns_base.clone(),
            // rns_scalar: self.rns_scalar.clone(),
            // transcript: self.transcript.clone(),
            transcript: None,

            _marker: self._marker,
        }
    }

    fn configure(meta: &mut ConstraintSystem<C::ScalarExt>) -> Self::Config {
        let instance_column = meta.instance_column();
        meta.enable_equality(instance_column.into());

        let verifier_config =
            VerifierChip::<'a, C, E, T>::configure(meta, instance_column, BIT_LEN_LIMB);

        Self::Config { verifier_config }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<C::ScalarExt>,
    ) -> Result<(), Error> {
        let mut transcript = self.transcript.clone();

        // TODO: transcript will be replace when it is finished
        let mut verifier_chip =
            VerifierChip::<C, E, T>::new(config.verifier_config.clone(), transcript.as_mut());

        verifier_chip.ecc_chip.integer_chip().range_chip().load_limb_range_table(&mut layouter)?;
        verifier_chip.ecc_chip.integer_chip().range_chip().load_overflow_range_tables(&mut layouter)?;

        let verifier_config = config.verifier_config.clone();
        layouter.assign_region(
            || "verfiy_single_0",
            |mut region| {
                println!("verify_single_0");
                let mut transcript = self.transcript.clone();

                // TODO: transcript will be replace when it is finished
                let mut verifier_chip =
                    VerifierChip::<C, E, T>::new(verifier_config.clone(), transcript.as_mut());
                let vk = &self.vk;

                verifier_chip.verify_proof(
                    &mut region,
                    vk,
                    self.log_n,
                )?;
                Ok(())
            },
        )

    }
}

fn integer_to_scalars<C: CurveAffine>(b: C::Base) -> Vec<C::ScalarExt> {
    decompose::<C::ScalarExt>(fe_to_big(b), 4, BIT_LEN_LIMB)
}
fn point_to_scalars<C: CurveAffine>(p: &C) -> Vec<C::ScalarExt> {
    let p = p.coordinates().unwrap();
    let mut ret = vec![];
    let px = p.x().clone();
    let py = p.y().clone();

    ret.extend(&integer_to_scalars::<C>(px));
    ret.extend(&integer_to_scalars::<C>(py));

    ret
}

fn main() {
    use halo2::dev::MockProver;
    use halo2::pairing::bn256::Fr as Fp;
    use halo2::pairing::bn256::G1Affine;
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;

    // ANCHOR: test-circuit
    // The number of rows in our circuit cannot exceed 2^k. Since our example
    // circuit is very small, we can pick a very small value here.
    let (sample_log_n, sample_pk, sample_proof, sample_instance_commitment, sample_quad) = {
        let k = 4;

        // Prepare the private and public inputs to the circuit!
        let constant = Fp::from(7);
        let a = Fp::from(2);
        let b = Fp::from(3);
        let c = constant * a.square() * b.square();

        // used for keygen
        let empty_circuit = MyCircuit {
            constant,
            a: None,
            b: None,
        };

        // Instantiate the circuit with the private inputs.
        let circuit = MyCircuit {
            constant,
            a: Some(a),
            b: Some(b),
        };

        // Initialize the polynomial commitment parameters
        let rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let public_inputs_size = 1;
        let params = Setup::<Bn256>::new(k, rng);
        let params_verifier = Setup::<Bn256>::verifier_params(&params, public_inputs_size).unwrap();

        // Initialize the proving key
        let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

        // Arrange the public input. We expose the multiplication result in row 0
        // of the instance column, so we position it there in our public inputs.
        let mut public_inputs = vec![c];

        // Given the correct public input, our circuit will verify.
        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        // Create a proof
        create_proof(
            &params,
            &pk,
            &[circuit.clone()],
            &[&[&public_inputs[..]]],
            &mut transcript,
        )
        .expect("proof generation should not fail");

        let proof: Vec<u8> = transcript.finalize();
        println!("proof size is {:?}", proof.len());

        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

        let (choice, efw) = verify_proof(
            &params_verifier,
            pk.get_vk(),
            &[&[&public_inputs[..]]],
            &mut transcript,
        )
        .unwrap();

        assert!(bool::from(choice));

        println!("simple-circuit proof valid!");

        let instance_commitment = {
            if public_inputs.len()
                > params_verifier.get_n() - (pk.get_vk().cs().blinding_factors() + 1)
            {
                panic!("Instance for single proof is too large");
            }
            params_verifier
                .commit_lagrange(public_inputs.clone())
                .to_affine()
        };

        (k, pk, proof, instance_commitment, efw)
    };
    let sample_vk = sample_pk.get_vk();

    // construct the single proof circuit structure
    let sample_transcript = Some(Blake2bRead::<_, _, Challenge255<_>>::init(
        &sample_proof[..],
    ));
    let single_proof_circuit = SingleProofCircuit {
        log_n: sample_log_n as usize,
        num_proofs: 1,
        num_instance_commitments: 1,
        vk: sample_vk,
        transcript: sample_transcript,
        _marker: Default::default(),
    };

    let single_empty_circuit = single_proof_circuit.without_witnesses();

    // 4. generate single proof vk and pk
    let k = 23; //TODO: this is just a tmp value
    let rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let mut public_inputs = point_to_scalars(&sample_instance_commitment);
    for p in sample_quad {
        public_inputs.extend(&point_to_scalars(&p));
    }
    let public_inputs_size = public_inputs.len();

    let prover = MockProver::run(k, &single_proof_circuit, vec![public_inputs.clone()]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
    println!("mock prover succeed!");

    println!("setup parameters");
    let params_filename = format!("/tmp/halo2-{}.params", k);
    let params_path = std::path::Path::new(&params_filename);
    let params = if params_path.exists() {
        println!("read halo2-{}.params from file", k);
        let file = std::fs::File::open(params_path).unwrap();
        Params::read(file).unwrap()
    } else {
        println!("create a new setup file");
        let params = Setup::<Bn256>::new(k, rng);
        let mut file = std::fs::File::create(params_path).unwrap();
        params.write(&mut file).unwrap();
        params
    };

    let params_verifier = Setup::<Bn256>::verifier_params(&params, public_inputs_size).unwrap();

    println!("ready to keygen");
    let vk = keygen_vk(&params, &single_empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &single_empty_circuit).expect("keygen_pk should not fail");

    println!("keygen finished");
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    // Create a proof
    create_proof(
        &params,
        &pk,
        &[single_proof_circuit.clone()],
        &[&[&public_inputs]],
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof: Vec<u8> = transcript.finalize();
    println!("proof size is {:?}", proof.len());

    // assert_eq!(
    //     proof.len(),
    //     halo2::dev::CircuitCost::<G1, MyCircuit<_>>::measure(K as usize, &circuit)
    //         .proof_size(2)
    //         .into(),
    // );

    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    let (choice, _) = verify_proof(
        &params_verifier,
        pk.get_vk(),
        &[&[&public_inputs]],
        &mut transcript,
    )
    .unwrap();
    assert!(bool::from(choice));
    println!("circuit proof valid!");
}
