use std::marker::PhantomData;

use halo2::{
    arithmetic::FieldExt,
    circuit::{Cell, Chip, Layouter, Region, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};
use halo2::plonk::{keygen_vk, keygen_pk, create_proof, verify_proof, VerifyingKey};
use halo2::poly::commitment::Setup;
use pairing::bn256::Bn256;
use rand::thread_rng;
use halo2::transcript::{Blake2bWrite, Challenge255, Blake2bRead, TranscriptRead, EncodedChallenge};
use halo2wrong::circuit::main_gate::{MainGateConfig, MainGate};
use halo2::arithmetic::CurveAffine;
use halo2wrong::circuit::ecc::EccConfig;
use halo2wrong::circuit::range::RangeChip;
use halo2wrong::rns::Rns;
use halo2wrong::circuit::ecc::base_field_ecc::BaseFieldEccChip;
use halo2_aggregation::VerifierChip;
use pairing::group::Curve;
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
struct SingleProofConfig {
    ecc_config: EccConfig
}

fn rns<C: CurveAffine, N: FieldExt>() -> (Rns<C::Base, N>, Rns<C::ScalarExt, N>) {
    let rns_base = Rns::<C::Base, N>::construct(BIT_LEN_LIMB);
    let rns_scalar = Rns::<C::Scalar, N>::construct(BIT_LEN_LIMB);
    (rns_base, rns_scalar)
}

fn setup<C: CurveAffine, N: FieldExt>(k_override: u32) -> (Rns<C::Base, N>, Rns<C::ScalarExt, N>, u32) {
    let (rns_base, rns_scalar) = rns::<C, N>();
    let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
    #[cfg(not(feature = "no_lookup"))]
        let mut k: u32 = (bit_len_lookup + 1) as u32;
    #[cfg(feature = "no_lookup")]
        let mut k: u32 = 8;
    if k_override != 0 {
        k = k_override;
    }
    (rns_base, rns_scalar, k)
}

impl SingleProofConfig {
    fn new<C: CurveAffine, N: FieldExt>(meta: &mut ConstraintSystem<N>) -> Self {
        let main_gate_config = MainGate::<N>::configure(meta);

        let (rns_base, rns_scalar) = rns::<C, N>();

        let mut overflow_bit_lengths: Vec<usize> = vec![];
        overflow_bit_lengths.extend(rns_base.overflow_lengths());
        overflow_bit_lengths.extend(rns_scalar.overflow_lengths());

        let range_config = RangeChip::<N>::configure(meta, &main_gate_config, overflow_bit_lengths);

        Self {
            ecc_config: EccConfig::new(main_gate_config, range_config),
        }
    }
}

#[derive(Debug, Clone)]
struct SingleProofCircuit<C: CurveAffine, N: FieldExt, E: EncodedChallenge<C>, T: TranscriptRead<C, E>> {
    log_n: usize,
    num_proofs: usize,
    vk: VerifyingKey<C>,
    rns_base: Rns<C::Base, N>,
    rns_scalar: Rns<C::ScalarExt, N>,
    transcript: T,

    instance_commitments: Vec<Option<C>>,
    instance_evals: Vec<Option<C::ScalarExt>>,
    _marker: PhantomData<E>,
}

impl<C: CurveAffine + CurveAffine<ScalarExt = N>, N: FieldExt, E: EncodedChallenge<C>, T: Clone + TranscriptRead<C, E>> Circuit<N> for SingleProofCircuit<C, N, E, T> {
    type Config = SingleProofConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            log_n: self.log_n,
            num_proofs: self.num_proofs,
            vk: self.vk.clone(),
            rns_base: self.rns_base.clone(),
            rns_scalar: self.rns_scalar.clone(),
            transcript: self.transcript.clone(),

            instance_commitments: vec![None],
            instance_evals: vec![None],
            _marker: self._marker,
        }
    }

    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
        SingleProofConfig::new::<C, N>(meta)
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
        let ecc_chip = BaseFieldEccChip::<C>::new(config.ecc_config.clone(), self.rns_base.clone())?;

        let mut transcript = self.transcript.clone();

        // TODO: transcript will be replace when it is finished
        let mut verifier_chip = VerifierChip::<C, E, T>::new(ecc_chip, Some(&mut transcript));

        layouter.assign_region(
            || "verfiy_single_0",
            |mut region| {
                let vk = &self.vk;
                let num_lookups = self.num_proofs * vk.cs.lookups.len();
                let perm_chunk_len = vk.cs.degree() - 2;
                let perm_num_columns = vk.permutation.get_perm_column_num();
                let mut input_expressions = vec![];
                let mut table_expressions = vec![];
                let mut offset = 0usize;

                for argument in vk.cs.lookups.iter() {
                    for input_expression in argument.input_expressions.iter() {
                        input_expressions.push(input_expression.clone());
                    }
                    for table_expression in argument.table_expressions.iter() {
                        table_expressions.push(table_expression.clone());
                    }
                }
                verifier_chip.verify_proof(
                    &mut region,
                    vk,
                    self.log_n,
                    vk.cs.blinding_factors(),
                    vk.cs.num_advice_columns,
                    vk.cs.num_fixed_columns,
                    num_lookups,
                    perm_num_columns,
                    perm_chunk_len,
                    input_expressions,
                    table_expressions,
                    &self.instance_commitments,
                    &self.instance_evals,
                    &mut offset,
                );
                Ok(())
            }
        )
    }
}

fn main() {
    use halo2::dev::MockProver;
    use pairing::bn256::Fr as Fp;
    use pairing::bn256::G1Affine;

    // ANCHOR: test-circuit
    // The number of rows in our circuit cannot exceed 2^k. Since our example
    // circuit is very small, we can pick a very small value here.
    let k = 4;

    // Prepare the private and public inputs to the circuit!
    let constant = Fp::from(7);
    let a = Fp::from(2);
    let b = Fp::from(3);
    let c = constant * a.square() * b.square();

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
    let mut rng = thread_rng();
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

    // If we try some other public input, the proof will fail!
    //public_inputs[0] += Fp::one();
    //let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
    //assert!(prover.verify().is_err());
    //println!("circuit satisfied!");
    // ANCHOR_END: test-circuit

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    // Create a proof
    create_proof(
        &params,
        &pk,
        &[circuit.clone()],
        &[&[&public_inputs[..]]],
        &mut transcript,
    ).expect("proof generation should not fail");
    let proof: Vec<u8> = transcript.finalize();
    println!("proof size is {:?}", proof.len());

    // assert_eq!(
    //     proof.len(),
    //     halo2::dev::CircuitCost::<G1, MyCircuit<_>>::measure(K as usize, &circuit)
    //         .proof_size(2)
    //         .into(),
    // );

    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    assert!(bool::from(
        verify_proof(
            &params_verifier,
            pk.get_vk(),
            &[&[&public_inputs[..]]],
            &mut transcript,
        ).unwrap()
    ));
    println!("circuit proof valid!");


    // Single proof circuit
    // 1. generate rns_base and rns_scalar
    let (rns_base, rns_scalar, single_proof_k) = setup::<G1Affine, Fp>(0);

    // 2. generate instance commitments
    let instance_commitment = {
        if public_inputs.len() > params_verifier.get_n() - (pk.get_vk().cs.blinding_factors() + 1) {
            panic!("Instance for single proof is too large");
        }
        params_verifier.commit_lagrange(public_inputs.clone()).to_affine()
    };

    // 3. construct the single proof circuit structure
    let single_proof_circuit = SingleProofCircuit {
        log_n: k as usize,
        num_proofs: 1,

        vk: pk.get_vk().clone(),
        rns_base,
        rns_scalar,
        transcript,

        instance_commitments: vec![Some(instance_commitment)],
        instance_evals: vec![None],

        _marker: Default::default(),
    };

    let single_empty_circuit = single_proof_circuit.without_witnesses();

    // 4. generate single proof vk and pk
    let k = 25; //TODO: this is just a tmp value
    let rng = thread_rng();
    let public_inputs_size = 1;
    let params = Setup::<Bn256>::new(k, rng);
    let params_verifier = Setup::<Bn256>::verifier_params(&params, public_inputs_size).unwrap();

    let vk = keygen_vk(&params, &single_empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &single_empty_circuit).expect("keygen_pk should not fail");

    let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    // Create a proof
    create_proof(
        &params,
        &pk,
        &[single_proof_circuit.clone()],
        &[&[&public_inputs[..]]],
        &mut transcript,
    ).expect("proof generation should not fail");
    let proof: Vec<u8> = transcript.finalize();
    println!("proof size is {:?}", proof.len());

    // assert_eq!(
    //     proof.len(),
    //     halo2::dev::CircuitCost::<G1, MyCircuit<_>>::measure(K as usize, &circuit)
    //         .proof_size(2)
    //         .into(),
    // );

    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    assert!(bool::from(
        verify_proof(
            &params_verifier,
            pk.get_vk(),
            &[&[&public_inputs[..]]],
            &mut transcript,
        ).unwrap()
    ));
    println!("circuit proof valid!");
}
