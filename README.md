# smp-zk-proofs

`smp-zk-proofs` is a Rust library for verifiable aggregation proofs in distributed spatial networks using zk-SNARKs. It provides Groth16 proofs over the BLS12-381 curve, with support for location proofs and training verification, plus post-quantum compatibility layers.

## What is being proven?

The library implements two proving statements:

- **Location proof**: a node knows secret coordinates `(x, y)` whose commitment lies inside a public bounding box.
- **Training proof**: a node knows a committed local weight update whose step count matches a public training schedule and whose observed loss stays below a public threshold.

## Backend: Groth16 with BLS12-381

This library uses **arkworks** with **Groth16** zk-SNARKs over the **BLS12-381** pairing-friendly curve. The implementation includes:

- Circuit-specific trusted setup for each circuit type
- R1CS constraint generation for range and equality checks
- Proof generation with cryptographic randomness
- Efficient verification using preprocessed verifying keys

## Repository layout

```text
smp-zk-proofs/
├── benches/
│   └── proof_benchmarks.rs
├── examples/
│   ├── simple_location_proof.rs
│   └── weight_aggregation_proof.rs
├── src/
│   ├── constraints/
│   │   ├── location_circuit.rs
│   │   ├── mod.rs
│   │   └── training_circuit.rs
│   ├── pq_compatibility/
│   │   └── mod.rs
│   ├── proofs/
│   │   ├── generator.rs
│   │   ├── mod.rs
│   │   ├── types.rs
│   │   └── verifier.rs
│   ├── error.rs
│   ├── lib.rs
│   └── utils/
│       └── mod.rs
├── tests/
│   └── end_to_end.rs
└── Cargo.toml
```

## Public inputs and proof objects

### Location proof inputs

- `BoundingBox { x_min, x_max, y_min, y_max }`
- `LocationPublicInputs { bounding_box, coordinate_commitment }`
- `LocationPrivateWitness { x, y, blinding }`

### Training proof inputs

- `TrainingPublicInputs { expected_steps, max_loss_milli, base_model_digest, update_commitment }`
- `TrainingPrivateWitness { steps_completed, observed_loss_milli, weight_update_digest, blinding }`

### Proof object

```rust
pub struct Proof {
    pub circuit: CircuitKind,
    pub scheme: ProofScheme,  // Groth16Bls12_381
    pub statement_digest: [u8; 32],
    pub constraint_digest: [u8; 32],
    pub zk_snark_proof: Option<ZkSnarkProof>,  // Groth16 (a, b, c) elements
}
```

### Verification Key

```rust
pub struct ZkSnarkVerifyingKey {
    pub alpha_g1: Vec<u8>,
    pub beta_g2: Vec<u8>,
    pub gamma_g2: Vec<u8>,
    pub delta_g2: Vec<u8>,
    pub gamma_abc_g1: Vec<u8>,
}
```

Proofs, verification keys, and public inputs support deterministic `bincode` serialization through `to_bytes()` and `from_bytes()` helpers.

## Computational complexity

For the Groth16 backend:

- **Setup**: O(n) where n is the number of constraints (one-time per circuit)
- **Prove**: O(n) multi-scalar multiplications in G1/G2
- **Verify**: O(1) pairing operations (typically ~3ms on modern hardware)

The benchmark harness in `benches/proof_benchmarks.rs` tracks latency and memory usage.

## Usage

```rust
use smp_zk_proofs::{
    BoundingBox, LocationPrivateWitness, LocationPublicInputs, 
    ProvingContext, prove_location, verify_location_proof,
};

// Setup the proving context (generates proving/verifying keys)
let context = ProvingContext::setup()?;

// Create witness and public inputs
let witness = LocationPrivateWitness {
    x: 41,
    y: 12,
    blinding: [3_u8; 32],
};
let public_inputs = LocationPublicInputs::from_witness(
    BoundingBox {
        x_min: 0,
        x_max: 100,
        y_min: 0,
        y_max: 50,
    },
    &witness,
)?;

// Generate proof
let proof = prove_location(&context, &public_inputs, &witness)?;

// Verify proof
if let Some(vk) = context.location_verification_key() {
    verify_location_proof(&vk, &public_inputs, &proof)?;
}
```

## Examples

Run the examples with Cargo:

```bash
cargo run --example simple_location_proof
cargo run --example weight_aggregation_proof
```

## Post-quantum compatibility

The `pq_compatibility` module provides:

- **DilithiumBackend**: Integration point for Dilithium lattice-based signatures (NIST PQC standard)
- **PQSecureAggregator**: Hash-based commitment schemes for aggregating multiple proofs
- **DilithiumVerificationGadget**: Framework for verifying PQ signatures within zk-SNARK circuits

These components enable hybrid classical/post-quantum security for long-term proof validity.

## Security considerations

- Trusted setup is circuit-specific; reuse parameters only for identical circuits
- Blinding factors must be cryptographically random (32 bytes from CSPRNG)
- For production use, consider multi-party computation (MPC) for trusted setup
- PQ signatures provide additional security against quantum adversaries
