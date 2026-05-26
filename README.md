# smp-zk-proofs

`smp-zk-proofs` is a Rust library scaffold for verifiable aggregation ledgers in distributed spatial networks. It provides a clean crate layout, deterministic proof-generation and verification flows, serialization helpers, runnable examples, and benchmark hooks so the repository can evolve toward Halo2/arkworks-backed zero-knowledge proofs without changing its public module boundaries.

## What is being proven?

The repository currently models two proving statements:

- **Location proof**: a node knows secret coordinates `(x, y)` whose commitment lies inside a public bounding box.
- **Training proof**: a node knows a committed local weight update whose step count matches a public training schedule and whose observed loss stays below a public threshold.

The current backend is a **development signed-transcript backend**. It validates circuit constraints locally, commits to the public statement, and signs the resulting transcript for downstream verification. This keeps the code paths, serialization, and examples stable while a full Halo2/arkworks proving backend is integrated.

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

```text
pub struct Proof {
    pub circuit: CircuitKind,
    pub scheme: ProofScheme,
    pub statement_digest: [u8; 32],
    pub constraint_digest: [u8; 32],
    pub signature: Vec<u8>,
}
```

Proofs, verification keys, and public inputs support deterministic `bincode` serialization through `to_bytes()` and `from_bytes()` helpers.

## Computational complexity

For the current development backend:

- `prove_location` / `prove_training`: **O(1)** hashing + Ed25519 signing over small transcripts.
- `verify_location_proof` / `verify_training_proof`: **O(1)** hashing + Ed25519 signature verification.

The benchmark harness in `benches/proof_benchmarks.rs` is ready to track latency as the backend evolves.

## Usage

```rust
use smp_zk_proofs::{
    BoundingBox, LocationPrivateWitness, LocationPublicInputs, ProvingContext,
    prove_location, verify_location_proof,
};

let context = ProvingContext::from_seed([7_u8; 32]);
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

let proof = prove_location(&context, &public_inputs, &witness)?;
verify_location_proof(&context.verification_key(), &public_inputs, &proof)?;
# Ok::<(), smp_zk_proofs::ZkProofError>(())
```

## Examples

Run the examples with Cargo:

```bash
cargo run --example simple_location_proof
cargo run --example weight_aggregation_proof
```

## Post-quantum placeholder

`src/pq_compatibility/` reserves a backend-neutral extension point so a future lattice- or hash-based proving system can be slotted in without rewriting the circuit-facing API.
