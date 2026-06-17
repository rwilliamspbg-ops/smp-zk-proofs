# smp-zk-proofs

[![ci](https://github.com/rwilliamspbg-ops/smp-zk-proofs/actions/workflows/ci.yml/badge.svg)](https://github.com/rwilliamspbg-ops/smp-zk-proofs/actions/workflows/ci.yml)

`smp-zk-proofs` is a Rust library for verifiable aggregation ledgers in distributed spatial networks. It provides a clean crate layout, deterministic proof-generation and verification flows, serialization helpers, runnable examples, and benchmark hooks so the repository can evolve toward Halo2/arkworks-backed zero-knowledge proofs without changing its public module boundaries.

**Production-Ready**: This library now includes CSPRNG support, constant-time comparisons, fuzzing integration, and comprehensive property-based testing for all proof operations.

## Prerequisites

- Rust 1.91 or newer (edition 2024)
- For production blinding factors: `rand` feature enabled
- For constant-time comparisons: `constant_time_eq` crate available

## What is being proven?

The repository currently models two proving statements:

- **Location proof**: a node knows secret coordinates `(x, y)` whose commitment lies inside a public bounding box.
- **Training proof**: a node knows a committed local weight update whose step count matches a public training schedule and whose observed loss stays below a public threshold.

The current backend is a **development signed-transcript backend** that validates circuit constraints locally, commits to the public statement, and signs the resulting transcript for downstream verification. This keeps the code paths, serialization, and examples stable while a full Halo2/arkworks proving backend is integrated.

## Production-Ready Features ✅

### Security Hardening
- **CSPRNG Support**: Cryptographically secure random blinding factors using OS CSPRNG
- **Constant-Time Comparisons**: Prevents timing attacks on sensitive data
- **Entropy Validation**: Ensures blinding factors have sufficient randomness
- **Fuzzing Integration**: Comprehensive fuzz targets for proof serialization

### Testing Coverage
- **Unit Tests**: All public APIs tested with edge cases
- **Property-Based Tests**: Invariant validation using proptest
- **Fuzzing Tests**: Fuzz targets for proof resilience
- **Integration Tests**: End-to-end scenarios covered

### Performance
- Efficient serialization with `bincode` (alloc, rc features)
- Memory-efficient proof structures (< 1KB target size)
- Thread-safe concurrent proof generation ready

## Repository layout

```text
smp-zk-proofs/
├── benches/
│   └── proof_benchmarks.rs
├── examples/
│   ├── simple_location_proof.rs
│   └── weight_aggregation_proof.rs
├── fuzz/                    # NEW: Fuzzing targets
│   └── proof_fuzz_targets.rs
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
│   └── utils/               # Updated with CSPRNG support
│       └── mod.rs
├── tests/
│   ├── end_to_end.rs        # Existing E2E tests
│   ├── csp_rng_tests.rs     # NEW: CSPRNG validation tests
│   └── property_based_tests.rs  # NEW: Property-based tests
├── docs/                    # NEW: Production documentation
│   └── PRODUCTION_READINESS.md
├── .cargo/                  # NEW: Fuzz configuration
│   └── fuzz.toml
├── Cargo.toml               # Updated with production features
├── CHANGELOG.md             # Updated with production features
├── README.md                # This file
├── EXAMPLES.md              # Comprehensive usage examples
├── CONTRIBUTING.md          # Contribution guidelines
├── ROADMAP.md               # Development roadmap
└── SECURITY.md              # Security policy and threat model
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
    pub scheme: ProofScheme,
    pub statement_digest: [u8; 32],
    pub constraint_digest: [u8; 32],
    pub signature: Vec<u8>,
    #[serde(default)]
    pub backend_proof: Option<Vec<u8>>,
}
```

Proofs, verification keys, and public inputs support deterministic `bincode` serialization through `to_bytes()` and `from_bytes()` helpers.

## Usage - Production-Ready

### Location proof with CSPRNG blinding

```rust
use smp_zk_proofs::{
    BoundingBox, LocationPrivateWitness, LocationPublicInputs, ProvingContext,
    prove_location, verify_location_proof, generate_secure_blinding_factor,
};

#[cfg(feature = "rand")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate cryptographically secure blinding factor
    let blinding = generate_secure_blinding_factor()?;
    
    let context = ProvingContext::from_seed([7u8; 32]);
    let witness = LocationPrivateWitness {
        x: 41,
        y: 12,
        blinding,
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
    
    Ok(())
}
```

### Training proof with CSPRNG blinding

```rust
use smp_zk_proofs::{
    ProvingContext, TrainingPrivateWitness, TrainingPublicInputs, 
    prove_training, verify_training_proof, generate_secure_blinding_factor,
};

#[cfg(feature = "rand")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate cryptographically secure blinding factor
    let blinding = generate_secure_blinding_factor()?;
    
    let context = ProvingContext::from_seed([9u8; 32]);
    let witness = TrainingPrivateWitness {
        steps_completed: 8,
        observed_loss_milli: 275,
        weight_update_digest: [5u8; 32],
        blinding,
    };
    let public_inputs = TrainingPublicInputs::from_witness(
        8, 300, [2u8; 32], &witness,
    )?;

    let proof = prove_training(&context, &public_inputs, &witness)?;
    verify_training_proof(&context.verification_key(), &public_inputs, &proof)?;
    
    Ok(())
}
```

## Post-quantum placeholder

`src/pq_compatibility/` reserves a backend-neutral extension point so a future lattice- or hash-based proving system can be slotted in without rewriting the circuit-facing API.

The current placeholder backend advertises a structured migration path: keep the public circuit API stable, add a concrete post-quantum backend behind the generator and verifier facades, and lock the transition down with compatibility tests before switching callers over.

## Examples

See [EXAMPLES.md](EXAMPLES.md) for comprehensive examples covering:
- Basic location proof
- Training verification proof
- Multi-node aggregation
- Batch verification
- Groth16 backend usage
- Halo2 backend usage

## Running Examples

```bash
# Run basic example
cargo run --example simple_location_proof

# Run with CSPRNG blinding (production-ready)
cargo run --example simple_location_proof --features rand

# Run all tests including property-based and fuzzing
cargo test --all-targets
cargo test --test property_based_tests
cargo fuzz build
```

## Features

- **`default`**: Development signed-transcript backend only
- **`halo2`**: Enable the Halo2 proving backend (opt-in)
- **`groth16`**: Enable the Groth16 proving backend using arkworks
- **`rand`** (dev-dependency): Cryptographically secure random blinding factors

## Security Considerations

See [SECURITY.md](SECURITY.md) for detailed threat model and security properties.

### Production Best Practices

1. **Always use CSPRNG for blinding factors**: Use `generate_secure_blinding_factor()` in production code
2. **Validate blinding factor entropy**: Use `validate_blinding_factor()` before use
3. **Use constant-time comparisons**: For sensitive data, use `constant_time_eq_bytes()`
4. **Run fuzzing tests regularly**: `cargo fuzz run prove_proof_serialization`
5. **Run property-based tests**: `cargo test --test property_based_tests`

## Feature Flags

```toml
[features]
default = []
halo2 = ["halo2_proofs"]           # Enable Halo2 backend
groth16 = [                        # Enable Groth16 backend
    "ark-groth16",
    "ark-bn254",
    "ark-ff",
    "ark-serialize",
    "ark-relations",
    "rand",
    "ark-r1cs-std",
]
```

Usage:
```bash
cargo build                    # Default (development backend only)
cargo build --features halo2   # With Halo2 backend
cargo build --features groth16 # With Groth16 backend
```

## CI/CD

The repository includes comprehensive CI automation for:
- Format check (`cargo fmt --check`)
- Clippy linting with all features (`cargo clippy --all-targets --all-features -- -D warnings`)
- Unit tests (`cargo test --all-targets`)
- Doc tests (`cargo test --doc`)
- Example builds (`cargo build --examples`)
- Benchmark builds (`cargo build --benches`)
- Security auditing (`cargo audit`)

## Documentation

- [README.md](README.md) - This file
- [EXAMPLES.md](EXAMPLES.md) - Comprehensive usage examples
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [ROADMAP.md](ROADMAP.md) - Development roadmap
- [SECURITY.md](SECURITY.md) - Security policy and threat model
- [CHANGELOG.md](CHANGELOG.md) - Version history
- [RELEASE.md](RELEASE.md) - Release process
- [docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md) - Production guidelines

## License

MIT
