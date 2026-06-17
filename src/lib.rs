#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

/// Circuit definitions and native constraint evaluation.
pub mod constraints;
/// Error types for all `smp-zk-proofs` operations.
pub mod error;
/// Post-quantum compatibility layer and backend descriptors.
pub mod pq_compatibility;
/// Proof generation, verification, types, and proving backends.
pub mod proofs;
/// Serialisation, hashing, and commitment utilities.
pub mod utils;

pub use constraints::{ConstraintReport, LocationCircuit, TrainingCircuit};
pub use error::ZkProofError;
pub use pq_compatibility::{
    PlaceholderBackend, PostQuantumBackend, PostQuantumBackendDescriptor, PostQuantumBackendStatus,
};
pub use proofs::generator::{ProvingContext, prove_location, prove_training};
pub use proofs::types::{
    BoundingBox, CircuitKind, LocationPrivateWitness, LocationPublicInputs, Proof, ProofScheme,
    TrainingPrivateWitness, TrainingPublicInputs, VerificationKey,
};
pub use proofs::verifier::{verify_location_proof, verify_training_proof};
#[cfg(feature = "rand")]
pub use utils::generate_csprng_blinding_factor;
#[cfg(feature = "rand")]
pub use utils::generate_secure_blinding_factor;
pub use utils::{
    constant_time_eq_bytes, deserialize, generate_deterministic_blinding_factor, hash_bytes,
    hash_serializable, location_commitment, serialize, training_commitment,
    validate_blinding_factor,
};
