#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod constraints;
pub mod error;
pub mod pq_compatibility;
pub mod proofs;
pub mod utils;

pub use constraints::{ConstraintReport, LocationCircuit, TrainingCircuit};
pub use error::ZkProofError;
pub use pq_compatibility::{PlaceholderBackend, PostQuantumBackend, PostQuantumBackendDescriptor};
pub use proofs::generator::{ProvingContext, prove_location, prove_training};
pub use proofs::types::{
    BoundingBox, CircuitKind, LocationPrivateWitness, LocationPublicInputs, Proof, ProofScheme,
    TrainingPrivateWitness, TrainingPublicInputs, VerificationKey,
};
pub use proofs::verifier::{verify_location_proof, verify_training_proof};
