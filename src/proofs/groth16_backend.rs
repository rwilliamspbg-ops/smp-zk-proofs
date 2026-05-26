//! Opt-in arkworks Groth16 backend integration scaffolding
//!
//! Compiled only when the `groth16` Cargo feature is enabled. Provides
//! scaffolded proving/verifying entrypoints to be implemented with arkworks.

#![cfg(feature = "groth16")]

use crate::ZkProofError;
use crate::proofs::types::{LocationPrivateWitness, LocationPublicInputs, TrainingPrivateWitness, TrainingPublicInputs};

/// Produce a Groth16 proof for the location circuit.
pub fn prove_location_groth16(
    _public_inputs: &LocationPublicInputs,
    _private_witness: &LocationPrivateWitness,
) -> Result<Vec<u8>, ZkProofError> {
    Err(ZkProofError::VerificationFailed(
        "Groth16 backend not implemented yet".to_owned(),
    ))
}

/// Produce a Groth16 proof for the training circuit.
pub fn prove_training_groth16(
    _public_inputs: &TrainingPublicInputs,
    _private_witness: &TrainingPrivateWitness,
) -> Result<Vec<u8>, ZkProofError> {
    Err(ZkProofError::VerificationFailed(
        "Groth16 backend not implemented yet".to_owned(),
    ))
}

/// Verify a serialized Groth16 proof for the location circuit.
pub fn verify_location_groth16(
    _verification_key: &[u8],
    _public_inputs: &LocationPublicInputs,
    _proof_bytes: &[u8],
) -> Result<(), ZkProofError> {
    Err(ZkProofError::VerificationFailed(
        "Groth16 backend not implemented yet".to_owned(),
    ))
}

/// Verify a serialized Groth16 proof for the training circuit.
pub fn verify_training_groth16(
    _verification_key: &[u8],
    _public_inputs: &TrainingPublicInputs,
    _proof_bytes: &[u8],
) -> Result<(), ZkProofError> {
    Err(ZkProofError::VerificationFailed(
        "Groth16 backend not implemented yet".to_owned(),
    ))
}
