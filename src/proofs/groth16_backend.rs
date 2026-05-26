//! Minimal mock Groth16 backend (opt-in via `groth16` feature)
//!
//! This is a lightweight placeholder used during Phase A to wire the proving
//! and verification plumbing without depending on heavy arkworks APIs. The
//! blob returned is a simple deterministic marker that the verifier checks.

#![cfg(feature = "groth16")]

//! Lightweight mock Groth16 backend retained for Phase A integration. The
//! real R1CS circuit is implemented in `groth16_circuits.rs` and will be
//! integrated into this backend in Phase B once dependencies and APIs are
//! stabilized.

use crate::ZkProofError;
use crate::proofs::types::{LocationPrivateWitness, LocationPublicInputs, TrainingPrivateWitness, TrainingPublicInputs};

const MOCK_PREFIX: &[u8] = b"MOCK_GROTH16_PROOF_V1";

/// Produce a mock Groth16 proof for the location circuit.
pub fn prove_location_groth16(
    _public_inputs: &LocationPublicInputs,
    _private_witness: &LocationPrivateWitness,
) -> Result<Vec<u8>, ZkProofError> {
    let mut out = Vec::with_capacity(MOCK_PREFIX.len() + 8);
    out.extend_from_slice(MOCK_PREFIX);
    out.extend_from_slice(&(32u64.to_le_bytes()));
    Ok(out)
}

/// Produce a mock Groth16 proof for the training circuit.
pub fn prove_training_groth16(
    _public_inputs: &TrainingPublicInputs,
    _private_witness: &TrainingPrivateWitness,
) -> Result<Vec<u8>, ZkProofError> {
    let mut out = Vec::with_capacity(MOCK_PREFIX.len() + 8);
    out.extend_from_slice(MOCK_PREFIX);
    out.extend_from_slice(&(64u64.to_le_bytes()));
    Ok(out)
}

/// Verify a mock Groth16 proof for the location circuit.
pub fn verify_location_groth16(
    _verification_key: &[u8],
    _public_inputs: &LocationPublicInputs,
    proof_bytes: &[u8],
) -> Result<(), ZkProofError> {
    if proof_bytes.len() < MOCK_PREFIX.len() {
        return Err(ZkProofError::VerificationFailed("invalid mock proof".to_owned()));
    }
    if &proof_bytes[..MOCK_PREFIX.len()] != MOCK_PREFIX {
        return Err(ZkProofError::VerificationFailed("mock proof prefix mismatch".to_owned()));
    }
    Ok(())
}

/// Verify a mock Groth16 proof for the training circuit.
pub fn verify_training_groth16(
    verification_key: &[u8],
    public_inputs: &TrainingPublicInputs,
    proof_bytes: &[u8],
) -> Result<(), ZkProofError> {
    let _ = (verification_key, public_inputs);
    verify_location_groth16(&[], &LocationPublicInputs { bounding_box: crate::proofs::types::BoundingBox { x_min: 0, x_max: 0, y_min: 0, y_max: 0 }, coordinate_commitment: [0u8; 32] }, proof_bytes)
}
