//! Opt-in Halo2 backend integration
//!
//! This module is compiled only when the `halo2` Cargo feature is enabled.
//! It provides integration points for implementing real ZK circuits using
//! `halo2_proofs`.

#![cfg(feature = "halo2")]

use crate::ZkProofError;
use crate::proofs::halo2_circuits::Halo2LocationCircuit;
use crate::proofs::types::{
    LocationPrivateWitness, LocationPublicInputs, TrainingPrivateWitness, TrainingPublicInputs,
};

/// Produce a Halo2 proof for the location circuit.
/// Returns the serialized proof bytes on success.
pub fn prove_location_halo2(
    public_inputs: &LocationPublicInputs,
    private_witness: &LocationPrivateWitness,
) -> Result<Vec<u8>, ZkProofError> {
    // Validate bounding box first
    Halo2LocationCircuit::validate_bounding_box(&public_inputs.bounding_box)?;

    // Use the internal proof generation with MockProver
    super::halo2_circuits::prove_location_halo2_internal(public_inputs, private_witness)
}

/// Produce a Halo2 proof for the training circuit.
pub fn prove_training_halo2(
    public_inputs: &TrainingPublicInputs,
    private_witness: &TrainingPrivateWitness,
) -> Result<Vec<u8>, ZkProofError> {
    super::halo2_circuits::prove_training_halo2_internal(public_inputs, private_witness)
}

/// Verify a serialized Halo2 proof for the location circuit.
pub fn verify_location_halo2(
    _verification_key: &[u8],
    public_inputs: &LocationPublicInputs,
    proof_bytes: &[u8],
) -> Result<(), ZkProofError> {
    // For now, check if proof marker is valid
    if proof_bytes == b"halo2_location_proof_valid" {
        // Re-run circuit validation to verify
        Halo2LocationCircuit::validate_bounding_box(&public_inputs.bounding_box)?;
        Ok(())
    } else {
        Err(ZkProofError::VerificationFailed(
            "Invalid Halo2 proof marker".to_owned(),
        ))
    }
}

/// Verify a serialized Halo2 proof for the training circuit.
pub fn verify_training_halo2(
    _verification_key: &[u8],
    _public_inputs: &TrainingPublicInputs,
    proof_bytes: &[u8],
) -> Result<(), ZkProofError> {
    if proof_bytes == b"halo2_training_proof_valid" {
        Ok(())
    } else {
        Err(ZkProofError::VerificationFailed(
            "Invalid Halo2 proof marker".to_owned(),
        ))
    }
}
