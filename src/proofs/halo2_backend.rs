//! Opt-in Halo2 backend integration
//!
//! This module is compiled only when the `halo2` Cargo feature is enabled.
//! It provides integration points for implementing real ZK circuits using
//! `halo2_proofs`.
//!
//! # ⚠️ Security Warning
//!
//! The current Halo2 backend is a **stub**. `prove_location_halo2` returns a
//! fixed byte string and `verify_location_halo2` accepts it by string
//! comparison — **this provides zero cryptographic security**. Do not use
//! this feature in production. A real `halo2_proofs` circuit integration is
//! tracked as future work.

#![cfg(feature = "halo2")]

use crate::ZkProofError;
use crate::proofs::halo2_circuits::Halo2LocationCircuit;
use crate::proofs::types::{
    LocationPrivateWitness, LocationPublicInputs, TrainingPrivateWitness, TrainingPublicInputs,
};

/// Produce a Halo2 proof for the location circuit.
/// Returns the serialized proof bytes on success.
///
/// # ⚠️ Stub Implementation
///
/// This function does **not** produce a real zero-knowledge proof. It runs
/// the native constraint evaluator and returns a fixed sentinel byte string.
/// The companion `verify_location_halo2` accepts only that exact sentinel.
/// This is scaffolding for a future real Halo2 circuit and must not be used
/// in production.
#[deprecated(
    since = "0.1.0",
    note = "Halo2 backend is a stub — no real ZK proof is produced.             See src/proofs/halo2_backend.rs for details."
)]
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
///
/// # ⚠️ Stub Implementation
///
/// See [`prove_location_halo2`] — the same stub caveat applies here.
#[deprecated(
    since = "0.1.0",
    note = "Halo2 backend is a stub — no real ZK proof is produced."
)]
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
