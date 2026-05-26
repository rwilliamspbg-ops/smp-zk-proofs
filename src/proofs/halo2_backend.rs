//! Opt-in Halo2 backend integration scaffolding
//!
//! This module is compiled only when the `halo2` Cargo feature is enabled.
//! It provides integration points for implementing real ZK circuits using
//! `halo2_proofs`. The current contents are scaffolding to keep the public
//! facades stable while we incrementally add circuits and wiring.

#![cfg(feature = "halo2")]

use crate::ZkProofError;
use crate::proofs::types::{LocationPrivateWitness, LocationPublicInputs, TrainingPrivateWitness, TrainingPublicInputs};

// Re-exported helpers and a minimal API surface so generator/verifier can call in.
// TODO: replace the placeholder types below with real `halo2_proofs` circuit and proof types.

/// Produce a Halo2 proof for the location circuit.
/// Returns the serialized proof bytes (backend-specific) on success.
pub fn prove_location_halo2(
    _public_inputs: &LocationPublicInputs,
    _private_witness: &LocationPrivateWitness,
) -> Result<Vec<u8>, ZkProofError> {
    Err(ZkProofError::VerificationFailed(
        "Halo2 backend not implemented yet".to_owned(),
    ))
}

/// Produce a Halo2 proof for the training circuit.
pub fn prove_training_halo2(
    _public_inputs: &TrainingPublicInputs,
    _private_witness: &TrainingPrivateWitness,
) -> Result<Vec<u8>, ZkProofError> {
    Err(ZkProofError::VerificationFailed(
        "Halo2 backend not implemented yet".to_owned(),
    ))
}

/// Verify a serialized Halo2 proof for the location circuit.
pub fn verify_location_halo2(
    _verification_key: &[u8],
    _public_inputs: &LocationPublicInputs,
    _proof_bytes: &[u8],
) -> Result<(), ZkProofError> {
    Err(ZkProofError::VerificationFailed(
        "Halo2 backend not implemented yet".to_owned(),
    ))
}

/// Verify a serialized Halo2 proof for the training circuit.
pub fn verify_training_halo2(
    _verification_key: &[u8],
    _public_inputs: &TrainingPublicInputs,
    _proof_bytes: &[u8],
) -> Result<(), ZkProofError> {
    Err(ZkProofError::VerificationFailed(
        "Halo2 backend not implemented yet".to_owned(),
    ))
}

// Future notes and TODOs:
// - Implement R1CS-style constraints using `halo2_proofs::plonk` APIs.
// - Build a `ProvingKey`/`VerifyingKey` serialization format that fits `VerificationKey`.
// - Wire `ProvingContext` to hold parameters/keys when `halo2` is enabled.
// - Add benchmarks to `benches/` that measure real proving/verifying latency and proof sizes.
