#![cfg(feature = "halo2")]
//! Halo2 circuit-facing helpers.

use crate::constraints::{Circuit, LocationCircuit, TrainingCircuit};
use crate::proofs::types::{
    BoundingBox, LocationPrivateWitness, LocationPublicInputs, TrainingPrivateWitness,
    TrainingPublicInputs,
};
use crate::ZkProofError;

/// Halo2 location circuit placeholder type.
pub struct Halo2LocationCircuit;

impl Halo2LocationCircuit {
    pub fn validate_bounding_box(bbox: &BoundingBox) -> Result<(), ZkProofError> {
        bbox.validate()
    }
}

/// Halo2 training circuit placeholder type.
pub struct Halo2TrainingCircuit;

/// Helper function to create a location proof with Halo2.
pub fn prove_location_halo2_internal(
    public: &LocationPublicInputs,
    witness: &LocationPrivateWitness,
) -> Result<Vec<u8>, ZkProofError> {
    Halo2LocationCircuit::validate_bounding_box(&public.bounding_box)?;
    LocationCircuit.evaluate(public, witness)?;
    Ok(b"halo2_location_proof_valid".to_vec())
}

/// Helper function to create a training proof with Halo2.
pub fn prove_training_halo2_internal(
    public: &TrainingPublicInputs,
    witness: &TrainingPrivateWitness,
) -> Result<Vec<u8>, ZkProofError> {
    TrainingCircuit.evaluate(public, witness)?;
    Ok(b"halo2_training_proof_valid".to_vec())
}
