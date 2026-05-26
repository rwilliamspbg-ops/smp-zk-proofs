#![cfg(feature = "halo2")]
//! Halo2 circuit definitions (scaffold)
//!
//! These modules intentionally avoid referencing `halo2_proofs` directly in the
//! default build. When the `halo2` feature is enabled, implement the circuits
//! here to mirror the checks performed by `LocationCircuit` and `TrainingCircuit`.

use crate::ZkProofError;
use crate::proofs::types::{LocationPrivateWitness, LocationPublicInputs, TrainingPrivateWitness, TrainingPublicInputs};

/// Halo2 location circuit skeleton.
pub struct Halo2LocationCircuit {
    // TODO: add fields for public inputs as halo2 `AssignedCell` or similar
}

impl Halo2LocationCircuit {
    pub fn new(_public: &LocationPublicInputs) -> Self {
        Self {}
    }

    /// TODO: Implement synthesis that enforces:
    /// - x,y in range of bounding box (range checks)
    /// - commitment opening verifies (SHA256 or Pedersen opening gadget)
    pub fn synthesize(&self, _witness: &LocationPrivateWitness) -> Result<(), ZkProofError> {
        Err(ZkProofError::VerificationFailed("halo2 synthesis not implemented".to_owned()))
    }
}

/// Halo2 training circuit skeleton.
pub struct Halo2TrainingCircuit;

impl Halo2TrainingCircuit {
    pub fn new() -> Self {
        Self {}
    }

    pub fn synthesize(&self, _public: &TrainingPublicInputs, _witness: &TrainingPrivateWitness) -> Result<(), ZkProofError> {
        Err(ZkProofError::VerificationFailed("halo2 synthesis not implemented".to_owned()))
    }
}
