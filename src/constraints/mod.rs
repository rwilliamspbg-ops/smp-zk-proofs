//! Circuit definitions and native constraint evaluation.
//!
//! Each circuit provides a [`Circuit::evaluate`] method that checks whether a
//! private witness satisfies the public constraints.  The result is a
//! [`ConstraintReport`] whose digest is committed to in the generated proof.

/// Location bounding-box circuit.
pub mod location_circuit;
/// Training step and loss-bound circuit.
pub mod training_circuit;

use serde::{Deserialize, Serialize};

use crate::{ZkProofError, proofs::types::CircuitKind, utils};

#[allow(missing_docs)]
pub use location_circuit::LocationCircuit;
#[allow(missing_docs)]
pub use training_circuit::TrainingCircuit;

/// Trait implemented by every circuit in this crate.
pub trait Circuit {
    /// The type of public inputs visible to the verifier.
    type PublicInputs;
    /// The type of private witness known only to the prover.
    type PrivateWitness;

    /// Returns the [`CircuitKind`] tag for this circuit.
    fn kind(&self) -> CircuitKind;

    /// Evaluate the circuit constraints against `public_inputs` and
    /// `private_witness`, returning a [`ConstraintReport`] on success or a
    /// [`ZkProofError::ConstraintUnsatisfied`] if any constraint fails.
    fn evaluate(
        &self,
        public_inputs: &Self::PublicInputs,
        private_witness: &Self::PrivateWitness,
    ) -> Result<ConstraintReport, ZkProofError>;
}

/// A record of which constraint checks passed for a given witness.
///
/// The [`ConstraintReport::digest`] is committed to inside the [`crate::Proof`]
/// so that verifiers can confirm the prover ran the correct circuit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintReport {
    /// Which circuit produced this report.
    pub circuit: CircuitKind,
    /// Human-readable labels for each satisfied constraint check.
    pub checks: Vec<String>,
}

impl ConstraintReport {
    /// Compute a SHA-256 digest over the serialised report.
    pub fn digest(&self) -> Result<[u8; 32], ZkProofError> {
        utils::hash_serializable(self)
    }
}
