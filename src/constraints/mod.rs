pub mod location_circuit;
pub mod training_circuit;

use serde::{Deserialize, Serialize};

use crate::{proofs::types::CircuitKind, utils, ZkProofError};

pub use location_circuit::LocationCircuit;
pub use training_circuit::TrainingCircuit;

pub trait Circuit {
    type PublicInputs;
    type PrivateWitness;

    fn kind(&self) -> CircuitKind;
    fn evaluate(
        &self,
        public_inputs: &Self::PublicInputs,
        private_witness: &Self::PrivateWitness,
    ) -> Result<ConstraintReport, ZkProofError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintReport {
    pub circuit: CircuitKind,
    pub checks: Vec<String>,
}

impl ConstraintReport {
    pub fn digest(&self) -> Result<[u8; 32], ZkProofError> {
        utils::hash_serializable(self)
    }
}
