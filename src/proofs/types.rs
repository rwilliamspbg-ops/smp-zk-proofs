use serde::{Deserialize, Serialize};

use crate::{utils, ZkProofError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitKind {
    Location,
    Training,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofScheme {
    DevelopmentSignedTranscriptV1,
    Halo2V1,
    Groth16V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundingBox {
    pub x_min: i64,
    pub x_max: i64,
    pub y_min: i64,
    pub y_max: i64,
}

impl BoundingBox {
    pub fn validate(&self) -> Result<(), ZkProofError> {
        if self.x_min > self.x_max {
            return Err(ZkProofError::InvalidPublicInputs(
                "x_min must not exceed x_max".to_owned(),
            ));
        }

        if self.y_min > self.y_max {
            return Err(ZkProofError::InvalidPublicInputs(
                "y_min must not exceed y_max".to_owned(),
            ));
        }

        Ok(())
    }

    pub fn contains(&self, x: i64, y: i64) -> bool {
        (self.x_min..=self.x_max).contains(&x) && (self.y_min..=self.y_max).contains(&y)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocationPublicInputs {
    pub bounding_box: BoundingBox,
    pub coordinate_commitment: [u8; 32],
}

impl LocationPublicInputs {
    pub fn from_witness(
        bounding_box: BoundingBox,
        witness: &LocationPrivateWitness,
    ) -> Result<Self, ZkProofError> {
        bounding_box.validate()?;
        Ok(Self {
            bounding_box,
            coordinate_commitment: utils::location_commitment(
                witness.x,
                witness.y,
                &witness.blinding,
            )?,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ZkProofError> {
        utils::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkProofError> {
        utils::deserialize(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocationPrivateWitness {
    pub x: i64,
    pub y: i64,
    pub blinding: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainingPublicInputs {
    pub expected_steps: u32,
    pub max_loss_milli: u64,
    pub base_model_digest: [u8; 32],
    pub update_commitment: [u8; 32],
}

impl TrainingPublicInputs {
    pub fn from_witness(
        expected_steps: u32,
        max_loss_milli: u64,
        base_model_digest: [u8; 32],
        witness: &TrainingPrivateWitness,
    ) -> Result<Self, ZkProofError> {
        Ok(Self {
            expected_steps,
            max_loss_milli,
            base_model_digest,
            update_commitment: utils::training_commitment(
                base_model_digest,
                witness.weight_update_digest,
                &witness.blinding,
            )?,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ZkProofError> {
        utils::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkProofError> {
        utils::deserialize(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainingPrivateWitness {
    pub steps_completed: u32,
    pub observed_loss_milli: u64,
    pub weight_update_digest: [u8; 32],
    pub blinding: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationKey {
    pub verifying_key: [u8; 32],
}

impl VerificationKey {
    pub fn to_bytes(&self) -> Result<Vec<u8>, ZkProofError> {
        utils::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkProofError> {
        utils::deserialize(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    pub circuit: CircuitKind,
    pub scheme: ProofScheme,
    pub statement_digest: [u8; 32],
    pub constraint_digest: [u8; 32],
    pub signature: Vec<u8>,
    #[serde(default)]
    pub backend_proof: Option<Vec<u8>>,
}

impl Proof {
    pub fn to_bytes(&self) -> Result<Vec<u8>, ZkProofError> {
        utils::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkProofError> {
        utils::deserialize(bytes)
    }
}
