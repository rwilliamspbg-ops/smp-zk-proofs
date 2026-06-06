//! Core proof types: circuits, schemes, witnesses, and proofs.

use serde::{Deserialize, Serialize};

use crate::{ZkProofError, utils};

/// Identifies which circuit produced or should verify a [`Proof`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitKind {
    /// Bounding-box location circuit.
    Location,
    /// ML training step and loss-bound circuit.
    Training,
}

/// Identifies the cryptographic scheme used to generate a [`Proof`].
///
/// `DevelopmentSignedTranscriptV1` uses Ed25519 over a SHA-256 transcript
/// and is suitable for development and testing only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofScheme {
    /// Ed25519-signed SHA-256 transcript (development only).
    DevelopmentSignedTranscriptV1,
    /// Halo2 PLONK-based proof (stub — see `halo2` feature docs).
    Halo2V1,
    /// Groth16 proof over BN-254 via arkworks.
    Groth16V1,
}

/// An axis-aligned bounding box expressed as closed integer intervals.
///
/// Both intervals are inclusive: a point `(x, y)` is inside the box when
/// `x_min <= x <= x_max` and `y_min <= y <= y_max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundingBox {
    /// Minimum x coordinate (inclusive).
    pub x_min: i64,
    /// Maximum x coordinate (inclusive).
    pub x_max: i64,
    /// Minimum y coordinate (inclusive).
    pub y_min: i64,
    /// Maximum y coordinate (inclusive).
    pub y_max: i64,
}

impl BoundingBox {
    /// Return `Ok(())` if the bounding box is geometrically valid
    /// (i.e. `x_min <= x_max` and `y_min <= y_max`).
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

    /// Return `true` if `(x, y)` lies within this bounding box (inclusive on
    /// all sides).
    pub fn contains(&self, x: i64, y: i64) -> bool {
        (self.x_min..=self.x_max).contains(&x) && (self.y_min..=self.y_max).contains(&y)
    }
}

/// Public inputs for a location proof.
///
/// Contains the bounding box the prover claims to be inside, plus a
/// commitment to the private coordinates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocationPublicInputs {
    /// The bounding box the prover asserts their coordinates fall within.
    pub bounding_box: BoundingBox,
    /// SHA-256 commitment to `(x, y, blinding)` — see [`crate::utils::location_commitment`].
    pub coordinate_commitment: [u8; 32],
}

impl LocationPublicInputs {
    /// Derive public inputs from a bounding box and a private witness.
    ///
    /// Validates the bounding box and computes the coordinate commitment.
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

    /// Serialise to bytes using bincode.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ZkProofError> {
        utils::serialize(self)
    }

    /// Deserialise from bytes using bincode.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkProofError> {
        utils::deserialize(bytes)
    }
}

/// Private witness for a location proof — known only to the prover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocationPrivateWitness {
    /// Private x coordinate.
    pub x: i64,
    /// Private y coordinate.
    pub y: i64,
    /// 32-byte blinding factor used in the coordinate commitment.
    pub blinding: [u8; 32],
}

/// Public inputs for a training proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainingPublicInputs {
    /// Exact number of training steps the prover must have completed.
    pub expected_steps: u32,
    /// Maximum allowed training loss (in milli-units, e.g. 10 000 = loss 10.0).
    pub max_loss_milli: u64,
    /// SHA-256 digest of the base model before the update.
    pub base_model_digest: [u8; 32],
    /// Commitment to `(base_model_digest, weight_update_digest, blinding)`.
    pub update_commitment: [u8; 32],
}

impl TrainingPublicInputs {
    /// Derive public inputs from training parameters and a private witness.
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

    /// Serialise to bytes using bincode.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ZkProofError> {
        utils::serialize(self)
    }

    /// Deserialise from bytes using bincode.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkProofError> {
        utils::deserialize(bytes)
    }
}

/// Private witness for a training proof — known only to the prover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainingPrivateWitness {
    /// Number of training steps actually completed.
    pub steps_completed: u32,
    /// Observed loss in milli-units.
    pub observed_loss_milli: u64,
    /// SHA-256 digest of the weight update tensor.
    pub weight_update_digest: [u8; 32],
    /// 32-byte blinding factor for the update commitment.
    pub blinding: [u8; 32],
}

/// The Ed25519 verification key corresponding to a [`crate::proofs::generator::ProvingContext`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationKey {
    /// Raw 32-byte Ed25519 verifying-key bytes.
    pub verifying_key: [u8; 32],
}

impl VerificationKey {
    /// Serialise to bytes using bincode.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ZkProofError> {
        utils::serialize(self)
    }

    /// Deserialise from bytes using bincode.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkProofError> {
        utils::deserialize(bytes)
    }
}

/// A zero-knowledge proof produced by one of the proving backends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// Which circuit this proof covers.
    pub circuit: CircuitKind,
    /// Which proving scheme was used.
    pub scheme: ProofScheme,
    /// SHA-256 digest of the serialised public inputs.
    pub statement_digest: [u8; 32],
    /// SHA-256 digest of the constraint report produced during proving.
    pub constraint_digest: [u8; 32],
    /// Ed25519 signature over the proof transcript (empty for non-dev schemes).
    pub signature: Vec<u8>,
    /// Opaque backend-specific proof bytes (Groth16 / Halo2), if applicable.
    #[serde(default)]
    pub backend_proof: Option<Vec<u8>>,
}

impl Proof {
    /// Serialise to bytes using bincode.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ZkProofError> {
        utils::serialize(self)
    }

    /// Deserialise from bytes using bincode.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkProofError> {
        utils::deserialize(bytes)
    }
}
