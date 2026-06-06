use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_groth16::{Proof as ArkProof, ProvingKey, VerifyingKey as ArkVerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

use crate::{ZkProofError, utils};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitKind {
    Location,
    Training,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofScheme {
    Groth16Bls12_381,
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

/// Wrapper for arkworks Groth16 proof with serialization support
#[derive(Debug, Clone)]
pub struct ZkSnarkProof {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
    pub c: Vec<u8>,
}

impl ZkSnarkProof {
    pub fn from_arkworks_proof(proof: &ArkProof<Bls12_381>) -> Result<Self, ZkProofError> {
        let mut a_bytes = Vec::new();
        let mut b_bytes = Vec::new();
        let mut c_bytes = Vec::new();
        
        proof.a.serialize_compressed(&mut a_bytes)
            .map_err(|e| ZkProofError::SerializationFailed(e.to_string()))?;
        proof.b.serialize_compressed(&mut b_bytes)
            .map_err(|e| ZkProofError::SerializationFailed(e.to_string()))?;
        proof.c.serialize_compressed(&mut c_bytes)
            .map_err(|e| ZkProofError::SerializationFailed(e.to_string()))?;
        
        Ok(Self {
            a: a_bytes,
            b: b_bytes,
            c: c_bytes,
        })
    }
    
    pub fn to_arkworks_proof(&self) -> Result<ArkProof<Bls12_381>, ZkProofError> {
        let a = <BlsFr as CanonicalDeserialize>::deserialize_compressed_unchecked(&self.a[..])
            .map_err(|e| ZkProofError::DeserializationFailed(e.to_string()))?;
        let b = <ark_ec::AffinePointProjective<<Bls12_381 as ark_ec::pairing::Pairing>::G2> as CanonicalDeserialize>::deserialize_compressed(&self.b[..])
            .map_err(|e| ZkProofError::DeserializationFailed(e.to_string()))?;
        let c = <BlsFr as CanonicalDeserialize>::deserialize_compressed_unchecked(&self.c[..])
            .map_err(|e| ZkProofError::DeserializationFailed(e.to_string()))?;
        
        Ok(ArkProof { a, b, c })
    }
}

/// Wrapper for arkworks verifying key
#[derive(Debug, Clone)]
pub struct ZkSnarkVerifyingKey {
    pub alpha_g1: Vec<u8>,
    pub beta_g2: Vec<u8>,
    pub gamma_g2: Vec<u8>,
    pub delta_g2: Vec<u8>,
    pub gamma_abc_g1: Vec<u8>,
}

impl ZkSnarkVerifyingKey {
    pub fn from_arkworks_vk(vk: &ArkVerifyingKey<Bls12_381>) -> Result<Self, ZkProofError> {
        let mut alpha_g1 = Vec::new();
        let mut beta_g2 = Vec::new();
        let mut gamma_g2 = Vec::new();
        let mut delta_g2 = Vec::new();
        let mut gamma_abc_g1 = Vec::new();
        
        vk.alpha_g1.serialize_compressed(&mut alpha_g1)
            .map_err(|e| ZkProofError::SerializationFailed(e.to_string()))?;
        vk.beta_g2.serialize_compressed(&mut beta_g2)
            .map_err(|e| ZkProofError::SerializationFailed(e.to_string()))?;
        vk.gamma_g2.serialize_compressed(&mut gamma_g2)
            .map_err(|e| ZkProofError::SerializationFailed(e.to_string()))?;
        vk.delta_g2.serialize_compressed(&mut delta_g2)
            .map_err(|e| ZkProofError::SerializationFailed(e.to_string()))?;
        vk.gamma_abc_g1.serialize_compressed(&mut gamma_abc_g1)
            .map_err(|e| ZkProofError::SerializationFailed(e.to_string()))?;
        
        Ok(Self {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        })
    }
    
    pub fn to_arkworks_vk(&self) -> Result<ArkVerifyingKey<Bls12_381>, ZkProofError> {
        let alpha_g1 = <BlsFr as CanonicalDeserialize>::deserialize_compressed_unchecked(&self.alpha_g1[..])
            .map_err(|e| ZkProofError::DeserializationFailed(e.to_string()))?;
        let beta_g2 = <ark_ec::AffinePointProjective<<Bls12_381 as ark_ec::pairing::Pairing>::G2> as CanonicalDeserialize>::deserialize_compressed(&self.beta_g2[..])
            .map_err(|e| ZkProofError::DeserializationFailed(e.to_string()))?;
        let gamma_g2 = <ark_ec::AffinePointProjective<<Bls12_381 as ark_ec::pairing::Pairing>::G2> as CanonicalDeserialize>::deserialize_compressed(&self.gamma_g2[..])
            .map_err(|e| ZkProofError::DeserializationFailed(e.to_string()))?;
        let delta_g2 = <ark_ec::AffinePointProjective<<Bls12_381 as ark_ec::pairing::Pairing>::G2> as CanonicalDeserialize>::deserialize_compressed(&self.delta_g2[..])
            .map_err(|e| ZkProofError::DeserializationFailed(e.to_string()))?;
        let gamma_abc_g1_data: Vec<BlsFr> = ark_serialize::CanonicalDeserialize::deserialize_compressed_unchecked(&self.gamma_abc_g1[..])
            .map_err(|e| ZkProofError::DeserializationFailed(e.to_string()))?;
        
        Ok(ArkVerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1: gamma_abc_g1_data,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationKey {
    pub verifying_key: [u8; 32],
    pub zk_snark_vk: Option<ZkSnarkVerifyingKey>,
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
    pub zk_snark_proof: Option<ZkSnarkProof>,
}

impl Proof {
    pub fn to_bytes(&self) -> Result<Vec<u8>, ZkProofError> {
        utils::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkProofError> {
        utils::deserialize(bytes)
    }
}
