use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::ZkProofError;

pub fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, ZkProofError> {
    bincode::serialize(value).map_err(Into::into)
}

pub fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ZkProofError> {
    bincode::deserialize(bytes).map_err(Into::into)
}

pub fn hash_bytes(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

pub fn hash_serializable<T: Serialize>(value: &T) -> Result<[u8; 32], ZkProofError> {
    Ok(hash_bytes(&[&serialize(value)?]))
}

pub fn location_commitment(x: i64, y: i64, blinding: &[u8; 32]) -> Result<[u8; 32], ZkProofError> {
    hash_serializable(&(b"location-commitment-v1", x, y, blinding))
}

pub fn training_commitment(
    base_model_digest: [u8; 32],
    update_digest: [u8; 32],
    blinding: &[u8; 32],
) -> Result<[u8; 32], ZkProofError> {
    hash_serializable(&(
        b"training-commitment-v1",
        base_model_digest,
        update_digest,
        blinding,
    ))
}
