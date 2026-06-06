//! Serialisation, hashing, and commitment helpers.

use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::ZkProofError;

/// Serialise `value` to a `Vec<u8>` using bincode.
pub fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, ZkProofError> {
    bincode::serialize(value).map_err(Into::into)
}

/// Deserialise a value of type `T` from `bytes` using bincode.
pub fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ZkProofError> {
    bincode::deserialize(bytes).map_err(Into::into)
}

/// Compute a SHA-256 digest over the concatenation of all `parts`.
pub fn hash_bytes(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Serialise `value` with bincode then return its SHA-256 digest.
pub fn hash_serializable<T: Serialize>(value: &T) -> Result<[u8; 32], ZkProofError> {
    Ok(hash_bytes(&[&serialize(value)?]))
}

/// Commit to a `(x, y)` coordinate pair with a 32-byte blinding factor.
///
/// Uses domain separation tag `"location-commitment-v1"` so that commitments
/// from different domains cannot be confused.
pub fn location_commitment(x: i64, y: i64, blinding: &[u8; 32]) -> Result<[u8; 32], ZkProofError> {
    hash_serializable(&(b"location-commitment-v1", x, y, blinding))
}

/// Commit to a model weight update given its digest, the base-model digest,
/// and a 32-byte blinding factor.
///
/// Uses domain separation tag `"training-commitment-v1"`.
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
