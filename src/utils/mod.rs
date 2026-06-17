//! Serialisation, hashing, and commitment helpers.
//!
//! Production-ready utilities with CSPRNG support for blinding factors.

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

/// Generate a cryptographically secure random 32-byte blinding factor.
///
/// Uses the operating system's CSPRNG for production-ready randomness.
///
/// # Panics
///
/// Panics if the OS RNG is not available or fails to generate random bytes.
/// Use in production code with proper error handling.
#[cfg(feature = "rand")]
pub fn generate_csprng_blinding_factor() -> [u8; 32] {
    use rand::rngs::OsRng;
    OsRng.random_bytes::<32>()
}

/// Generate a deterministic blinding factor from a seed for testing.
///
/// Use this only for deterministic tests, not production.
pub fn generate_deterministic_blinding_factor(seed: [u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"BLINDING_SEED:");
    hasher.update(&seed);
    Into::<[u8; 32]>::into(hasher.finalize())
}

/// Constant-time comparison for blinding factors.
///
/// Prevents timing attacks when comparing sensitive values.
pub fn constant_time_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    use constant_time_eq::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Generate a cryptographically secure random blinding factor using CSPRNG.
///
/// This is the recommended approach for production code.
/// Returns an error if RNG initialization fails.
#[cfg(feature = "rand")]
pub fn generate_secure_blinding_factor() -> Result<[u8; 32], ZkProofError> {
    use rand::rngs::OsRng;
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    Ok(bytes)
}

/// Validate that a blinding factor has sufficient entropy.
///
/// Returns an error if the blinding factor appears to be weak (all zeros, etc.).
pub fn validate_blinding_factor(blinding: &[u8; 32]) -> Result<(), ZkProofError> {
    // Check for obviously weak values
    let zero_count = blinding.iter().filter(|&&b| b == 0).count();
    if zero_count > blinding.len() / 2 {
        return Err(ZkProofError::InvalidPublicInputs(
            "Blinding factor has insufficient entropy".to_owned(),
        ));
    }

    // Check for all-same-value weakness
    let unique_values = blinding.iter().collect::<std::collections::HashSet<_>>();
    if unique_values.len() < 4 {
        return Err(ZkProofError::InvalidPublicInputs(
            "Blinding factor has insufficient entropy".to_owned(),
        ));
    }

    Ok(())
}
