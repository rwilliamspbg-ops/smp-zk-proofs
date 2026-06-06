//! Proof generation, verification, types, and backend integrations.

/// Proof generation entry points and context.
pub mod generator;
#[cfg(feature = "groth16")]
/// Groth16 proof generation and verification via arkworks.
pub mod groth16_backend;
#[cfg(feature = "groth16")]
/// R1CS circuit definitions for the Groth16 backend.
pub mod groth16_circuits;
#[cfg(feature = "halo2")]
/// Halo2 backend integration (stub — see module docs).
pub mod halo2_backend;
#[cfg(feature = "halo2")]
/// Halo2 circuit placeholder types.
pub mod halo2_circuits;
/// Core proof types: circuits, schemes, witnesses, and proofs.
pub mod types;
/// Proof verification for all supported schemes.
pub mod verifier;

use crate::{ZkProofError, utils};
use serde::Serialize;
use types::{CircuitKind, ProofScheme};

/// Build the deterministic byte message that is signed (generator) or verified
/// against (verifier) for a `DevelopmentSignedTranscriptV1` proof.
///
/// The message is a concatenation of the serialised circuit kind, proof scheme,
/// the 32-byte statement digest, the 32-byte constraint digest, and the
/// serialised public inputs.  Both sides must produce identical bytes from
/// identical inputs for signature verification to succeed.
pub fn transcript_message<T: Serialize>(
    circuit: CircuitKind,
    scheme: ProofScheme,
    statement_digest: [u8; 32],
    constraint_digest: [u8; 32],
    public_inputs: &T,
) -> Result<Vec<u8>, ZkProofError> {
    let mut message = Vec::new();
    message.extend_from_slice(&utils::serialize(&circuit)?);
    message.extend_from_slice(&utils::serialize(&scheme)?);
    message.extend_from_slice(&statement_digest);
    message.extend_from_slice(&constraint_digest);
    message.extend_from_slice(&utils::serialize(public_inputs)?);
    Ok(message)
}
