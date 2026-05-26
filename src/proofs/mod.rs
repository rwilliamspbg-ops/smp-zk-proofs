pub mod generator;
pub mod types;
pub mod verifier;
#[cfg(feature = "halo2")]
pub mod halo2_backend;
#[cfg(feature = "groth16")]
pub mod groth16_backend;
#[cfg(feature = "groth16")]
pub mod groth16_circuits;

use crate::{ZkProofError, utils};
use serde::Serialize;

pub(crate) fn transcript_message<T: Serialize>(
    circuit: types::CircuitKind,
    scheme: types::ProofScheme,
    statement_digest: [u8; 32],
    constraint_digest: [u8; 32],
    public_inputs: &T,
) -> Result<[u8; 32], ZkProofError> {
    utils::hash_serializable(&(
        circuit,
        scheme,
        statement_digest,
        constraint_digest,
        public_inputs,
    ))
}
