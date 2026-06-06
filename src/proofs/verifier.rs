use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;

use crate::{
    ZkProofError,
    proofs::{transcript_message, types::*},
    utils,
};

pub fn verify_location_proof(
    verification_key: &VerificationKey,
    public_inputs: &LocationPublicInputs,
    proof: &Proof,
) -> Result<(), ZkProofError> {
    // If the proof is a Halo2 proof and the feature is enabled, route to halo2 verifier.
    #[cfg(feature = "halo2")]
    {
        if proof.scheme == ProofScheme::Halo2V1
            && let Some(bytes) = &proof.backend_proof
        {
            return crate::proofs::halo2_backend::verify_location_halo2(
                &verification_key.verifying_key,
                public_inputs,
                bytes,
            );
        }
    }

    #[cfg(feature = "groth16")]
    {
        if proof.scheme == ProofScheme::Groth16V1
            && let Some(bytes) = &proof.backend_proof
        {
            return crate::proofs::groth16_backend::verify_location_groth16(
                &verification_key.verifying_key,
                public_inputs,
                bytes,
            );
        }
    }

    verify_proof(
        verification_key,
        CircuitKind::Location,
        public_inputs,
        proof,
    )
}

pub fn verify_training_proof(
    verification_key: &VerificationKey,
    public_inputs: &TrainingPublicInputs,
    proof: &Proof,
) -> Result<(), ZkProofError> {
    #[cfg(feature = "halo2")]
    {
        if proof.scheme == ProofScheme::Halo2V1
            && let Some(bytes) = &proof.backend_proof
        {
            return crate::proofs::halo2_backend::verify_training_halo2(
                &verification_key.verifying_key,
                public_inputs,
                bytes,
            );
        }
    }

    #[cfg(feature = "groth16")]
    {
        if proof.scheme == ProofScheme::Groth16V1
            && let Some(bytes) = &proof.backend_proof
        {
            return crate::proofs::groth16_backend::verify_training_groth16(
                &verification_key.verifying_key,
                public_inputs,
                bytes,
            );
        }
    }

    verify_proof(
        verification_key,
        CircuitKind::Training,
        public_inputs,
        proof,
    )
}

fn verify_proof<T: Serialize>(
    verification_key: &VerificationKey,
    expected_circuit: CircuitKind,
    public_inputs: &T,
    proof: &Proof,
) -> Result<(), ZkProofError> {
    if proof.circuit != expected_circuit {
        return Err(ZkProofError::VerificationFailed(format!(
            "proof circuit {:?} does not match expected {:?}",
            proof.circuit, expected_circuit
        )));
    }

    if proof.scheme != ProofScheme::DevelopmentSignedTranscriptV1 {
        return Err(ZkProofError::VerificationFailed(
            "unsupported proof scheme".to_owned(),
        ));
    }

    let expected_statement_digest = utils::hash_serializable(public_inputs)?;
    if proof.statement_digest != expected_statement_digest {
        return Err(ZkProofError::VerificationFailed(
            "statement digest does not match the supplied public inputs".to_owned(),
        ));
    }

    let message = transcript_message(
        proof.circuit,
        proof.scheme,
        proof.statement_digest,
        proof.constraint_digest,
        public_inputs,
    )?;

    let signature_bytes: [u8; 64] = proof
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| ZkProofError::VerificationFailed("invalid signature length".to_owned()))?;
    let signature = Signature::from_bytes(&signature_bytes);
    let verifying_key =
        VerifyingKey::from_bytes(&verification_key.verifying_key).map_err(|error| {
            ZkProofError::VerificationFailed(format!("invalid verification key: {error}"))
        })?;

    verifying_key.verify(&message, &signature).map_err(|error| {
        ZkProofError::VerificationFailed(format!("signature verification failed: {error}"))
    })
}
