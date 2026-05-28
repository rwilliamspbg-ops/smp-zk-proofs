//! Minimal mock Groth16 backend (opt-in via `groth16` feature)
//!
//! This is a lightweight placeholder used during Phase A to wire the proving
//! and verification plumbing without depending on heavy arkworks APIs. The
//! blob returned is a simple deterministic marker that the verifier checks.

#![cfg(feature = "groth16")]

//! Groth16 backend using a minimal EmptyCircuit to produce valid Groth16 proofs
//! and verification. This allows us to generate/verify real arkworks proofs
//! while the real `LocationR1CS` integration is finalized.

use crate::ZkProofError;
use crate::proofs::types::{
    LocationPrivateWitness, LocationPublicInputs, TrainingPrivateWitness, TrainingPublicInputs,
};

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof as GrothProof, VerifyingKey, prepare_verifying_key};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use rand::rngs::OsRng;
use std::io::Cursor;

/// Empty circuit with no constraints - used to exercise Groth16 plumbing.
struct EmptyCircuit;
impl ConstraintSynthesizer<Fr> for EmptyCircuit {
    fn generate_constraints(self, _cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        Ok(())
    }
}

fn serialize_with_len<T: CanonicalSerialize>(obj: &T) -> Result<Vec<u8>, ZkProofError> {
    let mut v = Vec::new();
    obj.serialize_uncompressed(&mut v)
        .map_err(|e| ZkProofError::VerificationFailed(format!("serialize error: {e}")))?;
    Ok(v)
}

fn deserialize_vk(bytes: &[u8]) -> Result<VerifyingKey<Bn254>, ZkProofError> {
    let mut cursor = Cursor::new(bytes);
    VerifyingKey::<Bn254>::deserialize_with_mode(&mut cursor, Compress::No, Validate::Yes)
        .map_err(|e| ZkProofError::VerificationFailed(format!("vk deserialize: {e}")))
}

fn deserialize_proof(bytes: &[u8]) -> Result<GrothProof<Bn254>, ZkProofError> {
    let mut cursor = Cursor::new(bytes);
    GrothProof::<Bn254>::deserialize_with_mode(&mut cursor, Compress::No, Validate::Yes)
        .map_err(|e| ZkProofError::VerificationFailed(format!("proof deserialize: {e}")))
}

/// Produce a Groth16 proof for the location circuit (EmptyCircuit placeholder).
pub fn prove_location_groth16(
    _public_inputs: &LocationPublicInputs,
    _private_witness: &LocationPrivateWitness,
) -> Result<Vec<u8>, ZkProofError> {
    let circuit = EmptyCircuit;

    let mut rng = OsRng;
    let params = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng)
        .map_err(|e| ZkProofError::VerificationFailed(format!("param gen: {e}")))?;

    let proof =
        Groth16::<Bn254>::create_random_proof_with_reduction(EmptyCircuit, &params, &mut rng)
            .map_err(|e| ZkProofError::VerificationFailed(format!("proof gen: {e}")))?;

    let vk = params.vk;
    let vk_bytes = serialize_with_len(&vk)?;
    let mut proof_bytes = Vec::new();
    proof
        .serialize_uncompressed(&mut proof_bytes)
        .map_err(|e| ZkProofError::VerificationFailed(format!("proof serialize: {e}")))?;

    let vk_len = (vk_bytes.len() as u32).to_le_bytes();
    let mut out = Vec::with_capacity(4 + vk_bytes.len() + proof_bytes.len());
    out.extend_from_slice(&vk_len);
    out.extend_from_slice(&vk_bytes);
    out.extend_from_slice(&proof_bytes);
    Ok(out)
}

/// Produce a Groth16 proof for the training circuit (placeholder using EmptyCircuit).
pub fn prove_training_groth16(
    _public_inputs: &TrainingPublicInputs,
    _private_witness: &TrainingPrivateWitness,
) -> Result<Vec<u8>, ZkProofError> {
    prove_location_groth16(
        &LocationPublicInputs {
            bounding_box: crate::proofs::types::BoundingBox {
                x_min: 0,
                x_max: 0,
                y_min: 0,
                y_max: 0,
            },
            coordinate_commitment: [0u8; 32],
        },
        &LocationPrivateWitness {
            x: 0,
            y: 0,
            blinding: [0u8; 32],
        },
    )
}

/// Verify a serialized Groth16 proof for the location circuit (EmptyCircuit).
pub fn verify_location_groth16(
    _verification_key: &[u8],
    _public_inputs: &LocationPublicInputs,
    proof_blob: &[u8],
) -> Result<(), ZkProofError> {
    if proof_blob.len() < 4 {
        return Err(ZkProofError::VerificationFailed(
            "proof blob too short".to_owned(),
        ));
    }
    let vk_len = u32::from_le_bytes(proof_blob[0..4].try_into().unwrap()) as usize;
    if proof_blob.len() < 4 + vk_len {
        return Err(ZkProofError::VerificationFailed(
            "invalid proof blob".to_owned(),
        ));
    }
    let vk_bytes = &proof_blob[4..4 + vk_len];
    let proof_bytes = &proof_blob[4 + vk_len..];

    let vk = deserialize_vk(vk_bytes)?;
    let pvk = prepare_verifying_key(&vk);

    let proof = deserialize_proof(proof_bytes)?;

    // Empty public inputs for the placeholder circuit
    let public_frs: Vec<Fr> = Vec::new();

    let verified = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_frs)
        .map_err(|e| ZkProofError::VerificationFailed(format!("verify: {e}")))?;
    if verified {
        Ok(())
    } else {
        Err(ZkProofError::VerificationFailed(
            "proof did not verify".to_owned(),
        ))
    }
}

/// Verify a serialized Groth16 proof for the training circuit (placeholder).
pub fn verify_training_groth16(
    verification_key: &[u8],
    public_inputs: &TrainingPublicInputs,
    proof_bytes: &[u8],
) -> Result<(), ZkProofError> {
    let _ = (verification_key, public_inputs);
    verify_location_groth16(
        &[],
        &LocationPublicInputs {
            bounding_box: crate::proofs::types::BoundingBox {
                x_min: 0,
                x_max: 0,
                y_min: 0,
                y_max: 0,
            },
            coordinate_commitment: [0u8; 32],
        },
        proof_bytes,
    )
}
