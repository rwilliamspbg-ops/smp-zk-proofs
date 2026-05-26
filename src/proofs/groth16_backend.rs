//! Minimal mock Groth16 backend (opt-in via `groth16` feature)
//!
//! This is a lightweight placeholder used during Phase A to wire the proving
//! and verification plumbing without depending on heavy arkworks APIs. The
//! blob returned is a simple deterministic marker that the verifier checks.

#![cfg(feature = "groth16")]

//! Groth16 backend integration using arkworks. This module builds and verifies
//! Groth16 proofs for the `LocationR1CS` circuit. The proof blob format is:
//! [u32 vk_len][vk_bytes][proof_bytes].

use crate::ZkProofError;
use crate::proofs::types::{LocationPrivateWitness, LocationPublicInputs, TrainingPrivateWitness, TrainingPublicInputs};
use crate::proofs::groth16_circuits::LocationR1CS;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof as GrothProof, VerifyingKey, prepare_verifying_key};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Compress, Validate};
use rand::rngs::OsRng;
use std::io::Cursor;

fn serialize_with_len<T: CanonicalSerialize>(obj: &T) -> Result<Vec<u8>, ZkProofError> {
    let mut v = Vec::new();
    obj.serialize(&mut v).map_err(|e| ZkProofError::VerificationFailed(format!("serialize error: {e}")))?;
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

/// Produce a Groth16 proof for the location circuit. Embeds the verifying key
/// in the returned blob so callers need not manage separate VKs for Phase A.
pub fn prove_location_groth16(
    public_inputs: &LocationPublicInputs,
    private_witness: &LocationPrivateWitness,
) -> Result<Vec<u8>, ZkProofError> {
    // Map inputs to u32 (assume non-negative and fit into u32)
    let x = private_witness.x as u32;
    let y = private_witness.y as u32;
    let x_min = public_inputs.bounding_box.x_min as u32;
    let x_max = public_inputs.bounding_box.x_max as u32;
    let y_min = public_inputs.bounding_box.y_min as u32;
    let y_max = public_inputs.bounding_box.y_max as u32;

    let circuit = LocationR1CS { x, y, x_min, x_max, y_min, y_max };

    let mut rng = OsRng;
    let params = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng)
        .map_err(|e| ZkProofError::VerificationFailed(format!("param gen: {e}")))?;

    // Build circuit again for proof creation (witnesses are provided via closures)
    let circuit_for_prove = LocationR1CS { x, y, x_min, x_max, y_min, y_max };
    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(circuit_for_prove, &params, &mut rng)
        .map_err(|e| ZkProofError::VerificationFailed(format!("proof gen: {e}")))?;

    let vk = params.vk;
    let vk_bytes = serialize_with_len(&vk)?;
    let mut proof_bytes = Vec::new();
    proof.serialize(&mut proof_bytes).map_err(|e| ZkProofError::VerificationFailed(format!("proof serialize: {e}")))?;

    let vk_len = (vk_bytes.len() as u32).to_le_bytes();
    let mut out = Vec::with_capacity(4 + vk_bytes.len() + proof_bytes.len());
    out.extend_from_slice(&vk_len);
    out.extend_from_slice(&vk_bytes);
    out.extend_from_slice(&proof_bytes);
    Ok(out)
}

/// Produce a Groth16 proof for the training circuit. Placeholder reusing the
/// location proving path for Phase A.
pub fn prove_training_groth16(
    public_inputs: &TrainingPublicInputs,
    _private_witness: &TrainingPrivateWitness,
) -> Result<Vec<u8>, ZkProofError> {
    let bounding = crate::proofs::types::BoundingBox { x_min: 0, x_max: 0, y_min: 0, y_max: 0 };
    let loc_pub = LocationPublicInputs { bounding_box: bounding, coordinate_commitment: public_inputs.base_model_digest };
    let loc_priv = LocationPrivateWitness { x: 0, y: 0, blinding: [0u8; 32] };
    prove_location_groth16(&loc_pub, &loc_priv)
}

/// Verify a serialized Groth16 proof for the location circuit.
pub fn verify_location_groth16(
    _verification_key: &[u8],
    public_inputs: &LocationPublicInputs,
    proof_blob: &[u8],
) -> Result<(), ZkProofError> {
    if proof_blob.len() < 4 {
        return Err(ZkProofError::VerificationFailed("proof blob too short".to_owned()));
    }
    let vk_len = u32::from_le_bytes(proof_blob[0..4].try_into().unwrap()) as usize;
    if proof_blob.len() < 4 + vk_len {
        return Err(ZkProofError::VerificationFailed("invalid proof blob".to_owned()));
    }
    let vk_bytes = &proof_blob[4..4 + vk_len];
    let proof_bytes = &proof_blob[4 + vk_len..];

    let vk = deserialize_vk(vk_bytes)?;
    let pvk = prepare_verifying_key(&vk);

    let proof = deserialize_proof(proof_bytes)?;

    // Build public inputs vector: x_min,x_max,y_min,y_max as field elements
    let mut public_frs = Vec::new();
    public_frs.push(Fr::from(public_inputs.bounding_box.x_min as u64));
    public_frs.push(Fr::from(public_inputs.bounding_box.x_max as u64));
    public_frs.push(Fr::from(public_inputs.bounding_box.y_min as u64));
    public_frs.push(Fr::from(public_inputs.bounding_box.y_max as u64));

    let verified = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_frs)
        .map_err(|e| ZkProofError::VerificationFailed(format!("verify: {e}")))?;
    if verified {
        Ok(())
    } else {
        Err(ZkProofError::VerificationFailed("proof did not verify".to_owned()))
    }
}

/// Verify a serialized Groth16 proof for the training circuit (placeholder).
pub fn verify_training_groth16(
    verification_key: &[u8],
    public_inputs: &TrainingPublicInputs,
    proof_bytes: &[u8],
) -> Result<(), ZkProofError> {
    let _ = (verification_key, public_inputs);
    verify_location_groth16(&[], &LocationPublicInputs { bounding_box: crate::proofs::types::BoundingBox { x_min: 0, x_max: 0, y_min: 0, y_max: 0 }, coordinate_commitment: [0u8; 32] }, proof_bytes)
}
