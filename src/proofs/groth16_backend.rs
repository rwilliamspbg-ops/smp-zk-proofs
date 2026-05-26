//! Minimal mock Groth16 backend (opt-in via `groth16` feature)
//!
//! This is a lightweight placeholder used during Phase A to wire the proving
//! and verification plumbing without depending on heavy arkworks APIs. The
//! blob returned is a simple deterministic marker that the verifier checks.

#![cfg(feature = "groth16")]

use crate::ZkProofError;
use crate::proofs::types::{LocationPrivateWitness, LocationPublicInputs, TrainingPrivateWitness, TrainingPublicInputs};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof, Proof as GrothProof, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::uint::UInt32;
use rand::rngs::OsRng;

// Real R1CS Location circuit: private `x,y` (u32), public bounding box
// `x_min,x_max,y_min,y_max` (u32). Enforces x_min <= x <= x_max and same for y
// using UInt32 comparison gadgets.
struct LocationR1CS {
    x: u32,
    y: u32,
    x_min: u32,
    x_max: u32,
    y_min: u32,
    y_max: u32,
}

impl ConstraintSynthesizer<Fr> for LocationR1CS {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x_var = UInt32::<Fr>::new_witness(cs.clone(), || Ok(self.x))?;
        let y_var = UInt32::<Fr>::new_witness(cs.clone(), || Ok(self.y))?;

        let x_min_var = UInt32::<Fr>::new_input(cs.clone(), || Ok(self.x_min))?;
        let x_max_var = UInt32::<Fr>::new_input(cs.clone(), || Ok(self.x_max))?;
        let y_min_var = UInt32::<Fr>::new_input(cs.clone(), || Ok(self.y_min))?;
        let y_max_var = UInt32::<Fr>::new_input(cs.clone(), || Ok(self.y_max))?;

        // enforce x_min <= x <= x_max
        x_var.enforce_cmp(&x_min_var, core::cmp::Ordering::GreaterOrEqual)?;
        x_var.enforce_cmp(&x_max_var, core::cmp::Ordering::LessOrEqual)?;

        // enforce y_min <= y <= y_max
        y_var.enforce_cmp(&y_min_var, core::cmp::Ordering::GreaterOrEqual)?;
        y_var.enforce_cmp(&y_max_var, core::cmp::Ordering::LessOrEqual)?;

        Ok(())
    }
}

fn serialize_with_len<T: CanonicalSerialize>(obj: &T) -> Result<Vec<u8>, ZkProofError> {
    let mut v = Vec::new();
    obj.serialize(&mut v).map_err(|e| ZkProofError::VerificationFailed(format!("serialize error: {e}")))?;
    Ok(v)
}

fn deserialize_vk(bytes: &[u8]) -> Result<VerifyingKey<Bn254>, ZkProofError> {
    let mut cursor = bytes;
    VerifyingKey::<Bn254>::deserialize(&mut cursor).map_err(|e| ZkProofError::VerificationFailed(format!("vk deserialize: {e}")))
}

/// Produce a Groth16 proof for the location circuit. Embeds the verifying key
/// into the returned blob so callers need not manage separate keys for Phase A.
pub fn prove_location_groth16(
    public_inputs: &LocationPublicInputs,
    private_witness: &LocationPrivateWitness,
) -> Result<Vec<u8>, ZkProofError> {
    // Map inputs to u32 (assume non-negative and fit into u32 as agreed)
    let x = private_witness.x as u32;
    let y = private_witness.y as u32;
    let x_min = public_inputs.bounding_box.x_min as u32;
    let x_max = public_inputs.bounding_box.x_max as u32;
    let y_min = public_inputs.bounding_box.y_min as u32;
    let y_max = public_inputs.bounding_box.y_max as u32;

    let circuit = LocationR1CS { x, y, x_min, x_max, y_min, y_max };

    let mut rng = OsRng;
    let params = generate_random_parameters::<Bn254, _, _>(circuit, &mut rng)
        .map_err(|e| ZkProofError::VerificationFailed(format!("param gen: {e}")))?;

    // Rebuild circuit for proof creation (with same witness)
    let circuit_for_prove = LocationR1CS { x, y, x_min, x_max, y_min, y_max };
    let proof = create_random_proof(circuit_for_prove, &params, &mut rng)
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

/// Produce a Groth16 proof for the training circuit. For Phase A we reuse the
/// same location circuit shape as a placeholder; Training will be implemented
/// properly in Phase B.
pub fn prove_training_groth16(
    public_inputs: &TrainingPublicInputs,
    _private_witness: &TrainingPrivateWitness,
) -> Result<Vec<u8>, ZkProofError> {
    // Map to a trivial bounding box and dummy witness derived from inputs to
    // keep signatures consistent.
    let bounding = crate::proofs::types::BoundingBox { x_min: 0, x_max: 0, y_min: 0, y_max: 0 };
    let loc_pub = LocationPublicInputs { bounding_box: bounding, coordinate_commitment: public_inputs.base_model_digest };
    let loc_priv = LocationPrivateWitness { x: 0, y: 0, blinding: [0u8; 32] };
    prove_location_groth16(&loc_pub, &loc_priv)
}

/// Verify a serialized Groth16 proof for the location circuit. The vk is
/// embedded in the proof blob as produced by `prove_location_groth16`.
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

    let mut proof_cursor = proof_bytes;
    let proof = GrothProof::<Bn254>::deserialize(&mut proof_cursor)
        .map_err(|e| ZkProofError::VerificationFailed(format!("proof deserialize: {e}")))?;

    // Build public inputs vector: x_min,x_max,y_min,y_max as field elements
    let mut public_frs = Vec::new();
    public_frs.push(Fr::from(public_inputs.bounding_box.x_min as u64));
    public_frs.push(Fr::from(public_inputs.bounding_box.x_max as u64));
    public_frs.push(Fr::from(public_inputs.bounding_box.y_min as u64));
    public_frs.push(Fr::from(public_inputs.bounding_box.y_max as u64));

    verify_proof(&pvk, &proof, &public_frs).map_err(|e| ZkProofError::VerificationFailed(format!("verify: {e}")))
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
