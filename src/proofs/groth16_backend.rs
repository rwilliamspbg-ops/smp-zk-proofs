//! Groth16 backend using arkworks (opt-in via `groth16` feature)
//!
//! This module provides real Groth16 proof generation and verification
//! using the LocationR1CS circuit for bounding box constraints.

use crate::ZkProofError;
use crate::proofs::types::{
    LocationPrivateWitness, LocationPublicInputs, TrainingPrivateWitness, TrainingPublicInputs,
};

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof as GrothProof, VerifyingKey, prepare_verifying_key};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use rand::rngs::OsRng;
use std::io::Cursor;

// Re-export the LocationR1CS circuit
pub use super::groth16_circuits::LocationR1CS;

#[derive(Clone)]
/// R1CS circuit that enforces `steps_completed == expected_steps` and
/// `observed_loss <= max_loss`.
pub struct TrainingR1CS {
    /// Private number of training steps completed (witness).
    pub steps_completed: u32,
    /// Private observed training loss in milli-units (witness).
    pub observed_loss: u64,
    /// Expected step count (public input).
    pub expected_steps: u32,
    /// Maximum allowed loss in milli-units (public input).
    pub max_loss: u64,
}

impl ConstraintSynthesizer<Fr> for TrainingR1CS {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let steps_var =
            FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(self.steps_completed)))?;
        let loss_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(self.observed_loss)))?;

        let expected_steps_var =
            FpVar::<Fr>::new_input(cs.clone(), || Ok(Fr::from(self.expected_steps)))?;
        let max_loss_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(Fr::from(self.max_loss)))?;

        // Enforce steps_completed == expected_steps (exact match required)
        steps_var.enforce_equal(&expected_steps_var)?;

        // Enforce observed_loss <= max_loss
        let lt_loss = loss_var.is_cmp(&max_loss_var, core::cmp::Ordering::Less, true)?;
        let eq_loss = loss_var.is_eq(&max_loss_var)?;
        let le_loss = Boolean::kary_or(&[lt_loss, eq_loss])?;
        le_loss.enforce_equal(&Boolean::TRUE)?;

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

fn non_negative_i64_to_u32(value: i64, field: &str) -> Result<u32, ZkProofError> {
    u32::try_from(value).map_err(|_| {
        ZkProofError::InvalidPublicInputs(format!("{field} must be a non-negative 32-bit integer"))
    })
}

/// Produce a Groth16 proof for the location circuit using LocationR1CS
pub fn prove_location_groth16(
    public_inputs: &LocationPublicInputs,
    private_witness: &LocationPrivateWitness,
) -> Result<Vec<u8>, ZkProofError> {
    // Create the R1CS circuit with actual witness values
    let circuit = LocationR1CS {
        x: non_negative_i64_to_u32(private_witness.x, "x")?,
        y: non_negative_i64_to_u32(private_witness.y, "y")?,
        x_min: non_negative_i64_to_u32(public_inputs.bounding_box.x_min, "x_min")?,
        x_max: non_negative_i64_to_u32(public_inputs.bounding_box.x_max, "x_max")?,
        y_min: non_negative_i64_to_u32(public_inputs.bounding_box.y_min, "y_min")?,
        y_max: non_negative_i64_to_u32(public_inputs.bounding_box.y_max, "y_max")?,
    };

    let mut rng = OsRng;
    // WARNING: this generates a fresh ephemeral trusted setup on every call.
    // In production, generate parameters once, persist them, and pass them in
    // to avoid the per-call cost and to use a proper MPC ceremony.
    let params =
        Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng)
            .map_err(|e| ZkProofError::VerificationFailed(format!("param gen: {e}")))?;

    // ark-groth16 panics (assert!) when R1CS constraints are unsatisfied.
    // Wrap in catch_unwind to surface that as a proper ZkProofError.
    let proof = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &params, &mut OsRng)
    }))
    .map_err(|_| ZkProofError::VerificationFailed("R1CS constraints unsatisfied".to_owned()))?
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

/// Produce a Groth16 proof for the training circuit using TrainingR1CS
pub fn prove_training_groth16(
    public_inputs: &TrainingPublicInputs,
    private_witness: &TrainingPrivateWitness,
) -> Result<Vec<u8>, ZkProofError> {
    let circuit = TrainingR1CS {
        steps_completed: private_witness.steps_completed,
        observed_loss: private_witness.observed_loss_milli,
        expected_steps: public_inputs.expected_steps,
        max_loss: public_inputs.max_loss_milli,
    };

    let mut rng = OsRng;
    // WARNING: ephemeral trusted setup — see prove_location_groth16 for details.
    let params =
        Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng)
            .map_err(|e| ZkProofError::VerificationFailed(format!("param gen: {e}")))?;

    // ark-groth16 panics (debug_assert) when the R1CS is unsatisfied, so we
    // catch that panic and surface it as a proper ZkProofError instead.
    let proof = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &params, &mut OsRng)
    }))
    .map_err(|_| ZkProofError::VerificationFailed("R1CS constraints unsatisfied".to_owned()))?
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

/// Verify a serialized Groth16 proof for the location circuit
pub fn verify_location_groth16(
    _verification_key: &[u8],
    public_inputs: &LocationPublicInputs,
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

    let public_frs = vec![
        Fr::from(non_negative_i64_to_u32(
            public_inputs.bounding_box.x_min,
            "x_min",
        )?),
        Fr::from(non_negative_i64_to_u32(
            public_inputs.bounding_box.x_max,
            "x_max",
        )?),
        Fr::from(non_negative_i64_to_u32(
            public_inputs.bounding_box.y_min,
            "y_min",
        )?),
        Fr::from(non_negative_i64_to_u32(
            public_inputs.bounding_box.y_max,
            "y_max",
        )?),
    ];

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

/// Verify a serialized Groth16 proof for the training circuit
pub fn verify_training_groth16(
    _verification_key: &[u8],
    public_inputs: &TrainingPublicInputs,
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

    let public_frs = vec![
        Fr::from(public_inputs.expected_steps),
        Fr::from(public_inputs.max_loss_milli),
    ];

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
