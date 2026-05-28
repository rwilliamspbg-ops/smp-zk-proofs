use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;

use crate::{
    ConstraintReport, LocationCircuit, TrainingCircuit, ZkProofError,
    constraints::Circuit,
    proofs::{transcript_message, types::*},
    utils,
};

#[derive(Debug)]
pub struct ProvingContext {
    signing_key: SigningKey,
}

impl ProvingContext {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn verification_key(&self) -> VerificationKey {
        VerificationKey {
            verifying_key: self.signing_key.verifying_key().to_bytes(),
        }
    }
}

pub fn prove_location(
    context: &ProvingContext,
    public_inputs: &LocationPublicInputs,
    private_witness: &LocationPrivateWitness,
) -> Result<Proof, ZkProofError> {
    let report = LocationCircuit.evaluate(public_inputs, private_witness)?;
    sign_proof(context, public_inputs, report)
}

pub fn prove_training(
    context: &ProvingContext,
    public_inputs: &TrainingPublicInputs,
    private_witness: &TrainingPrivateWitness,
) -> Result<Proof, ZkProofError> {
    let report = TrainingCircuit.evaluate(public_inputs, private_witness)?;
    sign_proof(context, public_inputs, report)
}

#[cfg(feature = "halo2")]
pub fn prove_location_halo2(
    _context: &ProvingContext,
    public_inputs: &LocationPublicInputs,
    private_witness: &LocationPrivateWitness,
) -> Result<Proof, ZkProofError> {
    // Build a Halo2 proof (scaffold) and wrap it into the existing `Proof` type.
    let proof_bytes = crate::proofs::halo2_backend::prove_location_halo2(public_inputs, private_witness)?;
    let report = LocationCircuit.evaluate(public_inputs, private_witness)?;
    let statement_digest = utils::hash_serializable(public_inputs)?;
    let constraint_digest = report.digest()?;

    Ok(Proof {
        circuit: report.circuit,
        scheme: ProofScheme::Halo2V1,
        statement_digest,
        constraint_digest,
        signature: Vec::new(),
        backend_proof: Some(proof_bytes),
    })
}

#[cfg(feature = "halo2")]
pub fn prove_training_halo2(
    _context: &ProvingContext,
    public_inputs: &TrainingPublicInputs,
    private_witness: &TrainingPrivateWitness,
) -> Result<Proof, ZkProofError> {
    let proof_bytes = crate::proofs::halo2_backend::prove_training_halo2(public_inputs, private_witness)?;
    let report = TrainingCircuit.evaluate(public_inputs, private_witness)?;
    let statement_digest = utils::hash_serializable(public_inputs)?;
    let constraint_digest = report.digest()?;

    Ok(Proof {
        circuit: report.circuit,
        scheme: ProofScheme::Halo2V1,
        statement_digest,
        constraint_digest,
        signature: Vec::new(),
        backend_proof: Some(proof_bytes),
    })
}

#[cfg(feature = "groth16")]
pub fn prove_location_groth16(
    _context: &ProvingContext,
    public_inputs: &LocationPublicInputs,
    private_witness: &LocationPrivateWitness,
) -> Result<Proof, ZkProofError> {
    let proof_bytes = crate::proofs::groth16_backend::prove_location_groth16(public_inputs, private_witness)?;
    let report = LocationCircuit.evaluate(public_inputs, private_witness)?;
    let statement_digest = utils::hash_serializable(public_inputs)?;
    let constraint_digest = report.digest()?;

    Ok(Proof {
        circuit: report.circuit,
        scheme: ProofScheme::Groth16V1,
        statement_digest,
        constraint_digest,
        signature: Vec::new(),
        backend_proof: Some(proof_bytes),
    })
}

#[cfg(feature = "groth16")]
pub fn prove_training_groth16(
    _context: &ProvingContext,
    public_inputs: &TrainingPublicInputs,
    private_witness: &TrainingPrivateWitness,
) -> Result<Proof, ZkProofError> {
    let proof_bytes = crate::proofs::groth16_backend::prove_training_groth16(public_inputs, private_witness)?;
    let report = TrainingCircuit.evaluate(public_inputs, private_witness)?;
    let statement_digest = utils::hash_serializable(public_inputs)?;
    let constraint_digest = report.digest()?;

    Ok(Proof {
        circuit: report.circuit,
        scheme: ProofScheme::Groth16V1,
        statement_digest,
        constraint_digest,
        signature: Vec::new(),
        backend_proof: Some(proof_bytes),
    })
}

fn sign_proof<T: Serialize>(
    context: &ProvingContext,
    public_inputs: &T,
    report: ConstraintReport,
) -> Result<Proof, ZkProofError> {
    let statement_digest = utils::hash_serializable(public_inputs)?;
    let constraint_digest = report.digest()?;
    let scheme = ProofScheme::DevelopmentSignedTranscriptV1;
    let message = transcript_message(
        report.circuit,
        scheme,
        statement_digest,
        constraint_digest,
        public_inputs,
    )?;
    let signature = context.signing_key.sign(&message).to_bytes().to_vec();

    Ok(Proof {
        circuit: report.circuit,
        scheme,
        statement_digest,
        constraint_digest,
        signature,
        backend_proof: None,
    })
}
