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
    })
}
