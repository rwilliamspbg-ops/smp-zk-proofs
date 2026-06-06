use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;

use crate::{
    ConstraintReport, LocationCircuit, TrainingCircuit, ZkProofError,
    constraints::Circuit,
    proofs::{transcript_message, types::*},
    utils,
};

/// Holds the Ed25519 signing key used to produce development-scheme proofs.
///
/// # ⚠️ Key generation
///
/// [`ProvingContext::from_seed`] derives a signing key directly from a raw
/// 32-byte seed with no key-derivation function. This is convenient for
/// deterministic testing but **must not be used for production key generation**
/// — use a cryptographically secure RNG and a proper KDF instead.
#[derive(Debug)]
pub struct ProvingContext {
    signing_key: SigningKey,
}

impl ProvingContext {
    /// Create a `ProvingContext` from a raw 32-byte seed.
    ///
    /// # ⚠️ Security note
    ///
    /// The seed is used directly as an Ed25519 scalar — ensure it has at least
    /// 128 bits of entropy and is never reused across contexts.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    /// Return the [`VerificationKey`] corresponding to this context's signing key.
    pub fn verification_key(&self) -> VerificationKey {
        VerificationKey {
            verifying_key: self.signing_key.verifying_key().to_bytes(),
        }
    }
}

/// Prove that a private location witness satisfies the bounding-box constraints
/// declared in `public_inputs`, using the development signed-transcript scheme.
///
/// Returns a [`Proof`] whose signature can be verified with the corresponding
/// [`VerificationKey`] obtained via [`ProvingContext::verification_key`].
///
/// # Errors
///
/// Returns [`ZkProofError::ConstraintUnsatisfied`] if the witness lies outside
/// the declared bounding box, or a serialisation error if hashing fails.
pub fn prove_location(
    context: &ProvingContext,
    public_inputs: &LocationPublicInputs,
    private_witness: &LocationPrivateWitness,
) -> Result<Proof, ZkProofError> {
    let report = LocationCircuit.evaluate(public_inputs, private_witness)?;
    sign_proof(context, public_inputs, report)
}

/// Prove that a private training witness satisfies the step-count and
/// loss-bound constraints declared in `public_inputs`.
///
/// # Errors
///
/// Returns [`ZkProofError::ConstraintUnsatisfied`] if `steps_completed` does
/// not match `expected_steps`, or if `observed_loss_milli` exceeds
/// `max_loss_milli`.
pub fn prove_training(
    context: &ProvingContext,
    public_inputs: &TrainingPublicInputs,
    private_witness: &TrainingPrivateWitness,
) -> Result<Proof, ZkProofError> {
    let report = TrainingCircuit.evaluate(public_inputs, private_witness)?;
    sign_proof(context, public_inputs, report)
}

#[cfg(feature = "halo2")]
/// Wrap a stub Halo2 location proof in the standard [`Proof`] envelope.
/// See [`crate::proofs::halo2_backend`] for the stub caveat.
#[allow(deprecated)]
pub fn prove_location_halo2(
    _context: &ProvingContext,
    public_inputs: &LocationPublicInputs,
    private_witness: &LocationPrivateWitness,
) -> Result<Proof, ZkProofError> {
    // Build a Halo2 proof (scaffold) and wrap it into the existing `Proof` type.
    let proof_bytes =
        crate::proofs::halo2_backend::prove_location_halo2(public_inputs, private_witness)?;
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
/// Wrap a stub Halo2 training proof in the standard [`Proof`] envelope.
#[allow(deprecated)]
pub fn prove_training_halo2(
    _context: &ProvingContext,
    public_inputs: &TrainingPublicInputs,
    private_witness: &TrainingPrivateWitness,
) -> Result<Proof, ZkProofError> {
    let proof_bytes =
        crate::proofs::halo2_backend::prove_training_halo2(public_inputs, private_witness)?;
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
/// Wrap a Groth16 location proof in the standard [`Proof`] envelope.
pub fn prove_location_groth16(
    _context: &ProvingContext,
    public_inputs: &LocationPublicInputs,
    private_witness: &LocationPrivateWitness,
) -> Result<Proof, ZkProofError> {
    let proof_bytes =
        crate::proofs::groth16_backend::prove_location_groth16(public_inputs, private_witness)?;
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
/// Wrap a Groth16 training proof in the standard [`Proof`] envelope.
pub fn prove_training_groth16(
    _context: &ProvingContext,
    public_inputs: &TrainingPublicInputs,
    private_witness: &TrainingPrivateWitness,
) -> Result<Proof, ZkProofError> {
    let proof_bytes =
        crate::proofs::groth16_backend::prove_training_groth16(public_inputs, private_witness)?;
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
