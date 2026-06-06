use thiserror::Error;

/// The error type for all `smp-zk-proofs` operations.
#[derive(Debug, Error)]
pub enum ZkProofError {
    /// A public input value (e.g. bounding-box coordinates) is out of range or
    /// otherwise invalid.
    #[error("invalid public inputs: {0}")]
    InvalidPublicInputs(String),
    /// A circuit constraint was not satisfied by the supplied witness.
    #[error("constraint not satisfied: {0}")]
    ConstraintUnsatisfied(String),
    /// Serialisation to bytes failed.
    #[error("serialization error: {0}")]
    SerializationFailed(String),
    /// Deserialisation from bytes failed.
    #[error("deserialization error: {0}")]
    DeserializationFailed(String),
    /// Proof verification failed (wrong key, tampered proof, bad scheme, etc.).
    #[error("proof verification failed: {0}")]
    VerificationFailed(String),
    /// Prover setup (e.g. trusted-setup parameter generation) failed.
    #[error("setup failed: {0}")]
    SetupFailed(String),
    /// Proof generation failed for a reason other than constraint violation.
    #[error("proof generation failed: {0}")]
    ProofGenerationFailed(String),
    /// An underlying I/O error occurred.
    #[error("IO error: {0}")]
    IoError(String),
}

impl From<Box<bincode::ErrorKind>> for ZkProofError {
    fn from(error: Box<bincode::ErrorKind>) -> Self {
        Self::SerializationFailed(error.to_string())
    }
}

impl From<std::io::Error> for ZkProofError {
    fn from(error: std::io::Error) -> Self {
        Self::IoError(error.to_string())
    }
}
