use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZkProofError {
    #[error("invalid public inputs: {0}")]
    InvalidPublicInputs(String),
    #[error("constraint not satisfied: {0}")]
    ConstraintUnsatisfied(String),
    #[error("serialization error: {0}")]
    SerializationFailed(String),
    #[error("deserialization error: {0}")]
    DeserializationFailed(String),
    #[error("proof verification failed: {0}")]
    VerificationFailed(String),
    #[error("setup failed: {0}")]
    SetupFailed(String),
    #[error("proof generation failed: {0}")]
    ProofGenerationFailed(String),
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
