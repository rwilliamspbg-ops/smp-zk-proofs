use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZkProofError {
    #[error("invalid public inputs: {0}")]
    InvalidPublicInputs(String),
    #[error("constraint not satisfied: {0}")]
    ConstraintUnsatisfied(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("proof verification failed: {0}")]
    VerificationFailed(String),
}

impl From<Box<bincode::ErrorKind>> for ZkProofError {
    fn from(error: Box<bincode::ErrorKind>) -> Self {
        Self::Serialization(error.to_string())
    }
}
