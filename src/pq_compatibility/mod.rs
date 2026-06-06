//! Post-Quantum Cryptography Compatibility Module
//!
//! This module provides a comprehensive post-quantum cryptography (PQC) integration
//! for zero-knowledge proofs, supporting multiple quantum-resistant backends including
//! lattice-based, hash-based, and code-based cryptographic schemes.
//!
//! ## Features
//!
//! - **Multiple PQC Backends**: Lattice (Kyber-inspired), Hash (SHA-3/Keccak), Code-based
//! - **Hybrid Mode**: Classical + PQC proofs for gradual migration
//! - **Migration Tools**: Automated tools for transitioning existing proofs
//! - **Security Metrics**: NIST security level tracking and validation
//!
//! ## Example Usage
//!
//! ```rust
//! use smp_zk_proofs::pq_compatibility::{
//!     PqcBackendType, PqcConfig, generate_pqc_location_proof, verify_pqc_location_proof
//! };
//!
//! // Configure PQC backend with 128-bit security
//! let config = PqcConfig::new(PqcBackendType::Lattice, 128);
//!
//! // Generate a PQC location proof
//! let proof = generate_pqc_location_proof(&location_data, &config)?;
//!
//! // Verify the proof
//! let is_valid = verify_pqc_location_proof(&proof, &public_inputs, &config)?;
//! ```

/// Status of the post-quantum backend implementation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostQuantumBackendStatus {
    /// Backend is reserved for future implementation
    Reserved,
    /// Backend is planned but not yet implemented
    Planned,
    /// Backend is ready for production use
    Ready,
}

/// Descriptor providing metadata about a post-quantum backend
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostQuantumBackendDescriptor {
    /// Human-readable name of the backend
    pub name: &'static str,
    /// Current implementation status
    pub status: PostQuantumBackendStatus,
    /// Additional notes about the backend
    pub notes: &'static str,
    /// Steps required for migration to this backend
    pub migration_steps: &'static [&'static str],
}

/// Core trait that all post-quantum backends must implement
pub trait PostQuantumBackend {
    /// Returns the descriptor for this backend
    fn descriptor(&self) -> PostQuantumBackendDescriptor;
}

/// Type identifier for different PQC backend algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqcBackendType {
    /// Lattice-based cryptography (Kyber/Dilithium inspired)
    Lattice,
    /// Hash-based cryptography (SHA-3/Keccak based)
    Hash,
    /// Code-based cryptography (McEliece/Niederreiter)
    Code,
    /// Hybrid mode combining classical and PQC
    Hybrid,
}

impl PqcBackendType {
    /// Returns the NIST security level for common parameter sets
    pub fn get_nist_security_level(&self) -> u32 {
        match self {
            PqcBackendType::Lattice => 3, // AES-192 equivalent
            PqcBackendType::Hash => 5,    // AES-256 equivalent
            PqcBackendType::Code => 5,    // AES-256 equivalent
            PqcBackendType::Hybrid => 3,  // Minimum of components
        }
    }

    /// Check if this backend is production-ready
    pub fn is_production_ready(&self) -> bool {
        matches!(
            self,
            PqcBackendType::Lattice | PqcBackendType::Hash | PqcBackendType::Hybrid
        )
    }
}

/// Configuration for PQC operations
#[derive(Debug, Clone)]
pub struct PqcConfig {
    /// The backend type to use
    pub backend_type: PqcBackendType,
    /// Target security level in bits (e.g., 128, 192, 256)
    pub security_level_bits: u32,
    /// Enable hybrid mode (classical + PQC)
    pub hybrid_mode: bool,
    /// Custom parameters for specific backends
    pub custom_params: std::collections::HashMap<String, String>,
}

impl PqcConfig {
    /// Create a new PQC configuration
    pub fn new(backend_type: PqcBackendType, security_level_bits: u32) -> Self {
        Self {
            backend_type,
            security_level_bits,
            hybrid_mode: false,
            custom_params: std::collections::HashMap::new(),
        }
    }

    /// Enable hybrid mode
    pub fn with_hybrid_mode(mut self, enabled: bool) -> Self {
        self.hybrid_mode = enabled;
        self
    }

    /// Add a custom parameter
    pub fn with_param(mut self, key: &str, value: &str) -> Self {
        self.custom_params
            .insert(key.to_string(), value.to_string());
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), PqcError> {
        if self.security_level_bits < 128 {
            return Err(PqcError::InsufficientSecurityLevel(
                self.security_level_bits,
            ));
        }

        if !self.backend_type.is_production_ready() && !cfg!(test) {
            return Err(PqcError::BackendNotReady(self.backend_type));
        }

        Ok(())
    }
}

impl Default for PqcConfig {
    fn default() -> Self {
        Self::new(PqcBackendType::Lattice, 128)
    }
}

/// Error types for PQC operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum PqcError {
    #[error("Insufficient security level: {0} bits (minimum 128)")]
    InsufficientSecurityLevel(u32),

    #[error("Backend {0:?} is not ready for production use")]
    BackendNotReady(PqcBackendType),

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid proof format: {0}")]
    InvalidProofFormat(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Hybrid proof mismatch: {0}")]
    HybridMismatch(String),
}

/// Result type for PQC operations
pub type PqcResult<T> = Result<T, PqcError>;

// Sub-modules
pub mod hybrid_mode;
pub mod lattice_backend;
pub mod migration;
pub mod pq_backends;

pub use hybrid_mode::*;
pub use migration::*;
pub use pq_backends::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_config_creation() {
        let config = PqcConfig::new(PqcBackendType::Lattice, 128);
        assert_eq!(config.backend_type, PqcBackendType::Lattice);
        assert_eq!(config.security_level_bits, 128);
        assert!(!config.hybrid_mode);
    }

    #[test]
    fn test_pqc_config_validation() {
        let config = PqcConfig::new(PqcBackendType::Lattice, 128);
        assert!(config.validate().is_ok());

        let weak_config = PqcConfig::new(PqcBackendType::Lattice, 64);
        assert!(weak_config.validate().is_err());
    }

    #[test]
    fn test_hybrid_mode_config() {
        let config = PqcConfig::new(PqcBackendType::Lattice, 128)
            .with_hybrid_mode(true)
            .with_param("optimization", "speed");

        assert!(config.hybrid_mode);
        assert_eq!(
            config.custom_params.get("optimization"),
            Some(&"speed".to_string())
        );
    }
}
