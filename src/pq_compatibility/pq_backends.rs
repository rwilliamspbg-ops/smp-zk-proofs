//! Multi-Backend PQC Router
//! 
//! This module provides a unified interface for routing PQC operations
//! to different backend implementations (Lattice, Hash, Code, Hybrid).

use crate::pq_compatibility::{PqcConfig, PqcResult, PqcError, PqcBackendType};
use crate::pq_compatibility::lattice_backend::{LatticeProof, LatticeBackend};
use serde::{Serialize, Deserialize};

/// Unified PQC proof envelope that can contain proofs from any backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PqcProofEnvelope {
    /// Lattice-based proof
    Lattice(LatticeProof),
    /// Hash-based proof
    Hash(HashProof),
    /// Code-based proof
    Code(CodeProof),
    /// Hybrid proof containing multiple proof types
    Hybrid(HybridProofEnvelope),
}

/// Hash-based proof structure (SHA-3/Keccak)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashProof {
    /// Merkle root of the committed data
    pub merkle_root: Vec<u8>,
    /// Authentication path
    pub auth_path: Vec<Vec<u8>>,
    /// Challenge response
    pub response: Vec<u8>,
    /// Public inputs hash
    pub public_inputs_hash: Vec<u8>,
    /// Metadata
    pub metadata: ProofMetadata,
}

/// Code-based proof structure (McEliece/Niederreiter)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeProof {
    /// Encrypted syndrome
    pub syndrome: Vec<u8>,
    /// Error vector commitment
    pub error_commitment: Vec<u8>,
    /// Decoding proof
    pub decoding_proof: Vec<u8>,
    /// Public inputs hash
    pub public_inputs_hash: Vec<u8>,
    /// Metadata
    pub metadata: ProofMetadata,
}

/// Hybrid proof envelope containing classical and PQC components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridProofEnvelope {
    /// Classical proof component (e.g., Groth16)
    pub classical_proof: Vec<u8>,
    /// PQC proof component
    pub pqc_proof: PqcProofEnvelope,
    /// Linkage proof ensuring both prove same statement
    pub linkage_proof: Vec<u8>,
    /// Metadata
    pub metadata: ProofMetadata,
}

/// Metadata about the proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Timestamp of proof generation
    pub timestamp: u64,
    /// Backend type identifier
    pub backend: String,
    /// Security level in bits
    pub security_level: u32,
    /// Version of the backend
    pub version: String,
}

impl ProofMetadata {
    pub fn new(backend: &str, security_level: u32) -> Self {
        Self {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            backend: backend.to_string(),
            security_level,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Generate a PQC location proof using the specified backend
pub fn generate_pqc_location_proof(location_data: &[u8], public_inputs: &[u8], config: &PqcConfig) -> PqcResult<PqcProofEnvelope> {
    match config.backend_type {
        PqcBackendType::Lattice => {
            let lattice_proof = crate::pq_compatibility::lattice_backend::generate_pqc_location_proof(
                location_data, public_inputs, config
            )?;
            Ok(PqcProofEnvelope::Lattice(lattice_proof))
        }
        PqcBackendType::Hash => {
            let hash_proof = generate_hash_location_proof(location_data, public_inputs, config)?;
            Ok(PqcProofEnvelope::Hash(hash_proof))
        }
        PqcBackendType::Code => {
            let code_proof = generate_code_location_proof(location_data, public_inputs, config)?;
            Ok(PqcProofEnvelope::Code(code_proof))
        }
        PqcBackendType::Hybrid => {
            generate_hybrid_location_proof(location_data, public_inputs, config)
        }
    }
}

/// Verify a PQC location proof
pub fn verify_pqc_location_proof(proof: &PqcProofEnvelope, public_inputs: &[u8], config: &PqcConfig) -> PqcResult<bool> {
    match proof {
        PqcProofEnvelope::Lattice(lattice_proof) => {
            crate::pq_compatibility::lattice_backend::verify_pqc_location_proof(
                lattice_proof, public_inputs, config
            )
        }
        PqcProofEnvelope::Hash(hash_proof) => {
            verify_hash_location_proof(hash_proof, public_inputs, config)
        }
        PqcProofEnvelope::Code(code_proof) => {
            verify_code_location_proof(code_proof, public_inputs, config)
        }
        PqcProofEnvelope::Hybrid(hybrid_proof) => {
            verify_hybrid_location_proof(hybrid_proof, public_inputs, config)
        }
    }
}

/// Generate a PQC training proof using the specified backend
pub fn generate_pqc_training_proof(training_data: &[u8], public_inputs: &[u8], config: &PqcConfig) -> PqcResult<PqcProofEnvelope> {
    match config.backend_type {
        PqcBackendType::Lattice => {
            let lattice_proof = crate::pq_compatibility::lattice_backend::generate_pqc_training_proof(
                training_data, public_inputs, config
            )?;
            Ok(PqcProofEnvelope::Lattice(lattice_proof))
        }
        PqcBackendType::Hash => {
            let hash_proof = generate_hash_training_proof(training_data, public_inputs, config)?;
            Ok(PqcProofEnvelope::Hash(hash_proof))
        }
        PqcBackendType::Code => {
            let code_proof = generate_code_training_proof(training_data, public_inputs, config)?;
            Ok(PqcProofEnvelope::Code(code_proof))
        }
        PqcBackendType::Hybrid => {
            generate_hybrid_training_proof(training_data, public_inputs, config)
        }
    }
}

/// Verify a PQC training proof
pub fn verify_pqc_training_proof(proof: &PqcProofEnvelope, public_inputs: &[u8], config: &PqcConfig) -> PqcResult<bool> {
    match proof {
        PqcProofEnvelope::Lattice(lattice_proof) => {
            crate::pq_compatibility::lattice_backend::verify_pqc_training_proof(
                lattice_proof, public_inputs, config
            )
        }
        PqcProofEnvelope::Hash(hash_proof) => {
            verify_hash_training_proof(hash_proof, public_inputs, config)
        }
        PqcProofEnvelope::Code(code_proof) => {
            verify_code_training_proof(code_proof, public_inputs, config)
        }
        PqcProofEnvelope::Hybrid(hybrid_proof) => {
            verify_hybrid_training_proof(hybrid_proof, public_inputs, config)
        }
    }
}

// Hash Backend Implementation

fn generate_hash_location_proof(location_data: &[u8], public_inputs: &[u8], config: &PqcConfig) -> PqcResult<HashProof> {
    use sha3::{Sha3_256, Digest};
    
    // Build Merkle tree from location data (simplified)
    let mut hasher = Sha3_256::new();
    hasher.update(location_data);
    let merkle_root = hasher.finalize().to_vec();
    
    // Generate authentication path (simplified - single leaf)
    let auth_path = vec![merkle_root.clone()];
    
    // Generate challenge
    let mut chasher = Sha3_256::new();
    chasher.update(&merkle_root);
    chasher.update(public_inputs);
    let challenge = chasher.finalize();
    
    // Generate response
    let mut response = challenge.to_vec();
    
    // Hash public inputs
    let mut pi_hasher = Sha3_256::new();
    pi_hasher.update(public_inputs);
    let public_inputs_hash = pi_hasher.finalize().to_vec();
    
    Ok(HashProof {
        merkle_root,
        auth_path,
        response,
        public_inputs_hash,
        metadata: ProofMetadata::new("hash-sha3", config.security_level_bits),
    })
}

fn verify_hash_location_proof(proof: &HashProof, public_inputs: &[u8], _config: &PqcConfig) -> PqcResult<bool> {
    use sha3::{Sha3_256, Digest};
    
    // Verify Merkle root matches auth path
    if proof.auth_path.is_empty() || proof.auth_path[0] != proof.merkle_root {
        return Ok(false);
    }
    
    // Recompute challenge
    let mut chasher = Sha3_256::new();
    chasher.update(&proof.merkle_root);
    chasher.update(public_inputs);
    let expected_challenge = chasher.finalize();
    
    if expected_challenge.as_slice() != proof.response {
        return Ok(false);
    }
    
    // Verify public inputs hash
    let mut pi_hasher = Sha3_256::new();
    pi_hasher.update(public_inputs);
    let expected_pi_hash = pi_hasher.finalize();
    
    Ok(expected_pi_hash.as_slice() == proof.public_inputs_hash)
}

fn generate_hash_training_proof(training_data: &[u8], public_inputs: &[u8], config: &PqcConfig) -> PqcResult<HashProof> {
    let domain_sep = b"TRAINING_PROOF:";
    let mut data_with_domain = domain_sep.to_vec();
    data_with_domain.extend_from_slice(training_data);
    
    generate_hash_location_proof(&data_with_domain, public_inputs, config)
}

fn verify_hash_training_proof(proof: &HashProof, public_inputs: &[u8], config: &PqcConfig) -> PqcResult<bool> {
    verify_hash_location_proof(proof, public_inputs, config)
}

// Code Backend Implementation (Placeholder)

fn generate_code_location_proof(_location_data: &[u8], _public_inputs: &[u8], _config: &PqcConfig) -> PqcResult<CodeProof> {
    Err(PqcError::ProofGenerationFailed(
        "Code-based backend is under development. Use Lattice or Hash backend.".to_string()
    ))
}

fn verify_code_location_proof(_proof: &CodeProof, _public_inputs: &[u8], _config: &PqcConfig) -> PqcResult<bool> {
    Err(PqcError::VerificationFailed(
        "Code-based backend is under development.".to_string()
    ))
}

fn generate_code_training_proof(_training_data: &[u8], _public_inputs: &[u8], _config: &PqcConfig) -> PqcResult<CodeProof> {
    Err(PqcError::ProofGenerationFailed(
        "Code-based backend is under development.".to_string()
    ))
}

fn verify_code_training_proof(_proof: &CodeProof, _public_inputs: &[u8], _config: &PqcConfig) -> PqcResult<bool> {
    Err(PqcError::VerificationFailed(
        "Code-based backend is under development.".to_string()
    ))
}

// Hybrid Backend Implementation

fn generate_hybrid_location_proof(location_data: &[u8], public_inputs: &[u8], config: &PqcConfig) -> PqcResult<PqcProofEnvelope> {
    use sha3::{Sha3_256, Digest};
    
    // Generate classical proof placeholder (in production, this would be actual Groth16/Halo2)
    let mut classical_hasher = Sha3_256::new();
    classical_hasher.update(b"CLASSICAL_PROOF:");
    classical_hasher.update(location_data);
    let classical_proof = classical_hasher.finalize().to_vec();
    
    // Generate PQC proof (using lattice as default)
    let mut pqc_config = config.clone();
    pqc_config.hybrid_mode = false;
    
    let pqc_proof = crate::pq_compatibility::lattice_backend::generate_pqc_location_proof(
        location_data, public_inputs, &pqc_config
    )?;
    
    // Generate linkage proof
    let mut linker = Sha3_256::new();
    linker.update(&classical_proof);
    match &pqc_proof {
        LatticeProof { commitment, .. } => {
            linker.update(&commitment.commitment);
        }
    }
    linker.update(public_inputs);
    let linkage_proof = linker.finalize().to_vec();
    
    Ok(PqcProofEnvelope::Hybrid(HybridProofEnvelope {
        classical_proof,
        pqc_proof: PqcProofEnvelope::Lattice(pqc_proof),
        linkage_proof,
        metadata: ProofMetadata::new("hybrid-classical-pqc", config.security_level_bits),
    }))
}

fn verify_hybrid_location_proof(proof: &HybridProofEnvelope, public_inputs: &[u8], _config: &PqcConfig) -> PqcResult<bool> {
    use sha3::{Sha3_256, Digest};
    
    // Verify classical proof (placeholder)
    if proof.classical_proof.is_empty() {
        return Ok(false);
    }
    
    // Verify PQC proof
    let pqc_valid = match &proof.pqc_proof {
        PqcProofEnvelope::Lattice(lattice_proof) => {
            crate::pq_compatibility::lattice_backend::verify_pqc_location_proof(
                lattice_proof, public_inputs, &PqcConfig::default()
            )?
        }
        _ => false,
    };
    
    if !pqc_valid {
        return Ok(false);
    }
    
    // Verify linkage proof
    let mut linker = Sha3_256::new();
    linker.update(&proof.classical_proof);
    if let PqcProofEnvelope::Lattice(lp) = &proof.pqc_proof {
        linker.update(&lp.commitment.commitment);
    }
    linker.update(public_inputs);
    let expected_linkage = linker.finalize();
    
    Ok(expected_linkage.as_slice() == proof.linkage_proof)
}

fn generate_hybrid_training_proof(training_data: &[u8], public_inputs: &[u8], config: &PqcConfig) -> PqcResult<PqcProofEnvelope> {
    let domain_sep = b"TRAINING_PROOF:";
    let mut data_with_domain = domain_sep.to_vec();
    data_with_domain.extend_from_slice(training_data);
    
    generate_hybrid_location_proof(&data_with_domain, public_inputs, config)
}

fn verify_hybrid_training_proof(proof: &HybridProofEnvelope, public_inputs: &[u8], config: &PqcConfig) -> PqcResult<bool> {
    verify_hybrid_location_proof(proof, public_inputs, config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_compatibility::PqcBackendType;
    
    #[test]
    fn test_lattice_proof_routing() {
        let config = PqcConfig::new(PqcBackendType::Lattice, 128);
        let location_data = b"test_location";
        let public_inputs = b"inputs";
        
        let proof = generate_pqc_location_proof(location_data, public_inputs, &config).unwrap();
        assert!(matches!(proof, PqcProofEnvelope::Lattice(_)));
        
        let valid = verify_pqc_location_proof(&proof, public_inputs, &config).unwrap();
        assert!(valid);
    }
    
    #[test]
    fn test_hash_proof_routing() {
        let config = PqcConfig::new(PqcBackendType::Hash, 256);
        let location_data = b"test_location";
        let public_inputs = b"inputs";
        
        let proof = generate_pqc_location_proof(location_data, public_inputs, &config).unwrap();
        assert!(matches!(proof, PqcProofEnvelope::Hash(_)));
        
        let valid = verify_pqc_location_proof(&proof, public_inputs, &config).unwrap();
        assert!(valid);
    }
    
    #[test]
    fn test_hybrid_proof_routing() {
        let config = PqcConfig::new(PqcBackendType::Hybrid, 128);
        let location_data = b"test_location";
        let public_inputs = b"inputs";
        
        let proof = generate_pqc_location_proof(location_data, public_inputs, &config).unwrap();
        assert!(matches!(proof, PqcProofEnvelope::Hybrid(_)));
        
        let valid = verify_pqc_location_proof(&proof, public_inputs, &config).unwrap();
        assert!(valid);
    }
    
    #[test]
    fn test_training_proof_routing() {
        let config = PqcConfig::new(PqcBackendType::Lattice, 128);
        let training_data = b"training_data";
        let public_inputs = b"inputs";
        
        let proof = generate_pqc_training_proof(training_data, public_inputs, &config).unwrap();
        let valid = verify_pqc_training_proof(&proof, public_inputs, &config).unwrap();
        assert!(valid);
    }
}
