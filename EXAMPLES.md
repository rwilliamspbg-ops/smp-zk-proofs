# ZK Proof Examples

This document provides practical examples for using the smp-zk-proofs library.

## Table of Contents
- [Basic Location Proof](#basic-location-proof)
- [Training Verification Proof](#training-verification-proof)
- [Multi-Node Aggregation](#multi-node-aggregation)
- [Batch Verification](#batch-verification)
- [Using Groth16 Backend](#using-groth16-backend)
- [Using Halo2 Backend](#using-halo2-backend)

## Basic Location Proof

Prove that a device's coordinates are within a specified bounding box without revealing the exact location.

```rust
use smp_zk_proofs::constraints::{Circuit, LocationCircuit};
use smp_zk_proofs::proofs::types::*;
use smp_zk_proofs::proofs::generator;
use smp_zk_proofs::proofs::verifier;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Define the bounding box (public)
    let bounding_box = BoundingBox {
        x_min: 0,
        x_max: 1000,
        y_min: 0,
        y_max: 1000,
    };
    
    // Private witness: actual coordinates and blinding factor
    let private_witness = LocationPrivateWitness {
        x: 500,  // Secret coordinate
        y: 500,  // Secret coordinate
        blinding: [42u8; 32],  // Random blinding factor
    };
    
    // Create public inputs from witness
    let public_inputs = LocationPublicInputs::from_witness(
        bounding_box,
        &private_witness,
    )?;
    
    // Evaluate circuit constraints locally (optional, for debugging)
    let circuit = LocationCircuit;
    let report = circuit.evaluate(&public_inputs, &private_witness)?;
    println!("Circuit checks passed: {:?}", report.checks);
    
    // Generate a development proof (signed transcript)
    let proof = generator::generate_proof(
        CircuitKind::Location,
        ProofScheme::DevelopmentSignedTranscriptV1,
        &public_inputs,
        &private_witness,
    )?;
    
    // Verify the proof
    let vk = VerificationKey {
        verifying_key: [0u8; 32],
    };
    verifier::verify_proof(&vk, &proof)?;
    
    println!("✓ Location proof verified successfully!");
    Ok(())
}
```

## Training Verification Proof

Prove that a model was trained for the expected number of steps with acceptable loss.

```rust
use smp_zk_proofs::constraints::TrainingCircuit;
use smp_zk_proofs::proofs::types::*;
use smp_zk_proofs::proofs::generator;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Public parameters
    let expected_steps = 1000;
    let max_loss_milli = 10000;  // 10% loss
    let base_model_digest = [1u8; 32];
    
    // Private witness
    let private_witness = TrainingPrivateWitness {
        steps_completed: 1000,
        observed_loss_milli: 5000,  // 5% actual loss
        weight_update_digest: [2u8; 32],
        blinding: [3u8; 32],
    };
    
    // Create public inputs
    let public_inputs = TrainingPublicInputs::from_witness(
        expected_steps,
        max_loss_milli,
        base_model_digest,
        &private_witness,
    )?;
    
    // Generate proof
    let proof = generator::generate_proof(
        CircuitKind::Training,
        ProofScheme::DevelopmentSignedTranscriptV1,
        &public_inputs,
        &private_witness,
    )?;
    
    println!("✓ Training proof generated: {} bytes", proof.signature.len());
    Ok(())
}
```

## Multi-Node Aggregation

Aggregate proofs from multiple nodes in a spatial network.

```rust
use smp_zk_proofs::proofs::types::*;
use smp_zk_proofs::proofs::generator;
use sha2::{Sha256, Digest};

struct NodeProof {
    node_id: u32,
    proof: Proof,
}

fn aggregate_proofs(proofs: Vec<NodeProof>) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut hasher = Sha256::new();
    
    for node_proof in &proofs {
        // Hash each proof
        let proof_bytes = node_proof.proof.to_bytes()?;
        hasher.update(&node_proof.node_id.to_le_bytes());
        hasher.update(&proof_bytes);
    }
    
    let aggregation_hash = hasher.finalize().into();
    println!("✓ Aggregated {} proofs into hash: {:x?}", proofs.len(), aggregation_hash);
    Ok(aggregation_hash)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Simulate multiple nodes generating location proofs
    let mut node_proofs = Vec::new();
    
    for node_id in 0..5 {
        let bounding_box = BoundingBox {
            x_min: node_id * 100,
            x_max: (node_id + 1) * 100,
            y_min: 0,
            y_max: 1000,
        };
        
        let private_witness = LocationPrivateWitness {
            x: node_id as i64 * 100 + 50,
            y: 500,
            blinding: [node_id as u8; 32],
        };
        
        let public_inputs = LocationPublicInputs::from_witness(
            bounding_box,
            &private_witness,
        )?;
        
        let proof = generator::generate_proof(
            CircuitKind::Location,
            ProofScheme::DevelopmentSignedTranscriptV1,
            &public_inputs,
            &private_witness,
        )?;
        
        node_proofs.push(NodeProof { node_id, proof });
    }
    
    // Aggregate all proofs
    let aggregated_hash = aggregate_proofs(node_proofs)?;
    
    Ok(())
}
```

## Batch Verification

Verify multiple proofs efficiently.

```rust
use smp_zk_proofs::proofs::types::*;
use smp_zk_proofs::proofs::verifier;

struct VerificationResult {
    proof_index: usize,
    valid: bool,
    error: Option<String>,
}

fn batch_verify(
    vk: &VerificationKey,
    proofs: &[Proof],
) -> Vec<VerificationResult> {
    let mut results = Vec::with_capacity(proofs.len());
    
    for (i, proof) in proofs.iter().enumerate() {
        match verifier::verify_proof(vk, proof) {
            Ok(()) => {
                results.push(VerificationResult {
                    proof_index: i,
                    valid: true,
                    error: None,
                });
            }
            Err(e) => {
                results.push(VerificationResult {
                    proof_index: i,
                    valid: false,
                    error: Some(e.to_string()),
                });
            }
        }
    }
    
    results
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate multiple proofs
    let mut proofs = Vec::new();
    
    for i in 0..10 {
        let bounding_box = BoundingBox {
            x_min: 0,
            x_max: 1000,
            y_min: 0,
            y_max: 1000,
        };
        
        let private_witness = LocationPrivateWitness {
            x: 500,
            y: 500,
            blinding: [i as u8; 32],
        };
        
        let public_inputs = LocationPublicInputs::from_witness(
            bounding_box,
            &private_witness,
        )?;
        
        let proof = generator::generate_proof(
            CircuitKind::Location,
            ProofScheme::DevelopmentSignedTranscriptV1,
            &public_inputs,
            &private_witness,
        )?;
        
        proofs.push(proof);
    }
    
    // Batch verify
    let vk = VerificationKey {
        verifying_key: [0u8; 32],
    };
    
    let results = batch_verify(&vk, &proofs);
    
    let valid_count = results.iter().filter(|r| r.valid).count();
    println!("✓ Verified {}/{} proofs", valid_count, proofs.len());
    
    Ok(())
}
```

## Using Groth16 Backend

Generate and verify proofs using the Groth16 backend (requires `groth16` feature).

```rust
// Add to Cargo.toml:
// [dependencies]
// smp-zk-proofs = { version = "0.1", features = ["groth16"] }

#[cfg(feature = "groth16")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use smp_zk_proofs::proofs::groth16_backend;
    
    let bounding_box = BoundingBox {
        x_min: 0,
        x_max: 1000,
        y_min: 0,
        y_max: 1000,
    };
    
    let private_witness = LocationPrivateWitness {
        x: 500,
        y: 500,
        blinding: [42u8; 32],
    };
    
    let public_inputs = LocationPublicInputs::from_witness(
        bounding_box,
        &private_witness,
    )?;
    
    // Generate Groth16 proof
    let proof_bytes = groth16_backend::prove_location_groth16(
        &public_inputs,
        &private_witness,
    )?;
    
    println!("✓ Groth16 proof generated: {} bytes", proof_bytes.len());
    
    // Verify Groth16 proof
    groth16_backend::verify_location_groth16(
        &[],
        &public_inputs,
        &proof_bytes,
    )?;
    
    println!("✓ Groth16 proof verified!");
    Ok(())
}

#[cfg(not(feature = "groth16"))]
fn main() {
    println!("Enable groth16 feature: cargo run --features groth16");
}
```

## Using Halo2 Backend

Generate and verify proofs using the Halo2 backend (requires `halo2` feature).

```rust
// Add to Cargo.toml:
// [dependencies]
// smp-zk-proofs = { version = "0.1", features = ["halo2"] }

#[cfg(feature = "halo2")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use smp_zk_proofs::proofs::halo2_backend;
    
    let bounding_box = BoundingBox {
        x_min: 0,
        x_max: 1000,
        y_min: 0,
        y_max: 1000,
    };
    
    let private_witness = LocationPrivateWitness {
        x: 500,
        y: 500,
        blinding: [42u8; 32],
    };
    
    let public_inputs = LocationPublicInputs::from_witness(
        bounding_box,
        &private_witness,
    )?;
    
    // Generate Halo2 proof
    let proof_bytes = halo2_backend::prove_location_halo2(
        &public_inputs,
        &private_witness,
    )?;
    
    println!("✓ Halo2 proof generated: {} bytes", proof_bytes.len());
    
    // Verify Halo2 proof
    halo2_backend::verify_location_halo2(
        &[],
        &public_inputs,
        &proof_bytes,
    )?;
    
    println!("✓ Halo2 proof verified!");
    Ok(())
}

#[cfg(not(feature = "halo2"))]
fn main() {
    println!("Enable halo2 feature: cargo run --features halo2");
}
```

## Running Examples

```bash
# Run basic example
cargo run --example simple_location_proof

# Run with Groth16 backend
cargo run --example simple_location_proof --features groth16

# Run with Halo2 backend
cargo run --example simple_location_proof --features halo2

# Run all tests
cargo test

# Run tests with Groth16
cargo test --features groth16

# Run benchmarks
cargo bench
```

## Best Practices

1. **Blinding Factors**: Always use cryptographically secure random bytes for blinding factors in production.

2. **Bounding Box Validation**: Validate bounding boxes before creating proofs to avoid constraint failures.

3. **Proof Storage**: Store proofs with their corresponding public inputs for later verification.

4. **Backend Selection**: 
   - Use DevelopmentSignedTranscriptV1 for prototyping
   - Use Groth16 for production with small proof sizes
   - Use Halo2 for transparent setup and post-quantum considerations

5. **Error Handling**: Always handle `ZkProofError` variants appropriately in production code.
