# Quick Start Guide - Production Usage

This guide shows how to quickly set up and use `smp-zk-proofs` in a production environment.

## Prerequisites

- Rust 1.91 or newer
- Cargo installed
- For blinding factors: Linux/macOS (for OsRng CSPRNG support)

## Step 1: Add to Your Project

```toml
# In your Cargo.toml
[dependencies]
smp-zk-proofs = { path = "../smp-zk-proofs" }  # Or use published crate when available
```

## Step 2: Enable Production Features

```toml
# Recommended for production
smp-zk-proofs = { 
    version = "0.1",
    features = ["rand"],  # CSPRNG support
    default-features = true
}
```

## Step 3: Basic Production Usage

```rust
use smp_zk_proofs::{
    BoundingBox, LocationPrivateWitness, LocationPublicInputs, 
    ProvingContext, prove_location, verify_location_proof,
    generate_secure_blinding_factor, validate_blinding_factor,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate cryptographically secure blinding factor
    let blinding = generate_secure_blinding_factor()?;
    
    // Validate the blinding factor has sufficient entropy
    validate_blinding_factor(&blinding)?;
    
    // Create proving context
    let context = ProvingContext::from_seed([7u8; 32]);
    
    // Create witness with secure blinding
    let witness = LocationPrivateWitness {
        x: 41,
        y: 12,
        blinding,
    };
    
    // Create public inputs
    let public_inputs = LocationPublicInputs::from_witness(
        BoundingBox {
            x_min: 0,
            x_max: 100,
            y_min: 0,
            y_max: 50,
        },
        &witness,
    )?;

    // Generate proof
    let proof = prove_location(&context, &public_inputs, &witness)?;
    
    // Verify proof
    verify_location_proof(&context.verification_key(), &public_inputs, &proof)?;
    
    println!("✓ Proof generated and verified successfully!");
    
    Ok(())
}
```

## Step 4: Production Error Handling

```rust
use smp_zk_proofs::ZkProofError;

fn generate_proof_with_retry(
    context: &ProvingContext,
    public_inputs: &LocationPublicInputs,
    witness: &LocationPrivateWitness,
    max_retries: u32,
) -> Result<Proof, Error> {
    for attempt in 0..=max_retries {
        match prove_location(context, public_inputs, witness) {
            Ok(proof) => return Ok(proof),
            Err(ZkProofError::ConstraintUnsatisfied(msg)) => {
                // Log constraint failure (not transient)
                error!("Constraint validation failed: {}", msg);
                return Err(Error::ConstraintViolation(msg));
            }
            Err(ZkProofError::SerializationFailed(e)) => {
                // Retry on serialization errors (could be transient)
                if attempt < max_retries {
                    warn!("Serialization failed, retrying...");
                    continue;
                }
                return Err(Error::SerializationFailed(e));
            }
            Err(e) => {
                error!("Unexpected error: {:?}", e);
                return Err(Error::Internal(format!("Unexpected error: {:?}", e)));
            }
        }
    }
    
    Err(Error::MaxRetriesExceeded)
}
```

## Step 5: Batch Proof Generation

```rust
use smp_zk_proofs::{ProvingContext, LocationPrivateWitness};
use tokio::task::JoinHandle;

async fn generate_multiple_proofs(
    context: &ProvingContext,
    witnesses: Vec<LocationPrivateWitness>,
) -> Result<Vec<Proof>, Error> {
    // Spawn tasks for parallel proof generation
    let mut handles = Vec::new();
    
    for witness in witnesses {
        let context_clone = context.clone();
        let handle = tokio::spawn(async move {
            let public_inputs = LocationPublicInputs::from_witness(
                BoundingBox { x_min: 0, x_max: 100, y_min: 0, y_max: 50 },
                &witness,
            )?;
            
            prove_location(&context_clone, &public_inputs, &witness)
        });
        
        handles.push(handle);
    }
    
    // Collect results
    let mut proofs = Vec::with_capacity(handles.len());
    for handle in handles {
        match handle.await {
            Ok(Ok(proof)) => proofs.push(proof),
            Ok(Err(e)) => return Err(e),
            Err(e) => return Err(Error::TaskFailed(format!("Task failed: {:?}", e))),
        }
    }
    
    Ok(proofs)
}
```

## Step 6: Production Monitoring

```rust
use tracing::{info, warn, error};

fn prove_and_monitor(
    context: &ProvingContext,
    public_inputs: &LocationPublicInputs,
    witness: &LocationPrivateWitness,
) -> Result<Proof, Error> {
    let start = std::time::Instant::now();
    
    // Generate proof
    let proof = prove_location(context, public_inputs, witness)?;
    
    let duration = start.elapsed();
    
    // Log with metrics
    info!(
        "Proof generated in {}ms",
        duration.as_millis()
    );
    
    if duration > std::time::Duration::from_secs(1) {
        warn!("Proof generation took longer than 1 second");
    }
    
    Ok(proof)
}
```

## Step 7: Production Configuration

```rust
// Use environment variables for production configuration
use std::env;

struct ProofConfig {
    seed: [u8; 32],
    max_retries: u32,
    timeout_ms: u64,
}

impl ProofConfig {
    fn from_env() -> Result<Self, Error> {
        let seed = env::var("PROOF_SEED")
            .map_err(|_| Error::MissingEnvVar("PROOF_SEED".into()))?
            .as_bytes()
            .try_into()
            .map_err(|_| Error::InvalidEnvVar("PROOF_SEED".into()))?;
        
        let max_retries = env::var("PROOF_MAX_RETRIES")
            .map_err(|_| Error::MissingEnvVar("PROOF_MAX_RETRIES".into()))?
            .parse()
            .map_err(|_| Error::InvalidEnvVar("PROOF_MAX_RETRIES".into()))?;
        
        let timeout_ms = env::var("PROOF_TIMEOUT_MS")
            .map_err(|_| Error::MissingEnvVar("PROOF_TIMEOUT_MS".into()))?
            .parse()
            .map_err(|_| Error::InvalidEnvVar("PROOF_TIMEOUT_MS".into()))?;
        
        Ok(ProofConfig { seed, max_retries, timeout_ms })
    }
}
```

## Step 8: Production Deployment Checklist

- [ ] Enable `rand` feature in Cargo.toml
- [ ] Use `generate_secure_blinding_factor()` for all proofs
- [ ] Validate blinding factors with `validate_blinding_factor()`
- [ ] Implement proper error handling for all operations
- [ ] Add logging with tracing crate
- [ ] Configure monitoring and alerting
- [ ] Set up key rotation procedures
- [ ] Test with production-like workloads
- [ ] Review security guidelines (docs/SECURITY_GUIDELINES.md)

## Common Production Issues

### Issue: Blinding Factor Generation Fails

**Symptom**: `generate_secure_blinding_factor()` returns error

**Solution**: Use deterministic blinding for testing, or ensure OS RNG is available:

```rust
#[cfg(feature = "rand")]
use smp_zk_proofs::generate_deterministic_blinding_factor;

// For testing or environments without OS RNG
let seed = [0u8; 32];
let blinding = generate_deterministic_blinding_factor(seed);
```

### Issue: Proof Generation Timeout

**Symptom**: Proofs take too long to generate

**Solution**: 
1. Use smaller bounding boxes for faster proofs
2. Implement retry logic with backoff
3. Consider parallel proof generation
4. Monitor and optimize circuit complexity

## Next Steps

- Read [SECURITY_GUIDELINES.md](SECURITY_GUIDELINES.md) for security best practices
- Review [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) for full production checklist
- Check [EXAMPLES.md](../EXAMPLES.md) for advanced usage patterns
- See [ROADMAP.md](../ROADMAP.md) for future enhancements

## Support

For production support:
1. Check the GitHub Issues for known problems
2. Review the documentation in `docs/` directory
3. Contact maintainers through GitHub repository
