# Security Guidelines for Production Usage

This document provides security guidelines for using `smp-zk-proofs` in production environments.

## Cryptographic Best Practices

### 1. Always Use CSPRNG for Blinding Factors

**❌ Never use fixed or predictable values:**

```rust
// INSECURE - Do not use in production
let blinding = [0u8; 32];  // All zeros - CRITICAL VULNERABILITY
let blinding = [42u8; 32]; // Fixed value - CRITICAL VULNERABILITY
```

**✅ Use CSPRNG for production:**

```rust
#[cfg(feature = "rand")]
use smp_zk_proofs::generate_secure_blinding_factor;

let blinding = generate_secure_blinding_factor()?;
// This uses OS CSPRNG (OsRng) for cryptographically secure randomness
```

### 2. Validate Blinding Factor Entropy

**Always validate before use:**

```rust
use smp_zk_proofs::validate_blinding_factor;

let result = validate_blinding_factor(&blinding);
if result.is_err() {
    error!("Blinding factor has insufficient entropy: {:?}", result.err());
}
```

### 3. Use Constant-Time Comparisons

**For sensitive data comparisons:**

```rust
#[cfg(feature = "constant_time_eq")]
use smp_zk_proofs::constant_time_eq_bytes;

// Prevents timing attacks
if constant_time_eq_bytes(&expected_blinding, &received_blinding) {
    // Proceed with sensitive operation
}
```

## Key Management

### Verification Key Distribution

- **Use TLS** for key distribution in production
- **Authenticate keys** using digital signatures or HMAC
- **Implement key rotation** policies (e.g., rotate every 30 days)
- **Log all key operations** with sufficient context (but not sensitive data)

```rust
// Example: Secure key verification before use
fn verify_key_integrity(key: &VerificationKey, expected_hash: &[u8; 32]) -> Result<(), Error> {
    let computed_hash = hash_serializable(key)?;
    if computed_hash != *expected_hash {
        return Err(Error::KeyTampering("Verification key integrity check failed".into()));
    }
    Ok(())
}
```

### Key Storage

- **Never store keys in plaintext** in configuration files
- **Use secure key stores** (e.g., AWS KMS, Azure Key Vault)
- **Encrypt at rest** with AES-256-GCM
- **Implement access controls** for key retrieval

## Input Validation

### Bounding Box Validation

```rust
use smp_zk_proofs::BoundingBox;

fn validate_and_create_box(x_min: i64, x_max: i64, y_min: i64, y_max: i64) -> Result<BoundingBox, Error> {
    let box_ = BoundingBox { x_min, x_max, y_min, y_max };
    
    // Validate geometric validity
    box_.validate()?;
    
    // Additional production checks
    if x_min < -1000000 || x_max > 1000000 {
        return Err(Error::InvalidBoundingBox("Coordinates out of acceptable range".into()));
    }
    
    Ok(box_)
}
```

### Loss Threshold Validation

```rust
fn validate_loss_threshold(max_loss_milli: u64) -> Result<(), Error> {
    if max_loss_milli == 0 {
        return Err(Error::InvalidThreshold("Loss threshold must be positive".into()));
    }
    
    if max_loss_milli > 1_000_000 {
        return Err(Error::InvalidThreshold("Loss threshold exceeds maximum allowed value".into()));
    }
    
    Ok(())
}
```

## Error Handling

### Production Error Handling Pattern

```rust
use smp_zk_proofs::{ZkProofError, prove_location};

fn generate_proof_secure(context: &ProvingContext, public_inputs: &LocationPublicInputs, 
                        witness: &LocationPrivateWitness) -> Result<Proof, Error> {
    // Validate inputs before proof generation
    public_inputs.bounding_box.validate()?;
    
    // Generate proof with proper error handling
    match prove_location(context, public_inputs, witness) {
        Ok(proof) => {
            // Log success with non-sensitive information
            info!("Proof generated successfully: {} bytes", proof.to_bytes()?.len());
            Ok(proof)
        }
        Err(ZkProofError::ConstraintUnsatisfied(msg)) => {
            error!("Constraint validation failed: {}", msg);
            Err(Error::ConstraintViolation(msg))
        }
        Err(ZkProofError::SerializationFailed(e)) => {
            error!("Serialization error: {}", e);
            Err(Error::SerializationFailed(e))
        }
        Err(e) => {
            error!("Unexpected error: {:?}", e);
            Err(Error::Internal(format!("Unexpected error: {:?}", e)))
        }
    }
}
```

## Monitoring and Observability

### Proof Generation Metrics

Track these metrics in production:

- **Proof generation time** (p50, p95, p99)
- **Proof verification time** (p50, p95, p99)
- **Success/failure rates** by error type
- **Input validation failures** (rate and reasons)
- **Key rotation events**

### Alerting Thresholds

```yaml
# Example Prometheus alerting rules
groups:
  - name: smp-zk-proofs-alerts
    rules:
      - alert: HighProofGenerationLatency
        expr: histogram_quantile(0.95, rate(proof_generation_duration_seconds_bucket[5m])) > 1.0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Proof generation latency is high (p95 > 1s)"
      
      - alert: HighProofFailureRate
        expr: rate(proof_generation_total{result="failure"}[5m]) / rate(proof_generation_total[5m]) > 0.05
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: "Proof generation failure rate is high (>5%)"
```

## Security Testing

### Regular Fuzzing Runs

```bash
# Build fuzz targets
cargo fuzz build

# Run fuzz tests (limit to prevent resource exhaustion)
cargo fuzz run prove_proof_serialization -- -max_total_time=60s

# View coverage report
cargo tarpaulin --out Html --output-dir ./coverage
```

### Property-Based Testing

```bash
# Run property-based tests
cargo test --test property_based_tests -- --nocapture

# Generate coverage report
cargo tarpaulin --out Html --output-dir ./coverage-prop
```

## Incident Response

### When a Vulnerability is Discovered

1. **Immediate Actions**
   - Rotate all affected keys
   - Revoke and regenerate verification keys
   - Update blinding factors for all active proofs

2. **Communication**
   - Notify affected users immediately
   - Provide migration instructions
   - Publish security advisory with CVE if applicable

3. **Remediation**
   - Fix the vulnerability
   - Release patched version
   - Update documentation with new best practices

### Security Incident Checklist

- [ ] Assess impact and scope
- [ ] Determine affected users/systems
- [ ] Prepare incident response plan
- [ ] Notify stakeholders (users, management, legal)
- [ ] Implement temporary mitigations
- [ ] Fix root cause
- [ ] Test fix thoroughly
- [ ] Release patched version
- [ ] Document incident and lessons learned

## Compliance Considerations

### Data Protection

- **Never log sensitive data** (blinding factors, coordinates, losses)
- **Encrypt proofs at rest** when storing long-term
- **Use TLS 1.3+** for all network communication
- **Implement access logging** for proof verification operations

### Audit Requirements

Keep records of:
- Key generation timestamps and methods
- Proof generation logs (without sensitive data)
- Verification results and outcomes
- Security incident reports

## Recommended Dependencies

Ensure these dependencies are up-to-date:

```toml
[dependencies]
ed25519-dalek = "2.2.0"  # Cryptographically secure signatures
rand = "0.8"             # CSPRNG support
constant_time_eq = "0.3" # Timing-attack prevention

[dev-dependencies]
proptest = "1.4"         # Property-based testing
cargo-fuzz = "0.7"       # Fuzzing integration
```

## Security Audit Checklist

Before deploying to production:

- [ ] All dependencies are up-to-date and audited
- [ ] CSPRNG is enabled for blinding factors
- [ ] Constant-time comparisons used for sensitive data
- [ ] Input validation implemented for all operations
- [ ] Error handling prevents information disclosure
- [ ] Logging excludes sensitive data
- [ ] Fuzzing tests pass regularly
- [ ] Property-based tests cover invariants
- [ ] Security review completed by qualified personnel
- [ ] Incident response plan documented and tested

## Conclusion

Following these security guidelines ensures `smp-zk-proofs` is used securely in production environments. Regular security testing, proper key management, and vigilant monitoring are essential for maintaining a secure deployment.

For questions or security concerns, contact the maintainers through the GitHub repository or security advisory channels.
