# Roadmap

This document outlines the planned development roadmap for `smp-zk-proofs`.

## Phase A: Foundation (Current - v0.1.x)

**Status**: ✅ Complete

- [x] Stable public API for location and training proofs
- [x] Development signed-transcript backend
- [x] Deterministic serialization for proofs and keys
- [x] End-to-end tests and examples
- [x] CI/CD automation
- [x] Documentation and benchmarks

## Phase B: Real ZK Backends (v0.2.x)

### Halo2 Backend
- [ ] Implement full Halo2 circuits for location constraints
  - Range checks for bounding box verification
  - Pedersen/Poseidon commitment opening gadgets
- [ ] Implement full Halo2 circuits for training constraints
  - Step count verification
  - Loss threshold comparison
- [ ] Proving key and verifying key generation
- [ ] SRS/trusted setup documentation
- [ ] Performance benchmarks comparing to development backend

### Groth16 Backend
- [ ] Implement R1CS constraints for location circuit
  - Replace EmptyCircuit with actual LocationR1CS
  - Add commitment verification constraints
- [ ] Implement R1CS constraints for training circuit
- [ ] Circuit parameter tuning for optimal proof size
- [ ] Integration tests with real arkworks proofs

## Phase C: Advanced Features (v0.3.x)

### Proof Aggregation
- [ ] Batch verification of multiple proofs
- [ ] Recursive proof composition
- [ ] Aggregated training proofs from multiple nodes

### Enhanced Privacy
- [ ] Zero-knowledge range proofs (not just commitment binding)
- [ ] Privacy-preserving loss verification
- [ ] Selective disclosure mechanisms

### Performance Optimization
- [ ] Parallel proof generation
- [ ] GPU acceleration hooks
- [ ] Memory-efficient circuit synthesis

## Phase D: Post-Quantum Migration (v0.4.x)

- [ ] Evaluate post-quantum proving schemes
  - Lattice-based (e.g., lattice-based SNARKs)
  - Hash-based (e.g., STARKs)
  - Code-based approaches
- [ ] Implement PQ backend behind existing API
- [ ] Hybrid classical+PQ proof modes
- [ ] Migration tooling and compatibility layer
- [ ] Security analysis and documentation

## Phase E: Production Hardening (v1.0.x)

- [ ] Formal security audit
- [ ] Fuzzing infrastructure
- [ ] Comprehensive property-based testing
- [ ] Production deployment guides
- [ ] Monitoring and observability tools
- [ ] Long-term support policy

## Ongoing Maintenance

### Documentation
- [ ] API reference documentation
- [ ] Tutorial series for new users
- [ ] Architecture decision records (ADRs)
- [ ] Video walkthroughs

### Testing
- [ ] Increase test coverage to >90%
- [ ] Add property-based tests with proptest
- [ ] Cross-platform testing (Windows, macOS, Linux)
- [ ] WASM compatibility testing

### Community
- [ ] Regular release cadence
- [ ] Community feedback incorporation
- [ ] Ecosystem integrations
- [ ] Conference presentations and workshops

## Getting Involved

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute to any of these initiatives. Pick a task that interests you and open an issue to discuss your approach.

## Version Compatibility

| Version | Rust Edition | Breaking Changes |
|---------|-------------|------------------|
| 0.1.x   | 2024        | Initial release  |
| 0.2.x   | 2024        | Backend APIs     |
| 0.3.x   | 2024        | TBD              |
| 1.0.x   | 2024+       | Stabilized API   |

## Notes

- Timeline estimates are approximate and may shift based on community priorities
- Security considerations take precedence over feature additions
- All major changes will go through RFC process before implementation
