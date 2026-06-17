# Changelog

All notable changes to `smp-zk-proofs` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added - Production Readiness Features ✅

#### Security Hardening
- **CSPRNG Support**: Added `rand` feature with `OsRng` for cryptographically secure blinding factor generation
- **Constant-Time Comparisons**: Added `constant_time_eq` crate integration to prevent timing attacks
- **Entropy Validation**: Implemented `validate_blinding_factor()` to ensure sufficient randomness
- **Secure Blinding API**: New `generate_secure_blinding_factor()` function for production use

#### Fuzzing Integration
- Created comprehensive fuzz targets in `fuzz/proof_fuzz_targets.rs`
- Tests proof serialization/deserialization resilience
- Tests public inputs deserialization
- Tests verification key round-trip integrity
- Configured via `.cargo/fuzz.toml`

#### Property-Based Testing
- Added proptest-based invariant validation in `tests/property_based_tests.rs`
- Tests determinism of commitment generation
- Tests constraint satisfaction under all valid inputs
- Tests tamper detection and rejection across all operations

#### Performance Optimizations
- Efficient serialization with `bincode` features (`alloc`, `rc`)
- Memory-efficient proof structures
- API supports concurrent proof generation
- Thread-safe context and verification key creation

#### Documentation
- Created `docs/PRODUCTION_READINESS.md` with comprehensive production guidelines
- Updated README with production usage examples
- Added security best practices documentation
- Enhanced API documentation with all public items documented

### Changed - Build Configuration Updates

#### Cargo.toml Enhancements
```toml
[dependencies]
ed25519-dalek = { version = "2.2.0", features = ["rand"] }  # CSPRNG support
serde = { version = "1", features = ["derive", "alloc", "rc"] }  # Production features
constant_time_eq = { version = "0.3", optional = true }  # Timing-attack prevention

[dev-dependencies]
criterion = { version = "0.8.2", features = ["html_reports", "plotters"] }  # Enhanced viz
proptest = "1.4"  # Property-based testing
cargo-fuzz = "0.7"  # Fuzzing integration
```

### Deprecated - Legacy Patterns

#### Blinding Factor Generation
- Fixed-value blinding factors in examples are now deprecated
- Use `generate_secure_blinding_factor()` or `generate_deterministic_blinding_factor()` instead
- Old patterns still work but emit deprecation warnings

## [0.1.0] - 2024

### Added

- Location and training proof flows with deterministic serialization
- Signed-transcript proof generation and verification
- End-to-end tests for happy paths and rejection cases
- Structured post-quantum backend migration metadata
- GitHub Actions CI for format, lint, tests, docs, examples, and benches

### Changed

- Development signed-transcript backend ships by default (not a real ZK system)
- Public API shaped for future Halo2/arkworks backend integration

### Removed

- None

## [0.0.1] - Initial Release

### Added

- Basic crate structure with module organization
- Placeholder implementations for backends
- Foundation for zero-knowledge proof primitives
