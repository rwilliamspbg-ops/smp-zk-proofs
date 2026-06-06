# Contributing to smp-zk-proofs

Thank you for considering contributing to `smp-zk-proofs`! This document provides guidelines for contributing to the project.

## Code of Conduct

This project adheres to the Rust Code of Conduct. Please be respectful and inclusive in all interactions.

## How to Contribute

### Reporting Issues

- Check if the issue already exists before creating a new one
- Provide a clear description of the problem
- Include steps to reproduce, expected behavior, and actual behavior
- Mention your Rust version and platform

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run the full test suite:
   ```bash
   cargo fmt --check
   cargo clippy --all-targets --all-features -- -D warnings
   cargo test --all-targets
   cargo test --doc
   ```
5. Commit your changes with clear messages
6. Push to your fork and open a pull request

### Coding Standards

- Follow Rust formatting conventions (`cargo fmt`)
- Address all Clippy warnings
- Write tests for new functionality
- Update documentation for public APIs
- Keep functions focused and well-named

## Development Setup

```bash
# Clone the repository
git clone https://github.com/rwilliamspbg-ops/smp-zk-proofs.git
cd smp-zk-proofs

# Install the correct Rust toolchain
rustup override set 1.91.0

# Build the project
cargo build

# Run tests
cargo test --all-targets

# Run examples
cargo run --example simple_location_proof
cargo run --example weight_aggregation_proof
```

## Feature Flags

- `halo2`: Enable the Halo2 proving backend (experimental)
- `groth16`: Enable the Groth16 proving backend using arkworks

To test with features:
```bash
cargo test --all-targets --features groth16
cargo build --features halo2
```

## Architecture Overview

The crate is organized into these main modules:

- `constraints`: Circuit definitions and constraint evaluation
- `proofs`: Proof generation, verification, and types
- `utils`: Serialization, hashing, and commitment helpers
- `pq_compatibility`: Extension points for post-quantum backends

## Testing Guidelines

- Unit tests should live in the same file as the code they test
- Integration tests go in the `tests/` directory
- Test both success paths and failure cases
- Include edge cases (boundary values, empty inputs, etc.)

## Documentation

- Document all public items with `///` comments
- Include usage examples in doc comments
- Run `cargo doc --open` to preview documentation

## Release Process

See [RELEASE.md](RELEASE.md) for the release checklist.

## Questions?

Open an issue for questions or discussions about the project.
