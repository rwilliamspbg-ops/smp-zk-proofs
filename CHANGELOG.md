# Changelog

## 0.1.0

Initial public release of `smp-zk-proofs`.

### Highlights

- Stable public API for location and training proof flows.
- Deterministic serialization for proofs, verification keys, and public inputs.
- End-to-end tests covering success paths and tamper rejection.
- Example binaries for both proof flows.
- CI and release automation for repeatable validation.

### Added

- Location and training proof flows with deterministic serialization.
- Signed-transcript proof generation and verification.
- End-to-end tests for happy paths and rejection cases.
- Structured post-quantum backend migration metadata.
- GitHub Actions CI for format, lint, tests, docs, examples, and benches.

### Usage Notes

- The release ships a development signed-transcript backend rather than a production ZK proving system.
- The public API is intentionally shaped so a future Halo2/arkworks backend can slot in without breaking callers.
- The examples in `examples/` are runnable from a clean checkout with `cargo run --example ...`.

### Notes

- This release keeps the development signed-transcript backend in place while preserving the public API for a future zero-knowledge backend.