# Changelog

## 0.1.0

Initial public release of `smp-zk-proofs`.

### Added

- Location and training proof flows with deterministic serialization.
- Signed-transcript proof generation and verification.
- End-to-end tests for happy paths and rejection cases.
- Structured post-quantum backend migration metadata.
- GitHub Actions CI for format, lint, tests, docs, examples, and benches.

### Notes

- This release keeps the development signed-transcript backend in place while preserving the public API for a future zero-knowledge backend.