# Release Checklist

Use this before tagging a release:

1. Confirm `cargo fmt --check` passes.
2. Confirm `cargo clippy --all-targets --all-features --locked -- -D warnings` passes.
3. Confirm `cargo test --all-targets --locked` passes.
4. Confirm `cargo test --doc --locked` passes.
5. Confirm `cargo build --examples --locked` passes.
6. Confirm `cargo build --benches --locked` passes.
7. Update `CHANGELOG.md`.
8. Tag the release from a clean working tree.