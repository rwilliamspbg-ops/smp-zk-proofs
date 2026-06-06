#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"

if [[ -z "$version" ]]; then
  echo "usage: $0 <version>" >&2
  exit 1
fi

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "version must be in the form X.Y.Z" >&2
  exit 1
fi

# Verify cargo is available without assuming a rustup install layout.
if ! command -v cargo &>/dev/null; then
  echo "cargo not found; install Rust from https://rustup.rs" >&2
  exit 1
fi

echo "running release checks for v${version}"
cargo fmt --check --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo test --doc
cargo build --examples
cargo build --benches
cargo package --no-verify

tag="v${version}"

if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
  echo "tag ${tag} already exists" >&2
  exit 1
fi

git tag -a "$tag" -m "Release ${tag}"
echo "created tag ${tag} — push with: git push origin ${tag}"
