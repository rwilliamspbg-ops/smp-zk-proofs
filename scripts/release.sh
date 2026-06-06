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

echo "running release checks"
source "$HOME/.cargo/env"
cargo fmt --check --all
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
cargo test --doc --locked
cargo build --examples --locked
cargo build --benches --locked
cargo package --allow-dirty

tag="v${version}"

if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
  echo "tag ${tag} already exists" >&2
  exit 1
fi

git tag -a "$tag" -m "Release ${tag}"
echo "created tag ${tag}"