Threat model and security properties
===================================

This document sketches the threat model and security properties for `smp-zk-proofs`.

Goals
- Proofs assert that a prover knows a private witness that satisfies the public circuit constraints.
- Verifiers should reject any tampered proof or proof produced by an untrusted key.

Adversary model
- Provers are potentially malicious and may attempt to forge proofs or leak secrets.
- The verifier's environment may be untrusted; verification must be deterministic and rely only on the public inputs and verification key.
- Communication channels may be compromised; integrity is ensured by proof verification.

Security properties
- Soundness: For a given proving backend, it should be computationally infeasible for a prover to convince a verifier of a false statement except with negligible probability.
- Binding of commitments: Commitments used in public inputs (e.g., location/training commitments) must be collision-resistant (we currently use SHA-256-based commitments).
- Confidentiality: Private witnesses are never serialized into proofs or public inputs by default; backends must not leak witness data.

Notes on backends
- The current default backend is a development signed-transcript backend and provides only a basic integrity check (signature over a hashed transcript). It is NOT a zero-knowledge proof system and does not provide soundness against proving false statements beyond the circuit-side checks.
- When a real ZK backend (Halo2/arkworks) is enabled, the backend must provide formal soundness and (optionally) zero-knowledge properties. The crate will document the exact curve parameters, SRS/trusted setup requirements (if any), and proof size/verification costs.

Operational recommendations
- Keep verification keys and any trusted setup material under strict access control.
- Pin backend versions and exact curve parameters in `Cargo.toml` and release notes.
- Add compatibility tests to ensure serialized proof formats and verification keys are stable across releases.
