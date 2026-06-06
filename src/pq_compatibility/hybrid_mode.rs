//! Hybrid Mode: Classical + Post-Quantum Proof Support
//!
//! This module provides configuration and utilities for running classical
//! and post-quantum proofs in parallel during migration periods, enabling
//! a gradual transition to fully post-quantum security.

/// Strategy for combining classical and post-quantum proofs in hybrid mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HybridStrategy {
    /// Both classical and PQC proofs must verify successfully.
    #[default]
    RequireBoth,
    /// Post-quantum proof is primary; classical is retained for fallback.
    PqcPrimary,
    /// Classical proof is primary; PQC is retained for auditing.
    ClassicalPrimary,
}
