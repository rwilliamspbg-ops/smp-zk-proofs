//! Migration utilities for transitioning from classical to post-quantum proofs.
//!
//! This module provides a placeholder backend and migration helpers for
//! projects that plan to adopt post-quantum cryptography in the future.

use crate::pq_compatibility::{
    PostQuantumBackend, PostQuantumBackendDescriptor, PostQuantumBackendStatus,
};

/// A placeholder post-quantum backend used during the migration period before
/// a production post-quantum proving backend is integrated into the system.
///
/// This backend exposes a migration plan via its descriptor, helping teams
/// understand the steps required to adopt a real post-quantum backend.
pub struct PlaceholderBackend;

impl PostQuantumBackend for PlaceholderBackend {
    fn descriptor(&self) -> PostQuantumBackendDescriptor {
        PostQuantumBackendDescriptor {
            name: "placeholder-pq-backend",
            status: PostQuantumBackendStatus::Reserved,
            notes: "Reserved slot for a future post-quantum proving backend. \
                    Not suitable for production use.",
            migration_steps: &[
                "Implement the public circuit API for the chosen PQC scheme.",
                "Register the new backend in PqcBackendType and route proofs accordingly.",
                "Run the full test suite to validate correctness and performance targets.",
            ],
        }
    }
}
