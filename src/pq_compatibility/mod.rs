#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostQuantumBackendStatus {
    Reserved,
    Planned,
    Ready,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostQuantumBackendDescriptor {
    pub name: &'static str,
    pub status: PostQuantumBackendStatus,
    pub notes: &'static str,
    pub migration_steps: &'static [&'static str],
}

pub trait PostQuantumBackend {
    fn descriptor(&self) -> PostQuantumBackendDescriptor;
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PlaceholderBackend;

impl PostQuantumBackend for PlaceholderBackend {
    fn descriptor(&self) -> PostQuantumBackendDescriptor {
        PostQuantumBackendDescriptor {
            name: "placeholder-pq-backend",
            status: PostQuantumBackendStatus::Reserved,
            notes: "Reserved extension point for a future post-quantum proving backend built on lattice- or hash-based primitives.",
            migration_steps: &[
                "Define the post-quantum proof transcript format without changing the public circuit API.",
                "Introduce a concrete backend implementation behind the existing generator and verifier facades.",
                "Add compatibility tests that prove the new backend can replace the placeholder without breaking serialization or verification.",
            ],
        }
    }
}
