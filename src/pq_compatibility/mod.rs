#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostQuantumBackendDescriptor {
    pub name: &'static str,
    pub status: &'static str,
    pub notes: &'static str,
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
            status: "reserved",
            notes: "Reserved extension point for a future lattice- or hash-based proving backend.",
        }
    }
}
