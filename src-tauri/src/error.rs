use serde::{Serialize, Serializer};

/// Unified application error. Serialised to the frontend as a plain message.
#[derive(Debug, thiserror::Error)]
pub enum NexusError {
    #[error("Npcap is not installed or could not be loaded. {0}")]
    NpcapMissing(String),
    #[error("Capture error: {0}")]
    Capture(String),
    #[error("Insufficient permissions to capture on this interface: {0}. Try running NEXUS as Administrator, or reinstall Npcap with the non-admin access option enabled.")]
    Permission(String),
    #[error("Invalid capture filter: {0}")]
    InvalidFilter(String),
    #[error("A capture is already running.")]
    AlreadyCapturing,
    #[error("No capture is running.")]
    NotCapturing,
    #[error("File error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid capture file: {0}")]
    BadCaptureFile(String),
    #[error("Database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("Serialisation error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Invalid(String),
}

impl Serialize for NexusError {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

pub type Result<T> = std::result::Result<T, NexusError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_serialise_as_their_message_for_the_frontend() {
        let json = serde_json::to_string(&NexusError::NotCapturing).unwrap();
        assert_eq!(json, "\"No capture is running.\"");
        let json = serde_json::to_string(&NexusError::InvalidFilter("bad".into())).unwrap();
        assert_eq!(json, "\"Invalid capture filter: bad\"");
    }

    #[test]
    fn io_and_database_errors_convert_with_context() {
        let io: NexusError = std::io::Error::new(std::io::ErrorKind::NotFound, "gone").into();
        assert!(io.to_string().starts_with("File error:"));
        let permission = NexusError::Permission("denied".into()).to_string();
        assert!(permission.contains("Administrator"));
    }
}
