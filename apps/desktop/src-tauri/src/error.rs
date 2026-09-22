//! The shell's structured error taxonomy.
//!
//! One type crosses every IPC boundary, so `code` is the only way a caller can
//! branch on a failure without matching on prose. The serialised shape is
//! `{code, message, field?}` (specs/015 contracts/ipc-contract.md, C-IPC-2).
use crate::trust::BinaryTrustError;
use serde::Serialize;

/// Structured shell/IPC error.
///
/// Every shell helper used to return a bare message, so a caller could only
/// branch on prose (`msg.contains("not found")`) and the frontend received an
/// opaque rejection it had to read as text. `code` is the machine-readable half.
///
/// It serialises as `{code, message, field?}` — the contract in
/// `specs/015-full-audit-remediation/contracts/ipc-contract.md` (C-IPC-2). The
/// earlier shape was the message string, chosen so `String(e)` in the shipped
/// frontend kept working; that is what made the code unreachable, and a code no
/// caller can read is the same as no code. Both UIs now unwrap the object through
/// `lib/ipcError.ts`, which still accepts a bare string because the Android
/// bridge rejects with prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommandError {
    pub code: &'static str,
    pub message: String,
    /// Which `Settings` field the command rejected, using the name the frontend
    /// state uses (`httpPort`, not `http_port`) so the form can attach the error
    /// to the input that caused it. `None` for everything that is not about a
    /// field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<&'static str>,
}

impl CommandError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            field: None,
        }
    }

    /// A rejected setting. `field` is the camelCase key of the `Settings` value
    /// that failed, which is the only way the UI can show it anywhere but in a
    /// log line.
    pub fn validation(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            code: "validation",
            message: message.into(),
            field: Some(field),
        }
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CommandError {}

impl From<String> for CommandError {
    fn from(message: String) -> Self {
        Self {
            code: "internal",
            message,
            field: None,
        }
    }
}

impl From<&str> for CommandError {
    fn from(message: &str) -> Self {
        Self {
            code: "internal",
            message: message.to_string(),
            field: None,
        }
    }
}

impl From<serde_json::Error> for CommandError {
    fn from(e: serde_json::Error) -> Self {
        Self {
            code: "encode",
            message: e.to_string(),
            field: None,
        }
    }
}

impl From<tauri::Error> for CommandError {
    fn from(e: tauri::Error) -> Self {
        Self {
            code: "shell",
            message: e.to_string(),
            field: None,
        }
    }
}

impl From<ureq::Error> for CommandError {
    fn from(e: ureq::Error) -> Self {
        Self {
            code: "network",
            message: e.to_string(),
            field: None,
        }
    }
}

impl From<BinaryTrustError> for CommandError {
    fn from(e: BinaryTrustError) -> Self {
        let code = match e {
            BinaryTrustError::Authenticode(_, _) => "authenticode",
            BinaryTrustError::PublisherMismatch { .. } => "publisher_mismatch",
            BinaryTrustError::HashMismatch { .. } => "hash_mismatch",
            BinaryTrustError::MissingHash { .. } => "missing_hash",
            BinaryTrustError::AnchorNotPublished { .. } => "anchor_not_published",
            BinaryTrustError::Validation(_) => "validation",
        };
        Self {
            code,
            message: e.to_string(),
            field: None,
        }
    }
}

impl From<std::io::Error> for CommandError {
    fn from(e: std::io::Error) -> Self {
        let code = match e.kind() {
            std::io::ErrorKind::NotFound => "not_found",
            std::io::ErrorKind::PermissionDenied => "permission_denied",
            std::io::ErrorKind::AlreadyExists => "already_exists",
            _ => "io",
        };
        Self {
            code,
            message: e.to_string(),
            field: None,
        }
    }
}
