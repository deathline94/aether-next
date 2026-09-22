use thiserror::Error;

#[derive(Error, Debug)]
pub enum AetherError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("quic: {0}")]
    Quic(#[from] quiche::Error),

    #[error("h3: {0}")]
    H3(#[from] quiche::h3::Error),

    #[error("tls: {0}")]
    Tls(String),

    #[error("ech: {0}")]
    Ech(String),

    #[error("masque: {0}")]
    Masque(String),

    #[error("prober: no clean endpoint found")]
    NoCleanEndpoint,

    #[error("capsule: {0}")]
    Capsule(String),

    #[error("api: {0}")]
    Api(String),

    #[error("other: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, AetherError>;

impl AetherError {
    /// A stable, machine-readable name for the failure.
    ///
    /// The reason this exists is that `Other(String)` is what 230-odd call sites
    /// build, so the *message* was the only thing left — and a GUI cannot branch on
    /// a sentence without pattern-matching prose, which is exactly how the shell
    /// ended up tearing a healthy session down over one log line. The code is the
    /// channel; the message stays for humans.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io(_) => "io",
            Self::Quic(_) => "quic",
            Self::H3(_) => "h3",
            Self::Tls(_) => "tls",
            Self::Ech(_) => "ech",
            Self::Masque(_) => "masque",
            Self::NoCleanEndpoint => "no_clean_endpoint",
            Self::Capsule(_) => "capsule",
            Self::Api(_) => "api",
            Self::Other(_) => "other",
        }
    }

    /// Could a fresh attempt plausibly succeed with nothing changed by the user?
    ///
    /// Transport-level and upstream failures are transient: another edge, or the
    /// same edge in a moment. Identity, pin and configuration failures are not —
    /// retrying them burns a scan cycle and ends in the same place, which is why
    /// the distinction is worth a separate exit code for the supervising shell.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Io(e) => matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::NotConnected
            ),
            Self::Quic(_) | Self::H3(_) | Self::Capsule(_) => true,
            Self::Api(_) => true,
            Self::NoCleanEndpoint => true,
            Self::Tls(_) | Self::Masque(_) | Self::Ech(_) | Self::Other(_) => false,
        }
    }
}
