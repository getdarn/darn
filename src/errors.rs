/// Error type shared across the library layers.
///
/// The Python original stringifies every exception into the per-host result
/// message, so what matters here is the `Display` text, not variant
/// granularity.
#[derive(thiserror::Error, Debug)]
pub enum DarnError {
    #[error("{0}")]
    Ssh(String),
    /// An SSH connection that got as far as authentication and was refused.
    /// Separate from `Ssh` only so `server add` can offer to install a key;
    /// it prints and exits the same way.
    #[error("{0}")]
    SshAuth(String),
    /// An SSH connection to a host whose key is in no known_hosts file.
    /// Separate from `Ssh` only so `server add` can offer to record it; it
    /// prints and exits the same way. A *mismatched* key is not this — that
    /// stays `Ssh`, and fatal.
    #[error("{0}")]
    SshHostKeyUnknown(String),
    #[error("{0}")]
    Unsupported(String),
    #[error("{0}")]
    Timeout(String),
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    /// A usage error; exits with status 2 like click's BadParameter/UsageError.
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Other(String),
}
