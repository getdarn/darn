/// Error type shared across the library layers.
///
/// The Python original stringifies every exception into the per-host result
/// message, so what matters here is the `Display` text, not variant
/// granularity.
#[derive(thiserror::Error, Debug)]
pub enum DarnError {
    #[error("{0}")]
    Ssh(String),
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
