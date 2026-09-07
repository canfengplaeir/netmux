//! Centralized error handling for the netmux core.

/// Aggregate error type for the netmux core library.
#[derive(Debug, thiserror::Error)]
pub enum NetmuxError {
    /// Raised when an operation is not supported by the underlying platform.
    #[error("unsupported on this platform: {0}")]
    Unsupported(&'static str),

    /// A permission problem (e.g. missing CAP_NET_ADMIN for TUN / raw sockets).
    #[error("permission denied: {0}")]
    Permission(String),

    /// OS syscall / ioctl error.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    /// Invalid configuration supplied to the aggregator or a policy.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// Interface not found.
    #[error("no such interface: {0}")]
    NotFound(String),

    /// An internal invariant was violated.
    #[error("internal error: {0}")]
    Internal(String),

    /// Serialization / configuration persistence error.
    #[error("configuration persistence error: {0}")]
    Persist(String),
}

impl NetmuxError {
    /// Convenience constructor for [`NetmuxError::Permission`].
    pub fn permission(msg: impl Into<String>) -> Self {
        NetmuxError::Permission(msg.into())
    }

    /// Convenience constructor for [`NetmuxError::Io`].
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        NetmuxError::Io {
            context: context.into(),
            source,
        }
    }

    /// Convenience constructor for [`NetmuxError::Config`].
    pub fn config(msg: impl Into<String>) -> Self {
        NetmuxError::Config(msg.into())
    }
}

impl From<std::io::Error> for NetmuxError {
    fn from(source: std::io::Error) -> Self {
        NetmuxError::Io {
            context: "io error".into(),
            source,
        }
    }
}

/// Shorthand alias most call sites use.
pub type Result<T> = std::result::Result<T, NetmuxError>;