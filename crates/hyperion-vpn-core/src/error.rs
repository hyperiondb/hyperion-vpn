use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("handshake failed")]
    Handshake,

    #[error("peer is not an authorized admin")]
    Unauthorized,

    #[error("protocol violation: {0}")]
    Protocol(String),

    #[error("destination not permitted: {0}")]
    EgressDenied(String),
}
