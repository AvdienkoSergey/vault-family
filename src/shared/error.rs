use crate::crypto_operations::CryptoError;
use std::fmt;

#[derive(Debug)]
pub enum SharedError {
    Connection(String),
    Schema(String),
    Database(String),
    Crypto(CryptoError),
    NotFound(String),
    Forbidden(String),
    MemberLimit(String),
    NoKeypair(String),
}

impl fmt::Display for SharedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SharedError::Connection(msg) => write!(f, "connection error: {msg}"),
            SharedError::Schema(msg) => write!(f, "schema error: {msg}"),
            SharedError::Database(msg) => write!(f, "database error: {msg}"),
            SharedError::Crypto(err) => write!(f, "crypto error: {err}"),
            SharedError::NotFound(msg) => write!(f, "not found: {msg}"),
            SharedError::Forbidden(msg) => write!(f, "forbidden: {msg}"),
            SharedError::MemberLimit(msg) => write!(f, "member limit: {msg}"),
            SharedError::NoKeypair(msg) => write!(f, "no keypair: {msg}"),
        }
    }
}

impl From<CryptoError> for SharedError {
    fn from(e: CryptoError) -> Self {
        SharedError::Crypto(e)
    }
}
