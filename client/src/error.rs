use anyhow::Result as AnyhowResult;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Crypto(crypto_box::aead::Error),
    Serialization(bincode::Error),
    InvalidKey,
    UntrustedPeer,
    UnexpectedMessage,
    NetworkClosed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::Crypto(e) => write!(f, "Crypto error: {:?}", e),
            Error::Serialization(e) => write!(f, "Serialization error: {}", e),
            Error::InvalidKey => write!(f, "Invalid public key"),
            Error::UntrustedPeer => write!(f, "Peer key not trusted"),
            Error::UnexpectedMessage => write!(f, "Unexpected message type"),
            Error::NetworkClosed => write!(f, "Network connection closed unexpectedly"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<crypto_box::aead::Error> for Error {
    fn from(err: crypto_box::aead::Error) -> Self {
        Error::Crypto(err)
    }
}

impl From<bincode::Error> for Error {
    fn from(err: bincode::Error) -> Self {
        Error::Serialization(err)
    }
}

pub type Result<T> = AnyhowResult<T, Error>;