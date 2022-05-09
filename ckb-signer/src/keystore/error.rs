use std::io;

use ckb_types::H160;
use thiserror::Error;

#[derive(Error, Debug, Eq, PartialEq)]
pub enum Error {
    #[error("Account locked: {0:x}")]
    AccountLocked(H160),

    #[error("Account not found: {0:x}")]
    AccountNotFound(H160),

    #[error("Key mismatch, got {got:x}, expected: {expected:x}")]
    KeyMismatch { got: H160, expected: H160 },

    #[error("Key already exists {0:x}")]
    KeyExists(H160),

    #[error("Wrong password for {0:x}")]
    WrongPassword(H160),

    #[error("Check password failed")]
    CheckPasswordFailed,

    #[error("Parse json failed: {0}")]
    ParseJsonFailed(String),

    #[error("Unsupported cipher: {0}")]
    UnsupportedCipher(String),

    #[error("Unsupported kdf: {0}")]
    UnsupportedKdf(String),

    #[error("Generate secp256k1 secret failed, tried: {0}")]
    GenSecpFailed(u16),

    #[error("Invalid secp256k1 secret key")]
    InvalidSecpSecret,

    #[error("Search derived address failed")]
    SearchDerivedAddrFailed,

    #[error("IO error: {0}")]
    Io(String),

    #[error("Other error: {0}")]
    Other(String),
}

impl From<String> for Error {
    fn from(err: String) -> Error {
        Error::Other(err)
    }
}

impl From<&str> for Error {
    fn from(err: &str) -> Error {
        Error::Other(err.to_owned())
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err.to_string())
    }
}
