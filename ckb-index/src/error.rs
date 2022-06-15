use std::io;

use thiserror::Error;

use crate::index::IndexError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Rocksdb error: {0}")]
    Rocksdb(rocksdb::Error),
    #[error("IO error: {0}")]
    Io(io::Error),
    #[error("Index DB error: {0}")]
    Index(IndexError),
    #[error("Other error: {0}")]
    Other(String),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<rocksdb::Error> for Error {
    fn from(err: rocksdb::Error) -> Error {
        Error::Rocksdb(err)
    }
}

impl From<IndexError> for Error {
    fn from(err: IndexError) -> Error {
        Error::Index(err)
    }
}

impl From<String> for Error {
    fn from(err: String) -> Error {
        Error::Other(err)
    }
}
