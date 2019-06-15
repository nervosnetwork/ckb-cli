use std::io;

use crate::IndexError;

#[derive(Debug)]
pub enum Error {
    #[cfg(feature = "local")]
    Rocksdb(rocksdb::Error),

    Io(io::Error),
    Index(IndexError),
    Other(String),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

#[cfg(feature = "local")]
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
