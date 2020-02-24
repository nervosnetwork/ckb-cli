use ::std::fmt::Debug;

use ckb_sdk::wallet::Bip32Error;

use failure::Fail;

use ledger::LedgerError;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "App-agnostic ledger error: {}", _0)]
    LedgerError(LedgerError),
    #[fail(display = "Error in client-side BIP-32 calculations: {}", _0)]
    Bip32Error(Bip32Error),
    #[fail(display = "Error in secp256k1 marshalling: {}", _0)]
    Secp256k1Error(secp256k1::Error),
}

impl From<LedgerError> for Error {
    fn from(err: LedgerError) -> Self {
        Error::LedgerError(err)
    }
}

impl From<Bip32Error> for Error {
    fn from(err: Bip32Error) -> Self {
        Error::Bip32Error(err)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(err: secp256k1::Error) -> Self {
        Error::Secp256k1Error(err)
    }
}
