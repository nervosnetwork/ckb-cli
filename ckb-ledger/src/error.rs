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
    #[fail(
        display = "Error when parsing ledger response, remaining response too short to parse: expected {} bytes, got data {:?}",
        _0, _1
    )]
    RestOfResponseTooShort { expected: usize, tail: Vec<u8> },
    #[fail(
        display = "Error when parsing ledger response, remaining response left over after parse: {:?}",
        _0
    )]
    TrailingExtraReponse { tail: Vec<u8> },
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
