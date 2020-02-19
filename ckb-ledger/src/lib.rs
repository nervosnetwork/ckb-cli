use std::path::PathBuf;

use ckb_sdk::wallet::{
    AbstractKeyStore, AbstractMasterPrivKey, DerivationPath, ExtendedPubKey, ScryptType,
};
use ckb_types::H160;
use failure::Fail;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

pub struct LedgerKeyStore {
    _scrypt_type: ScryptType,
}

impl AbstractKeyStore for LedgerKeyStore {
    const SOURCE_NAME: &'static str = "ledger hardware wallet";

    type Err = LedgerError;

    fn list_accounts(&mut self) -> Box<dyn Iterator<Item = (usize, H160)>> {
        //unimplemented!()
        Box::new(::std::iter::empty())
    }

    fn from_dir(_dir: PathBuf, _scrypt_type: ScryptType) -> Result<Self, LedgerError> {
        //unimplemented!()
        Ok(LedgerKeyStore { _scrypt_type })
    }
}

#[derive(Debug, Fail, Eq, PartialEq)]
pub enum LedgerError {
    //#[fail(display = "Human interface device error: {}", _0)]
    #[fail(display = "Human interface device error")]
    HidError,
    // TODO
}

impl AbstractMasterPrivKey for LedgerKeyStore {
    type Err = LedgerError;

    fn extended_pubkey(&self, _path: Option<&DerivationPath>) -> Result<ExtendedPubKey, Self::Err> {
        unimplemented!()
    }
}
