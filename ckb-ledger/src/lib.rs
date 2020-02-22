use std::path::PathBuf;

use log::debug;

use ckb_sdk::wallet::{
    AbstractKeyStore, AbstractMasterPrivKey, DerivationPath, ExtendedPubKey, ScryptType,
};
use ckb_types::H160;
use failure::Fail;

use ledger::{ApduCommand, LedgerApp, LedgerError};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

pub struct LedgerKeyStore {
    ledger_app: Option<LedgerApp>,
}

impl LedgerKeyStore {
    fn init(&mut self) -> Result<&mut LedgerApp, LedgerError> {
        match self.ledger_app {
            Some(ref mut ledger_app) => Ok(ledger_app),
            None => {
                self.ledger_app = Some(LedgerApp::new()?);
                self.init()
            }
        }
    }

    fn check_version(&mut self) -> Result<(), LedgerError> {
        let ledger_app = self.init()?;
        {
            let command = ApduCommand {
                cla: 0x80,
                ins: 0x00,
                p1: 0x00,
                p2: 0x00,
                length: 0,
                data: Vec::new(),
            };
            let result = ledger_app.exchange(command)?;;
            debug!("Nervos CBK App Version: {:?}", result);
        }
        {
            let command = ApduCommand {
                cla: 0x80,
                ins: 0x09,
                p1: 0x00,
                p2: 0x00,
                length: 0,
                data: Vec::new(),
            };
            let result = ledger_app.exchange(command)?;
            debug!("Nervos CBK App Git Hash: {:?}", result);
        }
        Ok(())
    }
}

impl AbstractKeyStore for LedgerKeyStore {
    const SOURCE_NAME: &'static str = "ledger hardware wallet";

    type Err = LedgerKeyStoreError;

    fn list_accounts(&mut self) -> Result<Box<dyn Iterator<Item = (usize, H160)>>, Self::Err> {
        let _ = self.check_version(); //.expect("oh no!");
        Ok(Box::new(::std::iter::empty()))
    }

    fn from_dir(_dir: PathBuf, _scrypt_type: ScryptType) -> Result<Self, LedgerKeyStoreError> {
        //unimplemented!()
        Ok(LedgerKeyStore { ledger_app: None })
    }
}

#[derive(Debug, Fail)]
pub enum LedgerKeyStoreError {
    #[fail(display = "App-agnostic ledger error: {}", _0)]
    LedgerError(LedgerError),
    // TODO
}

impl From<LedgerError> for LedgerKeyStoreError {
    fn from(err: LedgerError) -> Self {
        LedgerKeyStoreError::LedgerError(err)
    }
}

impl AbstractMasterPrivKey for LedgerKeyStore {
    type Err = LedgerKeyStoreError;

    fn extended_pubkey(&self, _path: Option<&DerivationPath>) -> Result<ExtendedPubKey, Self::Err> {
        unimplemented!()
    }
}
