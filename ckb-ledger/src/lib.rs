use std::path::PathBuf;

use ::std::fmt::Debug;

use log::debug;

use byteorder::{BigEndian, WriteBytesExt};
use ckb_sdk::wallet::{
    AbstractKeyStore, AbstractMasterPrivKey, Bip32Error, ChildNumber, ExtendedPubKey, ScryptType,
};
use ckb_types::H160;
use failure::Fail;
use secp256k1::key::PublicKey;

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
            let response = ledger_app.exchange(command)?;;
            debug!("Nervos CBK Ledger app Version: {:?}", response);
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
            let response = ledger_app.exchange(command)?;
            debug!("Nervos CBK Ledger app Git Hash: {:?}", response);
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
    #[fail(display = "Error in client-side BIP-32 calculations: {}", _0)]
    Bip32Error(Bip32Error),
    #[fail(display = "Error in secp256k1 marshalling")]
    Secp256k1Error(secp256k1::Error),
}

impl From<LedgerError> for LedgerKeyStoreError {
    fn from(err: LedgerError) -> Self {
        LedgerKeyStoreError::LedgerError(err)
    }
}

impl From<Bip32Error> for LedgerKeyStoreError {
    fn from(err: Bip32Error) -> Self {
        LedgerKeyStoreError::Bip32Error(err)
    }
}

impl From<secp256k1::Error> for LedgerKeyStoreError {
    fn from(err: secp256k1::Error) -> Self {
        LedgerKeyStoreError::Secp256k1Error(err)
    }
}

impl AbstractMasterPrivKey for &mut LedgerKeyStore {
    type Err = LedgerKeyStoreError;

    fn extended_pubkey<P>(self, path: &P) -> Result<ExtendedPubKey, Self::Err>
    where
        P: ?Sized + Debug + AsRef<[ChildNumber]>,
    {
        let ledger_app = self.init()?;
        let mut data = Vec::new();
        for &child_num in path.as_ref().iter() {
            data.write_u32::<BigEndian>(From::from(child_num))
                .expect("IO error not possible when writing to Vec last I checked");
        }
        let command = ApduCommand {
            cla: 0x80,
            ins: 0x02,
            p1: 0x00,
            p2: 0x00,
            length: 0,
            data,
        };
        let response = ledger_app.exchange(command)?;
        debug!(
            "Nervos CBK Ledger app extended pub key raw {:?}",
            (path, response)
        );
        Ok(ExtendedPubKey {
            depth: path.as_ref().len() as u8,
            parent_fingerprint: unimplemented!(),
            child_number: ChildNumber::from_hardened_idx(0)?,
            public_key: PublicKey::from_slice(&response.data)?,
            chain_code: unimplemented!(),
        })
    }
}
