use std::path::PathBuf;

use std::fmt::Debug;
use std::io::Write;

use log::debug;

use bitcoin_hashes::{hash160, Hash};
use byteorder::{BigEndian, WriteBytesExt};
use ckb_sdk::wallet::{
    AbstractKeyStore, AbstractMasterPrivKey, ChainCode, ChildNumber, ExtendedPubKey, Fingerprint,
    ScryptType,
};
use ckb_types::{H160, H256};

use secp256k1::{key::PublicKey, recovery::RecoverableSignature, Signature};

use ledger::{LedgerApp, LedgerError};

pub mod apdu;
mod error;
pub mod parse;

pub use error::Error as LedgerKeyStoreError;

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
            let command = apdu::app_version();
            let response = ledger_app.exchange(command)?;;
            debug!("Nervos CBK Ledger app Version: {:?}", response);
        }
        {
            let command = apdu::app_git_hash();
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

impl AbstractMasterPrivKey for &mut LedgerKeyStore {
    type Err = LedgerKeyStoreError;

    fn extended_pubkey<P>(self, path: &P) -> Result<ExtendedPubKey, Self::Err>
    where
        P: ?Sized + Debug + AsRef<[ChildNumber]>,
    {
        let ledger_app = self.init()?;
        let mut data = Vec::new();
        data.write_u8(path.as_ref().len() as u8)
            .expect("IO error not possible when writing to Vec last I checked");
        for &child_num in path.as_ref().iter() {
            data.write_u32::<BigEndian>(From::from(child_num))
                .expect("IO error not possible when writing to Vec last I checked");
        }
        let command = apdu::extend_public_key(data);
        let response = ledger_app.exchange(command)?;
        debug!(
            "Nervos CBK Ledger app extended pub key raw public key {:?} for path {:?}",
            &response, &path
        );
        let mut resp = &response.data[..];
        let len_slice = parse::split_off_at(&mut resp, 1)?;
        let len = match *len_slice {
            [len] => len as usize,
            _ => unreachable!("we used 1 above so this should be a 1-element slice"),
        };
        let raw_public_key = parse::split_off_at(&mut resp, len)?;
        parse::assert_nothing_left(resp)?;
        Ok(ExtendedPubKey {
            depth: path.as_ref().len() as u8,
            parent_fingerprint: {
                let mut engine = hash160::Hash::engine();
                engine
                    .write_all(b"`parent_fingerprint` currently unused by Nervos.")
                    .expect("write must ok");
                Fingerprint::from(&hash160::Hash::from_engine(engine)[0..4])
            },
            child_number: ChildNumber::from_hardened_idx(0)?,
            public_key: PublicKey::from_slice(&raw_public_key)?,
            chain_code: ChainCode([0; 32]), // dummy, unused
        })
    }

    fn sign<P>(&self, message: &H256, path: &P) -> Result<Signature, Self::Err>
    where
        P: ?Sized + Debug + AsRef<[ChildNumber]>,
    {
        unimplemented!()
    }

    fn sign_recoverable<P>(
        &self,
        message: &H256,
        path: &P,
    ) -> Result<RecoverableSignature, Self::Err>
    where
        P: ?Sized + Debug + AsRef<[ChildNumber]>,
    {
        unimplemented!()
    }
}
