use std::path::PathBuf;

use std::collections::HashMap;
use std::fmt::Debug;
use std::io::Write;

use log::debug;

use bitcoin_hashes::{hash160, Hash};
use byteorder::{BigEndian, WriteBytesExt};
use ckb_sdk::wallet::{
    AbstractKeyStore, AbstractMasterPrivKey, ChainCode, ChildNumber, ExtendedPubKey, Fingerprint,
    ScryptType,
};
use ckb_types::H256;

use secp256k1::{key::PublicKey, recovery::RecoverableSignature, Signature};

use ledger::{LedgerApp as RawLedgerApp, LedgerError as RawLedgerError};

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
    discovered_devices: HashMap<LedgerId, LedgerCap>,
}

#[derive(Clone, Default, PartialEq, Eq, Hash, Debug)]
// TODO make contain actual id to distinguish between ledgers
pub struct LedgerId;

impl LedgerKeyStore {
    fn new() -> Self {
        LedgerKeyStore {
            discovered_devices: HashMap::new(),
        }
    }

    fn refresh(&mut self) -> Result<(), RawLedgerError> {
        self.discovered_devices.clear();
        // TODO fix ledger library so can put in all ledgers
        let raw_ledger_app = RawLedgerApp::new()?;
        let ledger_app = LedgerCap::from_ledger(raw_ledger_app)?;
        self.discovered_devices
            .insert(ledger_app.id.clone(), ledger_app);
        Ok(())
    }
}

impl AbstractKeyStore for LedgerKeyStore {
    const SOURCE_NAME: &'static str = "ledger hardware wallet";

    type Err = LedgerKeyStoreError;

    type AccountId = LedgerId;

    type AccountCap = LedgerCap;

    fn list_accounts(&mut self) -> Result<Box<dyn Iterator<Item = Self::AccountId>>, Self::Err> {
        self.refresh()?;
        let key_copies: Vec<_> = self.discovered_devices.keys().cloned().collect();
        Ok(Box::new(key_copies.into_iter()))
    }

    fn from_dir(_dir: PathBuf, _scrypt_type: ScryptType) -> Result<Self, LedgerKeyStoreError> {
        // TODO maybe force the initialization of the HidAPI "lazy static"?
        Ok(LedgerKeyStore::new())
    }

    fn borrow_account<'a, 'b>(
        &'a mut self,
        account_id: &'b Self::AccountId,
    ) -> Result<&'a Self::AccountCap, Self::Err> {
        self.refresh()?;
        self.discovered_devices
            .get(account_id)
            .ok_or_else(|| LedgerKeyStoreError::LedgerNotFound {
                id: account_id.clone(),
            })
    }
}

/// A ledger device with the Nervos app.
pub struct LedgerCap {
    id: LedgerId,
    ledger_app: RawLedgerApp,
}

impl LedgerCap {
    /// Create from a ledger device, checking that a proper version of the
    /// Nervos app is installed.
    fn from_ledger(_raw_ledger_app: RawLedgerApp) -> Result<Self, RawLedgerError> {
        let ledger_app = RawLedgerApp::new()?;
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
        Ok(LedgerCap {
            id: LedgerId,
            ledger_app: ledger_app,
        })
    }
}

impl AbstractMasterPrivKey for LedgerCap {
    type Err = LedgerKeyStoreError;

    fn extended_pubkey<P>(&self, path: &P) -> Result<ExtendedPubKey, Self::Err>
    where
        P: ?Sized + Debug + AsRef<[ChildNumber]>,
    {
        static WRITE_ERR_MSG: &'static str =
            "IO error not possible when writing to Vec last I checked";
        let mut data = Vec::new();
        data.write_u8(path.as_ref().len() as u8)
            .expect(WRITE_ERR_MSG);
        for &child_num in path.as_ref().iter() {
            data.write_u32::<BigEndian>(From::from(child_num))
                .expect(WRITE_ERR_MSG);
        }
        let command = apdu::extend_public_key(data);
        let response = self.ledger_app.exchange(command)?;
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

    fn sign<P>(&self, _message: &H256, _path: &P) -> Result<Signature, Self::Err>
    where
        P: ?Sized + Debug + AsRef<[ChildNumber]>,
    {
        unimplemented!()
    }

    fn sign_recoverable<P>(
        &self,
        _message: &H256,
        _path: &P,
    ) -> Result<RecoverableSignature, Self::Err>
    where
        P: ?Sized + Debug + AsRef<[ChildNumber]>,
    {
        unimplemented!()
    }
}
