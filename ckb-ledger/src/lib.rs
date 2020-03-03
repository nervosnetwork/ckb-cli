use std::path::PathBuf;

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

use byteorder::{BigEndian, WriteBytesExt};
use log::debug;
use secp256k1::{key::PublicKey, recovery::RecoverableSignature, recovery::RecoveryId, Signature};

use ckb_sdk::wallet::{
    is_valid_derivation_path, AbstractKeyStore, AbstractMasterPrivKey, AbstractPrivKey,
    ChildNumber, DerivationPath, ScryptType,
};
use ckb_sdk::SignEntireHelper;
use ckb_types::H256;

use ledger::ApduCommand;
use ledger::LedgerApp as RawLedgerApp;

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
    discovered_devices: HashMap<LedgerId, LedgerMasterCap>,
}

#[derive(Clone, Default, PartialEq, Eq, Hash, Debug)]
// TODO make contain actual id to distinguish between ledgers
pub struct LedgerId(pub H256);

impl LedgerKeyStore {
    fn new() -> Self {
        LedgerKeyStore {
            discovered_devices: HashMap::new(),
        }
    }

    fn refresh(&mut self) -> Result<(), LedgerKeyStoreError> {
        self.discovered_devices.clear();
        // TODO fix ledger library so can put in all ledgers
        if let Ok(raw_ledger_app) = RawLedgerApp::new() {
            let ledger_app = LedgerMasterCap::from_ledger(raw_ledger_app)?;
            self.discovered_devices
                .insert(ledger_app.id.clone(), ledger_app);
        }
        Ok(())
    }
}

impl AbstractKeyStore for LedgerKeyStore {
    const SOURCE_NAME: &'static str = "ledger hardware wallet";

    type Err = LedgerKeyStoreError;

    type AccountId = LedgerId;

    type AccountCap = LedgerMasterCap;

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
#[derive(Clone)]
pub struct LedgerMasterCap {
    id: LedgerId,
    // TODO no Arc once we have "generic associated types" and can just borrow the device.
    ledger_app: Arc<RawLedgerApp>,
}

impl LedgerMasterCap {
    /// Create from a ledger device, checking that a proper version of the
    /// Nervos app is installed.
    fn from_ledger(ledger_app: RawLedgerApp) -> Result<Self, LedgerKeyStoreError> {
        let command = apdu::get_wallet_id();
        let response = ledger_app.exchange(command)?;
        debug!("Nervos CKB Ledger app wallet id: {:?}", response);

        let mut resp = &response.data[..];
        // TODO: The ledger app gives us 64 bytes but we only use 32
        // bytes. We should either limit how many the ledger app
        // gives, or take all 64 bytes here.
        let raw_wallet_id = parse::split_off_at(&mut resp, 32)?;
        let _ = parse::split_off_at(&mut resp, 32)?;
        parse::assert_nothing_left(resp)?;

        Ok(LedgerMasterCap {
            id: LedgerId(H256::from_slice(raw_wallet_id).unwrap()),
            ledger_app: Arc::new(ledger_app),
        })
    }
}

const P1_FIRST: u8 = 0x00;
const P1_NEXT: u8 = 0x01;
const P1_LAST: u8 = 0x80;

const WRITE_ERR_MSG: &'static str = "IO error not possible when writing to Vec last I checked";

impl AbstractMasterPrivKey for LedgerMasterCap {
    type Err = LedgerKeyStoreError;

    type Privkey = LedgerCap;

    fn extended_privkey(&self, path: &[ChildNumber]) -> Result<LedgerCap, Self::Err> {
        if !is_valid_derivation_path(path.as_ref()) {
            return Err(LedgerKeyStoreError::InvalidDerivationPath {
                path: path.as_ref().iter().cloned().collect(),
            });
        }

        Ok(LedgerCap {
            master: self.clone(),
            path: From::from(path.as_ref()),
        })
    }
}

/// A ledger device with the Nervos app constrained to a specific derivation path.
#[derive(Clone)]
pub struct LedgerCap {
    master: LedgerMasterCap,
    pub path: DerivationPath,
}

// Only not using impl trait because unstable
type LedgerClosure = Box<dyn FnOnce(Vec<u8>) -> Result<RecoverableSignature, LedgerKeyStoreError>>;

impl AbstractPrivKey for LedgerCap {
    type Err = LedgerKeyStoreError;

    type SignerSingleShot = SignEntireHelper<LedgerClosure, Self::Err>;

    fn public_key(&self) -> Result<secp256k1::PublicKey, Self::Err> {
        let mut data = Vec::new();
        data.write_u8(self.path.as_ref().len() as u8)
            .expect(WRITE_ERR_MSG);
        for &child_num in self.path.as_ref().iter() {
            data.write_u32::<BigEndian>(From::from(child_num))
                .expect(WRITE_ERR_MSG);
        }
        let command = apdu::extend_public_key(data);
        let response = self.master.ledger_app.exchange(command)?;
        debug!(
            "Nervos CBK Ledger app extended pub key raw public key {:?} for path {:?}",
            &response, &self.path
        );
        let mut resp = &response.data[..];
        let len = parse::split_first(&mut resp)? as usize;
        let raw_public_key = parse::split_off_at(&mut resp, len)?;
        parse::assert_nothing_left(resp)?;
        Ok(PublicKey::from_slice(&raw_public_key)?)
    }

    fn sign(&self, message: &H256) -> Result<Signature, Self::Err> {
        unimplemented!("Need to generalize method to not take hash")
        //let signature = self.sign_recoverable(message)?;
        //Ok(RecoverableSignature::to_standard(&signature))
    }

    fn begin_sign_recoverable(&self) -> Self::SignerSingleShot {
        unimplemented!()
    }
    /*
    fn sign_recoverable(&self, message: &H256) -> Result<RecoverableSignature, Self::Err> {
        let mut raw_path = Vec::new();
        raw_path
            .write_u8(self.path.as_ref().len() as u8)
            .expect(WRITE_ERR_MSG);
        for &child_num in self.path.as_ref().iter() {
            raw_path
                .write_u32::<BigEndian>(From::from(child_num))
                .expect(WRITE_ERR_MSG);
        }

        let mut raw_message = Vec::new();
        for &child_num in message.as_ref().iter() {
            raw_message
                .write_u8(From::from(child_num))
                .expect(WRITE_ERR_MSG);
        }

        debug!(
            "Nervos CKB Ledger app request {:?} with length {:?}",
            &(raw_path),
            &(raw_path.len() as u8)
        );

        self.master.ledger_app.exchange(ApduCommand {
            cla: 0x80,
            ins: 0x03,
            p1: P1_FIRST,
            p2: 0,
            length: raw_path.len() as u8,
            data: raw_path,
        })?;

        let response = self.master.ledger_app.exchange(ApduCommand {
            cla: 0x80,
            ins: 0x03,
            p1: P1_LAST | P1_NEXT,
            p2: 0,
            length: 32,
            data: raw_message,
        })?;

        let mut raw_signature = response.data.clone();
        let raw_bytes = &mut raw_signature[..];

        // TODO: Figure why this is necessary. For some reason
        // SECP256k1 doesn’t like 0x31 bytes.
        raw_bytes[0] = 0x30;

        // TODO: determine a real recovery id
        let recovery_id = RecoveryId::from_i32(0)?;

        Ok(RecoverableSignature::from_compact(
            &Signature::serialize_compact(&Signature::from_der(raw_bytes)?),
            recovery_id,
        )?)
    }
    */
}
