use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;

use bitcoin::util::bip32::DerivationPath;
use ckb_sdk::traits::{Signer, SignerError};
use ckb_sdk::util::serialize_signature;
use ckb_types::{bytes::Bytes, core::TransactionView, H160, H256};

use super::{KeyChain, KeyStore, KeyTimeout};

/// A signer use filesystem keystore as backend.
pub struct FileSystemKeystoreSigner {
    keystore: Arc<Mutex<KeyStore>>,
    hd_ids: HashMap<H160, (DerivationPath, Option<KeyChain>)>,
}

impl FileSystemKeystoreSigner {
    pub fn new(keystore: KeyStore) -> FileSystemKeystoreSigner {
        let keystore = Arc::new(Mutex::new(keystore));
        FileSystemKeystoreSigner {
            keystore,
            hd_ids: HashMap::default(),
        }
    }
    pub fn lock(&self, hash160: &H160) -> bool {
        self.keystore.lock().lock(hash160)
    }
    pub fn unlock(&self, hash160: &H160, password: &[u8]) -> Result<KeyTimeout, SignerError> {
        self.keystore
            .lock()
            .unlock(hash160, password)
            .map_err(|err| SignerError::Other(err.into()))
    }
    pub fn cache_key_set(
        &mut self,
        hash160: &H160,
        external_len: u32,
        change_len: u32,
    ) -> Result<(), SignerError> {
        let mut keystore = self.keystore.lock();
        let ckb_root_opt = keystore.get_ckb_root(hash160, true);
        if ckb_root_opt.is_none() {
            self.hd_ids.remove(hash160);
        }
        let ckb_root = ckb_root_opt
            .ok_or_else(|| SignerError::Other("master key not found".to_string().into()))?;
        self.hd_ids
            .insert(hash160.clone(), (DerivationPath::default(), None));

        let key_set = ckb_root.derived_key_set_by_index(0, external_len, 0, change_len);
        for (path, pubkey_hash) in key_set.external {
            self.hd_ids
                .insert(pubkey_hash, (path, Some(KeyChain::External)));
        }
        for (path, pubkey_hash) in key_set.change {
            self.hd_ids
                .insert(pubkey_hash, (path, Some(KeyChain::Change)));
        }
        Ok(())
    }
    fn get_id_info(&self, id: &[u8]) -> Option<(H160, DerivationPath, Option<KeyChain>)> {
        if id.len() != 20 {
            return None;
        }
        let mut buf = [0u8; 20];
        buf.copy_from_slice(id);
        let hash160 = H160::from(buf);
        if let Some((path, key_chain)) = self.hd_ids.get(&hash160) {
            return Some((hash160, path.clone(), *key_chain));
        }
        if self.keystore.lock().has_account(&hash160, true) {
            return Some((hash160, DerivationPath::default(), None));
        }
        None
    }
}

impl Signer for FileSystemKeystoreSigner {
    fn match_id(&self, id: &[u8]) -> bool {
        self.get_id_info(id).is_some()
    }

    fn sign(
        &self,
        id: &[u8],
        message: &[u8],
        recoverable: bool,
        _tx: &TransactionView,
    ) -> Result<Bytes, SignerError> {
        let (hash160, path, _key_chain) = self.get_id_info(id).ok_or(SignerError::IdNotFound)?;
        if message.len() != 32 {
            return Err(SignerError::InvalidMessage(format!(
                "expected length: 32, got: {}",
                message.len()
            )));
        }
        let msg = H256::from_slice(message).unwrap();

        if recoverable {
            self.keystore
                .lock()
                .sign_recoverable(&hash160, &path, &msg)
                .map(|signature| Bytes::from(serialize_signature(&signature).to_vec()))
                .map_err(|err| SignerError::Other(err.into()))
        } else {
            self.keystore
                .lock()
                .sign(&hash160, &path, &msg)
                .map(|signature| Bytes::from(signature.serialize_compact().to_vec()))
                .map_err(|err| SignerError::Other(err.into()))
        }
    }
}
