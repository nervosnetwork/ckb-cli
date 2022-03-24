use std::collections::HashMap;

use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_sdk::bip32::DerivationPath;
use ckb_sdk::traits::{
    Signer, SignerError, TransactionDependencyError, TransactionDependencyProvider,
};
use ckb_sdk::util::serialize_signature;
use ckb_sdk::SECP256K1;
use ckb_types::{bytes::Bytes, core::TransactionView, H160, H256};
use ckb_wallet::KeyChain;

use super::arg_parser::PrivkeyWrapper;
use crate::plugin::{KeyStoreHandler, SignTarget};

impl Signer for PrivkeyWrapper {
    fn match_id(&self, id: &[u8]) -> bool {
        if id.len() != 20 {
            return false;
        }
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &self.0);
        *id == blake2b_256(&pubkey.serialize()[..])[0..20]
    }

    fn sign(
        &self,
        id: &[u8],
        message: &[u8],
        recoverable: bool,
        _tx: &TransactionView,
    ) -> Result<Bytes, SignerError> {
        if !self.match_id(id) {
            return Err(SignerError::IdNotFound);
        }
        if message.len() != 32 {
            return Err(SignerError::InvalidMessage(format!(
                "expected length: 32, got: {}",
                message.len()
            )));
        }
        let msg = secp256k1::Message::from_slice(message).expect("Convert to message failed");
        if recoverable {
            let sig = SECP256K1.sign_recoverable(&msg, &self.0);
            Ok(Bytes::from(serialize_signature(&sig).to_vec()))
        } else {
            let sig = SECP256K1.sign(&msg, &self.0);
            Ok(Bytes::from(sig.serialize_compact().to_vec()))
        }
    }
}

pub struct KeyStoreHandlerSigner {
    handler: KeyStoreHandler,
    tx_dep_provider: Box<dyn TransactionDependencyProvider>,
    hd_ids: HashMap<H160, (DerivationPath, Option<KeyChain>, H160)>,
    passwords: HashMap<H160, String>,
    change_paths: HashMap<H160, String>,
}

impl KeyStoreHandlerSigner {
    pub fn new(
        handler: KeyStoreHandler,
        tx_dep_provider: Box<dyn TransactionDependencyProvider>,
    ) -> KeyStoreHandlerSigner {
        KeyStoreHandlerSigner {
            handler,
            tx_dep_provider,
            hd_ids: HashMap::default(),
            passwords: HashMap::default(),
            change_paths: HashMap::default(),
        }
    }
    pub fn set_password(&mut self, account: H160, password: String) {
        self.passwords.insert(account, password);
    }
    pub fn set_change_path(&mut self, account: H160, change_path: String) {
        self.change_paths.insert(account, change_path);
    }
    pub fn cache_key_set(
        &mut self,
        account: H160,
        external_start: u32,
        external_length: u32,
        change_start: u32,
        change_length: u32,
        password: Option<String>,
    ) -> Result<(), String> {
        let key_set = self.handler.derived_key_set_by_index(
            account.clone(),
            external_start,
            external_length,
            change_start,
            change_length,
            password,
        )?;
        for (path, pubkey_hash) in key_set.external {
            self.hd_ids.insert(
                pubkey_hash,
                (path, Some(KeyChain::External), account.clone()),
            );
        }
        for (path, pubkey_hash) in key_set.change {
            self.hd_ids
                .insert(pubkey_hash, (path, Some(KeyChain::Change), account.clone()));
        }
        Ok(())
    }
    fn get_id_info(&self, id: &[u8]) -> Option<(H160, DerivationPath, Option<KeyChain>, H160)> {
        if id.len() != 16 {
            return None;
        }
        let mut buf = [0u8; 20];
        buf.copy_from_slice(id);
        let hash160 = H160::from(buf);
        if let Some((path, key_chain, account)) = self.hd_ids.get(&hash160) {
            return Some((hash160, path.clone(), *key_chain, account.clone()));
        }
        if self
            .handler
            .has_account(hash160.clone())
            .unwrap_or_default()
        {
            return Some((hash160.clone(), DerivationPath::empty(), None, hash160));
        }
        None
    }
}

impl Signer for KeyStoreHandlerSigner {
    fn match_id(&self, id: &[u8]) -> bool {
        self.get_id_info(id).is_some()
    }

    fn sign(
        &self,
        id: &[u8],
        message: &[u8],
        recoverable: bool,
        tx: &TransactionView,
    ) -> Result<Bytes, SignerError> {
        let (hash160, path, _key_chain, account) =
            self.get_id_info(id).ok_or(SignerError::IdNotFound)?;
        if message.len() != 32 {
            return Err(SignerError::InvalidMessage(format!(
                "expected length: 32, got: {}",
                message.len()
            )));
        }
        let msg = H256::from_slice(message).unwrap();

        let (password, sign_target) = if self
            .handler
            .has_account_in_default(hash160.clone())
            .map_err(|err| SignerError::Other(err.into()))?
        {
            let password = self.passwords.get(&account).cloned().ok_or_else(|| {
                SignerError::Other(format!("no password is set for account: {:x}", account).into())
            })?;
            let target = SignTarget::AnyData(Default::default());
            (Some(password), target)
        } else {
            let inputs = tx
                .inputs()
                .into_iter()
                .map(|input| {
                    let tx_hash = &input.previous_output().tx_hash();
                    self.tx_dep_provider
                        .get_transaction(tx_hash)
                        .map(|tx_view| tx_view.data())
                        .map(json_types::Transaction::from)
                })
                .collect::<Result<Vec<_>, TransactionDependencyError>>()
                .map_err(|err| SignerError::Other(err.into()))?;
            let change_path = self.change_paths.get(&account).cloned().ok_or_else(|| {
                SignerError::Other(
                    format!("no change path is set for account: {:x}", account).into(),
                )
            })?;
            let target = SignTarget::Transaction {
                tx: tx.data().into(),
                change_path,
                inputs,
            };
            (None, target)
        };
        self.handler
            .sign(hash160, &path, msg, sign_target, password, recoverable)
            .map_err(|err| SignerError::Other(err.into()))
    }
}
