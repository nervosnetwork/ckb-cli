use std::collections::HashMap;

use anyhow::anyhow;
use bitcoin::util::bip32::DerivationPath;

use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_sdk::traits::{
    Signer, SignerError, TransactionDependencyError, TransactionDependencyProvider,
};
use ckb_sdk::types::ScriptId;
use ckb_sdk::util::serialize_signature;
use ckb_sdk::SECP256K1;
use ckb_signer::KeyChain;
use ckb_types::{bytes::Bytes, core::TransactionView, packed::Script, prelude::*, H160, H256};

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
            let sig = SECP256K1.sign_ecdsa_recoverable(&msg, &self.0);
            Ok(Bytes::from(serialize_signature(&sig).to_vec()))
        } else {
            let sig = SECP256K1.sign_ecdsa(&msg, &self.0);
            Ok(Bytes::from(sig.serialize_compact().to_vec()))
        }
    }
}

#[derive(Default, Clone)]
pub struct PrivkeySigner {
    privkeys: HashMap<H160, PrivkeyWrapper>,
    ids: HashMap<H160, H160>,
}

impl PrivkeySigner {
    pub fn new(keys: Vec<PrivkeyWrapper>) -> PrivkeySigner {
        let privkeys = HashMap::with_capacity(keys.len());
        let ids = HashMap::with_capacity(keys.len());
        let mut signer = PrivkeySigner { privkeys, ids };
        for key in keys {
            signer.add_privkey(key);
        }
        signer
    }

    pub fn has_account(&self, account: &H160) -> bool {
        self.privkeys.contains_key(account)
    }

    pub fn add_privkey(&mut self, privkey: PrivkeyWrapper) {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &privkey);
        let id = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20]).unwrap();
        self.privkeys.insert(id.clone(), privkey);
        self.ids.insert(id.clone(), id);
    }

    pub fn cache_account_lock_hash160(&mut self, account: H160, script_id: &ScriptId) -> bool {
        if self.privkeys.contains_key(&account) {
            let script_hash = Script::new_builder()
                .code_hash(script_id.code_hash.pack())
                .hash_type(script_id.hash_type.into())
                .args(Bytes::from(account.as_bytes().to_vec()).pack())
                .build()
                .calc_script_hash();
            let lock_hash160 = H160::from_slice(&script_hash.as_slice()[0..20]).unwrap();
            self.ids.insert(lock_hash160, account);
            true
        } else {
            false
        }
    }
}

impl Signer for PrivkeySigner {
    fn match_id(&self, id: &[u8]) -> bool {
        if id.len() != 20 {
            return false;
        }
        self.ids.contains_key(&H160::from_slice(id).unwrap())
    }

    fn sign(
        &self,
        id: &[u8],
        message: &[u8],
        recoverable: bool,
        tx: &TransactionView,
    ) -> Result<Bytes, SignerError> {
        if id.len() != 20 {
            return Err(SignerError::IdNotFound);
        }
        let hash160 = H160::from_slice(id).unwrap();
        let account = self.ids.get(&hash160).ok_or(SignerError::IdNotFound)?;
        let privkey = self.privkeys.get(account).expect("no privkey found");
        privkey.sign(id, message, recoverable, tx)
    }
}

pub struct KeyStoreHandlerSigner {
    handler: KeyStoreHandler,
    tx_dep_provider: Box<dyn TransactionDependencyProvider>,
    ids: HashMap<H160, (DerivationPath, Option<KeyChain>, H160)>,
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
            ids: HashMap::default(),
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

    pub fn cache_account_lock_hash160(&mut self, account: H160, script_id: &ScriptId) -> bool {
        if self
            .handler
            .has_account(account.clone())
            .unwrap_or_default()
        {
            let script_hash = Script::new_builder()
                .code_hash(script_id.code_hash.pack())
                .hash_type(script_id.hash_type.into())
                .args(Bytes::from(account.as_bytes().to_vec()).pack())
                .build()
                .calc_script_hash();
            let lock_hash160 = H160::from_slice(&script_hash.as_slice()[0..20]).unwrap();
            self.ids
                .insert(lock_hash160, (DerivationPath::default(), None, account));
            true
        } else {
            false
        }
    }

    pub fn cache_key_set(
        &mut self,
        account: H160,
        external_max_len: u32,
        change_last: H160,
        change_max_len: u32,
    ) -> Result<(), String> {
        let password = self.passwords.get(&account).cloned();
        let key_set = self.handler.derived_key_set(
            account.clone(),
            external_max_len,
            change_last,
            change_max_len,
            password,
        )?;
        for (path, pubkey_hash) in key_set.external {
            self.ids.insert(
                pubkey_hash,
                (path, Some(KeyChain::External), account.clone()),
            );
        }
        for (path, pubkey_hash) in key_set.change {
            self.ids
                .insert(pubkey_hash, (path, Some(KeyChain::Change), account.clone()));
        }
        Ok(())
    }

    fn get_id_info(&self, id: &[u8]) -> Option<(DerivationPath, Option<KeyChain>, H160)> {
        if id.len() != 20 {
            return None;
        }
        let mut buf = [0u8; 20];
        buf.copy_from_slice(id);
        let hash160 = H160::from(buf);
        if let Some((path, key_chain, account)) = self.ids.get(&hash160) {
            return Some((path.clone(), *key_chain, account.clone()));
        }
        if self
            .handler
            .has_account(hash160.clone())
            .unwrap_or_default()
        {
            return Some((DerivationPath::default(), None, hash160));
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
        let (path, _key_chain, account) = self.get_id_info(id).ok_or(SignerError::IdNotFound)?;
        if message.len() != 32 {
            return Err(SignerError::InvalidMessage(format!(
                "expected length: 32, got: {}",
                message.len()
            )));
        }
        let msg = H256::from_slice(message).unwrap();

        let (password, sign_target) = if self
            .handler
            .has_account_in_default(account.clone())
            .map_err(|err| SignerError::Other(anyhow!(err)))?
        {
            let password = self.passwords.get(&account).cloned().ok_or_else(|| {
                SignerError::Other(anyhow!("no password is set for account: {:x}", account))
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
                SignerError::Other(anyhow!("no change path is set for account: {:x}", account))
            })?;
            let target = SignTarget::Transaction {
                tx: tx.data().into(),
                change_path,
                inputs,
            };
            (None, target)
        };
        self.handler
            .sign(account, &path, msg, sign_target, password, recoverable)
            .map_err(|err| SignerError::Other(anyhow!(err)))
    }
}

pub struct CommonSigner {
    signers: Vec<Box<dyn Signer>>,
}

impl CommonSigner {
    pub fn new(signers: Vec<Box<dyn Signer>>) -> CommonSigner {
        CommonSigner { signers }
    }

    fn get_signer(&self, id: &[u8]) -> Option<&dyn Signer> {
        for signer in &self.signers {
            if signer.match_id(id) {
                return Some(signer.as_ref());
            }
        }
        None
    }
}

impl Signer for CommonSigner {
    fn match_id(&self, id: &[u8]) -> bool {
        self.get_signer(id).is_some()
    }

    fn sign(
        &self,
        id: &[u8],
        message: &[u8],
        recoverable: bool,
        tx: &TransactionView,
    ) -> Result<Bytes, SignerError> {
        let signer = self.get_signer(id).ok_or(SignerError::IdNotFound)?;
        signer.sign(id, message, recoverable, tx)
    }
}
