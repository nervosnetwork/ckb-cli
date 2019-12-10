mod error;
mod passphrase;
mod util;

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, Instant};

use super::bip32::{ChainCode, ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use chrono::{Datelike, Timelike, Utc};
use ckb_crypto::secp::SECP256K1;
use ckb_hash::blake2b_256;
use ckb_types::{H160, H256};
use faster_hex::hex_decode;
use rand::Rng;
use secp256k1::recovery::RecoverableSignature;
use uuid::Uuid;

pub use error::Error;
pub use passphrase::{CipherParams, Crypto, KdfParams, ScryptParams, ScryptType};
pub use util::{zeroize_privkey, zeroize_slice};

const KEYSTORE_VERSION: u32 = 3;
const KEYSTORE_ORIGIN: &str = "ckb-cli";

pub struct KeyStore {
    keys_dir: PathBuf,
    storage: PassphraseKeyStore,
    files: HashMap<H160, PathBuf>,
    unlocked_keys: HashMap<H160, TimedKey>,
}

impl Clone for KeyStore {
    fn clone(&self) -> KeyStore {
        KeyStore {
            keys_dir: self.keys_dir.clone(),
            storage: self.storage.clone(),
            files: self.files.clone(),
            unlocked_keys: HashMap::default(),
        }
    }
}

impl KeyStore {
    pub fn from_dir(dir: PathBuf, scrypt_type: ScryptType) -> Result<KeyStore, Error> {
        let abs_dir = dir.canonicalize()?;
        let mut key_store = KeyStore {
            keys_dir: abs_dir.clone(),
            storage: PassphraseKeyStore {
                keys_dir_path: abs_dir,
                scrypt_type,
            },
            files: HashMap::default(),
            unlocked_keys: HashMap::default(),
        };
        key_store.refresh_dir()?;
        Ok(key_store)
    }

    pub fn new_account(&mut self, password: &[u8]) -> Result<H160, Error> {
        let privkey = MasterPrivKey::try_new(1024)?;
        let key = Key::new(privkey);
        let abs_path = self.storage.store_key(key.filename(), &key, password)?;
        let hash160 = key.hash160().clone();
        self.files.insert(hash160.clone(), abs_path);
        Ok(hash160)
    }
    pub fn get_accounts(&mut self) -> &HashMap<H160, PathBuf> {
        self.refresh_dir().ok();
        &self.files
    }
    pub fn has_account(&mut self, hash160: &H160) -> bool {
        self.refresh_dir().ok();
        self.files.contains_key(hash160)
    }

    pub fn update(
        &mut self,
        hash160: &H160,
        password: &[u8],
        new_password: &[u8],
    ) -> Result<(), Error> {
        self.refresh_dir()?;
        let filepath = self.get_filepath(hash160)?;
        let key = self.storage.get_key(hash160, &filepath, password)?;
        self.storage
            .store_key(&filepath, &key, new_password)
            .map(|_| ())
    }
    pub fn delete(&mut self, hash160: &H160, password: &[u8]) -> Result<(), Error> {
        self.refresh_dir()?;
        let filepath = self.get_filepath(hash160)?;
        let _key = self.storage.get_key(hash160, &filepath, password)?;
        fs::remove_file(&filepath).map_err(Into::into)
    }

    pub fn lock(&mut self, hash160: &H160) -> bool {
        self.unlocked_keys.remove(hash160).is_some()
    }
    pub fn unlock(&mut self, hash160: &H160, password: &[u8]) -> Result<KeyTimeout, Error> {
        self.unlock_inner(hash160, password, None)
    }
    pub fn timed_unlock(
        &mut self,
        hash160: &H160,
        password: &[u8],
        keep: Duration,
    ) -> Result<KeyTimeout, Error> {
        self.unlock_inner(hash160, password, Some(keep))
    }
    pub fn get_lock_timeout(&self, hash160: &H160) -> Option<KeyTimeout> {
        self.unlocked_keys
            .get(hash160)
            .map(|timed_key| timed_key.timeout)
    }

    pub fn import(
        &mut self,
        data: &serde_json::Value,
        password: &[u8],
        new_password: &[u8],
    ) -> Result<H160, Error> {
        let key = Key::from_json(data, password)?;
        if self.files.contains_key(key.hash160()) {
            Err(Error::KeyExists(key.hash160().clone()))
        } else {
            let filepath = self.storage.store_key(key.filename(), &key, new_password)?;
            self.files.insert(key.hash160().clone(), filepath);
            Ok(key.hash160().clone())
        }
    }
    pub fn import_secp_key(
        &mut self,
        key: &secp256k1::SecretKey,
        password: &[u8],
    ) -> Result<H160, Error> {
        let key = Key::new(MasterPrivKey::from_secp_key(key));
        if self.files.contains_key(key.hash160()) {
            Err(Error::KeyExists(key.hash160().clone()))
        } else {
            let filepath = self.storage.store_key(key.filename(), &key, password)?;
            self.files.insert(key.hash160().clone(), filepath);
            Ok(key.hash160().clone())
        }
    }
    pub fn import_key(&mut self, key: &Key, password: &[u8]) -> Result<H160, Error> {
        if self.files.contains_key(key.hash160()) {
            Err(Error::KeyExists(key.hash160().clone()))
        } else {
            let filepath = self.storage.store_key(key.filename(), key, password)?;
            self.files.insert(key.hash160().clone(), filepath);
            Ok(key.hash160().clone())
        }
    }
    pub fn export(
        &self,
        hash160: &H160,
        password: &[u8],
        new_password: &[u8],
        scrypt_type: ScryptType,
    ) -> Result<serde_json::Value, Error> {
        let filepath = self.get_filepath(hash160)?;
        let key = self.storage.get_key(hash160, &filepath, password)?;
        Ok(key.to_json(new_password, scrypt_type))
    }
    pub fn export_key(&self, hash160: &H160, password: &[u8]) -> Result<MasterPrivKey, Error> {
        let filepath = self.get_filepath(hash160)?;
        let key = self.storage.get_key(hash160, &filepath, password)?;
        Ok(key.master_privkey)
    }

    pub fn sign(
        &mut self,
        hash160: &H160,
        path: Option<&DerivationPath>,
        message: &H256,
    ) -> Result<secp256k1::Signature, Error> {
        Ok(self
            .get_timed_key(hash160)?
            .master_privkey()
            .sign(message, path))
    }
    pub fn sign_recoverable(
        &mut self,
        hash160: &H160,
        path: Option<&DerivationPath>,
        message: &H256,
    ) -> Result<RecoverableSignature, Error> {
        Ok(self
            .get_timed_key(hash160)?
            .master_privkey()
            .sign_recoverable(message, path))
    }
    pub fn sign_with_password(
        &self,
        hash160: &H160,
        path: Option<&DerivationPath>,
        message: &H256,
        password: &[u8],
    ) -> Result<secp256k1::Signature, Error> {
        let filepath = self.get_filepath(hash160)?;
        let key = self.storage.get_key(hash160, &filepath, password)?;
        Ok(key.master_privkey.sign(message, path))
    }
    pub fn sign_recoverable_with_password(
        &self,
        hash160: &H160,
        path: Option<&DerivationPath>,
        message: &H256,
        password: &[u8],
    ) -> Result<RecoverableSignature, Error> {
        let filepath = self.get_filepath(hash160)?;
        let key = self.storage.get_key(hash160, &filepath, password)?;
        Ok(key.master_privkey.sign_recoverable(message, path))
    }
    pub fn extended_pubkey(
        &mut self,
        hash160: &H160,
        path: Option<&DerivationPath>,
    ) -> Result<ExtendedPubKey, Error> {
        Ok(self
            .get_timed_key(hash160)?
            .master_privkey()
            .extended_pubkey(path)?)
    }
    pub fn extended_pubkey_with_password(
        &mut self,
        hash160: &H160,
        path: Option<&DerivationPath>,
        password: &[u8],
    ) -> Result<ExtendedPubKey, Error> {
        let filepath = self.get_filepath(hash160)?;
        let key = self.storage.get_key(hash160, &filepath, password)?;
        Ok(key.master_privkey.extended_pubkey(path)?)
    }
    pub fn derived_key_set_with_password(
        &mut self,
        hash160: &H160,
        password: &[u8],
        external_max_len: u32,
        change_last: &H160,
        change_max_len: u32,
    ) -> Result<DerivedKeySet, Error> {
        let filepath = self.get_filepath(hash160)?;
        let key = self.storage.get_key(hash160, &filepath, password)?;
        key.derived_key_set(external_max_len, change_last, change_max_len)
    }
    pub fn derived_key_set_by_index_with_password(
        &mut self,
        hash160: &H160,
        password: &[u8],
        external_start: u32,
        external_length: u32,
        change_start: u32,
        change_length: u32,
    ) -> Result<DerivedKeySet, Error> {
        let filepath = self.get_filepath(hash160)?;
        let key = self.storage.get_key(hash160, &filepath, password)?;
        Ok(key.derived_key_set_by_index(
            external_start,
            external_length,
            change_start,
            change_length,
        ))
    }

    // NOTE: assume refresh keystore directory is not a hot action
    fn refresh_dir(&mut self) -> Result<(), Error> {
        let mut files = HashMap::default();
        for entry in fs::read_dir(&self.keys_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let filename = path.file_name().and_then(OsStr::to_str).unwrap();
                if let Some(hash160_hex) = filename.rsplitn(2, "--").next() {
                    let mut hash160_bin = [0u8; 20];
                    if hex_decode(hash160_hex.as_bytes(), &mut hash160_bin).is_ok() {
                        if let Ok(hash160) = H160::from_slice(&hash160_bin) {
                            files.insert(hash160, path.to_path_buf());
                        }
                    }
                }
            }
        }
        self.files = files;
        Ok(())
    }

    fn get_timed_key(&mut self, hash160: &H160) -> Result<&TimedKey, Error> {
        let is_expired = self
            .unlocked_keys
            .get(hash160)
            .ok_or_else(|| Error::AccountLocked(hash160.clone()))?
            .is_expired();
        if is_expired {
            self.unlocked_keys.remove(hash160);
            return Err(Error::AccountLocked(hash160.clone()));
        }

        let timed_key = self
            .unlocked_keys
            .get(hash160)
            .ok_or_else(|| Error::AccountLocked(hash160.clone()))?;
        Ok(timed_key)
    }

    fn get_filepath(&self, hash160: &H160) -> Result<PathBuf, Error> {
        self.files
            .get(hash160)
            .cloned()
            .ok_or_else(|| Error::AccountNotFound(hash160.clone()))
    }

    fn unlock_inner(
        &mut self,
        hash160: &H160,
        password: &[u8],
        keep: Option<Duration>,
    ) -> Result<KeyTimeout, Error> {
        let filepath = self.get_filepath(hash160)?;
        let key = self.storage.get_key(hash160, filepath, password)?;
        let entry = self.unlocked_keys.entry(hash160.clone());
        let value = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(TimedKey::new_timed(key, Duration::default())),
        };
        value.extend(keep);
        Ok(value.timeout)
    }
}

/// KeyStore protected by password
#[derive(Clone)]
struct PassphraseKeyStore {
    keys_dir_path: PathBuf,
    scrypt_type: ScryptType,
}

impl PassphraseKeyStore {
    // Loads and decrypts the key from disk.
    fn get_key<P: AsRef<Path>>(
        &self,
        hash160: &H160,
        filename: P,
        password: &[u8],
    ) -> Result<Key, Error> {
        let filepath = self.join_path(filename);
        let mut file = fs::File::open(&filepath)?;
        let data = serde_json::from_reader(&mut file)
            .map_err(|err| Error::ParseJsonFailed(err.to_string()))?;
        let key = Key::from_json(&data, password)?;
        if key.hash160() != hash160 {
            return Err(Error::KeyMismatch {
                got: key.hash160().clone(),
                expected: hash160.clone(),
            });
        }
        Ok(key)
    }

    // Writes and encrypts the key.
    fn store_key<P: AsRef<Path>>(
        &self,
        filename: P,
        key: &Key,
        password: &[u8],
    ) -> Result<PathBuf, Error> {
        let filepath = self.join_path(filename);
        let json_value = key.to_json(password, self.scrypt_type);
        let mut file = fs::File::create(&filepath)?;
        serde_json::to_writer(&mut file, &json_value).map_err(|err| Error::Io(err.to_string()))?;
        Ok(filepath)
    }

    // Joins filename with the key directory unless it is already absolute.
    fn join_path<P: AsRef<Path>>(&self, filename: P) -> PathBuf {
        if filename.as_ref().is_absolute() {
            filename.as_ref().to_path_buf()
        } else {
            self.keys_dir_path.join(filename.as_ref())
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum KeyTimeout {
    Infinite,
    Timeout(Instant),
}

impl fmt::Display for KeyTimeout {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let now = Instant::now();
        let output = match self {
            KeyTimeout::Timeout(timeout) if *timeout > now => {
                let total_secs = (*timeout - now).as_secs();
                let hours = total_secs / 3600;
                let left = total_secs % 3600;
                let minutes = left / 60;
                let seconds = left % 60;
                let time = match (hours, minutes, seconds) {
                    (0, 0, seconds) => format!("{} seconds", seconds),
                    (0, minutes, seconds) => format!("{} minutes, {} seconds", minutes, seconds),
                    (hours, minutes, seconds) => {
                        format!("{} hours, {} minutes, {} seconds", hours, minutes, seconds,)
                    }
                };
                format!("lock after: {}", time)
            }
            KeyTimeout::Timeout(_) => "locked".to_owned(),
            KeyTimeout::Infinite => "locked after exit interactive mode".to_owned(),
        };
        write!(f, "{}", output)
    }
}

struct TimedKey {
    key: Key,
    timeout: KeyTimeout,
}

impl TimedKey {
    fn master_privkey(&self) -> &MasterPrivKey {
        &self.key.master_privkey
    }

    fn new_timed(key: Key, keep: Duration) -> TimedKey {
        let timeout = Instant::now() + keep;
        TimedKey {
            key,
            timeout: KeyTimeout::Timeout(timeout),
        }
    }

    fn extend(&mut self, extra: Option<Duration>) {
        if self.is_expired() {
            self.timeout = KeyTimeout::Timeout(Instant::now());
        }
        if let Some(extra) = extra {
            if let KeyTimeout::Timeout(ref mut timeout) = self.timeout {
                *timeout += extra;
            }
        } else {
            self.timeout = KeyTimeout::Infinite;
        }
    }

    fn is_expired(&self) -> bool {
        match self.timeout {
            KeyTimeout::Timeout(timeout) => timeout <= Instant::now(),
            KeyTimeout::Infinite => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum KeyChain {
    External = 0,
    Change = 1,
}

pub struct DerivedKeySet {
    pub external: Vec<(DerivationPath, H160)>,
    pub change: Vec<(DerivationPath, H160)>,
}

impl DerivedKeySet {
    pub fn get_path(&self, hash160: &H160) -> Option<(KeyChain, DerivationPath)> {
        for (path, pubkey_hash) in &self.external {
            if pubkey_hash == hash160 {
                return Some((KeyChain::External, path.clone()));
            }
        }
        for (path, pubkey_hash) in &self.change {
            if pubkey_hash == hash160 {
                return Some((KeyChain::Change, path.clone()));
            }
        }
        None
    }
}

pub struct Key {
    // randomly generate uuid v4
    id: Uuid,
    // H160::from_slice(&blake2b_256(pubkey)[0..20])
    hash160: H160,
    // The extended secp256k1 private key (privkey + chaincode)
    master_privkey: MasterPrivKey,
}

impl Key {
    pub fn new(master_privkey: MasterPrivKey) -> Key {
        let id = Uuid::new_v4();
        let hash160 = master_privkey.hash160(None);
        Key {
            id,
            hash160,
            master_privkey,
        }
    }

    pub fn hash160(&self) -> &H160 {
        &self.hash160
    }

    pub fn derived_key_set(
        &self,
        external_max_len: u32,
        change_last: &H160,
        change_max_len: u32,
    ) -> Result<DerivedKeySet, Error> {
        let mut external_key_set = Vec::new();
        for i in 0..external_max_len {
            let path_string = format!("m/44'/309'/0'/{}/{}", KeyChain::External as u8, i);
            let path = DerivationPath::from_str(path_string.as_str()).unwrap();
            let pubkey_hash = self.derived_pubkey_hash(path.clone());
            external_key_set.push((path, pubkey_hash.clone()));
        }

        let mut change_key_set = Vec::new();
        for i in 0..change_max_len {
            let path_string = format!("m/44'/309'/0'/{}/{}", KeyChain::Change as u8, i);
            let path = DerivationPath::from_str(path_string.as_str()).unwrap();
            let pubkey_hash = self.derived_pubkey_hash(path.clone());
            change_key_set.push((path, pubkey_hash.clone()));
            if change_last == &pubkey_hash {
                return Ok(DerivedKeySet {
                    external: external_key_set,
                    change: change_key_set,
                });
            }
        }
        Err(Error::SearchDerivedAddrFailed)
    }

    pub fn derived_pubkey_hash(&self, path: DerivationPath) -> H160 {
        let extended_pubkey = self.master_privkey.extended_pubkey(Some(&path)).unwrap();
        let pubkey = extended_pubkey.public_key;
        H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
            .expect("Generate hash(H160) from pubkey failed")
    }

    pub fn derived_key_set_by_index(
        &self,
        external_start: u32,
        external_length: u32,
        change_start: u32,
        change_length: u32,
    ) -> DerivedKeySet {
        let get_pairs = |chain, start, length| {
            self.derived_pubkeys(chain, start, length)
                .into_iter()
                .map(|(path, extended_pubkey)| {
                    let pubkey = extended_pubkey.public_key;
                    let hash = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
                        .expect("Generate hash(H160) from pubkey failed");
                    (path, hash)
                })
                .collect::<Vec<_>>()
        };
        DerivedKeySet {
            external: get_pairs(KeyChain::External, external_start, external_length),
            change: get_pairs(KeyChain::Change, change_start, change_length),
        }
    }

    /// Public keys for external/change addresses
    pub fn derived_pubkeys(
        &self,
        chain: KeyChain,
        start: u32,
        length: u32,
    ) -> Vec<(DerivationPath, ExtendedPubKey)> {
        // At least one pubkey
        (0..length)
            .map(|i| {
                let path_string = format!("m/44'/309'/0'/{}/{}", chain as u8, i + start);
                let path = DerivationPath::from_str(path_string.as_str()).unwrap();
                let extended_pubkey = self.master_privkey.extended_pubkey(Some(&path)).unwrap();
                (path, extended_pubkey)
            })
            .collect()
    }

    pub fn filename(&self) -> String {
        let utc_now = Utc::now();
        let date = utc_now.date();
        let time = utc_now.time();
        format!(
            "UTC--{:04}-{:02}-{:02}T{:02}-{:02}-{:02}.{:09}Z--{:x}",
            date.year(),
            date.month(),
            date.day(),
            time.hour(),
            time.minute(),
            time.second(),
            time.nanosecond(),
            self.hash160(),
        )
    }

    pub fn from_json(data: &serde_json::Value, password: &[u8]) -> Result<Key, Error> {
        let id = util::get_str(data, "id").and_then(|id_str| {
            Uuid::parse_str(id_str)
                .map_err(|_| Error::ParseJsonFailed(format!("Invalid id: {}", id_str)))
        })?;

        let version = util::get_u64(data, "version")? as u32;
        if version != KEYSTORE_VERSION {
            return Err(Error::ParseJsonFailed(format!(
                "Unsupported keystore version: {}",
                version
            )));
        }

        let crypto = util::get_value(data, "crypto").and_then(|value| Crypto::from_json(value))?;
        if crypto.ciphertext().len() != 64 {
            return Err(Error::ParseJsonFailed(format!(
                "Invalid ciphertext length: {}, expected: 64",
                crypto.ciphertext().len()
            )));
        }
        let key_vec = crypto.decrypt(password)?;
        let mut key_bytes = [0u8; 64];
        key_bytes[..].copy_from_slice(&key_vec[..]);
        let master_privkey = MasterPrivKey::from_bytes(key_bytes)?;

        let hash160 = master_privkey.hash160(None);
        Ok(Key {
            id,
            hash160,
            master_privkey,
        })
    }

    pub fn to_json(&self, password: &[u8], scrypt_type: ScryptType) -> serde_json::Value {
        let mut buf = Uuid::encode_buffer();
        let id_str = self.id.to_hyphenated().encode_lower(&mut buf);
        let hash160_hex = format!("{:x}", self.hash160);
        let master_privkey = self.master_privkey.to_bytes();
        let crypto = Crypto::encrypt_key_scrypt(&master_privkey, password, scrypt_type);
        serde_json::json!({
            "origin": KEYSTORE_ORIGIN,
            "id": id_str,
            "version": KEYSTORE_VERSION,
            "hash160": hash160_hex,
            "crypto": crypto.to_json(),
        })
    }
}

pub struct MasterPrivKey {
    secp_secret_key: secp256k1::SecretKey,
    chain_code: [u8; 32],
}

impl MasterPrivKey {
    pub fn try_new(time: u16) -> Result<MasterPrivKey, Error> {
        let mut rng = rand::thread_rng();
        for _ in 0..time {
            let privkey_bytes: [u8; 32] = rng.gen();
            if let Ok(secp_secret_key) = secp256k1::SecretKey::from_slice(&privkey_bytes) {
                let chain_code: [u8; 32] = rng.gen();
                return Ok(MasterPrivKey {
                    secp_secret_key,
                    chain_code,
                });
            }
        }
        Err(Error::GenSecpFailed(time))
    }

    pub fn from_secp_key(secp_secret_key: &secp256k1::SecretKey) -> MasterPrivKey {
        let secp_secret_key = *secp_secret_key;
        let mut rng = rand::thread_rng();
        let chain_code = rng.gen();
        MasterPrivKey {
            secp_secret_key,
            chain_code,
        }
    }

    pub fn from_bytes(bytes: [u8; 64]) -> Result<MasterPrivKey, Error> {
        let secp_secret_key = secp256k1::SecretKey::from_slice(&bytes[0..32])
            .map_err(|_| Error::InvalidSecpSecret)?;
        let mut chain_code_bytes = [0u8; 32];
        chain_code_bytes.copy_from_slice(&bytes[32..64]);
        Ok(MasterPrivKey {
            secp_secret_key,
            chain_code: chain_code_bytes,
        })
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&self.secp_secret_key[..]);
        bytes[32..64].copy_from_slice(&self.chain_code[..]);
        bytes
    }

    fn sub_privkey(&self, path: Option<&DerivationPath>) -> ExtendedPrivKey {
        let sk = ExtendedPrivKey {
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::Normal { index: 0 },
            private_key: self.secp_secret_key,
            chain_code: ChainCode(self.chain_code),
        };
        if let Some(path) = path {
            sk.derive_priv(&SECP256K1, path)
                .expect("Derive sub-privkey error")
        } else {
            sk
        }
    }

    pub fn sign(&self, message: &H256, path: Option<&DerivationPath>) -> secp256k1::Signature {
        let message =
            secp256k1::Message::from_slice(message.as_bytes()).expect("Convert to message failed");
        let sub_sk = self.sub_privkey(path);
        SECP256K1.sign(&message, &sub_sk.private_key)
    }

    pub fn sign_recoverable(
        &self,
        message: &H256,
        path: Option<&DerivationPath>,
    ) -> RecoverableSignature {
        let message =
            secp256k1::Message::from_slice(message.as_bytes()).expect("Convert to message failed");
        let sub_sk = self.sub_privkey(path);
        SECP256K1.sign_recoverable(&message, &sub_sk.private_key)
    }

    pub fn extended_pubkey(&self, path: Option<&DerivationPath>) -> Result<ExtendedPubKey, String> {
        let sub_sk = self.sub_privkey(path);
        Ok(ExtendedPubKey::from_private(&SECP256K1, &sub_sk))
    }

    pub fn hash160(&self, path: Option<&DerivationPath>) -> H160 {
        let sub_sk = self.sub_privkey(path);
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sub_sk.private_key);
        H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
            .expect("Generate hash(H160) from pubkey failed")
    }
}

impl Drop for MasterPrivKey {
    fn drop(&mut self) {
        zeroize_privkey(&mut self.secp_secret_key);
        zeroize_slice(&mut self.chain_code);
    }
}
