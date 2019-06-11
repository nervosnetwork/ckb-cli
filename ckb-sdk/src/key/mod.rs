
use std::io::{Read, Write};
use std::str::FromStr;
use std::fs;
use std::path::{Path, PathBuf};

use faster_hex::{hex_decode};
use secp256k1::key;
use crypto::secp::{Pubkey, Privkey, Generator};
use rocksdb::{DB, ColumnFamily, Options, IteratorMode};
use serde_derive::{Deserialize, Serialize};

use crate::{NetworkType, Address, AddressFormat, ROCKSDB_COL_KEY};

pub const KEY_SECP256K1: &[u8] = b"secp256k1";
const KEY_DELIMITER: u8 = b':';

pub struct KeyManager<'a> {
    cf: ColumnFamily<'a>,
    db: &'a DB
}

impl<'a> KeyManager<'a> {
    pub fn new(db: &'a DB) -> KeyManager {
        let cf =
            db.cf_handle(ROCKSDB_COL_KEY)
            .unwrap_or_else(||{
                db.create_cf(ROCKSDB_COL_KEY, &Options::default())
                    .expect(&format!("Create ColumnFamily {} failed", ROCKSDB_COL_KEY))
            });
        KeyManager { cf, db }
    }

    pub fn add(&self, key: SecpKey) -> Result<(), String> {
        if let Some(privkey_path) = key.privkey_path {
            let db_key = RocksdbKey::new(key.pubkey);
            let db_value = RocksdbValue { privkey_path };
            self.db
                .put_cf(
                    self.cf,
                    db_key.to_bytes(),
                    bincode::serialize(&db_value).unwrap()
                )
                .map_err(Into::into)
        } else {
            Err("privkey path is empty".to_owned())
        }
    }

    pub fn remove(&self, key: SecpKey) -> Result<(), String> {
        let key_bytes = RocksdbKey::new(key.pubkey).to_bytes();
        if self.db.get_cf(self.cf, &key_bytes)?.is_some() {
            self.db.delete_cf(self.cf, &key_bytes)?;
            Ok(())
        } else {
            Err("key not exists".to_owned())
        }
    }

    pub fn get(&self, key: SecpKey) -> Result<SecpKey, String> {
        let db_key = RocksdbKey::new(key.pubkey);
        let key_bytes = db_key.to_bytes();
        match self.db.get_cf(self.cf, key_bytes)? {
            Some(db_vec) => {
                let db_value = bincode::deserialize(&db_vec).unwrap();
                Ok(SecpKey::from_db_kv(db_key, db_value))
            }
            None => Err("key not found".to_owned()),
        }
    }

    pub fn list(&self) -> Result<Vec<SecpKey>, String> {
        let mut keys = Vec::new();
        for (key_bytes, value_bytes) in self.db.iterator_cf(self.cf, IteratorMode::Start)? {
            let db_key = RocksdbKey::from_bytes(&key_bytes)?;
            let db_value: RocksdbValue = bincode::deserialize(&value_bytes).unwrap();
            let key = SecpKey::from_db_kv(db_key, db_value);
            keys.push(key);
        }
        Ok(keys)
    }

    pub fn clear(&self) -> Result<usize, String> {
        let mut count = 0;
        for (key_bytes, _) in self.db.iterator_cf(self.cf, IteratorMode::Start)? {
            self.db.delete_cf(self.cf, &key_bytes)?;
            count += 1;
        }
        Ok(count)
    }
}

#[derive(Debug)]
struct RocksdbKey {
    key_type: Vec<u8>,
    // TODO: support more key type
    pubkey: Pubkey,
}

impl RocksdbKey {
    fn new(pubkey: Pubkey) -> RocksdbKey {
        let key_type = KEY_SECP256K1.to_vec();
        RocksdbKey { key_type, pubkey }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.key_type.clone();
        bytes.push(KEY_DELIMITER);
        bytes.extend(self.pubkey.serialize());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<RocksdbKey, String> {
        let key_type = bytes
            .iter()
            .take_while(|byte| **byte != KEY_DELIMITER)
            .cloned()
            .collect::<Vec<u8>>();
        let pubkey_bytes = bytes
            .iter()
            .skip_while(|byte| **byte != KEY_DELIMITER)
            .cloned()
            .collect::<Vec<u8>>();
        let pubkey = Pubkey::from_slice(&pubkey_bytes).map_err(|err| err.to_string())?;
        Ok(RocksdbKey { key_type, pubkey })
    }

}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RocksdbValue {
    privkey_path: PathBuf,
}

pub struct SecpKey {
    privkey_path: Option<PathBuf>,
    privkey: Option<Privkey>,
    pubkey: Pubkey,
}

impl SecpKey {
    pub fn generate() -> SecpKey {
        let (privkey, pubkey) = Generator::new()
            .random_keypair()
            .expect("generate random key error");
        SecpKey { privkey_path: None, privkey: Some(privkey), pubkey }
    }

    pub fn path_exists(&self) -> bool {
        self.privkey_path
            .as_ref()
            .map(|path| Path::new(path).exists())
            .unwrap_or(false)
    }

    pub fn corrupted(&self) -> bool {
        self.privkey_path
            .as_ref()
            .map(|path| {
                match SecpKey::from_privkey_path(path) {
                    Ok(key) => key.pubkey != self.pubkey,
                    Err(_) => false,
                }
            })
            .unwrap_or(false)
    }

    fn from_db_kv(db_key: RocksdbKey, db_value: RocksdbValue) -> SecpKey {
        match SecpKey::from_privkey_path(db_value.privkey_path) {
            Ok(mut key) => {
                key.pubkey = db_key.pubkey;
                key
            },
            Err(_) => SecpKey::from_pubkey(db_key.pubkey)
        }
    }

    pub fn from_privkey(privkey: Privkey) -> Result<SecpKey, String> {
        let pubkey = privkey.pubkey().map_err(|err| err.to_string())?;
        Ok(SecpKey { privkey_path: None, privkey: Some(privkey), pubkey })
    }

    pub fn from_pubkey(pubkey: Pubkey) -> SecpKey {
        SecpKey { privkey_path: None, privkey: None, pubkey }
    }

    pub fn from_privkey_path<P: AsRef<Path>>(path: P) -> Result<SecpKey, String> {
        let path: PathBuf = path.as_ref().to_path_buf();
        let mut content = String::new();
        let mut file = fs::File::open(&path).map_err(|err| err.to_string())?;
        file.read_to_string(&mut content)
            .map_err(|err| err.to_string())?;
        let privkey_string: String = content
            .split_whitespace()
            .next()
            .map(|s| s.to_owned())
            .ok_or_else(|| "File is empty".to_string())?;
        let privkey_str = if privkey_string.starts_with("0x") || privkey_string.starts_with("0X") {
            &privkey_string[2..]
        } else {
            privkey_string.as_str()
        };
        let privkey = Privkey::from_str(privkey_str.trim()).map_err(|err| err.to_string())?;
        let pubkey = privkey.pubkey().map_err(|err| err.to_string())?;
        Ok(SecpKey { privkey_path: Some(path), privkey: Some(privkey), pubkey })
    }

    pub fn from_pubkey_str(mut pubkey_hex: &str) -> Result<SecpKey, String> {
        if pubkey_hex.starts_with("0x") || pubkey_hex.starts_with("0X") {
            pubkey_hex = &pubkey_hex[2..];
        }
        let mut pubkey_bytes = [0u8; 33];
        hex_decode(pubkey_hex.as_bytes(), &mut pubkey_bytes)
            .map_err(|err| format!("parse pubkey failed: {:?}", err))?;
        key::PublicKey::from_slice(&pubkey_bytes)
            .map_err(|err| err.to_string())
            .map(Into::into)
            .map(|pubkey| SecpKey{ privkey_path: None, privkey: None, pubkey })
    }

    pub fn save_to_path<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        if let Some(ref privkey) = self.privkey {
            let path = path.as_ref();
            if Path::new(path).exists() {
                return Err(format!(
                    "ERROR: output path ( {} ) already exists",
                    path.to_string_lossy()
                ));
            }
            let address = self.address()?;
            // TODO: support different network: testnet/mainnet
            let address_string = address.to_string(NetworkType::TestNet);
            let mut file = fs::File::create(path).map_err(|err| err.to_string())?;
            file.write(format!("{}\n", privkey.to_string()).as_bytes())
                .map_err(|err| err.to_string())?;
            file.write(format!("{}\n", address_string).as_bytes())
                .map_err(|err| err.to_string())?;
            Ok(())
        } else {
            Err(format!("Privkey is empty"))
        }
    }

    pub fn address(&self) -> Result<Address, String> {
        // TODO: support other address format
        Address::from_pubkey(AddressFormat::default(), &self.pubkey)
    }
}
