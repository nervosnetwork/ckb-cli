use std::path::PathBuf;

use crypto::secp::Pubkey;
use rocksdb::{ColumnFamily, IteratorMode, Options, DB};
use serde_derive::{Deserialize, Serialize};

use crate::{SecpKey, ROCKSDB_COL_KEY};

const KEY_SECP256K1: &[u8] = b"secp256k1";
const KEY_DELIMITER: u8 = b':';

pub struct KeyManager<'a> {
    cf: ColumnFamily<'a>,
    db: &'a DB,
}

impl<'a> KeyManager<'a> {
    pub fn new(db: &'a DB) -> KeyManager {
        let cf = db.cf_handle(ROCKSDB_COL_KEY).unwrap_or_else(|| {
            db.create_cf(ROCKSDB_COL_KEY, &Options::default())
                .unwrap_or_else(|_| panic!("Create ColumnFamily {} failed", ROCKSDB_COL_KEY))
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
                    bincode::serialize(&db_value).unwrap(),
                )
                .map_err(Into::into)
        } else {
            Err("privkey path is empty".to_owned())
        }
    }

    pub fn remove(&self, key: &SecpKey) -> Result<SecpKey, String> {
        let key = self.get(key)?;
        let key_bytes = RocksdbKey::new(key.pubkey.clone()).to_bytes();
        self.db.delete_cf(self.cf, &key_bytes)?;
        Ok(key)
    }

    pub fn get(&self, key: &SecpKey) -> Result<SecpKey, String> {
        let db_key = RocksdbKey::new(key.pubkey.clone());
        let key_bytes = db_key.to_bytes();
        match self.db.get_cf(self.cf, key_bytes)? {
            Some(db_vec) => {
                let db_value = bincode::deserialize(&db_vec).unwrap();
                Ok(from_db_kv(db_key, db_value))
            }
            None => Err("key not found".to_owned()),
        }
    }

    pub fn list(&self) -> Result<Vec<SecpKey>, String> {
        let mut keys = Vec::new();
        for (key_bytes, value_bytes) in self.db.iterator_cf(self.cf, IteratorMode::Start)? {
            let db_key = RocksdbKey::from_bytes(&key_bytes)?;
            let db_value: RocksdbValue = bincode::deserialize(&value_bytes).unwrap();
            let key = from_db_kv(db_key, db_value);
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
            .skip(key_type.len() + 1)
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

fn from_db_kv(db_key: RocksdbKey, db_value: RocksdbValue) -> SecpKey {
    match SecpKey::from_privkey_path(db_value.privkey_path) {
        Ok(mut key) => {
            key.pubkey = db_key.pubkey;
            key
        }
        Err(_) => SecpKey::from_pubkey(db_key.pubkey),
    }
}
