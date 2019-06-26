use std::collections::{BTreeMap, HashMap};
use std::mem;
use std::ops::Bound;

use super::{KVReader, KVTxn};

pub const LMDB_MAX_DBS: u32 = 6;
// 200MB extra disk space
pub const LMDB_EXTRA_MAP_SIZE: u64 = 200 * 1024 * 1024;

pub struct LmdbReader<'a> {
    store: rkv::SingleStore,
    reader: rkv::Reader<'a>,
}

impl<'a> LmdbReader<'a> {
    pub fn new(store: rkv::SingleStore, reader: rkv::Reader<'a>) -> LmdbReader<'a> {
        LmdbReader { store, reader }
    }
}

impl<'a> KVReader<'a> for LmdbReader<'a> {
    type Iter = ReaderIter<'a>;

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.store
            .get(&self.reader, key)
            .unwrap()
            .as_ref()
            .map(|value| value_to_bytes(value).to_vec())
    }

    fn iter_from(&'a self, key_start: &[u8]) -> Self::Iter {
        let iter = self.store.iter_from(&self.reader, key_start).unwrap();
        ReaderIter { iter }
    }
}

pub struct ReaderIter<'a> {
    iter: rkv::store::single::Iter<'a>,
}

impl<'a> Iterator for ReaderIter<'a> {
    type Item = (Vec<u8>, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|item_result| {
            let (key_ref, value_ref_opt) = item_result.unwrap();
            (
                key_ref.to_vec(),
                value_to_bytes(&value_ref_opt.unwrap()).to_vec(),
            )
        })
    }
}

pub struct LmdbTxn<'a> {
    store: rkv::SingleStore,
    writer: rkv::Writer<'a>,
    removed: HashMap<Vec<u8>, bool>,
    inserted: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl<'a> KVReader<'a> for LmdbTxn<'a> {
    type Iter = TxnIter<'a>;

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        if self.removed.contains_key(key) {
            return None;
        }

        self.inserted.get(key).cloned().or_else(|| {
            self.store
                .get(&self.writer, key)
                .unwrap()
                .as_ref()
                .map(|value| value_to_bytes(&value).to_vec())
        })
    }

    fn iter_from(&'a self, key_start: &[u8]) -> TxnIter<'a> {
        TxnIter::new(self, key_start)
    }
}

impl<'a> KVTxn<'a> for LmdbTxn<'a> {
    fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> Option<Vec<u8>> {
        self.removed.remove(&key);
        self.inserted.insert(key, value)
    }

    fn remove_maybe(&mut self, key: Vec<u8>, must_exists: bool) -> Option<bool> {
        self.inserted.remove(&key);
        self.removed.insert(key, must_exists)
    }

    fn commit(mut self) {
        log::debug!("Lmdb txn committing...");
        let mut common_keys = Vec::new();
        for (removed_key, must_exists) in self.removed {
            if self.inserted.contains_key(&removed_key) {
                common_keys.push(removed_key.clone());
            }
            if let Err(err) = self.store.delete(&mut self.writer, &removed_key) {
                if must_exists {
                    panic!(
                        "Txn remove key failed, key={:?}, error: {:?}",
                        removed_key, err
                    );
                }
            }
        }
        if !common_keys.is_empty() {
            panic!("Txn logic error, common keys: {:?}", common_keys);
        }

        for (key, value) in self.inserted {
            self.store
                .put(&mut self.writer, key, &rkv::Value::Blob(&value))
                .unwrap();
        }
        self.writer.commit().expect("Commit txn transaction failed");
        log::debug!("Lmdb txn commited!");
    }
}

impl<'a> LmdbTxn<'a> {
    pub fn new(store: rkv::SingleStore, writer: rkv::Writer<'a>) -> LmdbTxn<'a> {
        LmdbTxn {
            store,
            writer,
            removed: HashMap::default(),
            inserted: BTreeMap::default(),
        }
    }
}

pub struct TxnIter<'a> {
    iter: rkv::store::single::Iter<'a>,
    next_disk_pair: Option<(Vec<u8>, Vec<u8>)>,
    next_mem_pair: Option<(Vec<u8>, Vec<u8>)>,
    removed: &'a HashMap<Vec<u8>, bool>,
    inserted: &'a BTreeMap<Vec<u8>, Vec<u8>>,
}

impl<'a> TxnIter<'a> {
    fn new(txn: &'a LmdbTxn<'a>, key_start: &[u8]) -> TxnIter<'a> {
        let iter = txn.store.iter_from(&txn.writer, key_start).unwrap();
        let next_mem_pair = txn
            .inserted
            .range((Bound::Included(key_start.to_vec()), Bound::Unbounded))
            .next()
            .map(|(key, value)| (key.clone(), value.clone()));
        let mut txn_iter = TxnIter {
            iter,
            next_disk_pair: None,
            next_mem_pair,
            removed: &txn.removed,
            inserted: &txn.inserted,
        };
        txn_iter.next_disk_pair = txn_iter.update_next_disk_pair();
        txn_iter
    }

    fn update_next_mem_pair(&mut self) -> Option<(Vec<u8>, Vec<u8>)> {
        let (old_key, old_value) = self.next_mem_pair.take()?;
        self.next_mem_pair = self
            .inserted
            .range((Bound::Excluded(old_key.clone()), Bound::Unbounded))
            .next()
            .map(|(key, value)| (key.clone(), value.clone()));
        Some((old_key, old_value))
    }

    fn update_next_disk_pair(&mut self) -> Option<(Vec<u8>, Vec<u8>)> {
        let new_pair = self.iter.next().map(|item_result| {
            let (key_ref, value_ref_opt) = item_result.unwrap();
            (key_ref.to_vec(), value_ref_opt.unwrap().to_bytes().unwrap())
        });
        mem::replace(&mut self.next_disk_pair, new_pair)
    }
}

impl<'a> Iterator for TxnIter<'a> {
    // NOTE: assume key and value are small data
    type Item = (Vec<u8>, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (choose_mem, update_disk) = match (&self.next_disk_pair, &self.next_mem_pair) {
                (Some((ref disk_key, _)), Some((ref mem_key, _))) => {
                    (mem_key <= disk_key, disk_key <= mem_key)
                }
                (Some(_), None) => (false, true),
                (None, Some(_)) => (true, false),
                (None, None) => return None,
            };
            let next_pair = if choose_mem {
                if update_disk {
                    self.update_next_disk_pair();
                }
                self.update_next_mem_pair()
            } else {
                self.update_next_disk_pair()
            };
            let (next_key, next_value) = next_pair?;
            if !self.removed.contains_key(&next_key) {
                return Some((next_key, next_value));
            }
        }
    }
}

fn value_to_bytes<'a>(value: &'a rkv::Value) -> &'a [u8] {
    match value {
        rkv::Value::Blob(inner) => inner,
        _ => panic!("Invalid value type: {:?}", value),
    }
}
