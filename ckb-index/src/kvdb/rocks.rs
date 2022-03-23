use std::collections::{BTreeMap, HashMap};
use std::mem;
use std::ops::Bound;

use rocksdb::ops::{GetCF, IterateCF, WriteOps};
use rocksdb::{ColumnFamily, DBIterator, Direction, IteratorMode, WriteBatch, DB};

use super::{KVReader, KVTxn};

pub struct RocksReader<'a> {
    cf: &'a ColumnFamily,
    db: &'a DB,
}

impl<'a> RocksReader<'a> {
    pub fn new(db: &'a DB, cf: &'a ColumnFamily) -> RocksReader<'a> {
        RocksReader { db, cf }
    }
}

impl<'a> KVReader<'a> for RocksReader<'a> {
    type Iter = ReaderIter<'a>;

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        get_cf(self.db, self.cf, key)
    }

    fn iter_from(&'a self, key_start: &[u8]) -> Self::Iter {
        let mode = IteratorMode::From(key_start, Direction::Forward);
        let iter = self
            .db
            .iterator_cf(self.cf, mode)
            .expect("RocksReader iterator_cf failed");
        ReaderIter { iter }
    }
}

pub struct ReaderIter<'a> {
    iter: DBIterator<'a>,
}

impl<'a> Iterator for ReaderIter<'a> {
    type Item = (Vec<u8>, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter
            .next()
            .map(|(key, value)| (key.into(), value.into()))
    }
}

pub struct RocksTxn<'a> {
    cf: &'a ColumnFamily,
    db: &'a DB,
    removed: HashMap<Vec<u8>, bool>,
    inserted: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl<'a> RocksTxn<'a> {
    pub fn new(db: &'a DB, cf: &'a ColumnFamily) -> RocksTxn<'a> {
        RocksTxn {
            cf,
            db,
            removed: HashMap::default(),
            inserted: BTreeMap::default(),
        }
    }
}

impl<'a> KVReader<'a> for RocksTxn<'a> {
    type Iter = TxnIter<'a>;

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        if self.removed.contains_key(key) {
            return None;
        }
        self.inserted
            .get(key)
            .cloned()
            .or_else(|| get_cf(self.db, self.cf, key))
    }

    fn iter_from(&'a self, key_start: &[u8]) -> TxnIter<'a> {
        TxnIter::new(self, key_start)
    }
}

impl<'a> KVTxn<'a> for RocksTxn<'a> {
    fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> Option<Vec<u8>> {
        self.removed.remove(&key);
        self.inserted.insert(key, value)
    }

    fn remove_maybe(&mut self, key: Vec<u8>, must_exists: bool) -> Option<bool> {
        self.inserted.remove(&key);
        self.removed.insert(key, must_exists)
    }

    fn commit(self) {
        log::debug!("Rocks txn committing...");
        let mut common_keys = Vec::new();
        let mut batch = WriteBatch::default();
        for (removed_key, must_exists) in self.removed {
            if self.inserted.contains_key(&removed_key) {
                common_keys.push(removed_key.clone());
            }
            if let Err(err) = batch.delete_cf(self.cf, &removed_key) {
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
            batch
                .put_cf(self.cf, key, value)
                .expect("Put kv to rocks batch failed")
        }
        self.db
            .write(&batch)
            .expect("Commit rocks txn transaction failed");
        log::debug!("Rocks txn commited!");
    }
}

pub struct TxnIter<'a> {
    iter: ReaderIter<'a>,
    next_disk_pair: Option<(Vec<u8>, Vec<u8>)>,
    next_mem_pair: Option<(Vec<u8>, Vec<u8>)>,
    removed: &'a HashMap<Vec<u8>, bool>,
    inserted: &'a BTreeMap<Vec<u8>, Vec<u8>>,
}

impl<'a> TxnIter<'a> {
    fn new(txn: &'a RocksTxn<'a>, key_start: &[u8]) -> TxnIter<'a> {
        let mode = IteratorMode::From(key_start, Direction::Forward);
        let iter = txn
            .db
            .iterator_cf(txn.cf, mode)
            .expect("RocksReader iterator_cf failed");
        let mut reader_iter = ReaderIter { iter };
        let next_mem_pair = txn
            .inserted
            .range((Bound::Included(key_start.to_vec()), Bound::Unbounded))
            .next()
            .map(|(key, value)| (key.clone(), value.clone()));
        let next_disk_pair = reader_iter.next();
        TxnIter {
            iter: reader_iter,
            next_disk_pair,
            next_mem_pair,
            removed: &txn.removed,
            inserted: &txn.inserted,
        }
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
        mem::replace(&mut self.next_disk_pair, self.iter.next())
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

fn get_cf(db: &DB, cf: &ColumnFamily, key: &[u8]) -> Option<Vec<u8>> {
    db.get_cf(cf, key)
        .expect("RocksReader get_cf failed")
        .map(|value| value.to_vec())
}
