mod lmdb;
mod rocksdb;

pub use lmdb::{LmdbReader, LmdbTxn};

pub trait KVReader<'r> {
    type Iter: Iterator<Item = (Vec<u8>, Vec<u8>)>;
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn iter_from(&'r self, key_start: &[u8]) -> Self::Iter;
}

pub trait KVTxn<'r>: KVReader<'r> {
    fn put_pair(&mut self, (key, value): (Vec<u8>, Vec<u8>)) -> Option<Vec<u8>> {
        self.insert(key, value)
    }
    fn remove_ok(&mut self, key: Vec<u8>) -> Option<bool> {
        self.remove_maybe(key, false)
    }
    fn remove(&mut self, key: Vec<u8>) -> Option<bool> {
        self.remove_maybe(key, true)
    }
    fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> Option<Vec<u8>>;
    fn remove_maybe(&mut self, key: Vec<u8>, must_exists: bool) -> Option<bool>;
    fn commit(self);
}
