use std::collections::{BTreeMap, HashMap};
use std::mem;
use std::ops::Bound;

pub struct DBOverlay<'a> {
    store: rkv::SingleStore,
    writer: rkv::Writer<'a>,
    removed: HashMap<Vec<u8>, bool>,
    inserted: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl<'a> DBOverlay<'a> {
    pub fn new(store: rkv::SingleStore, writer: rkv::Writer<'a>) -> DBOverlay<'a> {
        DBOverlay {
            store,
            writer,
            removed: HashMap::default(),
            inserted: BTreeMap::default(),
        }
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        if self.removed.contains_key(key) {
            return None;
        }

        self.inserted.get(key).cloned().or_else(|| {
            self.store
                .get(&self.writer, key)
                .unwrap()
                .as_ref()
                .map(|value| match value {
                    rkv::Value::Blob(inner) => inner.to_vec(),
                    _ => panic!("Invalid value type: {:?}", value),
                })
        })
    }

    pub fn iter_from(&'a self, key_start: Vec<u8>) -> OverlayIter<'a> {
        OverlayIter::new(&self, key_start)
    }

    pub fn put_pair(&mut self, (key, value): (Vec<u8>, Vec<u8>)) -> Option<Vec<u8>> {
        self.insert(key, value)
    }
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> Option<Vec<u8>> {
        self.removed.remove(&key);
        self.inserted.insert(key, value)
    }

    fn remove_inner(&mut self, key: Vec<u8>, must_exists: bool) -> Option<bool> {
        self.inserted.remove(&key);
        self.removed.insert(key, must_exists)
    }
    pub fn remove_ok(&mut self, key: Vec<u8>) -> Option<bool> {
        self.remove_inner(key, false)
    }
    pub fn remove(&mut self, key: Vec<u8>) -> Option<bool> {
        self.remove_inner(key, true)
    }

    pub fn commit(mut self) {
        let mut common_keys = Vec::new();
        for (removed_key, must_exists) in self.removed {
            if self.inserted.contains_key(&removed_key) {
                common_keys.push(removed_key.clone());
            }
            let result = self.store.delete(&mut self.writer, removed_key);
            if must_exists {
                result.expect("Overlay remove key failed");
            }
        }
        if !common_keys.is_empty() {
            panic!("Overlay logic error, common keys: {:?}", common_keys);
        }

        for (key, value) in self.inserted {
            self.store
                .put(&mut self.writer, key, &rkv::Value::Blob(&value))
                .unwrap();
        }
        self.writer
            .commit()
            .expect("Commit overlay transaction failed");
    }
}

pub struct OverlayIter<'a> {
    iter: rkv::store::single::Iter<'a>,
    next_disk_pair: Option<(Vec<u8>, Vec<u8>)>,
    next_mem_pair: Option<(Vec<u8>, Vec<u8>)>,
    removed: &'a HashMap<Vec<u8>, bool>,
    inserted: &'a BTreeMap<Vec<u8>, Vec<u8>>,
}

impl<'a> OverlayIter<'a> {
    fn new(overlay: &'a DBOverlay<'a>, key_start: Vec<u8>) -> OverlayIter<'a> {
        let iter = overlay
            .store
            .iter_from(&overlay.writer, &key_start)
            .unwrap();
        let next_mem_pair = overlay
            .inserted
            .range((Bound::Included(key_start), Bound::Unbounded))
            .next()
            .map(|(key, value)| (key.clone(), value.clone()));
        let mut overlay_iter = OverlayIter {
            iter,
            next_disk_pair: None,
            next_mem_pair,
            removed: &overlay.removed,
            inserted: &overlay.inserted,
        };
        overlay_iter.next_disk_pair = overlay_iter.update_next_disk_pair();
        overlay_iter
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

impl<'a> Iterator for OverlayIter<'a> {
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
