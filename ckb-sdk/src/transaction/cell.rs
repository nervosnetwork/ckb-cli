
use rocksdb::{DB, ColumnFamily, Options, IteratorMode};
use ckb_core::{
    transaction::{CellOutput as CoreCellOutput},
};

use crate::{ROCKSDB_COL_CELL};

pub struct CellManager<'a> {
    cf: ColumnFamily<'a>,
    db: &'a DB
}

impl<'a> CellManager<'a> {
    pub fn new(db: &'a DB) -> CellManager {
        let cf =
            db.cf_handle(ROCKSDB_COL_CELL)
            .unwrap_or_else(||{
                db.create_cf(ROCKSDB_COL_CELL, &Options::default())
                    .expect(&format!("Create ColumnFamily {} failed", ROCKSDB_COL_CELL))
            });
        CellManager { cf, db }
    }

    pub fn add(&self, name: &str, cell: CoreCellOutput) -> Result<(), String> {
        let key_bytes = name.as_bytes().to_vec();
        let value_bytes = bincode::serialize(&cell).unwrap();
        self.db.put_cf(self.cf, key_bytes, value_bytes)?;
        Ok(())
    }

    pub fn remove(&self, name: &str) -> Result<(), String> {
        if self.db.get_cf(self.cf, name.as_bytes())?.is_some() {
            self.db.delete_cf(self.cf, name.as_bytes())?;
            Ok(())
        } else {
            Err("key not exists".to_owned())
        }
    }

    pub fn get(&self, name: &str) -> Result<CoreCellOutput, String> {
        match self.db.get_cf(self.cf, name.as_bytes())? {
            Some(db_vec) => bincode::deserialize(&db_vec).unwrap(),
            None => Err("key not exists".to_owned())
        }
    }

    pub fn list(&self) -> Result<Vec<(String, CoreCellOutput)>, String> {
        let mut pairs = Vec::new();
        for (key_bytes, value_bytes) in self.db.iterator_cf(self.cf, IteratorMode::Start)? {
            let name = String::from_utf8(key_bytes.to_vec()).unwrap();
            let cell: CoreCellOutput = bincode::deserialize(&value_bytes).unwrap();
            pairs.push((name, cell));
        }
        Ok(pairs)
    }
}
