mod error;
#[allow(clippy::mutable_key_type)]
mod index;
mod kvdb;
mod util;

pub use error::Error;
pub use index::{
    CellIndex, HashType, IndexDatabase, IndexError, Key as IndexKey, KeyMetrics as IndexKeyMetrics,
    KeyType as IndexKeyType, LiveCellInfo, TxInfo,
};
pub use kvdb::{KVReader, KVTxn, RocksReader, RocksTxn};
pub use util::{with_index_db, with_rocksdb};

pub const ROCKSDB_COL_INDEX_DB: &str = "index-db";
pub const VERSION: usize = 1;
