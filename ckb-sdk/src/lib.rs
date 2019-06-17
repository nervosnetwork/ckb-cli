mod basic;
mod chain;
mod error;
mod index;

#[cfg(feature = "local")]
mod key;
#[cfg(feature = "local")]
mod transaction;
#[cfg(feature = "local")]
mod util;

pub mod rpc;

pub use basic::{Address, AddressFormat, NetworkType, SecpKey, SECP_CODE_HASH};
pub use chain::{
    build_witness, GenesisInfo, TransferTransactionBuilder, MIN_SECP_CELL_CAPACITY, ONE_CKB,
};
pub use error::Error;
pub use index::{
    CellIndex, HashType, IndexDatabase, IndexError, Key as IndexKey, KeyMetrics as IndexKeyMetrics,
    KeyType as IndexKeyType, LiveCellInfo, TxInfo,
};
pub use rpc::HttpRpcClient;

#[cfg(feature = "local")]
pub use key::{KeyManager, SecpKey};
#[cfg(feature = "local")]
pub use transaction::{
    from_local_cell_out_point, to_local_cell_out_point, CellInputManager, CellManager,
    ScriptManager, TransactionManager, VerifyResult,
};
#[cfg(feature = "local")]
pub use util::with_rocksdb;

// 200MB extra disk space
pub const LMDB_EXTRA_MAP_SIZE: u64 = 200 * 1024 * 1024;

#[cfg(feature = "local")]
const ROCKSDB_COL_KEY: &str = "key";
#[cfg(feature = "local")]
const ROCKSDB_COL_CELL: &str = "cell";
#[cfg(feature = "local")]
const ROCKSDB_COL_CELL_INPUT: &str = "cell-input";
#[cfg(feature = "local")]
const ROCKSDB_COL_SCRIPT: &str = "script";
#[cfg(feature = "local")]
const ROCKSDB_COL_TX: &str = "tx";
