use super::types::{BlockDeltaInfo, CellIndex, HashType, HeaderInfo, LiveCellInfo, TxInfo};
use ckb_sdk::NetworkType;
use ckb_types::{
    packed::{Header, OutPoint, Script},
    prelude::*,
    H256,
};
use serde_derive::{Deserialize, Serialize};

#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Clone, Copy, Serialize, Deserialize)]
#[repr(u16)]
pub enum KeyType {
    // key => value: {type} => {block-hash}
    GenesisHash = 0,
    // key => value: {type} => {NetworkType}
    Network = 1,
    // key => value: {type} => {Header}
    LastHeader = 2,
    // key => value: {type} => u128
    TotalCapacity = 3,

    // >> hash-type: block, transaction, lock, data
    // key => value: {type}:{hash} => {hash-type}
    GlobalHash = 100,
    // key => value: {type}:{tx-hash} => {TxInfo}
    TxMap = 101,
    // >> Save recent headers for rollback a fork and for statistics
    // key => value: {type}:{block-number} => {HeaderInfo}
    RecentHeader = 103,
    // >> for rollback block when fork happened (keep 1000 blocks?)
    // key = value: {type}:{block-number} => {BlockDeltaInfo}
    BlockDelta = 104,

    // key => value: {type}:{OutPoint} => {LiveCellInfo}
    LiveCellMap = 200,
    // key => value: {type}:{block-number}:{CellIndex} => {OutPoint}
    LiveCellIndex = 201,

    // >> Store live cell owned by certain lock
    // key => value: {type}:{lock-hash} => Script
    LockScript = 300,
    // key => value: {type}:{lock-hash} => u64
    LockTotalCapacity = 301,
    // >> NOTE: Remove when capacity changed
    // key => value: {type}:{capacity(u64::MAX - u64)}:{lock-hash} => ()
    LockTotalCapacityIndex = 302,
    // key => value: {type}:{lock-hash}:{block-number}:{CellIndex} => {OutPoint}
    LockLiveCellIndex = 303,
    // key => value: {type}:{lock-hash}:{block-number}:{tx-index(u32)} => {tx-hash}
    LockTx = 304,

    // key => value: {type}:{type-hash}:{block-number}:{CellIndex} => {OutPoint}
    TypeLiveCellIndex = 400,

    // key => value: {type}:{code-hash}:{block-number}:{CellIndex} => {OutPoint}
    CodeLiveCellIndex = 500,
}

impl KeyType {
    pub fn to_bytes(self) -> Vec<u8> {
        (self as u16).to_be_bytes().to_vec()
    }

    pub fn from_bytes(bytes: [u8; 2]) -> KeyType {
        match u16::from_be_bytes(bytes) {
            0 => KeyType::GenesisHash,
            1 => KeyType::Network,
            2 => KeyType::LastHeader,
            3 => KeyType::TotalCapacity,

            100 => KeyType::GlobalHash,
            101 => KeyType::TxMap,
            103 => KeyType::RecentHeader,
            104 => KeyType::BlockDelta,

            200 => KeyType::LiveCellMap,
            201 => KeyType::LiveCellIndex,

            300 => KeyType::LockScript,
            301 => KeyType::LockTotalCapacity,
            302 => KeyType::LockTotalCapacityIndex,
            303 => KeyType::LockLiveCellIndex,
            304 => KeyType::LockTx,

            400 => KeyType::TypeLiveCellIndex,
            500 => KeyType::CodeLiveCellIndex,

            value => panic!("Unexpected key type: value={}", value),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Key {
    GenesisHash,
    Network,
    LastHeader,
    TotalCapacity,

    GlobalHash(H256),
    TxMap(H256),
    RecentHeader(u64),
    BlockDelta(u64),

    LiveCellMap(OutPoint),
    LiveCellIndex(u64, CellIndex),

    LockScript(H256),
    LockTotalCapacity(H256),
    LockTotalCapacityIndex(u64, H256),
    LockLiveCellIndexPrefix(H256, Option<u64>),
    LockLiveCellIndex(H256, u64, CellIndex),
    LockTx(H256, u64, u32),

    TypeLiveCellIndexPrefix(H256, Option<u64>),
    TypeLiveCellIndex(H256, u64, CellIndex),
    CodeLiveCellIndexPrefix(H256, Option<u64>),
    CodeLiveCellIndex(H256, u64, CellIndex),
}

impl Key {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Key::GenesisHash => KeyType::GenesisHash.to_bytes(),
            Key::Network => KeyType::Network.to_bytes(),
            Key::LastHeader => KeyType::LastHeader.to_bytes(),
            Key::TotalCapacity => KeyType::TotalCapacity.to_bytes(),
            Key::GlobalHash(hash) => {
                let mut bytes = KeyType::GlobalHash.to_bytes();
                bytes.extend(hash.as_bytes().to_vec());
                bytes
            }
            Key::TxMap(tx_hash) => {
                let mut bytes = KeyType::TxMap.to_bytes();
                bytes.extend(tx_hash.as_bytes().to_vec());
                bytes
            }
            Key::RecentHeader(number) => {
                let mut bytes = KeyType::RecentHeader.to_bytes();
                bytes.extend(number.to_be_bytes().to_vec());
                bytes
            }
            Key::BlockDelta(number) => {
                let mut bytes = KeyType::BlockDelta.to_bytes();
                bytes.extend(number.to_be_bytes().to_vec());
                bytes
            }
            Key::LiveCellMap(out_point) => {
                let mut bytes = KeyType::LiveCellMap.to_bytes();
                bytes.extend(out_point.as_slice().to_vec());
                bytes
            }
            Key::LiveCellIndex(number, cell_index) => {
                let mut bytes = KeyType::LiveCellIndex.to_bytes();
                // Must use big endian for sort
                bytes.extend(number.to_be_bytes().to_vec());
                bytes.extend(cell_index.to_bytes());
                bytes
            }
            Key::LockScript(lock_hash) => {
                let mut bytes = KeyType::LockScript.to_bytes();
                bytes.extend(lock_hash.as_bytes().to_vec());
                bytes
            }
            Key::LockTotalCapacity(lock_hash) => {
                let mut bytes = KeyType::LockTotalCapacity.to_bytes();
                bytes.extend(lock_hash.as_bytes().to_vec());
                bytes
            }
            Key::LockTotalCapacityIndex(capacity, lock_hash) => {
                // NOTE: large capacity stay front
                let capacity = std::u64::MAX - capacity;
                let mut bytes = KeyType::LockTotalCapacityIndex.to_bytes();
                bytes.extend(capacity.to_be_bytes().to_vec());
                bytes.extend(lock_hash.as_bytes().to_vec());
                bytes
            }
            Key::LockLiveCellIndexPrefix(lock_hash, number_opt) => {
                let mut bytes = KeyType::LockLiveCellIndex.to_bytes();
                bytes.extend(lock_hash.as_bytes().to_vec());
                if let Some(number) = number_opt {
                    bytes.extend(number.to_be_bytes().to_vec());
                }
                bytes
            }
            Key::LockLiveCellIndex(lock_hash, number, cell_index) => {
                let mut bytes = KeyType::LockLiveCellIndex.to_bytes();
                bytes.extend(lock_hash.as_bytes().to_vec());
                // Must use big endian for sort
                bytes.extend(number.to_be_bytes().to_vec());
                bytes.extend(cell_index.to_bytes());
                bytes
            }
            Key::LockTx(lock_hash, number, tx_index) => {
                let mut bytes = KeyType::LockTx.to_bytes();
                bytes.extend(lock_hash.as_bytes().to_vec());
                // Must use big endian for sort
                bytes.extend(number.to_be_bytes().to_vec());
                bytes.extend(tx_index.to_be_bytes().to_vec());
                bytes
            }

            Key::TypeLiveCellIndexPrefix(type_hash, number_opt) => {
                let mut bytes = KeyType::TypeLiveCellIndex.to_bytes();
                bytes.extend(type_hash.as_bytes().to_vec());
                if let Some(number) = number_opt {
                    bytes.extend(number.to_be_bytes().to_vec());
                }
                bytes
            }
            Key::TypeLiveCellIndex(type_hash, number, cell_index) => {
                let mut bytes = KeyType::TypeLiveCellIndex.to_bytes();
                bytes.extend(type_hash.as_bytes().to_vec());
                // Must use big endian for sort
                bytes.extend(number.to_be_bytes().to_vec());
                bytes.extend(cell_index.to_bytes());
                bytes
            }

            Key::CodeLiveCellIndexPrefix(code_hash, number_opt) => {
                let mut bytes = KeyType::CodeLiveCellIndex.to_bytes();
                bytes.extend(code_hash.as_bytes().to_vec());
                if let Some(number) = number_opt {
                    bytes.extend(number.to_be_bytes().to_vec());
                }
                bytes
            }
            Key::CodeLiveCellIndex(code_hash, number, cell_index) => {
                let mut bytes = KeyType::CodeLiveCellIndex.to_bytes();
                bytes.extend(code_hash.as_bytes().to_vec());
                // Must use big endian for sort
                bytes.extend(number.to_be_bytes().to_vec());
                bytes.extend(cell_index.to_bytes());
                bytes
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Key {
        let type_bytes = [bytes[0], bytes[1]];
        let key_type = KeyType::from_bytes(type_bytes);
        let args_bytes = &bytes[2..];
        match key_type {
            KeyType::GenesisHash => Key::GenesisHash,
            KeyType::Network => Key::Network,
            KeyType::LastHeader => Key::LastHeader,
            KeyType::TotalCapacity => Key::TotalCapacity,
            KeyType::GlobalHash => {
                let hash = H256::from_slice(args_bytes).unwrap();
                Key::GlobalHash(hash)
            }
            KeyType::TxMap => {
                let tx_hash = H256::from_slice(args_bytes).unwrap();
                Key::TxMap(tx_hash)
            }
            KeyType::RecentHeader => {
                assert_eq!(args_bytes.len(), 8);
                let mut number_bytes = [0u8; 8];
                number_bytes.copy_from_slice(&args_bytes[..8]);
                let number = u64::from_be_bytes(number_bytes);
                Key::RecentHeader(number)
            }
            KeyType::BlockDelta => {
                let mut number_bytes = [0u8; 8];
                number_bytes.copy_from_slice(args_bytes);
                let number = u64::from_be_bytes(number_bytes);
                Key::BlockDelta(number)
            }
            KeyType::LiveCellMap => {
                let out_point = OutPoint::new_unchecked(args_bytes.to_vec().into());
                Key::LiveCellMap(out_point)
            }
            KeyType::LiveCellIndex => {
                let mut number_bytes = [0u8; 8];
                let mut cell_index_bytes = [0u8; 8];
                number_bytes.copy_from_slice(&args_bytes[..8]);
                cell_index_bytes.copy_from_slice(&args_bytes[8..]);
                let number = u64::from_be_bytes(number_bytes);
                let cell_index = CellIndex::from_bytes(cell_index_bytes);
                Key::LiveCellIndex(number, cell_index)
            }
            KeyType::LockScript => {
                let lock_hash = H256::from_slice(args_bytes).unwrap();
                Key::LockScript(lock_hash)
            }
            KeyType::LockTotalCapacity => {
                let lock_hash = H256::from_slice(args_bytes).unwrap();
                Key::LockTotalCapacity(lock_hash)
            }
            KeyType::LockTotalCapacityIndex => {
                let mut capacity_bytes = [0u8; 8];
                capacity_bytes.copy_from_slice(&args_bytes[..8]);
                let lock_hash_bytes = &args_bytes[8..];
                // NOTE: large capacity stay front
                let capacity = std::u64::MAX - u64::from_be_bytes(capacity_bytes);
                let lock_hash = H256::from_slice(lock_hash_bytes).unwrap();
                Key::LockTotalCapacityIndex(capacity, lock_hash)
            }
            KeyType::LockLiveCellIndex => {
                let lock_hash_bytes = &args_bytes[..32];
                let mut number_bytes = [0u8; 8];
                number_bytes.copy_from_slice(&args_bytes[32..40]);
                let mut cell_index_bytes = [0u8; 8];
                cell_index_bytes.copy_from_slice(&args_bytes[40..]);
                let lock_hash = H256::from_slice(lock_hash_bytes).unwrap();
                let number = u64::from_be_bytes(number_bytes);
                let cell_index = CellIndex::from_bytes(cell_index_bytes);
                Key::LockLiveCellIndex(lock_hash, number, cell_index)
            }
            KeyType::LockTx => {
                let lock_hash_bytes = &args_bytes[..32];
                let mut number_bytes = [0u8; 8];
                let mut tx_index_bytes = [0u8; 4];
                number_bytes.copy_from_slice(&args_bytes[32..40]);
                tx_index_bytes.copy_from_slice(&args_bytes[40..]);
                let lock_hash = H256::from_slice(lock_hash_bytes).unwrap();
                let number = u64::from_be_bytes(number_bytes);
                let tx_index = u32::from_be_bytes(tx_index_bytes);
                Key::LockTx(lock_hash, number, tx_index)
            }
            KeyType::TypeLiveCellIndex => {
                let type_hash_bytes = &args_bytes[..32];
                let mut number_bytes = [0u8; 8];
                number_bytes.copy_from_slice(&args_bytes[32..40]);
                let mut cell_index_bytes = [0u8; 8];
                cell_index_bytes.copy_from_slice(&args_bytes[40..]);
                let type_hash = H256::from_slice(type_hash_bytes).unwrap();
                let number = u64::from_be_bytes(number_bytes);
                let cell_index = CellIndex::from_bytes(cell_index_bytes);
                Key::TypeLiveCellIndex(type_hash, number, cell_index)
            }
            KeyType::CodeLiveCellIndex => {
                let code_hash_bytes = &args_bytes[..32];
                let mut number_bytes = [0u8; 8];
                number_bytes.copy_from_slice(&args_bytes[32..40]);
                let mut cell_index_bytes = [0u8; 8];
                cell_index_bytes.copy_from_slice(&args_bytes[40..]);
                let code_hash = H256::from_slice(code_hash_bytes).unwrap();
                let number = u64::from_be_bytes(number_bytes);
                let cell_index = CellIndex::from_bytes(cell_index_bytes);
                Key::CodeLiveCellIndex(code_hash, number, cell_index)
            }
        }
    }

    pub fn key_type(&self) -> KeyType {
        match self {
            Key::GenesisHash => KeyType::GenesisHash,
            Key::Network => KeyType::Network,
            Key::LastHeader => KeyType::LastHeader,
            Key::TotalCapacity => KeyType::TotalCapacity,
            Key::GlobalHash(..) => KeyType::GlobalHash,
            Key::TxMap(..) => KeyType::TxMap,
            Key::RecentHeader(..) => KeyType::RecentHeader,
            Key::BlockDelta(..) => KeyType::BlockDelta,
            Key::LiveCellMap(..) => KeyType::LiveCellMap,
            Key::LiveCellIndex(..) => KeyType::LiveCellIndex,
            Key::LockScript(..) => KeyType::LockScript,
            Key::LockTotalCapacity(..) => KeyType::LockTotalCapacity,
            Key::LockTotalCapacityIndex(..) => KeyType::LockTotalCapacityIndex,
            Key::LockLiveCellIndexPrefix(..) => KeyType::LockLiveCellIndex,
            Key::LockLiveCellIndex(..) => KeyType::LockLiveCellIndex,
            Key::LockTx(..) => KeyType::LockTx,
            Key::TypeLiveCellIndexPrefix(..) => KeyType::TypeLiveCellIndex,
            Key::TypeLiveCellIndex(..) => KeyType::TypeLiveCellIndex,
            Key::CodeLiveCellIndexPrefix(..) => KeyType::CodeLiveCellIndex,
            Key::CodeLiveCellIndex(..) => KeyType::CodeLiveCellIndex,
        }
    }

    pub(crate) fn pair_genesis_hash(value: &H256) -> (Vec<u8>, Vec<u8>) {
        (Key::GenesisHash.to_bytes(), value.as_bytes().to_vec())
    }
    pub(crate) fn pair_network(value: NetworkType) -> (Vec<u8>, Vec<u8>) {
        let value_byte = match value {
            NetworkType::Mainnet => 0,
            NetworkType::Testnet => 1,
            NetworkType::Dev => 255,
        };
        (Key::Network.to_bytes(), vec![value_byte])
    }
    pub(crate) fn pair_last_header(value: &Header) -> (Vec<u8>, Vec<u8>) {
        (Key::LastHeader.to_bytes(), value.as_slice().to_vec())
    }
    pub(crate) fn pair_total_capacity(value: &u128) -> (Vec<u8>, Vec<u8>) {
        (Key::TotalCapacity.to_bytes(), value.to_le_bytes().to_vec())
    }

    pub(crate) fn pair_global_hash(hash: H256, value: HashType) -> (Vec<u8>, Vec<u8>) {
        (Key::GlobalHash(hash).to_bytes(), vec![value as u8])
    }
    pub(crate) fn pair_tx_map(tx_hash: H256, value: &TxInfo) -> (Vec<u8>, Vec<u8>) {
        (
            Key::TxMap(tx_hash).to_bytes(),
            bincode::serialize(value).unwrap(),
        )
    }
    pub(crate) fn pair_recent_header(value: &HeaderInfo) -> (Vec<u8>, Vec<u8>) {
        (
            Key::RecentHeader(value.header().number()).to_bytes(),
            bincode::serialize(value).unwrap(),
        )
    }
    pub(crate) fn pair_block_delta(value: &BlockDeltaInfo) -> (Vec<u8>, Vec<u8>) {
        let number = value.number();
        (
            Key::BlockDelta(number).to_bytes(),
            bincode::serialize(value).unwrap(),
        )
    }

    pub(crate) fn pair_live_cell_map(
        out_point: OutPoint,
        value: &LiveCellInfo,
    ) -> (Vec<u8>, Vec<u8>) {
        (
            Key::LiveCellMap(out_point).to_bytes(),
            bincode::serialize(value).unwrap(),
        )
    }
    pub(crate) fn pair_live_cell_index(
        (number, cell_index): (u64, CellIndex),
        value: &OutPoint,
    ) -> (Vec<u8>, Vec<u8>) {
        (
            Key::LiveCellIndex(number, cell_index).to_bytes(),
            value.as_slice().to_vec(),
        )
    }

    pub(crate) fn pair_lock_script(lock_hash: H256, value: &Script) -> (Vec<u8>, Vec<u8>) {
        (
            Key::LockScript(lock_hash).to_bytes(),
            value.as_slice().to_vec(),
        )
    }
    pub(crate) fn pair_lock_total_capacity(lock_hash: H256, value: u64) -> (Vec<u8>, Vec<u8>) {
        (
            Key::LockTotalCapacity(lock_hash).to_bytes(),
            value.to_le_bytes().to_vec(),
        )
    }
    pub(crate) fn pair_lock_total_capacity_index(
        (capacity, lock_hash): (u64, H256),
    ) -> (Vec<u8>, Vec<u8>) {
        (
            Key::LockTotalCapacityIndex(capacity, lock_hash).to_bytes(),
            [0u8].to_vec(),
        )
    }
    pub(crate) fn pair_lock_live_cell_index(
        (lock_hash, number, cell_index): (H256, u64, CellIndex),
        value: &OutPoint,
    ) -> (Vec<u8>, Vec<u8>) {
        (
            Key::LockLiveCellIndex(lock_hash, number, cell_index).to_bytes(),
            value.as_slice().to_vec(),
        )
    }
    pub(crate) fn pair_lock_tx(
        (lock_hash, number, tx_index): (H256, u64, u32),
        value: &H256,
    ) -> (Vec<u8>, Vec<u8>) {
        (
            Key::LockTx(lock_hash, number, tx_index).to_bytes(),
            value.as_bytes().to_vec(),
        )
    }

    pub(crate) fn pair_type_live_cell_index(
        (type_hash, number, cell_index): (H256, u64, CellIndex),
        value: &OutPoint,
    ) -> (Vec<u8>, Vec<u8>) {
        (
            Key::TypeLiveCellIndex(type_hash, number, cell_index).to_bytes(),
            value.as_slice().to_vec(),
        )
    }

    pub(crate) fn pair_code_live_cell_index(
        (code_hash, number, cell_index): (H256, u64, CellIndex),
        value: &OutPoint,
    ) -> (Vec<u8>, Vec<u8>) {
        (
            Key::CodeLiveCellIndex(code_hash, number, cell_index).to_bytes(),
            value.as_slice().to_vec(),
        )
    }
}

impl Into<Vec<u8>> for &Key {
    fn into(self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl Into<Vec<u8>> for Key {
    fn into(self) -> Vec<u8> {
        (&self).into()
    }
}

impl From<&[u8]> for Key {
    fn from(data: &[u8]) -> Key {
        Key::from_bytes(data)
    }
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeyMetrics {
    count: usize,
    key_size: usize,
    value_size: usize,
    total_size: usize,
}

impl KeyMetrics {
    pub fn add_pair(&mut self, key: &[u8], value: &[u8]) {
        self.count += 1;
        self.key_size += key.len();
        self.value_size += value.len();
        self.total_size += key.len() + value.len();
    }
}
