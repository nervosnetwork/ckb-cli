mod key;
mod types;

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt;
use std::io;

use ckb_sdk::{AddressPayload, GenesisInfo, NetworkType, ScriptWithAcpConfig};
use ckb_types::{
    core::{BlockView, HeaderView},
    packed::{Byte32, Header, OutPoint, Script},
    prelude::*,
};
use rocksdb::{ColumnFamily, DB};

use crate::{KVReader, KVTxn, RocksReader, RocksTxn};
pub use key::{Key, KeyMetrics, KeyType};
pub use types::{CellIndex, HashType, LiveCellInfo, TxInfo};

use types::{BlockDeltaInfo, KEEP_RECENT_BLOCKS};

// NOTE: You should reopen to increase database size when processed enough blocks
//  [reference]: https://stackoverflow.com/a/33571804
pub struct IndexDatabase<'a> {
    db: &'a DB,
    cf: &'a ColumnFamily,
    // network: NetworkType,
    genesis_info: GenesisInfo,
    last_header: Option<HeaderView>,
    tip_header: HeaderView,
    init_block_buf: Vec<BlockView>,
    // Disable record tx info by default
    enable_explorer: bool,
}

impl<'a> IndexDatabase<'a> {
    pub fn from_db(
        db: &'a DB,
        cf: &'a ColumnFamily,
        network: NetworkType,
        genesis_info: GenesisInfo,
        enable_explorer: bool,
    ) -> Result<IndexDatabase<'a>, IndexError> {
        let genesis_header = genesis_info.header().clone();
        assert_eq!(genesis_header.number(), 0);

        let (genesis_hash_opt, network_opt): (Option<Byte32>, Option<NetworkType>) = {
            let reader = RocksReader::new(db, cf);
            let genesis_hash_opt = reader
                .get(&Key::GenesisHash.to_bytes())
                .map(|bytes| Byte32::from_slice(&bytes).unwrap());
            let network_opt = reader
                .get(&Key::Network.to_bytes())
                .map(|bytes| match bytes[0] {
                    0 => NetworkType::Mainnet,
                    1 => NetworkType::Testnet,
                    255 => NetworkType::Dev,
                    _ => panic!("Corrupted index database (network field)"),
                });
            (genesis_hash_opt, network_opt)
        };
        if let Some(genesis_hash) = genesis_hash_opt {
            if network_opt != Some(network) {
                return Err(IndexError::InvalidNetworkType(format!(
                    "expected: {}, found: {:?}",
                    network, network_opt
                )));
            }
            let hash: Byte32 = genesis_header.hash();
            if genesis_hash != hash {
                return Err(IndexError::InvalidGenesis(format!(
                    "{:#x}, expected: {:#x}",
                    genesis_hash, hash,
                )));
            }
        } else {
            log::info!("genesis not found, init db");
            let mut writer = RocksTxn::new(db, cf);
            writer.put_pair(Key::pair_network(network));
            writer.put_pair(Key::pair_genesis_hash(&genesis_header.hash().unpack()));
            writer.commit();
        }

        let last_header = RocksReader::new(db, cf)
            .get(&Key::LastHeader.to_bytes())
            .map(|bytes| Header::new_unchecked(bytes.into()).into_view());
        Ok(IndexDatabase {
            db,
            cf,
            // network,
            last_header,
            genesis_info,
            tip_header: genesis_header,
            init_block_buf: Vec::new(),
            enable_explorer,
        })
    }

    pub fn apply_next_block(&mut self, block: BlockView) -> Result<(), IndexError> {
        let number = block.header().number();
        let block_hash = block.header().hash();
        if let Some(last_header) = self.last_header.clone() {
            if number != last_header.number() + 1 {
                return Err(IndexError::InvalidBlockNumber(number));
            }
            if block.header().parent_hash() != last_header.hash() {
                if number == 1 {
                    return Err(IndexError::IllegalBlock(block_hash));
                }

                log::warn!("Rollback because of block: {:#x}", block_hash);
                self.init_block_buf.clear();
                // Reload last header
                let last_block_delta: BlockDeltaInfo = {
                    let reader = RocksReader::new(self.db, self.cf);
                    let last_header: HeaderView = reader
                        .get(&Key::LastHeader.to_bytes())
                        .map(|bytes| Header::new_unchecked(bytes.into()).into_view())
                        .unwrap();
                    reader
                        .get(&Key::BlockDelta(last_header.number()).to_bytes())
                        .map(|bytes| bincode::deserialize(&bytes).unwrap())
                        .ok_or(IndexError::LongFork)?
                };
                let mut txn = RocksTxn::new(self.db, self.cf);
                last_block_delta.rollback(&mut txn);
                txn.commit();
                self.last_header = last_block_delta.parent_header();
                return Ok(());
            }
            if number > self.tip_header.number() {
                return Err(IndexError::BlockImmature(number));
            }
            self.apply_block_unchecked(block);
            Ok(())
        } else if number == 0 {
            let genesis_hash = self.genesis_info.header().hash();
            if block_hash != genesis_hash {
                Err(IndexError::InvalidGenesis(format!(
                    "{:#x}, expected: {:#x}",
                    block_hash, genesis_hash,
                )))
            } else {
                self.apply_block_unchecked(block);
                Ok(())
            }
        } else {
            Err(IndexError::NotInit)
        }
    }

    pub fn update_tip(&mut self, header: HeaderView) {
        self.tip_header = header
    }

    pub fn tip_header(&self) -> &HeaderView {
        &self.tip_header
    }

    pub fn last_header(&self) -> Option<&HeaderView> {
        self.last_header.as_ref()
    }

    pub fn last_number(&self) -> Option<u64> {
        self.last_header.as_ref().map(HeaderView::number)
    }

    pub fn next_number(&self) -> Option<u64> {
        self.last_number().map(|number| number + 1)
    }

    fn get_address_inner(&self, reader: &RocksReader, lock_hash: Byte32) -> Option<AddressPayload> {
        reader
            .get(&Key::LockScript(lock_hash.unpack()).to_bytes())
            .map(|bytes| {
                let script = Script::new_unchecked(bytes.into());
                // Meaningless AcpConfig
                AddressPayload::try_from(ScriptWithAcpConfig::new(&script, None)).unwrap()
            })
    }

    pub fn get_capacity(&self, lock_hash: Byte32) -> Option<u64> {
        let reader = RocksReader::new(self.db, self.cf);
        reader
            .get(&Key::LockTotalCapacity(lock_hash.unpack()).to_bytes())
            .map(|bytes| {
                let mut data = [0u8; 8];
                data.copy_from_slice(&bytes[..8]);
                u64::from_le_bytes(data)
            })
    }

    pub fn get_lock_script_by_hash(&self, lock_hash: Byte32) -> Option<Script> {
        let reader = RocksReader::new(self.db, self.cf);
        reader
            .get(&Key::LockScript(lock_hash.unpack()).to_bytes())
            .map(|bytes| Script::new_unchecked(bytes.into()))
    }

    pub fn get_live_cells_by_lock<F: FnMut(usize, &LiveCellInfo) -> (bool, bool)>(
        &self,
        lock_hash: Byte32,
        from_number: Option<u64>,
        terminator: F,
    ) -> Vec<LiveCellInfo> {
        let key_prefix = Key::LockLiveCellIndexPrefix(lock_hash.unpack(), None);
        let key_start = Key::LockLiveCellIndexPrefix(lock_hash.unpack(), from_number);
        self.get_live_cell_infos(key_prefix, key_start, terminator)
    }

    pub fn get_live_cells_by_type<F: FnMut(usize, &LiveCellInfo) -> (bool, bool)>(
        &self,
        type_hash: Byte32,
        from_number: Option<u64>,
        terminator: F,
    ) -> Vec<LiveCellInfo> {
        let key_prefix = Key::TypeLiveCellIndexPrefix(type_hash.unpack(), None);
        let key_start = Key::TypeLiveCellIndexPrefix(type_hash.unpack(), from_number);
        self.get_live_cell_infos(key_prefix, key_start, terminator)
    }

    pub fn get_live_cells_by_code<F: FnMut(usize, &LiveCellInfo) -> (bool, bool)>(
        &self,
        code_hash: Byte32,
        from_number: Option<u64>,
        terminator: F,
    ) -> Vec<LiveCellInfo> {
        let key_prefix = Key::CodeLiveCellIndexPrefix(code_hash.unpack(), None);
        let key_start = Key::CodeLiveCellIndexPrefix(code_hash.unpack(), from_number);
        self.get_live_cell_infos(key_prefix, key_start, terminator)
    }

    pub fn get_live_cell_infos<F: FnMut(usize, &LiveCellInfo) -> (bool, bool)>(
        &self,
        key_prefix: Key,
        key_start: Key,
        mut terminator: F,
    ) -> Vec<LiveCellInfo> {
        fn get_live_cell_info(reader: &RocksReader, out_point: OutPoint) -> Option<LiveCellInfo> {
            reader
                .get(&Key::LiveCellMap(out_point).to_bytes())
                .map(|bytes| bincode::deserialize(&bytes).unwrap())
        }

        let reader = RocksReader::new(self.db, self.cf);
        let key_prefix = key_prefix.to_bytes();
        let key_start = key_start.to_bytes();

        let mut infos = Vec::new();
        for (idx, (key_bytes, value_bytes)) in reader.iter_from(&key_start).enumerate() {
            if key_bytes[..key_prefix.len()] != key_prefix[..] {
                log::debug!("Reach the end of this lock");
                break;
            }
            let out_point = OutPoint::new_unchecked(value_bytes.into());
            let live_cell_info = get_live_cell_info(&reader, out_point).unwrap();
            let (stop, push_info) = terminator(idx, &live_cell_info);
            if push_info {
                infos.push(live_cell_info);
            }
            if stop {
                log::trace!("Stop search");
                break;
            }
        }
        infos
    }

    pub fn get_top_n(&self, n: usize) -> Vec<(Byte32, Option<AddressPayload>, u64)> {
        let reader = RocksReader::new(self.db, self.cf);
        let key_prefix: Vec<u8> = KeyType::LockTotalCapacityIndex.to_bytes();

        let mut pairs = Vec::new();
        for (key_bytes, _) in reader.iter_from(&key_prefix) {
            if key_bytes[..key_prefix.len()] != key_prefix[..] {
                log::debug!("Reach the end of this type");
                break;
            }
            if let Key::LockTotalCapacityIndex(capacity, lock_hash) = Key::from_bytes(&key_bytes) {
                let address_opt = self.get_address_inner(&reader, lock_hash.clone().pack());
                pairs.push((lock_hash.pack(), address_opt, capacity));
            } else {
                panic!("Got invalid key: {:?}", key_bytes);
            }
            if pairs.len() >= n {
                break;
            }
        }
        pairs
    }

    fn apply_block_unchecked(&mut self, block: BlockView) {
        let header = block.header();
        let block_hash = header.hash();
        log::debug!("Block: {} => {:x}", header.number(), block_hash);

        // TODO: should forbid query when Init
        self.last_header = Some(header);
        let blocks = if self.last_number().unwrap() < self.tip_header.number().saturating_sub(256) {
            self.init_block_buf.push(block);
            if self.init_block_buf.len() >= 200 {
                self.init_block_buf.split_off(0)
            } else {
                Vec::new()
            }
        } else {
            let mut blocks = self.init_block_buf.split_off(0);
            blocks.push(block);
            blocks
        };

        let mut txn = RocksTxn::new(self.db, self.cf);
        let blocks_len = blocks.len();
        for (idx, block) in blocks.into_iter().enumerate() {
            let clear_old = idx + 1 == blocks_len;
            let block_delta_info = BlockDeltaInfo::from_block(&block, &txn, clear_old);
            let number = block_delta_info.number();
            let hash = block_delta_info.hash();
            let result = block_delta_info.apply(&mut txn, self.enable_explorer);
            log::info!(
                "Block: {} => {:x} (chain_capacity={}, delta={}), txs={}, cell-removed={}, cell-added={}",
                number,
                hash,
                result.chain_capacity,
                result.capacity_delta,
                result.txs,
                result.cell_removed,
                result.cell_added,
            );
        }
        txn.commit();
    }

    pub fn get_metrics(&self, key_type_opt: Option<KeyType>) -> BTreeMap<KeyType, KeyMetrics> {
        let mut key_types = BTreeMap::default();
        if let Some(key_type) = key_type_opt {
            key_types.insert(key_type, KeyMetrics::default());
        } else {
            let mut types = vec![
                KeyType::GenesisHash,
                KeyType::Network,
                KeyType::LastHeader,
                KeyType::TotalCapacity,
                KeyType::RecentHeader,
                KeyType::BlockDelta,
                KeyType::LiveCellMap,
                KeyType::LiveCellIndex,
                KeyType::LockScript,
                KeyType::LockTotalCapacity,
                KeyType::LockTotalCapacityIndex,
                KeyType::LockLiveCellIndex,
                KeyType::TypeLiveCellIndex,
                KeyType::CodeLiveCellIndex,
            ];
            if self.enable_explorer {
                types.extend(vec![KeyType::TxMap, KeyType::LockTx, KeyType::GlobalHash]);
            }
            for key_type in types {
                key_types.insert(key_type, KeyMetrics::default());
            }
        }
        let reader = RocksReader::new(self.db, self.cf);
        for (key_type, metrics) in &mut key_types {
            let key_prefix = key_type.to_bytes();
            for (key_bytes, value_bytes) in reader.iter_from(&key_prefix) {
                if key_bytes[..key_prefix.len()] != key_prefix[..] {
                    log::debug!("Reach the end of this lock");
                    break;
                }
                metrics.add_pair(&key_bytes, &value_bytes);
            }
        }
        key_types
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum IndexError {
    BlockImmature(u64),
    IllegalBlock(Byte32),
    InvalidBlockNumber(u64),
    NotInit,
    IoError(String),
    InvalidGenesis(String),
    InvalidNetworkType(String),
    LongFork,
}

impl From<io::Error> for IndexError {
    fn from(err: io::Error) -> IndexError {
        IndexError::IoError(err.to_string())
    }
}

impl fmt::Display for IndexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            IndexError::BlockImmature(number) => {
                write!(
                    f,
                    "Current applied block number {} greater than tip block number",
                    number
                )?;
            }
            IndexError::IllegalBlock(_) => {
                write!(f, "Current applied block number is 1, but the parent hash not match genesis block hash")?;
            }
            IndexError::InvalidBlockNumber(number) => {
                write!(
                    f,
                    "Current applied block number {} is not the next block of lastest block",
                    number
                )?;
            }
            IndexError::NotInit => {
                write!(f, "Apply block before database initialization")?;
            }
            IndexError::IoError(msg) => {
                write!(f, "IO error: {}", msg)?;
            }
            IndexError::InvalidGenesis(msg) => {
                write!(f, "Genesis hash not match with DB, {}", msg)?;
            }
            IndexError::InvalidNetworkType(msg) => {
                write!(f, "NetworkType not match with DB, {}", msg)?;
            }
            IndexError::LongFork => {
                write!(
                    f,
                    "Already rollbacked {} blocks, long fork detected",
                    KEEP_RECENT_BLOCKS
                )?;
            }
        }
        Ok(())
    }
}
