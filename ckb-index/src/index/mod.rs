mod key;
mod types;

use std::collections::BTreeMap;
use std::fmt;
use std::io;

use ckb_sdk::{Address, GenesisInfo, NetworkType};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, HeaderView},
    packed::{Header, OutPoint, Script},
    prelude::*,
    H256,
};
use rocksdb::{ColumnFamily, DB};

use crate::{KVReader, KVTxn, RocksReader, RocksTxn};
pub use key::{Key, KeyMetrics, KeyType};
pub use types::{CellIndex, HashType, LiveCellInfo, TxInfo};

use types::BlockDeltaInfo;

// NOTE: You should reopen to increase database size when processed enough blocks
//  [reference]: https://stackoverflow.com/a/33571804
pub struct IndexDatabase<'a> {
    db: &'a DB,
    cf: ColumnFamily<'a>,
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
        cf: ColumnFamily<'a>,
        network: NetworkType,
        genesis_info: GenesisInfo,
        enable_explorer: bool,
    ) -> Result<IndexDatabase<'a>, IndexError> {
        let genesis_header = genesis_info.header().clone();
        assert_eq!(genesis_header.number(), 0);

        let (genesis_hash_opt, network_opt): (Option<H256>, Option<NetworkType>) = {
            let reader = RocksReader::new(db, cf);
            let genesis_hash_opt = reader
                .get(&Key::GenesisHash.to_bytes())
                .map(|bytes| H256::from_slice(&bytes).unwrap());
            let network_opt = reader
                .get(&Key::Network.to_bytes())
                .map(|bytes| NetworkType::from_u8(bytes[0]).unwrap());
            (genesis_hash_opt, network_opt)
        };
        if let Some(genesis_hash) = genesis_hash_opt {
            if network_opt != Some(network) {
                return Err(IndexError::InvalidNetworkType(format!(
                    "expected: {}, found: {:?}",
                    network, network_opt
                )));
            }
            let hash: H256 = genesis_header.hash().unpack();
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
        let block_hash: H256 = block.header().hash().unpack();
        if let Some(last_header) = self.last_header.clone() {
            if number != last_header.number() + 1 {
                return Err(IndexError::InvalidBlockNumber(number));
            }
            if block.header().parent_hash() != last_header.hash().unpack() {
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
                        .unwrap()
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
            let genesis_hash = self.genesis_info.header().hash().unpack();
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

    pub fn last_header(&self) -> Option<&HeaderView> {
        self.last_header.as_ref()
    }

    pub fn last_number(&self) -> Option<u64> {
        self.last_header.as_ref().map(HeaderView::number)
    }

    pub fn next_number(&self) -> Option<u64> {
        self.last_number().map(|number| number + 1)
    }

    fn get_address_inner(&self, reader: &RocksReader, lock_hash: H256) -> Option<Address> {
        reader
            .get(&Key::LockScript(lock_hash).to_bytes())
            .and_then(|bytes| {
                let script = Script::new_unchecked(bytes.into());
                script.args().get(0).and_then(|arg| {
                    let arg: Bytes = arg.unpack();
                    Address::from_lock_arg(&arg).ok()
                })
            })
    }

    pub fn get_capacity(&self, lock_hash: H256) -> Option<u64> {
        let reader = RocksReader::new(self.db, self.cf);
        reader
            .get(&Key::LockTotalCapacity(lock_hash).to_bytes())
            .map(|bytes| {
                let mut data = [0u8; 8];
                data.copy_from_slice(&bytes[..8]);
                u64::from_le_bytes(data)
            })
    }

    pub fn get_lock_hash_by_address(&self, address: Address) -> Option<H256> {
        let reader = RocksReader::new(self.db, self.cf);
        reader
            .get(&Key::SecpAddrLock(address).to_bytes())
            .map(|bytes| H256::from_slice(&bytes).unwrap())
    }

    pub fn get_lock_script_by_hash(&self, lock_hash: H256) -> Option<Script> {
        let reader = RocksReader::new(self.db, self.cf);
        reader
            .get(&Key::LockScript(lock_hash).to_bytes())
            .map(|bytes| Script::new_unchecked(bytes.into()))
    }

    // pub fn get_address(&self, lock_hash: H256) -> Option<Address> {
    //     let reader = env_read.read().unwrap();
    //     self.get_address_inner(&reader, lock_hash)
    // }

    pub fn get_live_cells_by_lock<F: FnMut(usize, &LiveCellInfo) -> (bool, bool)>(
        &self,
        lock_hash: H256,
        from_number: Option<u64>,
        terminator: F,
    ) -> Vec<LiveCellInfo> {
        let key_prefix = Key::LockLiveCellIndexPrefix(lock_hash.clone(), None);
        let key_start = Key::LockLiveCellIndexPrefix(lock_hash, from_number);
        self.get_live_cell_infos(key_prefix, key_start, terminator)
    }

    pub fn get_live_cells_by_type<F: FnMut(usize, &LiveCellInfo) -> (bool, bool)>(
        &self,
        type_hash: H256,
        from_number: Option<u64>,
        terminator: F,
    ) -> Vec<LiveCellInfo> {
        let key_prefix = Key::TypeLiveCellIndexPrefix(type_hash.clone(), None);
        let key_start = Key::TypeLiveCellIndexPrefix(type_hash, from_number);
        self.get_live_cell_infos(key_prefix, key_start, terminator)
    }

    pub fn get_live_cells_by_code<F: FnMut(usize, &LiveCellInfo) -> (bool, bool)>(
        &self,
        code_hash: H256,
        from_number: Option<u64>,
        terminator: F,
    ) -> Vec<LiveCellInfo> {
        let key_prefix = Key::CodeLiveCellIndexPrefix(code_hash.clone(), None);
        let key_start = Key::CodeLiveCellIndexPrefix(code_hash, from_number);
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

    pub fn get_top_n(&self, n: usize) -> Vec<(H256, Option<Address>, u64)> {
        let reader = RocksReader::new(self.db, self.cf);
        let key_prefix: Vec<u8> = KeyType::LockTotalCapacityIndex.to_bytes();

        let mut pairs = Vec::new();
        for (key_bytes, _) in reader.iter_from(&key_prefix) {
            if key_bytes[..key_prefix.len()] != key_prefix[..] {
                log::debug!("Reach the end of this type");
                break;
            }
            if let Key::LockTotalCapacityIndex(capacity, lock_hash) = Key::from_bytes(&key_bytes) {
                let address_opt = self.get_address_inner(&reader, lock_hash.clone());
                pairs.push((lock_hash, address_opt, capacity));
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
        let block_hash: H256 = header.hash().unpack();
        log::debug!("Block: {} => {:x}", header.number(), block_hash);

        // TODO: should forbid query when Init
        self.last_header = Some(header.clone());
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

        let secp_data_hash = self.genesis_info.secp_data_hash();
        let secp_type_hash = self.genesis_info.secp_type_hash();
        let mut txn = RocksTxn::new(self.db, self.cf);
        for block in blocks {
            let block_delta_info =
                BlockDeltaInfo::from_block(&block, &txn, secp_data_hash, secp_type_hash);
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
                KeyType::SecpAddrLock,
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
    IllegalBlock(H256),
    InvalidBlockNumber(u64),
    BlockInvalid(String),
    NotInit,
    IoError(String),
    InvalidGenesis(String),
    InvalidNetworkType(String),
}

impl From<io::Error> for IndexError {
    fn from(err: io::Error) -> IndexError {
        IndexError::IoError(err.to_string())
    }
}

impl fmt::Display for IndexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{:?}", self)
    }
}
