mod key;
mod kvdb;
mod types;

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use crate::{Address, GenesisInfo, NetworkType};
use ckb_core::{block::Block, header::Header, script::Script, transaction::CellOutPoint};
use numext_fixed_hash::H256;

const LMDB_MAX_DBS: u32 = 6;

pub use key::{Key, KeyMetrics, KeyType};
pub use types::{CellIndex, HashType, LiveCellInfo, TxInfo};

use kvdb::{KVReader, KVTxn, LmdbReader, LmdbTxn};
use types::BlockDeltaInfo;

// NOTE: You should reopen to increase database size when processed enough blocks
//  [reference]: https://stackoverflow.com/a/33571804
pub struct IndexDatabase {
    env_arc: Arc<RwLock<rkv::Rkv>>,
    store: rkv::SingleStore,
    // network: NetworkType,
    genesis_info: GenesisInfo,
    last_header: Option<Header>,
    tip_header: Header,
    init_block_buf: Vec<Block>,
    // Disable record tx info by default
    enable_tx: bool,
}

impl IndexDatabase {
    pub fn from_path(
        network: NetworkType,
        genesis_info: GenesisInfo,
        mut directory: PathBuf,
        extra_size: u64,
        enable_tx: bool,
    ) -> Result<IndexDatabase, IndexError> {
        fn dir_size<P: AsRef<Path>>(path: P) -> u64 {
            let mut total_size = 0;
            for dir_entry in fs::read_dir(path.as_ref()).unwrap() {
                let metadata = dir_entry.unwrap().metadata().unwrap();
                total_size += metadata.len();
            }
            total_size
        }

        let genesis_header = genesis_info.header().clone();
        assert_eq!(genesis_header.number(), 0);

        directory.push(format!("{:#x}", genesis_header.hash()));
        std::fs::create_dir_all(&directory)?;
        let map_size = dir_size(&directory) + extra_size;
        let env_arc = rkv::Manager::singleton()
            .write()
            .unwrap()
            .get_or_create(directory.as_path(), |path| {
                let mut env = rkv::Rkv::environment_builder();
                env.set_max_dbs(LMDB_MAX_DBS);
                env.set_map_size(map_size as usize);
                rkv::Rkv::from_env(path, env)
            })
            .unwrap();
        let (store, last_header) = {
            let env_read = env_arc.read().unwrap();
            // Then you can use the environment handle to get a handle to a datastore:
            let store: rkv::SingleStore = env_read
                .open_single("index", rkv::StoreOptions::create())
                .unwrap();
            let (genesis_hash_opt, network_opt): (Option<H256>, Option<NetworkType>) = {
                let reader = LmdbReader::new(store, env_read.read().expect("reader"));
                let genesis_hash_opt = reader
                    .get(&Key::GenesisHash.to_bytes())
                    .map(|bytes| bincode::deserialize(&bytes).unwrap());
                let network_opt = reader
                    .get(&Key::Network.to_bytes())
                    .map(|bytes| bincode::deserialize(&bytes).unwrap());
                (genesis_hash_opt, network_opt)
            };
            if let Some(genesis_hash) = genesis_hash_opt {
                if network_opt != Some(network) {
                    return Err(IndexError::InvalidNetworkType(format!(
                        "expected: {}, found: {:?}",
                        network, network_opt
                    )));
                }
                if &genesis_hash != genesis_header.hash() {
                    return Err(IndexError::InvalidGenesis(format!(
                        "{:#x}, expected: {:#x}",
                        genesis_hash,
                        genesis_header.hash(),
                    )));
                }
            } else {
                log::info!("genesis not found, init db");
                let mut writer = LmdbTxn::new(store, env_read.write().unwrap());
                writer.put_pair(Key::pair_network(network));
                writer.put_pair(Key::pair_genesis_hash(genesis_header.hash()));
                writer.commit();
            }

            let last_header = {
                let reader = LmdbReader::new(store, env_read.read().expect("reader"));
                reader
                    .get(&Key::LastHeader.to_bytes())
                    .map(|bytes| bincode::deserialize(&bytes).unwrap())
            };
            (store, last_header)
        };
        Ok(IndexDatabase {
            env_arc,
            store,
            // network,
            last_header,
            genesis_info,
            tip_header: genesis_header,
            init_block_buf: Vec::new(),
            enable_tx,
        })
    }

    pub fn apply_next_block(&mut self, block: Block) -> Result<(), IndexError> {
        let number = block.header().number();
        if let Some(last_header) = self.last_header.clone() {
            if number != last_header.number() + 1 {
                return Err(IndexError::InvalidBlockNumber(number));
            }
            if block.header().parent_hash() != last_header.hash() {
                if number == 1 {
                    return Err(IndexError::IllegalBlock(block.header().hash().clone()));
                }

                log::warn!("Rollback because of block: {:#x}", block.header().hash());
                self.init_block_buf.clear();
                // Reload last header
                let env_read = self.env_arc.read().unwrap();
                let last_block_delta: BlockDeltaInfo = {
                    let reader = LmdbReader::new(self.store, env_read.read().expect("reader"));
                    let last_header: Header = reader
                        .get(&Key::LastHeader.to_bytes())
                        .map(|bytes| bincode::deserialize(&bytes).unwrap())
                        .unwrap();
                    reader
                        .get(&Key::BlockDelta(last_header.number()).to_bytes())
                        .map(|bytes| bincode::deserialize(&bytes).unwrap())
                        .unwrap()
                };
                let writer = env_read.write().unwrap();
                let mut txn = LmdbTxn::new(self.store, writer);
                last_block_delta.rollback(&mut txn);
                txn.commit();
                self.last_header = last_block_delta.parent_header;
                return Ok(());
            }
            if number > self.tip_header.number() {
                return Err(IndexError::BlockImmature(number));
            }
            self.apply_block_unchecked(block);
            Ok(())
        } else if number == 0 {
            if block.header().hash() != self.genesis_info.header().hash() {
                Err(IndexError::InvalidGenesis(format!(
                    "{:#x}, expected: {:#x}",
                    block.header().hash(),
                    self.genesis_info.header().hash(),
                )))
            } else {
                self.apply_block_unchecked(block);
                Ok(())
            }
        } else {
            Err(IndexError::NotInit)
        }
    }

    pub fn update_tip(&mut self, header: Header) {
        self.tip_header = header
    }

    pub fn last_header(&self) -> Option<&Header> {
        self.last_header.as_ref()
    }

    pub fn last_number(&self) -> Option<u64> {
        self.last_header.as_ref().map(Header::number)
    }

    pub fn next_number(&self) -> Option<u64> {
        self.last_number().map(|number| number + 1)
    }

    fn get_address_inner(&self, reader: &LmdbReader, lock_hash: H256) -> Option<Address> {
        reader
            .get(&Key::LockScript(lock_hash).to_bytes())
            .and_then(|bytes| {
                let script: Script = bincode::deserialize(&bytes).unwrap();
                script
                    .args
                    .get(0)
                    .and_then(|arg| Address::from_lock_arg(&arg).ok())
            })
    }

    pub fn get_capacity(&self, lock_hash: H256) -> Option<u64> {
        let env_read = self.env_arc.read().unwrap();
        let reader = LmdbReader::new(self.store, env_read.read().unwrap());
        reader
            .get(&Key::LockTotalCapacity(lock_hash).to_bytes())
            .map(|bytes| bincode::deserialize(&bytes).unwrap())
    }

    pub fn get_lock_hash_by_address(&self, address: Address) -> Option<H256> {
        let env_read = self.env_arc.read().unwrap();
        let reader = LmdbReader::new(self.store, env_read.read().unwrap());
        reader
            .get(&Key::SecpAddrLock(address).to_bytes())
            .map(|bytes| bincode::deserialize(&bytes).unwrap())
    }

    pub fn get_lock_script_by_hash(&self, lock_hash: H256) -> Option<Script> {
        let env_read = self.env_arc.read().unwrap();
        let reader = LmdbReader::new(self.store, env_read.read().unwrap());
        reader
            .get(&Key::LockScript(lock_hash).to_bytes())
            .map(|bytes| bincode::deserialize(&bytes).unwrap())
    }

    // pub fn get_address(&self, lock_hash: H256) -> Option<Address> {
    //     let env_read = self.env_arc.read().unwrap();
    //     let reader = env_read.read().unwrap();
    //     self.get_address_inner(&reader, lock_hash)
    // }

    pub fn get_live_cell_infos<F: FnMut(usize, &LiveCellInfo) -> (bool, bool)>(
        &self,
        lock_hash: H256,
        from_number: Option<u64>,
        mut terminator: F,
    ) -> Vec<LiveCellInfo> {
        fn get_live_cell_info(
            reader: &LmdbReader,
            out_point: CellOutPoint,
        ) -> Option<LiveCellInfo> {
            reader
                .get(&Key::LiveCellMap(out_point).to_bytes())
                .map(|bytes| bincode::deserialize(&bytes).unwrap())
        }

        let env_read = self.env_arc.read().unwrap();
        let reader = LmdbReader::new(self.store, env_read.read().unwrap());
        let key_prefix = Key::LockLiveCellIndexPrefix(lock_hash.clone(), None).to_bytes();
        let key_start = Key::LockLiveCellIndexPrefix(lock_hash, from_number).to_bytes();

        let mut infos = Vec::new();
        for (idx, (key_bytes, value_bytes)) in reader.iter_from(&key_start).enumerate() {
            if key_bytes[..key_prefix.len()] != key_prefix[..] {
                log::debug!("Reach the end of this lock");
                break;
            }
            let out_point: CellOutPoint = bincode::deserialize(&value_bytes).unwrap();
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
        let env_read = self.env_arc.read().unwrap();
        let reader = LmdbReader::new(self.store, env_read.read().unwrap());
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

    fn apply_block_unchecked(&mut self, block: Block) {
        let header = block.header();
        log::debug!("Block: {} => {:x}", header.number(), header.hash());

        let env_read = self.env_arc.read().unwrap();
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

        let secp_code_hash = self.genesis_info.secp_code_hash();
        let writer = env_read.write().unwrap();
        let mut txn = LmdbTxn::new(self.store, writer);
        for block in blocks {
            let block_delta_info = BlockDeltaInfo::from_block(&block, &txn, secp_code_hash);
            let number = block_delta_info.number();
            let hash = block_delta_info.hash();
            let result = block_delta_info.apply(&mut txn, self.enable_tx);
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
            for key_type in &[
                KeyType::GenesisHash,
                KeyType::Network,
                KeyType::LastHeader,
                KeyType::TotalCapacity,
                KeyType::GlobalHash,
                KeyType::TxMap,
                KeyType::SecpAddrLock,
                KeyType::RecentHeader,
                KeyType::LiveCellMap,
                KeyType::LiveCellIndex,
                KeyType::LockScript,
                KeyType::LockTotalCapacity,
                KeyType::LockTotalCapacityIndex,
                KeyType::LockLiveCellIndex,
                KeyType::LockTx,
                KeyType::BlockDelta,
            ] {
                key_types.insert(*key_type, KeyMetrics::default());
            }
        }
        let env_read = self.env_arc.read().unwrap();
        let reader = LmdbReader::new(self.store, env_read.read().unwrap());
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
