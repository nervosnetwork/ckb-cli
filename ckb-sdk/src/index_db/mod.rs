mod key;
mod types;
mod util;

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use crate::{Address, NetworkType};
use ckb_core::{
    header::Header as CoreHeader, script::Script as CoreScript,
    transaction::CellOutPoint as CoreCellOutPoint,
};
use jsonrpc_types::{BlockNumber, BlockView, HeaderView};
use numext_fixed_hash::H256;

// 200GB
const LMDB_MAX_MAP_SIZE: usize = 200 * 1024 * 1024 * 1024;
const LMDB_MAX_DBS: u32 = 6;

pub use key::{Key, KeyMetrics, KeyType};
pub use types::{CellIndex, HashType, LiveCellInfo, TxInfo};

use types::BlockDeltaInfo;
use util::{put_pair, value_to_bytes};

pub struct LiveCellDatabase {
    env_arc: Arc<RwLock<rkv::Rkv>>,
    store: rkv::SingleStore,
    // network: NetworkType,
    last_header: CoreHeader,
    tip_header: HeaderView,
}

impl LiveCellDatabase {
    pub fn from_path(
        network: NetworkType,
        genesis_block: &BlockView,
        mut directory: PathBuf,
    ) -> Result<LiveCellDatabase, IndexError> {
        let genesis_header = &genesis_block.header;
        assert_eq!(genesis_header.inner.number.0, 0);

        directory.push(format!("{:#x}", genesis_header.hash));
        std::fs::create_dir_all(&directory)?;
        let env_arc = rkv::Manager::singleton()
            .write()
            .unwrap()
            .get_or_create(directory.as_path(), |path| {
                let mut env = rkv::Rkv::environment_builder();
                env.set_max_dbs(LMDB_MAX_DBS);
                env.set_map_size(LMDB_MAX_MAP_SIZE);
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
                let reader = env_read.read().expect("reader");
                let genesis_hash_opt = store
                    .get(&reader, Key::GenesisHash.to_bytes())
                    .unwrap()
                    .map(|value| bincode::deserialize(value_to_bytes(&value)).unwrap());
                let network_opt = store
                    .get(&reader, Key::Network.to_bytes())
                    .unwrap()
                    .map(|value| bincode::deserialize(value_to_bytes(&value)).unwrap());
                (genesis_hash_opt, network_opt)
            };
            if let Some(genesis_hash) = genesis_hash_opt {
                if network_opt != Some(network) {
                    return Err(IndexError::InvalidNetworkType(format!(
                        "expected: {}, found: {:?}",
                        network, network_opt
                    )));
                }
                if genesis_hash != genesis_header.hash {
                    return Err(IndexError::InvalidGenesis(format!("{:#x}", genesis_hash)));
                }
            } else {
                log::info!("genesis not found, init db");
                let mut writer = env_read.write().unwrap();
                put_pair(&store, &mut writer, Key::pair_network(&network));
                put_pair(
                    &store,
                    &mut writer,
                    Key::pair_genesis_hash(&genesis_header.hash),
                );
                writer.commit().unwrap();
            }

            let last_header = {
                let reader = env_read.read().expect("reader");
                store
                    .get(&reader, Key::LastHeader.to_bytes())
                    .unwrap()
                    .map(|value| bincode::deserialize(value_to_bytes(&value)).unwrap())
                    .unwrap_or(genesis_header.clone().into())
            };
            (store, last_header)
        };

        Ok(LiveCellDatabase {
            env_arc,
            store,
            // network,
            last_header,
            tip_header: genesis_header.clone(),
        })
    }

    pub fn apply_next_block(&mut self, block: &BlockView) -> Result<(), IndexError> {
        if block.header.inner.number.0 != self.last_header().number() + 1 {
            return Err(IndexError::BlockTooEarly);
        }
        if &block.header.inner.parent_hash != self.last_header().hash() {
            return Err(IndexError::BlockInvalid);
        }
        if block.header.inner.number.0 + 3 >= self.tip_header.inner.number.0 {
            return Err(IndexError::BlockImmature);
        }
        self.apply_block_unchecked(block);
        Ok(())
    }

    pub fn update_tip(&mut self, header: HeaderView) {
        self.tip_header = header
    }

    pub fn last_header(&self) -> &CoreHeader {
        &self.last_header
    }

    pub fn last_number(&self) -> u64 {
        self.last_header.number()
    }

    pub fn next_number(&self) -> BlockNumber {
        BlockNumber(self.last_header.number() + 1)
    }

    fn get(&self, reader: &rkv::Reader, key: &[u8]) -> Option<Vec<u8>> {
        self.store
            .get(reader, key)
            .unwrap()
            .map(|value| value_to_bytes(&value).to_vec())
    }

    fn get_address_inner(&self, reader: &rkv::Reader, lock_hash: H256) -> Option<Address> {
        self.get(reader, &Key::LockScript(lock_hash).to_bytes())
            .and_then(|bytes| {
                let script: CoreScript = bincode::deserialize(&bytes).unwrap();
                script
                    .args
                    .get(0)
                    .and_then(|arg| Address::from_lock_arg(&arg).ok())
            })
    }

    fn get_live_cell_info(
        &self,
        reader: &rkv::Reader,
        out_point: CoreCellOutPoint,
    ) -> Option<LiveCellInfo> {
        self.get(reader, &Key::LiveCellMap(out_point).to_bytes())
            .map(|bytes| bincode::deserialize(&bytes).unwrap())
    }

    pub fn get_capacity(&self, lock_hash: H256) -> Option<u64> {
        let env_read = self.env_arc.read().unwrap();
        let reader = env_read.read().unwrap();
        self.get(&reader, &Key::LockTotalCapacity(lock_hash).to_bytes())
            .map(|bytes| bincode::deserialize(&bytes).unwrap())
    }

    // pub fn get_address(&self, lock_hash: H256) -> Option<Address> {
    //     let env_read = self.env_arc.read().unwrap();
    //     let reader = env_read.read().unwrap();
    //     self.get_address_inner(&reader, lock_hash)
    // }

    pub fn get_live_cell_infos(
        &self,
        lock_hash: H256,
        total_capacity: u64,
    ) -> (Vec<LiveCellInfo>, u64) {
        let env_read = self.env_arc.read().unwrap();
        let reader = env_read.read().unwrap();
        let key_prefix: Vec<u8> = Key::LockLiveCellIndexPrefix(lock_hash).to_bytes();

        let mut infos = Vec::new();
        let mut result_total_capacity = 0;
        for item in self.store.iter_from(&reader, &key_prefix).unwrap() {
            let (key_bytes, value_bytes_opt) = item.unwrap();
            if &key_bytes[..key_prefix.len()] != &key_prefix[..] {
                log::debug!("Reach the end of this lock");
                break;
            }
            let value_bytes = value_bytes_opt.unwrap();
            let out_point: CoreCellOutPoint =
                bincode::deserialize(value_to_bytes(&value_bytes)).unwrap();
            let live_cell_info = self.get_live_cell_info(&reader, out_point).unwrap();
            result_total_capacity += live_cell_info.capacity;
            infos.push(live_cell_info);
            if result_total_capacity >= total_capacity {
                log::trace!("Got enough capacity");
                break;
            }
        }
        (infos, result_total_capacity)
    }

    pub fn get_top_n(&self, n: usize) -> Vec<(H256, Option<Address>, u64)> {
        let env_read = self.env_arc.read().unwrap();
        let reader = env_read.read().unwrap();
        let key_prefix: Vec<u8> = KeyType::LockTotalCapacityIndex.to_bytes();

        let mut pairs = Vec::new();
        for item in self.store.iter_from(&reader, &key_prefix).unwrap() {
            let (key_bytes, _) = item.unwrap();
            if &key_bytes[..key_prefix.len()] != &key_prefix[..] {
                log::debug!("Reach the end of this type");
                break;
            }
            if let Key::LockTotalCapacityIndex(capacity, lock_hash) = Key::from_bytes(key_bytes) {
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

    fn apply_block_unchecked(&mut self, block: &BlockView) {
        let header = &block.header;
        log::debug!("Block: {} => {:x}", header.inner.number.0, header.hash);
        let number = header.inner.number.0;

        let env_read = self.env_arc.read().unwrap();
        let block_delta_info = {
            let reader = env_read.read().unwrap();
            BlockDeltaInfo::from_view(block, &self.store, &reader)
        };
        let result = {
            let mut writer = env_read.write().unwrap();
            let result = block_delta_info.apply(&self.store, &mut writer);
            writer.commit().unwrap();
            self.last_header = block.header.clone().into();
            result
        };

        log::info!(
            "Block: {} => {:x} (chain_capacity={}, delta={}), txs={}, cell-removed={}, cell-added={}",
            number,
            header.hash,
            result.chain_capacity,
            result.capacity_delta,
            result.txs,
            result.cell_removed,
            result.cell_added,
        );
    }

    pub fn get_metrics(&self, key_type_opt: Option<KeyType>) -> BTreeMap<KeyType, KeyMetrics> {
        let mut key_types = BTreeMap::default();
        if let Some(key_type) = key_type_opt {
            key_types.insert(key_type, KeyMetrics::default());
        } else {
            for key_type in vec![
                KeyType::GenesisHash,
                KeyType::Network,
                KeyType::LastHeader,
                KeyType::TotalCapacity,
                KeyType::GlobalHash,
                KeyType::TxMap,
                KeyType::SecpAddrLock,
                KeyType::LiveCellMap,
                KeyType::LiveCellIndex,
                KeyType::LockScript,
                KeyType::LockTotalCapacity,
                KeyType::LockTotalCapacityIndex,
                KeyType::LockLiveCellIndex,
                KeyType::LockTx,
                KeyType::BlockDelta,
            ] {
                key_types.insert(key_type, KeyMetrics::default());
            }
        }
        let env_read = self.env_arc.read().unwrap();
        let reader = env_read.read().unwrap();
        for (key_type, metrics) in &mut key_types {
            let key_prefix = key_type.to_bytes();
            for item in self.store.iter_from(&reader, &key_prefix).unwrap() {
                let (key_bytes, value_bytes_opt) = item.unwrap();
                if &key_bytes[..key_prefix.len()] != &key_prefix[..] {
                    log::debug!("Reach the end of this lock");
                    break;
                }
                let value_bytes = value_bytes_opt.unwrap().to_bytes().unwrap();
                metrics.add_pair(&key_bytes, &value_bytes);
            }
        }
        key_types
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum IndexError {
    BlockImmature,
    BlockTooEarly,
    BlockInvalid,
    IoError(String),
    InvalidGenesis(String),
    InvalidNetworkType(String),
}

impl From<io::Error> for IndexError {
    fn from(err: io::Error) -> IndexError {
        IndexError::IoError(err.to_string())
    }
}
