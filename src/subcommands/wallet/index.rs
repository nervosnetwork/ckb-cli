use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs;
use std::io;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use bech32::{convert_bits, Bech32, ToBase32};
use bytes::Bytes;
use ckb_core::{
    script::Script as CoreScript,
    transaction::{
        CellInput as CoreCellInput, CellOutPoint as CoreCellOutPoint, OutPoint as CoreOutPoint,
    },
};
use crypto::secp::Pubkey;
use fs2::FileExt;
use hash::blake2b_256;
pub use jsonrpc_types::{
    BlockNumber, BlockView, Capacity, CellOutPoint, HeaderView, JsonBytes, Script, Transaction,
    TransactionView, Unsigned,
};
use numext_fixed_hash::{h256, H160, H256};
use serde_derive::{Deserialize, Serialize};

const PREFIX_MAINNET: &str = "ckb";
const PREFIX_TESTNET: &str = "ckt";
// \x01 is the P2PH version
const P2PH_MARK: &[u8] = b"\x01P2PH";
pub const SECP_CODE_HASH: H256 =
    h256!("0x9e3b3557f11b2b3532ce352bfe8017e9fd11d154c4c7f9b7aaaa1e621b539a08");

#[repr(u16)]
enum KeyType {
    // key => value: {type} => {block-hash}
    GenesisHash = 0,
    // key => value: {type} => {NetworkType}
    Network = 1,
    // key => value: {type} => {HeaderView}
    LastHeader = 2,

    // >> hash-type: block, transaction, lock, data
    // key => value: {type}:{hash} => {hash-type}
    GlobalHash = 100,
    // key => value: {type}:{tx-hash} => {TransactionInfo}
    TxSummary = 102,
    // key => value: {type}:{Address} => {lock-hash}
    SecpAddrLock = 103,

    // key => value: {type}:{CellOutPoint} => {LiveCellInfo}
    LiveCellMap = 200,
    // key => value: {type}:{block-number}:{CellIndex} => {CellOutPoint}
    LiveCellIndex = 201,
    // key => value: {type} => u128
    TotalCapacity = 202,

    // >> Store live cell owned by certain lock
    // key => value: {type}:{lock-hash} => CoreScript
    LockScript = 300,
    // key => value: {type}:{lock-hash} => u64
    LockTotalCapacity = 301,
    // >> removed when capacity changed
    // key => value: {type}:{capacity(u64)}:{lock-hash} => ()
    LockTotalCapacityIndex = 302,
    // key => value: {type}:{lock-hash}:{CellOutPoint} => ()
    LockLiveCell = 303,
    // key => value: {type}:{lock-hash}:{block-number}:{CellIndex} => {CellOutPoint}
    LockLiveCellIndex = 304,
    // key => value: {type}:{lock-hash}:{block-number}:{CellIndex} => {tx-hash}
    LockTx = 305,
}

impl KeyType {
    fn to_bytes(&self) -> Vec<u8> {
        (*self as u16).to_be_bytes().to_vec()
    }
}

#[derive(Debug, Clone)]
enum Key<'a> {
    GenesisHash,
    Network,
    LastHeader,

    GlobalHash(&'a H256),
    TxSummary(&'a H256),
    SecpAddrLock(&'a Address),

    LiveCellMap(&'a CellOutPoint),
    LiveCellIndex(u64, CellIndex),
    TotalCapacity,

    LockScript(&'a H256),
    LockTotalCapacity(&'a H256),
    LockLiveCell(&'a H256, &'a CellOutPoint),
    LockLiveCellIndex(&'a H256, u64, CellIndex),
    LockTx(&'a H256, u64, CellIndex),
}

impl<'a> Key<'a> {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Key::GenesisHash => KeyType::GenesisHash.to_bytes(),
            Key::Network => KeyType::Network.to_bytes(),
            Key::LastHeader => KeyType::LastHeader.to_bytes(),
            Key::GlobalHash(hash) => {
                let mut bytes = KeyType::GlobalHash.to_bytes();
                bytes.extend(bincode::serialize(hash).unwrap());
                bytes
            }
            Key::TxSummary(tx_hash) => {
                let mut bytes = KeyType::TxSummary.to_bytes();
                bytes.extend(bincode::serialize(tx_hash).unwrap());
                bytes
            }
            Key::SecpAddrLock(address) => {
                let mut bytes = KeyType::SecpAddrLock.to_bytes();
                bytes.extend(bincode::serialize(address).unwrap());
                bytes
            }
            Key::LiveCellMap(out_point) => {
                let mut bytes = KeyType::LiveCellMap.to_bytes();
                bytes.extend(bincode::serialize(out_point).unwrap());
                bytes
            }
            Key::LiveCellIndex(number, cell_index) => {
                let mut bytes = KeyType::LiveCellIndex.to_bytes();
                // Must use big endian for sort
                bytes.extend(number.to_be_bytes().to_vec());
                bytes.extend(cell_index.to_bytes());
                bytes
            }
            Key::TotalCapacity => KeyType::TotalCapacity.to_bytes(),
            Key::LockScript(lock_hash) => {
                let mut bytes = KeyType::LockScript.to_bytes();
                bytes.extend(bincode::serialize(lock_hash).unwrap());
                bytes
            }
            Key::LockTotalCapacity(lock_hash) => {
                let mut bytes = KeyType::LockTotalCapacity.to_bytes();
                bytes.extend(bincode::serialize(lock_hash).unwrap());
                bytes
            }
            Key::LockLiveCell(lock_hash, out_point) => {
                let mut bytes = KeyType::LockLiveCell.to_bytes();
                bytes.extend(bincode::serialize(lock_hash).unwrap());
                bytes.extend(bincode::serialize(out_point).unwrap());
                bytes
            }
            Key::LockLiveCellIndex(lock_hash, number, cell_index) => {
                let mut bytes = KeyType::LockLiveCellIndex.to_bytes();
                bytes.extend(bincode::serialize(lock_hash).unwrap());
                // Must use big endian for sort
                bytes.extend(number.to_be_bytes().to_vec());
                bytes.extend(cell_index.to_bytes());
                bytes
            }
            Key::LockTx(lock_hash, number, cell_index) => {
                let mut bytes = KeyType::LockTx.to_bytes();
                bytes.extend(bincode::serialize(lock_hash).unwrap());
                // Must use big endian for sort
                bytes.extend(number.to_be_bytes().to_vec());
                bytes.extend(cell_index.to_bytes());
                bytes
            }
        }
    }

    fn pair_genesis_hash(&self, value: &H256) -> (Vec<u8>, Vec<u8>) {
        match self {
            Key::GenesisHash => {}
            key => panic!("Invalid key for genesis hash: {:?}", key),
        }
        (self.to_bytes(), bincode::serialize(value).unwrap())
    }

    fn pair_network(&self, value: &NetworkType) -> (Vec<u8>, Vec<u8>) {
        match self {
            Key::Network => {}
            key => panic!("Invalid key for network: {:?}", key),
        }
        (self.to_bytes(), bincode::serialize(value).unwrap())
    }

    fn pair_last_header(&self, value: &HeaderView) -> (Vec<u8>, Vec<u8>) {
        match self {
            Key::LastHeader => {}
            key => panic!("Invalid key for last header: {:?}", key),
        }
        (self.to_bytes(), bincode::serialize(value).unwrap())
    }

    fn pair_global_hash(&self, value: &HashType) -> (Vec<u8>, Vec<u8>) {
        match self {
            Key::GlobalHash(..) => {}
            key => panic!("Invalid key for global hash: {:?}", key),
        }
        (self.to_bytes(), bincode::serialize(value).unwrap())
    }

    fn pair_tx_summary(&self, value: &TransactionInfo) -> (Vec<u8>, Vec<u8>) {
        match self {
            Key::TxSummary(..) => {}
            key => panic!("Invalid key for tx summary: {:?}", key),
        }
        (self.to_bytes(), bincode::serialize(value).unwrap())
    }

    fn pair_secp_addr_lock(&self, value: &H256) -> (Vec<u8>, Vec<u8>) {
        match self {
            Key::SecpAddrLock(..) => {}
            key => panic!("Invalid key for secp addr lock: {:?}", key),
        }
        (self.to_bytes(), bincode::serialize(value).unwrap())
    }

    fn pair_live_cell_map(&self, value: &LiveCellInfo) -> (Vec<u8>, Vec<u8>) {
        match self {
            Key::LiveCellMap(..) => {}
            key => panic!("Invalid key for live cell map: {:?}", key),
        }
        (self.to_bytes(), bincode::serialize(value).unwrap())
    }

    fn pair_live_cell_index(&self, value: &CellOutPoint) -> (Vec<u8>, Vec<u8>) {
        match self {
            Key::LiveCellIndex(..) => {}
            key => panic!("Invalid key for live cell index: {:?}", key),
        }
        (self.to_bytes(), bincode::serialize(value).unwrap())
    }

    fn pair_total_capacity(&self, value: &u128) -> (Vec<u8>, Vec<u8>) {
        match self {
            Key::TotalCapacity => {}
            key => panic!("Invalid key for total capacity: {:?}", key),
        }
        (self.to_bytes(), bincode::serialize(value).unwrap())
    }

    fn pair_lock_script(&self, value: &CoreScript) -> (Vec<u8>, Vec<u8>) {
        match self {
            Key::LockScript(..) => {}
            key => panic!("Invalid key for lock script: {:?}", key),
        }
        (self.to_bytes(), bincode::serialize(value).unwrap())
    }

    fn pair_lock_total_capacity(&self, value: &u64) -> (Vec<u8>, Vec<u8>) {
        match self {
            Key::LockTotalCapacity(..) => {}
            key => panic!("Invalid key for lock total capacity: {:?}", key),
        }
        (self.to_bytes(), bincode::serialize(value).unwrap())
    }

    fn pair_lock_live_cell(&self) -> (Vec<u8>, Vec<u8>) {
        match self {
            Key::LockLiveCell(..) => {}
            key => panic!("Invalid key for lock live cell: {:?}", key),
        }
        (self.to_bytes(), [0u8].to_vec())
    }

    fn pair_lock_live_cell_index(&self, value: &CellOutPoint) -> (Vec<u8>, Vec<u8>) {
        match self {
            Key::LockLiveCellIndex(..) => {}
            key => panic!("Invalid key for lock live cell index: {:?}", key),
        }
        (self.to_bytes(), bincode::serialize(value).unwrap())
    }

    fn pair_lock_tx(&self, value: &H256) -> (Vec<u8>, Vec<u8>) {
        match self {
            Key::LockTx(..) => {}
            key => panic!("Invalid key for lock tx: {:?}", key),
        }
        (self.to_bytes(), bincode::serialize(value).unwrap())
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
enum HashType {
    Block,
    Transaction,
    Lock,
    Data,
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NetworkType {
    MainNet,
    TestNet,
}

impl NetworkType {
    fn from_prefix(value: &str) -> Option<NetworkType> {
        match value {
            PREFIX_MAINNET => Some(NetworkType::MainNet),
            PREFIX_TESTNET => Some(NetworkType::TestNet),
            _ => None,
        }
    }

    fn to_prefix(&self) -> &'static str {
        match self {
            NetworkType::MainNet => PREFIX_MAINNET,
            NetworkType::TestNet => PREFIX_TESTNET,
        }
    }

    fn from_str(value: &str) -> Option<NetworkType> {
        match value {
            "mainnet" => Some(NetworkType::MainNet),
            "testnet" => Some(NetworkType::TestNet),
            _ => None,
        }
    }

    fn to_str(&self) -> &'static str {
        match self {
            NetworkType::MainNet => "mainnet",
            NetworkType::TestNet => "testnet",
        }
    }
}

impl fmt::Display for NetworkType {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.to_str())
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AddressFormat {
    // SECP256K1 algorithm	PK
    #[allow(dead_code)]
    SP2K,
    // SECP256R1 algorithm	PK
    #[allow(dead_code)]
    SP2R,
    // SECP256K1 + blake160	blake160(pk)
    P2PH,
    // Alias of SP2K	PK
    #[allow(dead_code)]
    P2PK,
}

impl Default for AddressFormat {
    fn default() -> AddressFormat {
        AddressFormat::P2PH
    }
}

impl AddressFormat {
    fn from_bytes(format: &[u8]) -> Result<AddressFormat, String> {
        match format {
            P2PH_MARK => Ok(AddressFormat::P2PH),
            _ => Err(format!("Unsupported address format data: {:?}", format)),
        }
    }

    fn to_bytes(&self) -> Result<Vec<u8>, String> {
        match self {
            AddressFormat::P2PH => Ok(P2PH_MARK.to_vec()),
            _ => Err(format!("Unsupported address format: {:?}", self)),
        }
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Address {
    format: AddressFormat,
    hash: H160,
}

impl Address {
    pub fn hash(&self) -> &H160 {
        &self.hash
    }

    pub fn lock_script(&self) -> CoreScript {
        CoreScript {
            args: vec![Bytes::from(self.hash.as_bytes())],
            code_hash: SECP_CODE_HASH.clone(),
        }
    }

    pub fn from_pubkey(format: AddressFormat, pubkey: &Pubkey) -> Result<Address, String> {
        if format != AddressFormat::P2PH {
            return Err("Only support P2PH for now".to_owned());
        }
        // Serialize pubkey as compressed format
        let hash = H160::from_slice(&blake2b_256(pubkey.serialize())[0..20])
            .expect("Generate hash(H160) from pubkey failed");
        Ok(Address { format, hash })
    }

    pub fn from_lock_arg(bytes: &[u8]) -> Result<Address, String> {
        let format = AddressFormat::P2PH;
        let hash = H160::from_slice(bytes).map_err(|err| err.to_string())?;
        Ok(Address { format, hash })
    }

    pub fn from_input(network: NetworkType, input: &str) -> Result<Address, String> {
        let value = Bech32::from_str(input).map_err(|err| err.to_string())?;
        if NetworkType::from_prefix(value.hrp())
            .filter(|input_network| input_network == &network)
            .is_none()
        {
            return Err(format!("Invalid hrp({}) for {}", value.hrp(), network));
        }
        let data = convert_bits(value.data(), 5, 8, false).unwrap();
        if data.len() != 25 {
            return Err(format!("Invalid input data length {}", data.len()));
        }
        let format = AddressFormat::from_bytes(&data[0..5])?;
        let hash = H160::from_slice(&data[5..25]).map_err(|err| err.to_string())?;
        Ok(Address { format, hash })
    }

    pub fn to_string(&self, network: NetworkType) -> String {
        let hrp = network.to_prefix();
        let mut data = [0; 25];
        let format_data = self.format.to_bytes().expect("Invalid address format");
        data[0..5].copy_from_slice(&format_data[0..5]);
        data[5..25].copy_from_slice(self.hash.as_fixed_bytes());
        let value = Bech32::new(hrp.to_string(), data.to_base32())
            .expect(&format!("Encode address failed: hash={:?}", self.hash));
        format!("{}", value)
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct LiveCellInfo {
    pub out_point: Arc<CellOutPoint>,
    pub lock_hash: H256,
    // Secp256k1 address
    pub capacity: u64,
    // Block number
    pub number: u64,
    // Location in the block
    index: CellIndex,
}

impl LiveCellInfo {
    pub fn core_input(&self) -> CoreCellInput {
        CoreCellInput {
            previous_output: CoreOutPoint {
                cell: Some(CoreCellOutPoint::from(CellOutPoint::clone(&self.out_point))),
                block_hash: None,
            },
            since: 0,
            args: vec![],
        }
    }
}

// LiveCell index in a block
#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy, Serialize, Deserialize)]
struct CellIndex {
    // The transaction index in the block
    tx_index: u32,
    // The output index in the transaction
    output_index: u32,
}

impl CellIndex {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.tx_index.to_be_bytes().to_vec();
        bytes.extend(self.output_index.to_be_bytes().to_vec());
        bytes
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
struct AddressIndex {
    lock_hash: H256,
    address: Address,
}

impl CellIndex {
    fn new(tx_index: u32, output_index: u32) -> CellIndex {
        CellIndex {
            tx_index,
            output_index,
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
struct TransactionIO {
    lock_hash: H256,
    capacity: u64,
    address: Option<Address>,
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
struct TransactionInfo {
    hash: H256,
    block_number: u64,
    block_timestamp: u64,
    inputs: Vec<TransactionIO>,
    outputs: Vec<TransactionIO>,
}

struct LiveCellMap {
    map: HashMap<Arc<CellOutPoint>, Arc<LiveCellInfo>>,
    blocks: BTreeMap<u64, HashMap<CellIndex, Arc<LiveCellInfo>>>,
    total_capacity: u128,
}

impl LiveCellMap {
    pub fn add(
        &mut self,
        store: rkv::SingleStore,
        writer: &mut rkv::Writer,
        info: Arc<LiveCellInfo>,
    ) {
        let capacity = info.capacity as u128;

        assert!(!self.map.contains_key(&info.out_point));
        self.map
            .insert(Arc::clone(&info.out_point), Arc::clone(&info));

        let block_live_cells = self.blocks.entry(info.number).or_default();
        assert!(!block_live_cells.contains_key(&info.index));
        block_live_cells.insert(info.index, info);

        self.total_capacity += capacity;
    }

    pub fn remove(
        &mut self,
        store: rkv::SingleStore,
        writer: &mut rkv::Writer,
        out_point: &CellOutPoint,
    ) -> Option<Arc<LiveCellInfo>> {
        let info_opt = self.map.remove(out_point);
        if let Some(ref info) = info_opt {
            let block_live_cells = self.blocks.get_mut(&info.number).expect("Block not exists");
            let inner_info = block_live_cells
                .remove(&info.index)
                .expect("LiveCell not exists in blocks");
            assert_eq!(&inner_info, info);
            if block_live_cells.is_empty() {
                self.blocks.remove(&info.number);
            }
            self.total_capacity -= info.capacity as u128;
        }
        info_opt
    }

    // pub fn get(&self, out_point: &CellOutPoint) -> Option<Arc<LiveCellInfo>> {
    //     self.map.get(out_point).cloned()
    // }

    pub fn size(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        let is_empty = self.map.is_empty();
        if is_empty {
            assert!(self.blocks.is_empty());
        }
        is_empty
    }
}

impl Default for LiveCellMap {
    fn default() -> LiveCellMap {
        LiveCellMap {
            map: HashMap::default(),
            blocks: BTreeMap::default(),
            total_capacity: 0,
        }
    }
}

pub struct LiveCellDatabase {
    env_arc: Arc<RwLock<rkv::Rkv>>,
    store: rkv::SingleStore,
    // TODO: add genesis hash
    network: NetworkType,
    last_header: HeaderView,
    tip_header: HeaderView,
    // live_cell_map: LiveCellMap,
    // secp_addrs: HashMap<H256, Address>,
    // > Fields not to be serialized
    // locks: HashMap<H256, LiveCellMap>,
}

impl LiveCellDatabase {
    pub fn from_path(
        network: NetworkType,
        genesis_block: &BlockView,
        directory: PathBuf,
    ) -> Result<LiveCellDatabase, IndexError> {
        let genesis_header = &genesis_block.header;
        assert_eq!(genesis_header.inner.number.0, 0);

        std::fs::create_dir_all(directory);
        let env_arc = rkv::Manager::singleton()
            .write()
            .unwrap()
            .get_or_create(directory.as_path(), rkv::Rkv::new)
            .unwrap();
        let (store, last_header) = {
            let env_read = env_arc.read().unwrap();
            // Then you can use the environment handle to get a handle to a datastore:
            let store: rkv::SingleStore = env_read
                .open_single("index", rkv::StoreOptions::create())
                .unwrap();
            let reader = env_read.read().expect("reader");
            let last_header = store
                .get(&reader, Key::LastHeader.to_bytes())
                .unwrap()
                .map(|value| bincode::deserialize(&value.to_bytes().unwrap()).unwrap())
                .unwrap_or(genesis_header.clone());
            (store, last_header)
        };

        Ok(LiveCellDatabase {
            env_arc,
            store,
            network,
            last_header,
            tip_header: genesis_header.clone(),
        })
    }

    /*
    pub fn from_fresh(network: NetworkType, genesis_block: &BlockView) -> LiveCellDatabase {
        let genesis_header = &genesis_block.header;
        assert_eq!(genesis_header.inner.number.0, 0);

        let mut db = LiveCellDatabase {
            network,
            // live_cell_map: LiveCellMap::default(),
            // last_header: genesis_header.clone(),
            tip_header: genesis_header.clone(),
            // secp_addrs: HashMap::default(),
            // locks: HashMap::default(),
        };
        db.apply_block_unchecked(genesis_block);
        db
    }
    */

    pub fn apply_next_block(&mut self, block: &BlockView) -> Result<(usize, usize), IndexError> {
        if block.header.inner.number.0 != self.last_header().inner.number.0 + 1 {
            return Err(IndexError::BlockTooEarly);
        }
        if block.header.inner.parent_hash != self.last_header().hash {
            return Err(IndexError::BlockInvalid);
        }
        if block.header.inner.number.0 + 3 >= self.tip_header.inner.number.0 {
            return Err(IndexError::BlockImmature);
        }

        Ok(self.apply_block_unchecked(block))
    }

    pub fn update_tip(&mut self, header: HeaderView) {
        self.tip_header = header
    }

    pub fn last_header(&self) -> &HeaderView {
        &self.last_header
    }

    pub fn last_number(&self) -> u64 {
        self.last_header.inner.number.0
    }

    pub fn next_number(&self) -> BlockNumber {
        BlockNumber(self.last_header.inner.number.0 + 1)
    }

    // pub fn get_live_cell(&self, out_point: &CellOutPoint) -> Option<Arc<LiveCellInfo>> {
    //     self.live_cell_map.get(out_point)
    // }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let env_read = self.env_arc.read().unwrap();
        let reader = env_read.read().unwrap();
        self.store
            .get(&reader, key)
            .unwrap()
            .map(|value| value.to_bytes().unwrap())
    }

    pub fn get_balance(&self, lock_hash: &H256) -> Option<u128> {
        self.get(&Key::LockTotalCapacity(lock_hash).to_bytes())
            .map(|value| bincode::deserialize(&value).unwrap())
    }

    pub fn get_live_cell_infos(
        &self,
        lock_hash: &H256,
        total_capacity: u64,
    ) -> (Vec<Arc<LiveCellInfo>>, Option<u64>) {
        self.locks
            .get(lock_hash)
            .map(|live_cell_map| {
                let mut result_total_capacity = 0;
                let mut infos = Vec::new();
                for live_cells in live_cell_map.blocks.values() {
                    for info in live_cells.values() {
                        if result_total_capacity < total_capacity {
                            infos.push(Arc::clone(info));
                            result_total_capacity += info.capacity;
                        } else {
                            return (infos, Some(result_total_capacity));
                        }
                    }
                }
                (infos, Some(result_total_capacity))
            })
            .unwrap_or_else(|| (Vec::new(), None))
    }

    pub fn get_top_n(&self, n: usize) -> Vec<(H256, Option<Address>, u64)> {
        let mut pairs = self
            .locks
            .iter()
            .map(|(lock_hash, live_cell_map)| {
                (
                    lock_hash.clone(),
                    self.secp_addrs.get(lock_hash).cloned(),
                    live_cell_map.total_capacity as u64,
                )
            })
            .collect::<Vec<_>>();
        pairs.sort_by(|a, b| b.2.cmp(&a.2));
        pairs.truncate(n);
        pairs
    }

    fn apply_block_unchecked(&mut self, block: &BlockView) -> (usize, usize) {
        let header = &block.header;
        log::debug!(
            "Process block: {} => {:#x}",
            header.inner.number.0,
            header.hash
        );
        let number = header.inner.number.0;
        let mut removed_in_block = 0;
        let mut added_in_block = 0;
        for (tx_index, tx) in block.transactions.iter().enumerate() {
            let (removed_in_tx, added_in_tx) = self.apply_transaction(tx, tx_index as u32, number);
            removed_in_block += removed_in_tx;
            added_in_block += added_in_tx;
        }
        self.last_header = block.header.clone();
        log::info!(
            "Process block: {} => {:#x} (total_capacity={}), removed={}, added={}",
            header.inner.number.0,
            header.hash,
            self.live_cell_map.total_capacity,
            removed_in_block,
            added_in_block,
        );
        (removed_in_block, added_in_block)
    }

    fn apply_transaction(
        &mut self,
        tx: &TransactionView,
        tx_index: u32,
        number: u64,
    ) -> (usize, usize) {
        let mut removed = 0;
        let mut added = 0;
        for input in &tx.inner.inputs {
            if let Some(ref out_point) = input.previous_output.cell {
                if self.remove_live_cell(&out_point).is_some() {
                    removed += 1;
                }
            }
        }
        for (output_index, output) in tx.inner.outputs.iter().enumerate() {
            let lock: CoreScript = output.lock.clone().into();
            let lock_hash = lock.hash();
            let capacity = output.capacity.0.as_u64();
            let out_point = Arc::new(CellOutPoint {
                tx_hash: tx.hash.clone(),
                index: Unsigned(output_index as u64),
            });
            let index = CellIndex::new(tx_index, output_index as u32);
            self.add_live_cell(out_point, index, lock_hash.clone(), capacity, number);

            if output.lock.code_hash == SECP_CODE_HASH {
                if output.lock.args.len() == 1 {
                    let lock_arg = &output.lock.args[0];
                    match Address::from_lock_arg(lock_arg.as_bytes()) {
                        Ok(address) => {
                            self.secp_addrs.insert(lock_hash, address);
                        }
                        Err(err) => {
                            log::info!("Invalid secp arg: {:?} => {}", lock_arg, err);
                        }
                    }
                } else {
                    log::info!("lock arg should given exact 1");
                }
            }
            added += 1;
        }
        (removed, added)
    }

    fn add_live_cell(
        &mut self,
        out_point: Arc<CellOutPoint>,
        index: CellIndex,
        lock_hash: H256,
        capacity: u64,
        number: u64,
    ) {
        let info = Arc::new(LiveCellInfo {
            out_point: Arc::clone(&out_point),
            index,
            lock_hash: lock_hash.clone(),
            capacity,
            number,
        });
        log::trace!(
            "add tx_hash={:#x}, index={}, lock_hash={}, capacity={}",
            out_point.tx_hash,
            out_point.index.0,
            info.lock_hash,
            info.capacity,
        );

        self.live_cell_map.add(Arc::clone(&info));
        self.locks.entry(lock_hash).or_default().add(info);
    }

    fn remove_live_cell(&mut self, out_point: &CellOutPoint) -> Option<Arc<LiveCellInfo>> {
        let info_opt = self.live_cell_map.remove(out_point);
        if let Some(ref info) = info_opt {
            log::trace!(
                "remove tx_hash={:#x}, index={}, lock_hash={}, capacity={}",
                out_point.tx_hash,
                out_point.index.0,
                info.lock_hash,
                info.capacity,
            );
            let map = self
                .locks
                .get_mut(&info.lock_hash)
                .expect("Target address must exists: {}");
            let inner_info = map.remove(out_point).expect("Info must exists");
            if map.is_empty() {
                self.locks.remove(&info.lock_hash);
                self.secp_addrs.remove(&info.lock_hash);
            }
            assert_eq!(info, &inner_info);
        }
        info_opt
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum IndexError {
    BlockImmature,
    BlockTooEarly,
    BlockInvalid,
    IoError(String),
    FileBroken(String),
}

impl From<io::Error> for IndexError {
    fn from(err: io::Error) -> IndexError {
        IndexError::IoError(err.to_string())
    }
}
