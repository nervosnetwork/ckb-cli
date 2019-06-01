use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs;
use std::io;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

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

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy)]
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

struct LiveCellMap {
    map: HashMap<Arc<CellOutPoint>, Arc<LiveCellInfo>>,
    blocks: BTreeMap<u64, HashMap<CellIndex, Arc<LiveCellInfo>>>,
    total_capacity: u128,
}

impl LiveCellMap {
    pub fn add(&mut self, info: Arc<LiveCellInfo>) {
        let capacity = info.capacity as u128;

        assert!(!self.map.contains_key(&info.out_point));
        self.map
            .insert(Arc::clone(&info.out_point), Arc::clone(&info));

        let block_live_cells = self.blocks.entry(info.number).or_default();
        assert!(!block_live_cells.contains_key(&info.index));
        block_live_cells.insert(info.index, info);

        self.total_capacity += capacity;
    }

    pub fn remove(&mut self, out_point: &CellOutPoint) -> Option<Arc<LiveCellInfo>> {
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
    network: NetworkType,
    last_header: HeaderView,
    tip_header: HeaderView,
    live_cell_map: LiveCellMap,
    secp_addrs: HashMap<H256, Address>,
    // Fields not to be serialized
    locks: HashMap<H256, LiveCellMap>,
}

impl LiveCellDatabase {
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<usize, IndexError> {
        log::info!("Save address database started");
        let mut file = fs::File::create(path)?;
        file.lock_exclusive()?;
        let network_string = self.network.to_string();
        let last_header_string =
            serde_json::to_string(&self.last_header).expect("Serialize last header error");
        let tip_header_string =
            serde_json::to_string(&self.tip_header).expect("Serialize tip header error");
        let total_capacity = self.live_cell_map.total_capacity.to_string();
        file.write(format!("{}\n", network_string).as_bytes())?;
        file.write(format!("{}\n", last_header_string).as_bytes())?;
        file.write(format!("{}\n", tip_header_string).as_bytes())?;
        file.write(format!("{}\n", total_capacity).as_bytes())?;

        let addr_index_count = self.secp_addrs.len().to_string();
        file.write(format!("{}\n", addr_index_count).as_bytes())?;
        for (lock_hash, address) in &self.secp_addrs {
            let addr_index = AddressIndex {
                lock_hash: lock_hash.clone(),
                address: address.clone(),
            };
            let addr_index_string =
                serde_json::to_string(&addr_index).expect("Serialize address index failed");
            file.write(format!("{}\n", addr_index_string).as_bytes())?;
        }

        let live_cell_count = self.live_cell_map.size().to_string();
        file.write(format!("{}\n", live_cell_count).as_bytes())?;
        for info in self.live_cell_map.map.values() {
            let live_cell_string =
                serde_json::to_string(&info).expect("Serialize LIVE_CELL failed");
            file.write(format!("{}\n", live_cell_string).as_bytes())?;
        }

        log::info!("Save address database finished");
        Ok(self.live_cell_map.size())
    }

    pub fn from_file<P: AsRef<Path>>(
        path: P,
        _genesis_block: &BlockView,
    ) -> Result<LiveCellDatabase, IndexError> {
        log::info!("Read database from file started");
        let file = fs::File::open(path)?;
        file.lock_exclusive()?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        // Load network type
        let line_network = lines.next().ok_or(IndexError::FileBroken(
            "read network field failed".to_owned(),
        ))??;
        let network = NetworkType::from_str(line_network.as_str()).ok_or(
            IndexError::FileBroken("parse network field failed".to_owned()),
        )?;

        // Load last header
        let line_last_header = lines.next().ok_or(IndexError::FileBroken(
            "read last_header field failed".to_owned(),
        ))??;
        let last_header = serde_json::from_str(line_last_header.as_str())
            .map_err(|_| IndexError::FileBroken("parse last_header field failed".to_owned()))?;

        // Load tip header
        let line_tip_header = lines.next().ok_or(IndexError::FileBroken(
            "read tip_header field failed".to_owned(),
        ))??;
        let tip_header = serde_json::from_str(line_tip_header.as_str())
            .map_err(|_| IndexError::FileBroken("parse tip_header field failed".to_owned()))?;

        let mut db = LiveCellDatabase {
            network,
            last_header,
            tip_header,
            live_cell_map: LiveCellMap::default(),
            secp_addrs: HashMap::default(),
            locks: HashMap::default(),
        };

        // Load total capacity for check
        let line_total_capacity = lines.next().ok_or(IndexError::FileBroken(
            "read live_cell count failed".to_owned(),
        ))??;
        let total_capacity: u128 = line_total_capacity
            .parse()
            .map_err(|_| IndexError::FileBroken("parse live_cell count failed".to_owned()))?;

        // Load secp address index
        let line_addr_index_count = lines.next().ok_or(IndexError::FileBroken(
            "read address index count failed".to_owned(),
        ))??;
        let addr_index_count: usize = line_addr_index_count
            .parse()
            .map_err(|_| IndexError::FileBroken("parse address index count failed".to_owned()))?;
        log::info!("addr_index_count: {}", addr_index_count);
        for idx in 0..addr_index_count {
            let line_addr_index = lines.next().ok_or_else(|| {
                IndexError::FileBroken(format!(
                    "read address index record failed: number={}",
                    idx + 1
                ))
            })??;
            let AddressIndex { lock_hash, address } =
                serde_json::from_str(line_addr_index.as_str()).map_err(|_| {
                    IndexError::FileBroken(format!(
                        "parse live_cell record failed: number={}",
                        idx + 1
                    ))
                })?;
            db.secp_addrs.insert(lock_hash, address);
        }

        // Load all live_cell
        let line_live_cell_count = lines.next().ok_or(IndexError::FileBroken(
            "read live_cell count failed".to_owned(),
        ))??;
        let live_cell_count: usize = line_live_cell_count
            .parse()
            .map_err(|_| IndexError::FileBroken("parse live_cell count failed".to_owned()))?;
        log::info!("live_cell_count: {}", live_cell_count);
        for idx in 0..live_cell_count {
            let line_live_cell = lines.next().ok_or_else(|| {
                IndexError::FileBroken(format!("read live_cell record failed: number={}", idx + 1))
            })??;
            let info: LiveCellInfo =
                serde_json::from_str(line_live_cell.as_str()).map_err(|_| {
                    IndexError::FileBroken(format!(
                        "parse live_cell record failed: number={}",
                        idx + 1
                    ))
                })?;
            db.add_live_cell(
                Arc::clone(&info.out_point),
                info.index,
                info.lock_hash,
                info.capacity,
                info.number,
            );
        }
        assert_eq!(total_capacity, db.live_cell_map.total_capacity);

        log::info!("Read database from file finished");
        Ok(db)
    }

    pub fn from_fresh(network: NetworkType, genesis_block: &BlockView) -> LiveCellDatabase {
        let genesis_header = &genesis_block.header;
        assert_eq!(genesis_header.inner.number.0, 0);

        let mut db = LiveCellDatabase {
            network,
            live_cell_map: LiveCellMap::default(),
            last_header: genesis_header.clone(),
            tip_header: genesis_header.clone(),
            secp_addrs: HashMap::default(),
            locks: HashMap::default(),
        };
        db.apply_block_unchecked(genesis_block);
        db
    }

    pub fn apply_next_block(&mut self, block: &BlockView) -> Result<(usize, usize), IndexError> {
        if block.header.inner.number.0 != self.last_header.inner.number.0 + 1 {
            return Err(IndexError::BlockTooEarly);
        }
        if block.header.inner.parent_hash != self.last_header.hash {
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

    pub fn get_balance(&self, lock_hash: &H256) -> Option<(u64, usize)> {
        self.locks
            .get(lock_hash)
            .map(|live_cell_map| (live_cell_map.total_capacity as u64, live_cell_map.size()))
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
