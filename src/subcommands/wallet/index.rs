

use std::collections::{HashMap, BTreeMap};
use std::fmt;
use std::io;
use std::io::{Write, BufRead, BufReader};
use std::fs;
use std::str::FromStr;
use std::path::Path;
use std::sync::Arc;

use fs2::FileExt;
use bech32::{Bech32, convert_bits};
use crypto::secp::Pubkey;
use hash::blake2b_256;
use bytes::Bytes;
use serde_derive::{Deserialize, Serialize};
use numext_fixed_hash::{h256, H256, H160};
use ckb_core::{
    script::{
        Script as CoreScript,
    },
    transaction::{
        CellInput as CoreCellInput,
        CellOutPoint as CoreCellOutPoint,
        OutPoint as CoreOutPoint,
    },
};
pub use jsonrpc_types::{
    JsonBytes,
    Script,
    BlockNumber,
    BlockView,
    HeaderView,
    Unsigned,
    CellOutPoint,
    Capacity,
    Transaction,
    TransactionView,
};


const PREFIX_MAINNET: &str = "ckb";
const PREFIX_TESTNET: &str = "ckt";
const P2PH_MARK: &[u8] = b"P2PH";
pub const SECP_CODE_HASH: H256 = h256!("0x9e3b3557f11b2b3532ce352bfe8017e9fd11d154c4c7f9b7aaaa1e621b539a08");

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
            _ => Err(format!("Unsupported address format: {:?}", self))
        }
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Address {
    format: AddressFormat,
    hash: H160,
}

impl Address {
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
        match network {
            NetworkType::MainNet => {
                if value.hrp() != PREFIX_MAINNET {
                    return Err(format!("Invalid hrp({}) for {}", value.hrp(), network));
                }
            }
            NetworkType::TestNet => {
                if value.hrp() != PREFIX_TESTNET {
                    return Err(format!("Invalid hrp({}) for {}", value.hrp(), network));
                }
            }
        }
        let data = convert_bits(value.data(), 5, 8, false).unwrap();
        if data.len() != 25 {
            return Err(format!("Invalid input data length {}", data.len()));
        }
        let format = AddressFormat::from_bytes(&data[1..5])?;
        let hash = H160::from_slice(&data[5..25]).map_err(|err| err.to_string())?;
        Ok(Address { format, hash })
    }

    pub fn to_string(&self, network: NetworkType) -> String {
        let hrp = network.to_prefix();
        let mut data = [0; 24];
        let format_data = self.format.to_bytes().expect("Invalid address format");
        data[0..4].copy_from_slice(&format_data[0..4]);
        data[4..24].copy_from_slice(self.hash.as_fixed_bytes());
        let data_u5 = convert_bits(&data, 8, 5, true).unwrap();
        let value = Bech32::new_check_data(hrp.to_string(), data_u5)
            .expect(&format!("Encode address failed: hash={:?}", self.hash));
        format!("{}", value)
    }
}


#[derive(Hash, Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct SecpUtxoInfo {
    pub out_point: Arc<CellOutPoint>,
    pub address: Address,
    pub capacity: u64,
    // Block number
    pub number: u64,
    // Location in the block
    utxo_index: UtxoIndex,
}

impl SecpUtxoInfo {
    pub fn core_input(&self) -> CoreCellInput {
        CoreCellInput {
            previous_output: CoreOutPoint{
                cell: Some(CoreCellOutPoint::from(CellOutPoint::clone(&self.out_point))),
                block_hash: None,
            },
            since: 0,
            args: vec![],
        }
    }
}

// Utxo index in a block
#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy, Serialize, Deserialize)]
struct UtxoIndex{
    // The transaction index in the block
    tx_index: u32,
    // The output index in the transaction
    output_index: u32,
}

impl UtxoIndex {
    fn new(tx_index: u32, output_index: u32) -> UtxoIndex {
        UtxoIndex { tx_index, output_index }
    }
}

struct SecpUtxoMap {
    map: HashMap<Arc<CellOutPoint>, Arc<SecpUtxoInfo>>,
    blocks: BTreeMap<u64, HashMap<UtxoIndex, Arc<SecpUtxoInfo>>>,
    total_capacity: u128,
}

impl SecpUtxoMap {
    pub fn add(&mut self, info: Arc<SecpUtxoInfo>) {
        let capacity = info.capacity as u128;

        assert!(!self.map.contains_key(&info.out_point));
        self.map.insert(Arc::clone(&info.out_point), Arc::clone(&info));

        let block_utxos = self.blocks
            .entry(info.number)
            .or_default();
        assert!(!block_utxos.contains_key(&info.utxo_index));
        block_utxos.insert(info.utxo_index, info);

        self.total_capacity += capacity;
    }

    pub fn remove(&mut self, out_point: &CellOutPoint) -> Option<Arc<SecpUtxoInfo>> {
        let info_opt = self.map.remove(out_point);
        if let Some(ref info) = info_opt {
            let block_utxos = self.blocks.get_mut(&info.number).expect("Block not exists");
            let inner_info = block_utxos
                .remove(&info.utxo_index)
                .expect("Utxo not exists in blocks");
            assert_eq!(&inner_info, info);
            if block_utxos.is_empty() {
                self.blocks.remove(&info.number);
            }
            self.total_capacity -= info.capacity as u128;
        }
        info_opt
    }

    pub fn get(&self, out_point: &CellOutPoint) -> Option<Arc<SecpUtxoInfo>> {
        self.map.get(out_point).cloned()
    }

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

impl Default for SecpUtxoMap {
    fn default() -> SecpUtxoMap {
        SecpUtxoMap {
            map: HashMap::default(),
            blocks: BTreeMap::default(),
            total_capacity: 0,
        }
    }
}

pub struct UtxoDatabase {
    network: NetworkType,
    last_header: HeaderView,
    tip_header: HeaderView,
    utxo_map: SecpUtxoMap,
    // Fields not to be serialized
    genesis_header: HeaderView,
    genesis_out_points: Vec<Vec<CellOutPoint>>,
    addresses: HashMap<Address, SecpUtxoMap>,
}

impl UtxoDatabase {
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<usize, IndexError> {
        log::info!("Save address database started");
        let mut file = fs::File::create(path)?;
        file.lock_exclusive()?;
        let network_string = self.network.to_string();
        let last_header_string = serde_json::to_string(&self.last_header)
            .expect("Serialize last header error");
        let tip_header_string = serde_json::to_string(&self.tip_header)
            .expect("Serialize tip header error");
        let utxo_count = self.utxo_map.size().to_string();
        let total_capacity = self.utxo_map.total_capacity.to_string();
        file.write(format!("{}\n", network_string).as_bytes())?;
        file.write(format!("{}\n", last_header_string).as_bytes())?;
        file.write(format!("{}\n", tip_header_string).as_bytes())?;
        file.write(format!("{}\n", utxo_count).as_bytes())?;
        file.write(format!("{}\n", total_capacity).as_bytes())?;

        for (out_point, info) in self.utxo_map.map.iter() {
            let utxo_string = serde_json::to_string(&info)
                .expect(format!("Serialize UTXO {:?} failed", out_point).as_str());
            file.write(format!("{}\n", utxo_string).as_bytes())?;
        }

        log::info!("Save address database finished");
        Ok(self.utxo_map.size())
    }

    pub fn from_file<P: AsRef<Path>>(
        path: P,
        genesis_block: &BlockView,
    ) -> Result<UtxoDatabase, IndexError> {
        log::info!("Read database from file started");
        let file = fs::File::open(path)?;
        file.lock_exclusive()?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        let line_network = lines.next()
            .ok_or(IndexError::FileBroken("read network field failed".to_owned()))??;
        let network = NetworkType::from_str(line_network.as_str())
            .ok_or(IndexError::FileBroken("parse network field failed".to_owned()))?;

        let line_last_header = lines.next()
            .ok_or(IndexError::FileBroken("read last_header field failed".to_owned()))??;
        let last_header = serde_json::from_str(line_last_header.as_str())
            .map_err(|_| IndexError::FileBroken("parse last_header field failed".to_owned()))?;

        let line_tip_header = lines.next()
            .ok_or(IndexError::FileBroken("read tip_header field failed".to_owned()))??;
        let tip_header = serde_json::from_str(line_tip_header.as_str())
            .map_err(|_| IndexError::FileBroken("parse tip_header field failed".to_owned()))?;

        let line_utxo_count = lines.next()
            .ok_or(IndexError::FileBroken("read utxo count failed".to_owned()))??;
        let utxo_count: usize = line_utxo_count.parse()
            .map_err(|_| IndexError::FileBroken("parse utxo count failed".to_owned()))?;

        let line_total_capacity = lines.next()
            .ok_or(IndexError::FileBroken("read utxo count failed".to_owned()))??;
        let total_capacity: u128 = line_total_capacity.parse()
            .map_err(|_| IndexError::FileBroken("parse utxo count failed".to_owned()))?;

        log::info!("utxo_count: {}", utxo_count);
        let mut database = UtxoDatabase {
            network,
            last_header,
            tip_header,
            utxo_map: SecpUtxoMap::default(),
            genesis_header: genesis_block.header.clone(),
            genesis_out_points: Vec::new(),
            addresses: HashMap::default(),
        };
        database.apply_genesis(genesis_block);

        for idx in 0..utxo_count {
            let line_utxo = lines.next()
                .ok_or_else(|| IndexError::FileBroken(
                    format!("read utxo record failed: number={}", idx+1)
                ))??;
            let info: SecpUtxoInfo = serde_json::from_str(line_utxo.as_str())
                .map_err(|_| IndexError::FileBroken(
                    format!("parse utxo record failed: number={}", idx+1)
                ))?;
            database.add_utxo(
                Arc::clone(&info.out_point),
                info.utxo_index,
                info.address,
                info.capacity,
                info.number,
            );
        }
        assert_eq!(total_capacity, database.utxo_map.total_capacity);

        log::info!("Read database from file finished");
        Ok(database)
    }

    pub fn from_fresh(network: NetworkType, genesis_block: &BlockView) -> UtxoDatabase {
        let genesis_header = &genesis_block.header;
        assert_eq!(genesis_header.inner.number.0, 0);

        let mut database = UtxoDatabase {
            network,
            utxo_map: SecpUtxoMap::default(),
            last_header: genesis_header.clone(),
            tip_header: genesis_header.clone(),
            genesis_header: genesis_block.header.clone(),
            genesis_out_points: Vec::new(),
            addresses: HashMap::default(),
        };
        database.apply_genesis(genesis_block);
        database.apply_block_unchecked(genesis_block);
        database
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

    pub fn get_utxo(&self, out_point: &CellOutPoint) -> Option<Arc<SecpUtxoInfo>> {
        self.utxo_map.get(out_point)
    }

    pub fn get_secp_dep(&self) -> CoreOutPoint {
        CoreOutPoint {
            cell: Some(self.genesis_out_points[0][1].clone().into()),
            block_hash: None,
        }
    }

    pub fn get_balance(&self, address: &Address) -> Option<u64> {
        self.addresses
            .get(address)
            .map(|utxo_map| utxo_map.total_capacity as u64)
    }

    pub fn get_utxo_infos(
        &self,
        address: &Address,
        total_capacity: u64,
    ) -> (Vec<Arc<SecpUtxoInfo>>, Option<u64>) {
        self.addresses.get(address)
            .map(|utxo_map| {
                let mut result_total_capacity = 0;
                let mut infos = Vec::new();
                for utxos in utxo_map.blocks.values() {
                    for info in utxos.values() {
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

    pub fn get_top_n(&self, n: usize) -> Vec<(Address, u64)> {
        let mut pairs = self.addresses
            .iter()
            .map(|(address, utxo_map)| (address.clone(), utxo_map.total_capacity as u64))
            .collect::<Vec<_>>();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }

    fn apply_genesis(&mut self, genesis_block: &BlockView) -> Result<(), String> {
        let mut error = None;
        self.genesis_out_points = genesis_block.transactions
            .iter()
            .enumerate()
            .map(|(tx_index, tx)| {
                tx.inner.outputs
                    .iter()
                    .enumerate()
                    .map(|(index, output)| {
                        if tx_index == 0 && index == 1 {
                            let code_hash = H256::from_slice(&blake2b_256(output.data.as_bytes()))
                                .expect("Convert to H256 error");
                            if code_hash != SECP_CODE_HASH {
                                error = Some(format!(
                                    "System secp script code hash error! found: {}, expected: {}",
                                    code_hash,
                                    SECP_CODE_HASH,
                                ));
                            }
                        }
                        CellOutPoint {
                            tx_hash: tx.hash.clone(),
                            index: Unsigned(index as u64),
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        if let Some(err) = error {
            Err(err)
        } else {
            Ok(())
        }
    }

    fn apply_block_unchecked(&mut self, block: &BlockView) -> (usize, usize) {
        let header = &block.header;
        log::debug!("Process block: {} => {:#x}", header.inner.number.0, header.hash);
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
            self.utxo_map.total_capacity,
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
                if self.remove_utxo(&out_point).is_some() {
                    removed += 1;
                }
            }
        }
        for (output_index, output) in tx.inner.outputs.iter().enumerate() {
            if output.lock.code_hash == SECP_CODE_HASH {
                if output.lock.args.len() != 1 {
                    log::info!("lock arg should given exact 1");
                    continue;
                }
                let lock_arg = &output.lock.args[0];
                match Address::from_lock_arg(lock_arg.as_bytes()) {
                    Ok(address) => {
                        let capacity = output.capacity.0.as_u64();
                        let out_point = Arc::new(CellOutPoint {
                            tx_hash: tx.hash.clone(),
                            index: Unsigned(output_index as u64),
                        });
                        let utxo_index = UtxoIndex::new(tx_index, output_index as u32);
                        self.add_utxo(out_point, utxo_index, address, capacity, number);
                        added += 1;
                    }
                    Err(err) => {
                        log::info!("Invalid secp arg: {:?} => {}", lock_arg, err);
                    }
                }
            }
        }
        (removed, added)
    }

    fn add_utxo(
        &mut self,
        out_point: Arc<CellOutPoint>,
        utxo_index: UtxoIndex,
        address: Address,
        capacity: u64,
        number: u64,
    ) {
        let info = Arc::new(SecpUtxoInfo {
            out_point: Arc::clone(&out_point),
            utxo_index,
            address: address.clone(),
            capacity,
            number,
        });
        log::trace!(
            "add tx_hash={:#x}, index={}, address={}, capacity={}",
            out_point.tx_hash,
            out_point.index.0,
            info.address.to_string(self.network),
            info.capacity,
        );

        self.utxo_map.add(Arc::clone(&info));
        self.addresses
            .entry(address.clone())
            .or_default()
            .add(info);
    }

    fn remove_utxo(&mut self, out_point: &CellOutPoint) -> Option<Arc<SecpUtxoInfo>> {
        let info_opt = self.utxo_map.remove(out_point);
        if let Some(ref info) = info_opt {
            log::trace!(
                "remove tx_hash={:#x}, index={}, address={}, capacity={}",
                out_point.tx_hash,
                out_point.index.0,
                info.address.to_string(self.network),
                info.capacity,
            );
            let map = self.addresses
                .get_mut(&info.address)
                .expect("Target address must exists: {}");
            let inner_info = map
                .remove(out_point)
                .expect("Info must exists");
            if map.is_empty() {
                self.addresses.remove(&info.address);
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
