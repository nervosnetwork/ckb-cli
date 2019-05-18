

use std::collections::{HashSet, HashMap};
use std::fmt;
use std::io;
use std::io::{Write, BufRead, BufReader};
use std::fs;
use std::str::FromStr;
use std::path::Path;
use std::sync::Arc;

use bech32::{Bech32, convert_bits};
use crypto::secp::Pubkey;
use hash::blake2b_256;
use serde_derive::{Deserialize, Serialize};
use numext_fixed_hash::{h256, H256, H160};
pub use jsonrpc_types::{
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
const SECP_CODE_HASH: H256 = h256!("0x9e3b3557f11b2b3532ce352bfe8017e9fd11d154c4c7f9b7aaaa1e621b539a08");

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

    fn to_string(&self) -> String {
        format!("{}", self)
    }
}

impl fmt::Display for NetworkType {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", match self {
            NetworkType::MainNet => "mainnet",
            NetworkType::TestNet => "testnet",
        })
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
    pub fn from_pubkey(format: AddressFormat, pubkey: Pubkey) -> Result<Address, String> {
        if format != AddressFormat::P2PH {
            return Err("Only support P2PH for now".to_owned());
        }
        // Serialize pubkey as compressed format
        let hash = H160::from_slice(&blake2b_256(&pubkey.serialize())[0..20])
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
        if value.data().len() != 25 {
            return Err(format!("Invalid input data length {}", value.data().len()));
        }
        let format_bytes = value.data()[0..5].to_vec().iter().map(|v| v.to_u8()).collect::<Vec<_>>();
        let format = AddressFormat::from_bytes(&format_bytes)?;
        let hash_bytes = value.data()[5..25].to_vec().iter().map(|v| v.to_u8()).collect::<Vec<_>>();
        let hash = H160::from_slice(&hash_bytes).map_err(|err| err.to_string())?;
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

#[derive(Serialize, Deserialize)]
struct SecpUtxoRecord {
    out_point: CellOutPoint,
    capacity: Capacity,
    address: Address,
}

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct SecpUtxoInfo {
    pub capacity: Capacity,
    pub address: Address,
}

struct SecpUtxoMap {
    map: HashMap<CellOutPoint, Arc<SecpUtxoInfo>>,
    total_capacity: u128,
}

impl SecpUtxoMap {
    pub fn add(&mut self, out_point: CellOutPoint, info: Arc<SecpUtxoInfo>) {
        assert!(!self.map.contains_key(&out_point));
        let capacity = info.capacity.0.as_u64() as u128;
        self.map.insert(out_point, info);
        self.total_capacity += capacity;
    }

    pub fn remove(&mut self, out_point: &CellOutPoint) -> Option<Arc<SecpUtxoInfo>> {
        let info_opt = self.map.remove(out_point);
        if let Some(ref info) = info_opt {
            self.total_capacity -= info.capacity.0.as_u64() as u128;
        }
        info_opt
    }

    pub fn get(&self, out_point: &CellOutPoint) -> Option<Arc<SecpUtxoInfo>> {
        self.map.get(out_point).cloned()
    }

    pub fn size(&self) -> usize {
        self.map.len()
    }
}

impl Default for SecpUtxoMap {
    fn default() -> SecpUtxoMap {
        SecpUtxoMap {
            map: HashMap::default(),
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
    addresses: HashMap<Address, SecpUtxoMap>,
}

impl UtxoDatabase {
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<usize, IndexError> {
        log::warn!("Save address database");
        let mut file = fs::File::create(path)?;
        let network_string = self.network.to_string();
        let last_header_string = serde_json::to_string(&self.last_header)
            .expect("Serialize last header error");
        let tip_header_string = serde_json::to_string(&self.tip_header)
            .expect("Serialize tip header error");
        let utxo_count = self.utxo_map.size().to_string();
        file.write(format!("{}\n", network_string).as_bytes())?;
        file.write(format!("{}\n", last_header_string).as_bytes())?;
        file.write(format!("{}\n", tip_header_string).as_bytes())?;
        file.write(format!("{}\n", utxo_count).as_bytes())?;

        for (out_point, info) in self.utxo_map.map.iter() {
            let record = SecpUtxoRecord {
                out_point: out_point.clone(),
                capacity: info.capacity.clone(),
                address: info.address.clone(),
            };
            let record_string = serde_json::to_string(&record)
                .expect(format!("Serialize UTXO {:?} failed", out_point).as_str());
            file.write(format!("{}\n", record_string).as_bytes())?;
        }

        log::warn!("Save address database");
        Ok(self.utxo_map.size())
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<UtxoDatabase, IndexError> {
        let reader = BufReader::new(fs::File::open(path)?);
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

        let mut database = UtxoDatabase {
            network,
            last_header,
            tip_header,
            utxo_map: SecpUtxoMap::default(),
            addresses: HashMap::default(),
        };
        for idx in 0..utxo_count {
            let line_utxo = lines.next()
                .ok_or_else(|| IndexError::FileBroken(
                    format!("read utxo record failed: number={}", idx+1)
                ))??;
            let SecpUtxoRecord { out_point, address, capacity }= serde_json::from_str(line_utxo.as_str())
                .map_err(|_| IndexError::FileBroken(
                    format!("parse utxo record failed: number={}", idx+1)
                ))?;
            database.add_utxo(out_point, address, capacity);
        }
        Ok(database)
    }

    pub fn from_genesis(network: NetworkType, genesis_block: &BlockView) -> UtxoDatabase {
        let genesis_header = &genesis_block.header;
        assert_eq!(genesis_header.inner.number.0, 0);

        let mut database = UtxoDatabase {
            network,
            utxo_map: SecpUtxoMap::default(),
            last_header: genesis_header.clone(),
            tip_header: genesis_header.clone(),
            addresses: HashMap::default(),
        };
        database.apply_block_unchecked(genesis_block);
        database
    }

    pub fn apply_next_block(&mut self, block: &BlockView) -> Result<(), IndexError> {
        if block.header.inner.number.0 != self.last_header.inner.number.0 + 1 {
            return Err(IndexError::BlockTooEarly);
        }
        if block.header.inner.parent_hash != self.last_header.hash {
            return Err(IndexError::BlockInvalid);
        }
        if block.header.inner.number.0 + 10 >= self.tip_header.inner.number.0 {
            return Err(IndexError::BlockImmature);
        }

        self.apply_block_unchecked(block);
        Ok(())
    }

    pub fn update_tip(&mut self, header: HeaderView) {
        self.tip_header = header
    }

    pub fn last_header(&self) -> &HeaderView {
        &self.last_header
    }

    pub fn current_number(&self) -> u64 {
        self.last_header.inner.number.0
    }

    pub fn next_number(&self) -> BlockNumber {
        BlockNumber(self.last_header.inner.number.0 + 1)
    }

    pub fn get_utxo(&self, out_point: &CellOutPoint) -> Option<Arc<SecpUtxoInfo>> {
        self.utxo_map.get(out_point)
    }

    fn apply_block_unchecked(&mut self, block: &BlockView) {
        let header = &block.header;
        println!("Process block: {} => {:#x}", header.inner.number.0, header.hash);
        for tx in &block.transactions {
            self.apply_transaction(tx);
        }
        self.last_header = block.header.clone();
        println!(
            "Process block: {} => {:#x} (total_capacity={})",
            header.inner.number.0,
            header.hash,
            self.utxo_map.total_capacity,
        );
    }

    fn apply_transaction(&mut self, tx: &TransactionView) {
        for input in &tx.inner.inputs {
            if let Some(ref out_point) = input.previous_output.cell {
                self.remove_utxo(&out_point);
            }
        }
        for (index, output) in tx.inner.outputs.iter().enumerate() {
            if output.lock.code_hash == SECP_CODE_HASH {
                let address = Address::from_lock_arg(output.lock.args[0].as_bytes())
                    .expect("Convert address from lock arg error");
                let capacity = output.capacity.clone();
                let out_point = CellOutPoint {
                    tx_hash: tx.hash.clone(),
                    index: Unsigned(index as u64),
                };
                self.add_utxo(out_point, address, capacity);
            }
        }
    }

    fn add_utxo(&mut self, out_point: CellOutPoint, address: Address, capacity: Capacity) {
        let info = Arc::new(SecpUtxoInfo {
            address: address.clone(),
            capacity: capacity.clone(),
        });
        println!(
            "add tx_hash={:#x}, index={}, address={}, capacity={}",
            out_point.tx_hash,
            out_point.index.0,
            info.address.to_string(self.network),
            info.capacity.0,
        );

        self.utxo_map.add(out_point.clone(), Arc::clone(&info));
        self.addresses
            .entry(address.clone())
            .or_default()
            .add(out_point, info);
    }

    fn remove_utxo(&mut self, out_point: &CellOutPoint) -> Option<Arc<SecpUtxoInfo>> {
        let info_opt = self.utxo_map.remove(out_point);
        if let Some(ref info) = info_opt {
            println!(
                "remove tx_hash={:#x}, index={}, address={}, capacity={}",
                out_point.tx_hash,
                out_point.index.0,
                info.address.to_string(self.network),
                info.capacity.0,
            );
            let map = self.addresses
                .get_mut(&info.address)
                .expect("Target address must exists: {}");
            let inner_info = map
                .remove(out_point)
                .expect("Info must exists");
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
