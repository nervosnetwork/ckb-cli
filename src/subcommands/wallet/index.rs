use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use bech32::{convert_bits, Bech32, ToBase32};
use bytes::Bytes;
use ckb_core::{
    header::Header as CoreHeader,
    script::Script as CoreScript,
    transaction::{
        CellInput as CoreCellInput, CellOutPoint as CoreCellOutPoint, OutPoint as CoreOutPoint,
    },
};
use crypto::secp::Pubkey;
use hash::blake2b_256;
pub use jsonrpc_types::{
    BlockNumber, BlockView, Capacity, CellOutPoint, HeaderView, JsonBytes, Script, Transaction,
    TransactionView, Unsigned,
};
use numext_fixed_hash::{h256, H160, H256};
use serde_derive::{Deserialize, Serialize};

// 200GB
const LMDB_MAX_MAP_SIZE: usize = 200 * 1024 * 1024 * 1024;
const LMDB_MAX_DBS: u32 = 6;
const PREFIX_MAINNET: &str = "ckb";
const PREFIX_TESTNET: &str = "ckt";
// \x01 is the P2PH version
const P2PH_MARK: &[u8] = b"\x01P2PH";
pub const SECP_CODE_HASH: H256 =
    h256!("0x9e3b3557f11b2b3532ce352bfe8017e9fd11d154c4c7f9b7aaaa1e621b539a08");

#[derive(Eq, PartialEq, Debug, Hash, Clone, Copy)]
#[repr(u16)]
enum KeyType {
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
    // key => value: {type}:{Address} => {lock-hash}
    SecpAddrLock = 102,

    // key => value: {type}:{CellOutPoint} => {LiveCellInfo}
    LiveCellMap = 200,
    // key => value: {type}:{block-number}:{CellIndex} => {CellOutPoint}
    LiveCellIndex = 201,

    // >> Store live cell owned by certain lock
    // key => value: {type}:{lock-hash} => CoreScript
    LockScript = 300,
    // key => value: {type}:{lock-hash} => u64
    LockTotalCapacity = 301,
    // >> NOTE: Remove when capacity changed
    // key => value: {type}:{capacity(u64::MAX - u64)}:{lock-hash} => ()
    LockTotalCapacityIndex = 302,
    // key => value: {type}:{lock-hash}:{block-number}:{CellIndex} => {CellOutPoint}
    LockLiveCellIndex = 303,
    // key => value: {type}:{lock-hash}:{block-number}:{tx-index(u32)} => {tx-hash}
    LockTx = 304,

    // >> for rollback block when fork happen (keep 1000 blocks?)
    // key = value: {type}:{block-number} => {BlockDeltaInfo}
    BlockDelta = 400,
}

impl KeyType {
    fn to_bytes(&self) -> Vec<u8> {
        (*self as u16).to_be_bytes().to_vec()
    }

    fn from_bytes(bytes: [u8; 2]) -> KeyType {
        match u16::from_be_bytes(bytes) {
            0 => KeyType::GenesisHash,
            1 => KeyType::Network,
            2 => KeyType::LastHeader,
            3 => KeyType::TotalCapacity,

            100 => KeyType::GlobalHash,
            101 => KeyType::TxMap,
            102 => KeyType::SecpAddrLock,

            200 => KeyType::LiveCellMap,
            201 => KeyType::LiveCellIndex,

            300 => KeyType::LockScript,
            301 => KeyType::LockTotalCapacity,
            302 => KeyType::LockTotalCapacityIndex,
            303 => KeyType::LockLiveCellIndex,
            304 => KeyType::LockTx,

            400 => KeyType::BlockDelta,
            value => panic!("Unexpected key type: value={}", value),
        }
    }
}

#[derive(Debug, Clone)]
enum Key {
    GenesisHash,
    Network,
    LastHeader,
    TotalCapacity,

    GlobalHash(H256),
    TxMap(H256),
    SecpAddrLock(Address),

    LiveCellMap(CoreCellOutPoint),
    LiveCellIndex(u64, CellIndex),

    LockScript(H256),
    LockTotalCapacity(H256),
    LockTotalCapacityIndex(u64, H256),
    // LockLiveCell(H256, CellOutPoint),
    LockLiveCellIndexPrefix(H256),
    LockLiveCellIndex(H256, u64, CellIndex),
    LockTx(H256, u64, u32),

    BlockDelta(u64),
}

impl Key {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Key::GenesisHash => KeyType::GenesisHash.to_bytes(),
            Key::Network => KeyType::Network.to_bytes(),
            Key::LastHeader => KeyType::LastHeader.to_bytes(),
            Key::TotalCapacity => KeyType::TotalCapacity.to_bytes(),
            Key::GlobalHash(hash) => {
                let mut bytes = KeyType::GlobalHash.to_bytes();
                bytes.extend(bincode::serialize(hash).unwrap());
                bytes
            }
            Key::TxMap(tx_hash) => {
                let mut bytes = KeyType::TxMap.to_bytes();
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
            Key::LockTotalCapacityIndex(capacity, lock_hash) => {
                // NOTE: large capacity stay front
                let capacity = std::u64::MAX - capacity;
                let mut bytes = KeyType::LockTotalCapacityIndex.to_bytes();
                bytes.extend(capacity.to_be_bytes().to_vec());
                bytes.extend(bincode::serialize(lock_hash).unwrap());
                bytes
            }
            // Key::LockLiveCell(lock_hash, out_point) => {
            //     let mut bytes = KeyType::LockLiveCell.to_bytes();
            //     bytes.extend(bincode::serialize(lock_hash).unwrap());
            //     bytes.extend(bincode::serialize(out_point).unwrap());
            //     bytes
            // }
            Key::LockLiveCellIndexPrefix(lock_hash) => {
                let mut bytes = KeyType::LockLiveCellIndex.to_bytes();
                bytes.extend(bincode::serialize(lock_hash).unwrap());
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
            Key::LockTx(lock_hash, number, tx_index) => {
                let mut bytes = KeyType::LockTx.to_bytes();
                bytes.extend(bincode::serialize(lock_hash).unwrap());
                // Must use big endian for sort
                bytes.extend(number.to_be_bytes().to_vec());
                bytes.extend(tx_index.to_be_bytes().to_vec());
                bytes
            }
            Key::BlockDelta(number) => {
                let mut bytes = KeyType::LockTx.to_bytes();
                bytes.extend(number.to_be_bytes().to_vec());
                bytes
            }
        }
    }

    fn from_bytes(bytes: &[u8]) -> Key {
        let type_bytes = [bytes[0], bytes[1]];
        let key_type = KeyType::from_bytes(type_bytes);
        let args_bytes = &bytes[2..];
        match key_type {
            KeyType::GenesisHash => Key::GenesisHash,
            KeyType::Network => Key::Network,
            KeyType::LastHeader => Key::LastHeader,
            KeyType::TotalCapacity => Key::TotalCapacity,
            KeyType::GlobalHash => {
                let hash = bincode::deserialize(args_bytes).unwrap();
                Key::GlobalHash(hash)
            }
            KeyType::TxMap => {
                let tx_hash = bincode::deserialize(args_bytes).unwrap();
                Key::TxMap(tx_hash)
            }
            KeyType::SecpAddrLock => {
                let address = bincode::deserialize(args_bytes).unwrap();
                Key::SecpAddrLock(address)
            }
            KeyType::LiveCellMap => {
                let out_point = bincode::deserialize(args_bytes).unwrap();
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
                let lock_hash = bincode::deserialize(args_bytes).unwrap();
                Key::LockScript(lock_hash)
            }
            KeyType::LockTotalCapacity => {
                let lock_hash = bincode::deserialize(args_bytes).unwrap();
                Key::LockTotalCapacity(lock_hash)
            }
            KeyType::LockTotalCapacityIndex => {
                let mut capacity_bytes = [0u8; 8];
                capacity_bytes.copy_from_slice(&args_bytes[..8]);
                let lock_hash_bytes = &args_bytes[8..];
                // NOTE: large capacity stay front
                let capacity = std::u64::MAX - u64::from_be_bytes(capacity_bytes);
                let lock_hash = bincode::deserialize(lock_hash_bytes).unwrap();
                Key::LockTotalCapacityIndex(capacity, lock_hash)
            }
            // KeyType::LockLiveCell => {
            // let lock_hash_bytes = &args_bytes[..32];
            // let out_point_bytes = &args_bytes[32..];
            // let lock_hash = bincode::deserialize(lock_hash_bytes).unwrap();
            // let out_point = bincode::deserialize(out_point_bytes).unwrap();
            // Key::LockLiveCell(lock_hash, out_point)
            // }
            KeyType::LockLiveCellIndex => {
                let lock_hash_bytes = &args_bytes[..32];
                let mut number_bytes = [0u8; 8];
                number_bytes.copy_from_slice(&args_bytes[32..40]);
                let mut cell_index_bytes = [0u8; 8];
                cell_index_bytes.copy_from_slice(&args_bytes[40..]);
                let lock_hash = bincode::deserialize(lock_hash_bytes).unwrap();
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
                let lock_hash = bincode::deserialize(lock_hash_bytes).unwrap();
                let number = u64::from_be_bytes(number_bytes);
                let tx_index = u32::from_be_bytes(tx_index_bytes);
                Key::LockTx(lock_hash, number, tx_index)
            }
            KeyType::BlockDelta => {
                let mut number_bytes = [0u8; 8];
                number_bytes.copy_from_slice(args_bytes);
                let number = u64::from_be_bytes(number_bytes);
                Key::BlockDelta(number)
            }
        }
    }

    fn key_type(&self) -> KeyType {
        match self {
            Key::GenesisHash => KeyType::GenesisHash,
            Key::Network => KeyType::Network,
            Key::LastHeader => KeyType::LastHeader,
            Key::TotalCapacity => KeyType::TotalCapacity,
            Key::GlobalHash(..) => KeyType::GlobalHash,
            Key::TxMap(..) => KeyType::TxMap,
            Key::SecpAddrLock(..) => KeyType::SecpAddrLock,
            Key::LiveCellMap(..) => KeyType::LiveCellMap,
            Key::LiveCellIndex(..) => KeyType::LiveCellIndex,
            Key::LockScript(..) => KeyType::LockScript,
            Key::LockTotalCapacity(..) => KeyType::LockTotalCapacity,
            Key::LockTotalCapacityIndex(..) => KeyType::LockTotalCapacityIndex,
            // Key::LockLiveCell(..) => KeyType::LockLiveCell,
            Key::LockLiveCellIndexPrefix(..) => KeyType::LockLiveCellIndex,
            Key::LockLiveCellIndex(..) => KeyType::LockLiveCellIndex,
            Key::LockTx(..) => KeyType::LockTx,
            Key::BlockDelta(..) => KeyType::BlockDelta,
        }
    }

    fn pair_genesis_hash(value: &H256) -> (Vec<u8>, Vec<u8>) {
        (
            Key::GenesisHash.to_bytes(),
            bincode::serialize(value).unwrap(),
        )
    }
    fn pair_network(value: &NetworkType) -> (Vec<u8>, Vec<u8>) {
        (Key::Network.to_bytes(), bincode::serialize(value).unwrap())
    }
    fn pair_last_header(value: &CoreHeader) -> (Vec<u8>, Vec<u8>) {
        (
            Key::LastHeader.to_bytes(),
            bincode::serialize(value).unwrap(),
        )
    }
    fn pair_total_capacity(value: &u128) -> (Vec<u8>, Vec<u8>) {
        (
            Key::TotalCapacity.to_bytes(),
            bincode::serialize(value).unwrap(),
        )
    }

    fn pair_global_hash(hash: H256, value: &HashType) -> (Vec<u8>, Vec<u8>) {
        (
            Key::GlobalHash(hash).to_bytes(),
            bincode::serialize(value).unwrap(),
        )
    }
    fn pair_tx_map(tx_hash: H256, value: &TxInfo) -> (Vec<u8>, Vec<u8>) {
        (
            Key::TxMap(tx_hash).to_bytes(),
            bincode::serialize(value).unwrap(),
        )
    }
    fn pair_secp_addr_lock(address: Address, value: &H256) -> (Vec<u8>, Vec<u8>) {
        (
            Key::SecpAddrLock(address).to_bytes(),
            bincode::serialize(value).unwrap(),
        )
    }

    fn pair_live_cell_map(out_point: CoreCellOutPoint, value: &LiveCellInfo) -> (Vec<u8>, Vec<u8>) {
        (
            Key::LiveCellMap(out_point).to_bytes(),
            bincode::serialize(value).unwrap(),
        )
    }
    fn pair_live_cell_index(
        (number, cell_index): (u64, CellIndex),
        value: &CoreCellOutPoint,
    ) -> (Vec<u8>, Vec<u8>) {
        (
            Key::LiveCellIndex(number, cell_index).to_bytes(),
            bincode::serialize(value).unwrap(),
        )
    }

    fn pair_lock_script(lock_hash: H256, value: &CoreScript) -> (Vec<u8>, Vec<u8>) {
        (
            Key::LockScript(lock_hash).to_bytes(),
            bincode::serialize(value).unwrap(),
        )
    }
    fn pair_lock_total_capacity(lock_hash: H256, value: &u64) -> (Vec<u8>, Vec<u8>) {
        (
            Key::LockTotalCapacity(lock_hash).to_bytes(),
            bincode::serialize(value).unwrap(),
        )
    }
    fn pair_lock_total_capacity_index((capacity, lock_hash): (u64, H256)) -> (Vec<u8>, Vec<u8>) {
        (
            Key::LockTotalCapacityIndex(capacity, lock_hash).to_bytes(),
            [0u8].to_vec(),
        )
    }
    // fn pair_lock_live_cell((lock_hash, out_point): (H256, CellOutPoint)) -> (Vec<u8>, Vec<u8>) {
    //     (
    //         Key::LockLiveCell(lock_hash, out_point).to_bytes(),
    //         [0u8].to_vec(),
    //     )
    // }
    fn pair_lock_live_cell_index(
        (lock_hash, number, cell_index): (H256, u64, CellIndex),
        value: &CoreCellOutPoint,
    ) -> (Vec<u8>, Vec<u8>) {
        (
            Key::LockLiveCellIndex(lock_hash, number, cell_index).to_bytes(),
            bincode::serialize(value).unwrap(),
        )
    }
    fn pair_lock_tx(
        (lock_hash, number, tx_index): (H256, u64, u32),
        value: &H256,
    ) -> (Vec<u8>, Vec<u8>) {
        (
            Key::LockTx(lock_hash, number, tx_index).to_bytes(),
            bincode::serialize(value).unwrap(),
        )
    }

    fn pair_block_delta(number: u64, value: &BlockDeltaInfo) -> (Vec<u8>, Vec<u8>) {
        (
            Key::BlockDelta(number).to_bytes(),
            bincode::serialize(value).unwrap(),
        )
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

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
struct BlockDeltaInfo {
    header: CoreHeader,
    txs: Vec<RichTxInfo>,
    locks: Vec<CoreScript>,
}

impl BlockDeltaInfo {
    fn from_view(
        block: &BlockView,
        store: &rkv::SingleStore,
        reader: &rkv::Reader,
    ) -> BlockDeltaInfo {
        let header: CoreHeader = block.header.clone().into();
        let number = block.header.inner.number.0;
        let timestamp = block.header.inner.timestamp.0;
        let mut locks = Vec::new();
        let txs = block
            .transactions
            .iter()
            .enumerate()
            .map(|(tx_index, tx)| {
                let mut inputs = Vec::new();
                let mut outputs = Vec::new();

                for input in &tx.inner.inputs {
                    if let Some(ref out_point) = input.previous_output.cell {
                        let live_cell_info: LiveCellInfo = store
                            .get(
                                reader,
                                Key::LiveCellMap(out_point.clone().into()).to_bytes(),
                            )
                            .unwrap()
                            .as_ref()
                            .map(|value| value_to_bytes(value))
                            .map(|bytes| bincode::deserialize(&bytes).unwrap())
                            .unwrap();
                        inputs.push(live_cell_info);
                    }
                }

                for (output_index, output) in tx.inner.outputs.iter().enumerate() {
                    let lock: CoreScript = output.lock.clone().into();
                    let lock_hash = lock.hash();
                    let capacity = output.capacity.0.as_u64();
                    let out_point = CoreCellOutPoint {
                        tx_hash: tx.hash.clone(),
                        index: output_index as u32,
                    };
                    let cell_index = CellIndex::new(tx_index as u32, output_index as u32);

                    locks.push(output.lock.clone().into());

                    let live_cell_info = LiveCellInfo {
                        out_point,
                        index: cell_index,
                        lock_hash: lock_hash,
                        capacity,
                        number,
                    };
                    outputs.push(live_cell_info);
                }

                RichTxInfo {
                    tx_hash: tx.hash.clone(),
                    tx_index: tx_index as u32,
                    block_number: number,
                    block_timestamp: timestamp,
                    inputs,
                    outputs,
                }
            })
            .collect::<Vec<_>>();

        BlockDeltaInfo { header, txs, locks }
    }

    fn apply(&self, store: &rkv::SingleStore, writer: &mut rkv::Writer) -> ApplyResult {
        let mut result = ApplyResult {
            chain_capacity: 0,
            capacity_delta: 0,
            txs: self.txs.len(),
            cell_added: 0,
            cell_removed: 0,
        };
        // Update cells and transactions
        put_pair(store, writer, Key::pair_last_header(&self.header));
        let mut capacity_deltas: HashMap<&H256, i64> = HashMap::default();
        for tx in &self.txs {
            put_pair(
                store,
                writer,
                Key::pair_tx_map(tx.tx_hash.clone(), &tx.to_thin()),
            );

            for LiveCellInfo {
                out_point,
                lock_hash,
                capacity,
                number,
                index,
            } in &tx.inputs
            {
                *capacity_deltas.entry(lock_hash).or_default() -= *capacity as i64;
                put_pair(
                    store,
                    writer,
                    Key::pair_lock_tx((lock_hash.clone(), *number, index.tx_index), &tx.tx_hash),
                );
                store
                    .delete(writer, Key::LiveCellMap(out_point.clone()).to_bytes())
                    .unwrap();
                store
                    .delete(writer, Key::LiveCellIndex(*number, *index).to_bytes())
                    .unwrap();
                store
                    .delete(
                        writer,
                        Key::LockLiveCellIndex(lock_hash.clone(), *number, *index).to_bytes(),
                    )
                    .unwrap();
            }

            for live_cell_info in &tx.outputs {
                let LiveCellInfo {
                    out_point,
                    lock_hash,
                    capacity,
                    number,
                    index,
                } = live_cell_info;
                *capacity_deltas.entry(lock_hash).or_default() += *capacity as i64;
                put_pair(
                    store,
                    writer,
                    Key::pair_lock_tx((lock_hash.clone(), *number, index.tx_index), &tx.tx_hash),
                );
                put_pair(
                    store,
                    writer,
                    Key::pair_live_cell_map(out_point.clone(), live_cell_info),
                );
                put_pair(
                    store,
                    writer,
                    Key::pair_live_cell_index((*number, *index), out_point),
                );
                put_pair(
                    store,
                    writer,
                    Key::pair_lock_live_cell_index((lock_hash.clone(), *number, *index), out_point),
                );
            }
            result.cell_removed += tx.inputs.len();
            result.cell_added += tx.outputs.len();
        }

        // Update capacity group by lock
        let mut capacity_delta: i64 = 0;
        for (lock_hash, delta) in capacity_deltas.iter().filter(|(_, delta)| **delta != 0) {
            capacity_delta += delta;
            let mut lock_capacity: u64 = store
                .get(
                    writer,
                    Key::LockTotalCapacity((*lock_hash).clone()).to_bytes(),
                )
                .unwrap()
                .map(|value| bincode::deserialize(value_to_bytes(&value)).unwrap())
                .unwrap_or(0);
            if let Err(err) = store.delete(
                writer,
                Key::LockTotalCapacityIndex(lock_capacity, (*lock_hash).clone()).to_bytes(),
            ) {
                log::debug!(
                    "Delete LockTotalCapacityIndex({}, {}) error: {:?}",
                    lock_capacity,
                    lock_hash,
                    err
                );
            };
            if *delta > 0 {
                lock_capacity += *delta as u64;
            } else if *delta < 0 {
                lock_capacity -= delta.abs() as u64;
            }
            put_pair(
                store,
                writer,
                Key::pair_lock_total_capacity((*lock_hash).clone(), &lock_capacity),
            );
            put_pair(
                store,
                writer,
                Key::pair_lock_total_capacity_index((lock_capacity, (*lock_hash).clone())),
            );
        }
        // Update chain total capacity
        let mut chain_capacity: u128 = store
            .get(writer, Key::TotalCapacity.to_bytes())
            .unwrap()
            .map(|value| bincode::deserialize(value_to_bytes(&value)).unwrap())
            .unwrap_or(0);
        if capacity_delta != 0 {
            if capacity_delta > 0 {
                chain_capacity += capacity_delta as u128;
            } else if capacity_delta < 0 {
                chain_capacity -= capacity_delta.abs() as u128;
            }
            put_pair(store, writer, Key::pair_total_capacity(&chain_capacity));
        }
        result.chain_capacity = chain_capacity as u64;
        result.capacity_delta = capacity_delta;

        for lock in &self.locks {
            let lock_hash = lock.hash();
            put_pair(
                store,
                writer,
                Key::pair_global_hash(lock_hash.clone(), &HashType::Lock),
            );
            put_pair(
                store,
                writer,
                Key::pair_lock_script(lock_hash.clone(), lock),
            );
            if lock.code_hash == SECP_CODE_HASH {
                if lock.args.len() == 1 {
                    let lock_arg = &lock.args[0];
                    match Address::from_lock_arg(&lock_arg) {
                        Ok(address) => {
                            put_pair(store, writer, Key::pair_secp_addr_lock(address, &lock_hash));
                        }
                        Err(err) => {
                            log::info!("Invalid secp arg: {:?} => {}", lock_arg, err);
                        }
                    }
                } else {
                    log::info!("lock arg should given exact 1");
                }
            }
        }
        result
    }

    fn rollback(&self, _store: &rkv::SingleStore, _writer: &mut rkv::Writer) {
        // TODO: rollback when fork happened
        unimplemented!();
    }
}

struct ApplyResult {
    chain_capacity: u64,
    capacity_delta: i64,
    txs: usize,
    cell_removed: usize,
    cell_added: usize,
}

fn put_pair(store: &rkv::SingleStore, writer: &mut rkv::Writer, (key, value): (Vec<u8>, Vec<u8>)) {
    store.put(writer, key, &rkv::Value::Blob(&value)).unwrap();
}

fn value_to_bytes<'a>(value: &'a rkv::Value) -> &'a [u8] {
    match value {
        rkv::Value::Blob(inner) => inner,
        _ => panic!("Invalid value type: {:?}", value),
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct LiveCellInfo {
    pub out_point: CoreCellOutPoint,
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
                cell: Some(self.out_point.clone()),
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

    fn from_bytes(bytes: [u8; 8]) -> CellIndex {
        let mut tx_index_bytes = [0u8; 4];
        let mut output_index_bytes = [0u8; 4];
        tx_index_bytes.copy_from_slice(&bytes[..4]);
        output_index_bytes.copy_from_slice(&bytes[4..]);
        CellIndex {
            tx_index: u32::from_be_bytes(tx_index_bytes),
            output_index: u32::from_be_bytes(output_index_bytes),
        }
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
struct RichTxInfo {
    tx_hash: H256,
    // Transaction index in target block
    tx_index: u32,
    block_number: u64,
    block_timestamp: u64,
    inputs: Vec<LiveCellInfo>,
    outputs: Vec<LiveCellInfo>,
}

impl RichTxInfo {
    fn to_thin(&self) -> TxInfo {
        TxInfo {
            tx_hash: self.tx_hash.clone(),
            tx_index: self.tx_index,
            block_number: self.block_number,
            block_timestamp: self.block_timestamp,
            inputs: self
                .inputs
                .iter()
                .map(|info| info.out_point.clone())
                .collect::<Vec<_>>(),
            outputs: self
                .outputs
                .iter()
                .map(|info| info.out_point.clone())
                .collect::<Vec<_>>(),
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
struct TxInfo {
    tx_hash: H256,
    // Transaction index in target block
    tx_index: u32,
    block_number: u64,
    block_timestamp: u64,
    inputs: Vec<CoreCellOutPoint>,
    outputs: Vec<CoreCellOutPoint>,
}

pub struct LiveCellDatabase {
    env_arc: Arc<RwLock<rkv::Rkv>>,
    store: rkv::SingleStore,
    // TODO: add genesis hash
    network: NetworkType,
    last_header: CoreHeader,
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
            let genesis_hash_opt: Option<H256> = {
                let reader = env_read.read().expect("reader");
                store
                    .get(&reader, Key::GenesisHash.to_bytes())
                    .unwrap()
                    .map(|value| bincode::deserialize(value_to_bytes(&value)).unwrap())
            };
            if let Some(genesis_hash) = genesis_hash_opt {
                if genesis_hash != genesis_header.hash {
                    return Err(IndexError::InvalidGenesis(format!("{:#x}", genesis_hash)));
                }
            } else {
                log::info!("genesis not found, init db");
                let mut writer = env_read.write().unwrap();
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
            network,
            last_header,
            tip_header: genesis_header.clone(),
        })
    }

    pub fn apply_next_block(&mut self, block: &BlockView) -> Result<(usize, usize), IndexError> {
        if block.header.inner.number.0 != self.last_header().number() + 1 {
            return Err(IndexError::BlockTooEarly);
        }
        if &block.header.inner.parent_hash != self.last_header().hash() {
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
        out_point: CellOutPoint,
    ) -> Option<LiveCellInfo> {
        self.get(reader, &Key::LiveCellMap(out_point.into()).to_bytes())
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
            let out_point: CellOutPoint =
                bincode::deserialize(&value_bytes_opt.unwrap().to_bytes().unwrap()).unwrap();
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

    fn apply_block_unchecked(&mut self, block: &BlockView) -> (usize, usize) {
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
        (result.cell_removed, result.cell_added)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum IndexError {
    BlockImmature,
    BlockTooEarly,
    BlockInvalid,
    IoError(String),
    InvalidGenesis(String),
}

impl From<io::Error> for IndexError {
    fn from(err: io::Error) -> IndexError {
        IndexError::IoError(err.to_string())
    }
}
