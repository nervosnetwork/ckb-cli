use std::collections::{HashMap, HashSet};

use ckb_types::{
    bytes::Bytes,
    core::{BlockView, Capacity, HeaderView},
    packed::{Byte32, CellInput, Header, OutPoint, Script},
    prelude::*,
    H256,
};
use serde_derive::{Deserialize, Serialize};

use super::key::{Key, KeyType};
use crate::{KVReader, KVTxn};

pub const KEEP_RECENT_HEADERS: u64 = 10_000;
pub const KEEP_RECENT_BLOCKS: u64 = 200;

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum HashType {
    Block = 0,
    Transaction = 1,
    Lock = 2,
    Data = 3,
}

// impl HashType {
//     pub(crate) fn from_u8(v: u8) -> Option<HashType> {
//         match v {
//             0 => Some(HashType::Block),
//             1 => Some(HashType::Transaction),
//             2 => Some(HashType::Lock),
//             3 => Some(HashType::Data),
//             _ => None,
//         }
//     }
// }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockDeltaInfo {
    pub(crate) header_info: HeaderInfo,
    pub(crate) parent_header: Option<Bytes>,
    txs: Vec<RichTxInfo>,
    locks: Vec<(H256, LockInfo)>,
    old_headers: Vec<u64>,
    old_blocks: Vec<u64>,
    old_chain_capacity: u128,
    new_chain_capacity: u128,
}

impl BlockDeltaInfo {
    pub(crate) fn hash(&self) -> Byte32 {
        self.header_info.header().hash()
    }
    pub(crate) fn number(&self) -> u64 {
        self.header_info.header().number()
    }
    pub(crate) fn parent_header(&self) -> Option<HeaderView> {
        self.parent_header
            .as_ref()
            .map(|bytes| Header::new_unchecked(bytes.clone()).into_view())
    }

    pub(crate) fn from_block<'r, T: KVReader<'r>>(
        block: &BlockView,
        reader: &'r T,
        clear_old: bool,
    ) -> BlockDeltaInfo {
        let block_header: HeaderView = block.header();
        let block_number = block_header.number();
        let timestamp = block_header.timestamp();

        // Collect old headers to be deleted
        let mut old_headers = Vec::new();
        let mut old_blocks = Vec::new();
        if clear_old {
            for (key_bytes, _) in reader.iter_from(&KeyType::RecentHeader.to_bytes()) {
                if let Key::RecentHeader(number) = Key::from_bytes(&key_bytes) {
                    if number + KEEP_RECENT_HEADERS <= block_number {
                        old_headers.push(number);
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            for (key_bytes, _) in reader.iter_from(&KeyType::BlockDelta.to_bytes()) {
                if let Key::BlockDelta(number) = Key::from_bytes(&key_bytes) {
                    if number + KEEP_RECENT_BLOCKS <= block_number {
                        old_blocks.push(number);
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
        log::info!(
            "old_headers: {:?}, old_blocks: {:?}",
            old_headers,
            old_blocks
        );

        let mut cell_removed = 0;
        let mut cell_added = 0;
        let mut locks: HashMap<H256, LockInfo> = HashMap::default();
        let mut live_cell_infos: HashMap<OutPoint, LiveCellInfo> = HashMap::default();
        let txs = block
            .transactions()
            .iter()
            .enumerate()
            .map(|(tx_index, tx)| {
                let mut inputs = Vec::new();
                let mut outputs = Vec::new();

                for out_point in tx
                    .inputs()
                    .into_iter()
                    .map(|input| input.previous_output())
                    .filter(|input| !input.is_null())
                {
                    let live_cell_info: LiveCellInfo =
                        live_cell_infos.get(&out_point).cloned().unwrap_or_else(|| {
                            reader
                                .get(&Key::LiveCellMap(out_point.clone()).to_bytes())
                                .map(|bytes| bincode::deserialize(&bytes).unwrap())
                                .unwrap()
                        });
                    let lock_hash = live_cell_info.lock_hash.clone();
                    let capacity = live_cell_info.capacity;
                    inputs.push(live_cell_info);

                    locks
                        .entry(lock_hash.clone())
                        .or_insert_with(move || {
                            let lock_capacity: u64 = reader
                                .get(&Key::LockTotalCapacity(lock_hash).to_bytes())
                                .map(|bytes| {
                                    let mut data = [0u8; 8];
                                    data.copy_from_slice(&bytes[..8]);
                                    u64::from_le_bytes(data)
                                })
                                .unwrap_or(0);
                            LockInfo::new(lock_capacity)
                        })
                        .add_input(capacity);
                }

                for (output_index, (output, data)) in tx
                    .outputs()
                    .into_iter()
                    .zip(tx.outputs_data().into_iter())
                    .enumerate()
                {
                    let lock: Script = output.lock().clone();
                    let lock_hash = lock.calc_script_hash();
                    let capacity: Capacity = output.capacity().unpack();
                    let capacity = capacity.as_u64();
                    let cell_index = CellIndex::new(tx_index as u32, output_index as u32);

                    let type_hashes = output.type_().to_opt().map(|type_script| {
                        (
                            type_script.code_hash().unpack(),
                            type_script.calc_script_hash().unpack(),
                        )
                    });

                    let live_cell_info = LiveCellInfo {
                        tx_hash: tx.hash().unpack(),
                        output_index: output_index as u32,
                        data_bytes: data.raw_data().len() as u64,
                        index: cell_index,
                        lock_hash: lock_hash.unpack(),
                        type_hashes,
                        capacity,
                        number: block_number,
                    };
                    let out_point = OutPoint::new(tx.hash(), output_index as u32);
                    live_cell_infos.insert(out_point, live_cell_info.clone());
                    // FIXME: The live cell may spend in the same block
                    outputs.push(live_cell_info);

                    let lock_info = locks.entry(lock_hash.unpack()).or_insert_with(|| {
                        let lock_capacity: u64 = reader
                            .get(&Key::LockTotalCapacity(lock_hash.unpack()).to_bytes())
                            .map(|bytes| {
                                let mut data = [0u8; 8];
                                data.copy_from_slice(&bytes[..8]);
                                u64::from_le_bytes(data)
                            })
                            .unwrap_or(0);
                        LockInfo::new(lock_capacity)
                    });
                    lock_info.set_script(lock.clone());
                    lock_info.add_output(capacity);
                }

                cell_removed += inputs.len();
                cell_added += outputs.len();
                RichTxInfo {
                    tx_hash: tx.hash().unpack(),
                    tx_index: tx_index as u32,
                    block_number,
                    block_timestamp: timestamp,
                    inputs,
                    outputs,
                }
            })
            .collect::<Vec<_>>();

        let locks_old_total: u64 = locks.values().map(|info| info.old_total_capacity).sum();
        let locks_new_total: u64 = locks.values().map(|info| info.new_total_capacity).sum();
        let old_chain_capacity: u128 = reader
            .get(&Key::TotalCapacity.to_bytes())
            .map(|bytes| {
                let mut data = [0u8; 16];
                data.copy_from_slice(&bytes[..16]);
                u128::from_le_bytes(data)
            })
            .unwrap_or(0);
        let new_chain_capacity: u128 =
            old_chain_capacity - u128::from(locks_old_total) + u128::from(locks_new_total);

        let capacity_delta = (new_chain_capacity as i128 - old_chain_capacity as i128) as i64;
        let header_info = HeaderInfo {
            header: block_header.data().as_slice().to_vec().into(),
            txs_size: block.transactions().len() as u32,
            uncles_size: block.uncle_hashes().len() as u32,
            proposals_size: block.union_proposal_ids().len() as u32,
            new_chain_capacity,
            capacity_delta,
            cell_removed: cell_removed as u32,
            cell_added: cell_added as u32,
        };

        let parent_header = if block_number > 0 {
            Some(
                reader
                    .get(&Key::RecentHeader(block_number - 1).to_bytes())
                    .map(|bytes| {
                        let info: HeaderInfo = bincode::deserialize(&bytes).unwrap();
                        info.header
                    })
                    .expect("Rollback so many blocks???"),
            )
        } else {
            None
        };
        BlockDeltaInfo {
            header_info,
            parent_header,
            txs,
            locks: locks.into_iter().collect::<Vec<_>>(),
            old_headers,
            old_blocks,
            old_chain_capacity,
            new_chain_capacity,
        }
    }

    pub(crate) fn apply<'r, T: KVTxn<'r>>(
        &self,
        txn: &mut T,
        enable_explorer: bool,
    ) -> ApplyResult {
        let header = Header::new_unchecked(self.header_info.header.clone()).into_view();
        let current_number: u64 = header.number();
        log::debug!(
            "apply block: number={}, txs={}, locks={}",
            current_number,
            self.txs.len(),
            self.locks.len(),
        );

        // Update cells and transactions
        for tx in &self.txs {
            if enable_explorer {
                txn.put_pair(Key::pair_tx_map(tx.tx_hash.clone(), &tx.to_thin()));
            }

            for LiveCellInfo {
                tx_hash,
                output_index,
                lock_hash,
                type_hashes,
                number,
                index,
                ..
            } in &tx.inputs
            {
                let out_point = OutPoint::new(tx_hash.pack(), *output_index);
                if enable_explorer {
                    txn.put_pair(Key::pair_lock_tx(
                        (lock_hash.clone(), *number, index.tx_index),
                        &tx.tx_hash,
                    ));
                }
                txn.remove(Key::LiveCellMap(out_point.clone()).to_bytes());
                txn.remove(Key::LiveCellIndex(*number, *index).to_bytes());
                txn.remove(Key::LockLiveCellIndex(lock_hash.clone(), *number, *index).to_bytes());
                if let Some((code_hash, script_hash)) = type_hashes {
                    txn.remove(
                        Key::CodeLiveCellIndex(code_hash.clone(), *number, *index).to_bytes(),
                    );
                    txn.remove(
                        Key::TypeLiveCellIndex(script_hash.clone(), *number, *index).to_bytes(),
                    );
                }
            }

            for live_cell_info in &tx.outputs {
                let LiveCellInfo {
                    tx_hash,
                    output_index,
                    lock_hash,
                    type_hashes,
                    number,
                    index,
                    ..
                } = live_cell_info;
                let out_point = OutPoint::new(tx_hash.pack(), *output_index);
                if enable_explorer {
                    txn.put_pair(Key::pair_lock_tx(
                        (lock_hash.clone(), *number, index.tx_index),
                        &tx.tx_hash,
                    ));
                }
                txn.put_pair(Key::pair_live_cell_map(out_point.clone(), live_cell_info));
                txn.put_pair(Key::pair_live_cell_index((*number, *index), &out_point));
                txn.put_pair(Key::pair_lock_live_cell_index(
                    (lock_hash.clone(), *number, *index),
                    &out_point,
                ));
                if let Some((code_hash, script_hash)) = type_hashes {
                    txn.put_pair(Key::pair_code_live_cell_index(
                        (code_hash.clone(), *number, *index),
                        &out_point,
                    ));
                    txn.put_pair(Key::pair_type_live_cell_index(
                        (script_hash.clone(), *number, *index),
                        &out_point,
                    ));
                }
            }
        }

        for (lock_hash, info) in &self.locks {
            let LockInfo {
                script_opt,
                old_total_capacity,
                new_total_capacity,
                ..
            } = info;
            if enable_explorer {
                txn.put_pair(Key::pair_global_hash(lock_hash.clone(), HashType::Lock));
            }
            if let Some(script) = script_opt {
                txn.put_pair(Key::pair_lock_script(
                    lock_hash.clone(),
                    &Script::new_unchecked(script.clone()),
                ));
            }

            if old_total_capacity != new_total_capacity {
                log::debug!(
                    "[total capacity]: lock_hash={:x}, old(remove)={}, new={}",
                    lock_hash,
                    old_total_capacity,
                    new_total_capacity
                );
                // Update lock capacity keys
                txn.remove_ok(
                    Key::LockTotalCapacityIndex(*old_total_capacity, (*lock_hash).clone())
                        .to_bytes(),
                );

                if *new_total_capacity > 0 {
                    txn.put_pair(Key::pair_lock_total_capacity(
                        (*lock_hash).clone(),
                        *new_total_capacity,
                    ));
                    log::debug!(
                        "[total capacity]: lock_hash={:x}, add new={}",
                        lock_hash,
                        new_total_capacity
                    );
                    txn.put_pair(Key::pair_lock_total_capacity_index((
                        *new_total_capacity,
                        (*lock_hash).clone(),
                    )));
                } else {
                    txn.remove(Key::LockTotalCapacity((*lock_hash).clone()).to_bytes());
                }
            }
        }

        // Update total capacity
        txn.put_pair(Key::pair_total_capacity(&self.new_chain_capacity));

        // Add recent header
        txn.put_pair(Key::pair_recent_header(&self.header_info));
        txn.put_pair(Key::pair_block_delta(&self));
        // Clean old header infos
        for old_number in &self.old_headers {
            txn.remove(Key::RecentHeader(*old_number).to_bytes());
        }
        for old_number in &self.old_blocks {
            txn.remove(Key::BlockDelta(*old_number).to_bytes());
        }
        // Update last header
        txn.put_pair(Key::pair_last_header(&Header::new_unchecked(
            self.header_info.header.clone(),
        )));

        self.header_info.clone().into()
    }

    pub(crate) fn rollback<'r, T: KVTxn<'r>>(&self, txn: &mut T) {
        log::debug!("rollback block: {:?}", self);

        let mut delete_lock_txs: HashSet<(H256, u64, u32)> = HashSet::default();
        for tx in &self.txs {
            txn.remove_ok(Key::TxMap(tx.tx_hash.clone()).to_bytes());
            for live_cell_info in &tx.inputs {
                let LiveCellInfo {
                    tx_hash,
                    output_index,
                    lock_hash,
                    type_hashes,
                    number,
                    index,
                    ..
                } = live_cell_info;
                let out_point = OutPoint::new(tx_hash.pack(), *output_index);
                delete_lock_txs.insert((lock_hash.clone(), *number, index.tx_index));
                txn.put_pair(Key::pair_live_cell_map(out_point.clone(), live_cell_info));
                txn.put_pair(Key::pair_live_cell_index((*number, *index), &out_point));
                txn.put_pair(Key::pair_lock_live_cell_index(
                    (lock_hash.clone(), *number, *index),
                    &out_point,
                ));
                if let Some((code_hash, script_hash)) = type_hashes {
                    txn.put_pair(Key::pair_code_live_cell_index(
                        (code_hash.clone(), *number, *index),
                        &out_point,
                    ));
                    txn.put_pair(Key::pair_type_live_cell_index(
                        (script_hash.clone(), *number, *index),
                        &out_point,
                    ));
                }
            }

            for live_cell_info in &tx.outputs {
                let LiveCellInfo {
                    tx_hash,
                    output_index,
                    lock_hash,
                    type_hashes,
                    number,
                    index,
                    ..
                } = live_cell_info;
                let out_point = OutPoint::new(tx_hash.pack(), *output_index);
                delete_lock_txs.insert((lock_hash.clone(), *number, index.tx_index));
                txn.remove(Key::LiveCellMap(out_point.clone()).to_bytes());
                txn.remove(Key::LiveCellIndex(*number, *index).to_bytes());
                txn.remove(Key::LockLiveCellIndex(lock_hash.clone(), *number, *index).to_bytes());
                if let Some((code_hash, script_hash)) = type_hashes {
                    txn.remove(
                        Key::CodeLiveCellIndex(code_hash.clone(), *number, *index).to_bytes(),
                    );
                    txn.remove(
                        Key::TypeLiveCellIndex(script_hash.clone(), *number, *index).to_bytes(),
                    );
                }
            }
        }
        for (lock_hash, number, tx_index) in delete_lock_txs {
            txn.remove_ok(Key::LockTx(lock_hash, number, tx_index).to_bytes());
        }

        for (lock_hash, info) in &self.locks {
            let LockInfo {
                old_total_capacity,
                new_total_capacity,
                ..
            } = info;

            if old_total_capacity != new_total_capacity {
                log::debug!(
                    "[rollback: total capacity]: lock_hash={:x}, old={}, new(remove)={}",
                    lock_hash,
                    old_total_capacity,
                    new_total_capacity
                );
                // Update lock capacity keys
                txn.remove_ok(
                    Key::LockTotalCapacityIndex(*new_total_capacity, (*lock_hash).clone())
                        .to_bytes(),
                );

                if *old_total_capacity > 0 {
                    txn.put_pair(Key::pair_lock_total_capacity(
                        (*lock_hash).clone(),
                        *old_total_capacity,
                    ));
                    log::debug!(
                        "[rollback: total capacity]: lock_hash={:x}, add old={}",
                        lock_hash,
                        old_total_capacity
                    );
                    txn.put_pair(Key::pair_lock_total_capacity_index((
                        *old_total_capacity,
                        (*lock_hash).clone(),
                    )));
                } else {
                    txn.remove(Key::LockTotalCapacity((*lock_hash).clone()).to_bytes());
                }
            }
        }
        // Rollback total capacity
        txn.put_pair(Key::pair_total_capacity(&self.old_chain_capacity));
        // Remove recent header
        txn.remove(Key::RecentHeader(self.number()).to_bytes());
        // Remove recent block
        txn.remove(Key::BlockDelta(self.number()).to_bytes());
        // Update last header
        txn.put_pair(Key::pair_last_header(&Header::new_unchecked(
            self.parent_header.clone().unwrap(),
        )));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockInfo {
    script_opt: Option<Bytes>,
    old_total_capacity: u64,
    new_total_capacity: u64,
    inputs_capacity: u64,
    outputs_capacity: u64,
}

impl LockInfo {
    fn new(old_total_capacity: u64) -> LockInfo {
        LockInfo {
            script_opt: None,
            old_total_capacity,
            new_total_capacity: old_total_capacity,
            inputs_capacity: 0,
            outputs_capacity: 0,
        }
    }

    fn set_script(&mut self, script: Script) {
        self.script_opt = Some(script.as_slice().to_vec().into());
    }

    fn add_input(&mut self, input_capacity: u64) {
        self.inputs_capacity += input_capacity;
        assert!(self.new_total_capacity >= input_capacity);
        self.new_total_capacity -= input_capacity;
    }

    fn add_output(&mut self, output_capacity: u64) {
        self.outputs_capacity += output_capacity;
        self.new_total_capacity += output_capacity;
    }
}

pub(crate) struct ApplyResult {
    pub chain_capacity: u128,
    pub capacity_delta: i64,
    pub cell_removed: u32,
    pub cell_added: u32,
    pub txs: u32,
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct LiveCellInfo {
    pub tx_hash: H256,
    pub output_index: u32,
    pub data_bytes: u64,
    pub lock_hash: H256,
    // Type script's code_hash and script_hash
    pub type_hashes: Option<(H256, H256)>,
    // Capacity
    pub capacity: u64,
    // Block number
    pub number: u64,
    // Location in the block
    pub index: CellIndex,
}

impl LiveCellInfo {
    pub fn out_point(&self) -> OutPoint {
        OutPoint::new(self.tx_hash.pack(), self.output_index)
    }
    pub fn input(&self) -> CellInput {
        CellInput::new(self.out_point(), 0)
    }
}

// LiveCell index in a block
#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub struct CellIndex {
    // The transaction index in the block
    pub tx_index: u32,
    // The output index in the transaction
    pub output_index: u32,
}

impl CellIndex {
    pub(crate) fn to_bytes(self) -> Vec<u8> {
        let mut bytes = self.tx_index.to_be_bytes().to_vec();
        bytes.extend(self.output_index.to_be_bytes().to_vec());
        bytes
    }

    pub(crate) fn from_bytes(bytes: [u8; 8]) -> CellIndex {
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

impl CellIndex {
    pub(crate) fn new(tx_index: u32, output_index: u32) -> CellIndex {
        CellIndex {
            tx_index,
            output_index,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct HeaderInfo {
    pub header: Bytes,
    pub txs_size: u32,
    pub uncles_size: u32,
    pub proposals_size: u32,
    pub new_chain_capacity: u128,
    pub capacity_delta: i64,
    pub cell_removed: u32,
    pub cell_added: u32,
}

impl HeaderInfo {
    pub fn header(&self) -> HeaderView {
        Header::new_unchecked(self.header.clone()).into_view()
    }
}

impl From<HeaderInfo> for ApplyResult {
    fn from(info: HeaderInfo) -> ApplyResult {
        ApplyResult {
            chain_capacity: info.new_chain_capacity,
            capacity_delta: info.capacity_delta,
            txs: info.txs_size,
            cell_removed: info.cell_removed,
            cell_added: info.cell_added,
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub(crate) struct RichTxInfo {
    tx_hash: H256,
    // Transaction index in target block
    tx_index: u32,
    block_number: u64,
    block_timestamp: u64,
    inputs: Vec<LiveCellInfo>,
    outputs: Vec<LiveCellInfo>,
}

impl RichTxInfo {
    pub(crate) fn to_thin(&self) -> TxInfo {
        TxInfo {
            tx_hash: self.tx_hash.clone(),
            tx_index: self.tx_index,
            block_number: self.block_number,
            block_timestamp: self.block_timestamp,
            inputs: self
                .inputs
                .iter()
                .map(|info| info.out_point().as_slice().to_vec().into())
                .collect::<Vec<_>>(),
            outputs: self
                .outputs
                .iter()
                .map(|info| info.out_point().as_slice().to_vec().into())
                .collect::<Vec<_>>(),
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct TxInfo {
    pub tx_hash: H256,
    // Transaction index in target block
    pub tx_index: u32,
    pub block_number: u64,
    pub block_timestamp: u64,
    pub inputs: Vec<Bytes>,
    pub outputs: Vec<Bytes>,
}

impl TxInfo {
    pub fn inputs(&self) -> Vec<OutPoint> {
        self.inputs
            .iter()
            .map(|data| OutPoint::new_unchecked(data.clone()))
            .collect::<Vec<_>>()
    }
    pub fn outputs(&self) -> Vec<OutPoint> {
        self.inputs
            .iter()
            .map(|data| OutPoint::new_unchecked(data.clone()))
            .collect::<Vec<_>>()
    }
}
