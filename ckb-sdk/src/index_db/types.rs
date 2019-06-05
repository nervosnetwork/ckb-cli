use std::collections::HashMap;

use ckb_core::{
    header::Header as CoreHeader,
    script::Script as CoreScript,
    transaction::{
        CellInput as CoreCellInput, CellOutPoint as CoreCellOutPoint, OutPoint as CoreOutPoint,
    },
};
use jsonrpc_types::BlockView;
use numext_fixed_hash::H256;
use serde_derive::{Deserialize, Serialize};

use super::key::Key;
use super::util::{put_pair, value_to_bytes};
use crate::{Address, SECP_CODE_HASH};

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum HashType {
    Block,
    Transaction,
    Lock,
    Data,
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct BlockDeltaInfo {
    pub(crate) header: CoreHeader,
    txs: Vec<RichTxInfo>,
    locks: Vec<CoreScript>,
}

impl BlockDeltaInfo {
    pub(crate) fn from_view(
        block: &BlockView,
        store: &rkv::SingleStore,
        writer: &rkv::Writer,
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
                                writer,
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

    pub(crate) fn apply(&self, store: &rkv::SingleStore, writer: &mut rkv::Writer) -> ApplyResult {
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
            if lock_capacity > 0 {
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
            } else {
                store
                    .delete(
                        writer,
                        Key::LockTotalCapacity((*lock_hash).clone()).to_bytes(),
                    )
                    .unwrap();
            }
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

    pub(crate) fn rollback(&self, _store: &rkv::SingleStore, _writer: &mut rkv::Writer) {
        // TODO: rollback when fork happened
        unimplemented!();
    }
}

pub(crate) struct ApplyResult {
    pub chain_capacity: u64,
    pub capacity_delta: i64,
    pub txs: usize,
    pub cell_removed: usize,
    pub cell_added: usize,
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
    pub index: CellIndex,
}

impl LiveCellInfo {
    pub fn core_input(&self) -> CoreCellInput {
        CoreCellInput {
            previous_output: CoreOutPoint {
                cell: Some(self.out_point.clone()),
                block_hash: None,
            },
            since: 0,
        }
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
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
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
pub struct TxInfo {
    pub tx_hash: H256,
    // Transaction index in target block
    pub tx_index: u32,
    pub block_number: u64,
    pub block_timestamp: u64,
    pub inputs: Vec<CoreCellOutPoint>,
    pub outputs: Vec<CoreCellOutPoint>,
}
