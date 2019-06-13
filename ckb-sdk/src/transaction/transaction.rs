use std::collections::HashMap;
use std::sync::Arc;

use ckb_chain_spec::consensus::Consensus;
use ckb_core::extras::{BlockExt, EpochExt, TransactionAddress};
use ckb_core::{
    block::Block,
    cell::{
        resolve_transaction, BlockInfo, CellMeta, CellMetaBuilder, CellProvider, CellStatus,
        HeaderProvider, HeaderStatus,
    },
    header::Header,
    transaction::{
        CellOutPoint, CellOutput, OutPoint, ProposalShortId, Transaction, TransactionBuilder,
        Witness,
    },
    uncle::UncleBlock,
    BlockNumber, Cycle, EpochNumber,
};
use ckb_db::Error as CkbDbError;
use ckb_script::{ScriptConfig, TransactionScriptsVerifier};
use ckb_store::{ChainStore, StoreBatch};
use fnv::FnvHashSet;
use hash::blake2b_256;
use numext_fixed_hash::{H160, H256};
use rocksdb::{ColumnFamily, IteratorMode, Options, DB};

use super::{from_local_cell_out_point, CellManager};
use crate::{build_witness, HttpRpcClient, SecpKey, ROCKSDB_COL_TX, SECP_CODE_HASH};

pub struct TransactionManager<'a> {
    cf: ColumnFamily<'a>,
    db: &'a DB,
}

impl<'a> TransactionManager<'a> {
    pub fn new(db: &'a DB) -> TransactionManager {
        let cf = db.cf_handle(ROCKSDB_COL_TX).unwrap_or_else(|| {
            db.create_cf(ROCKSDB_COL_TX, &Options::default())
                .expect(&format!("Create ColumnFamily {} failed", ROCKSDB_COL_TX))
        });
        TransactionManager { cf, db }
    }

    pub fn add(&self, tx: &Transaction) -> Result<(), String> {
        if tx.inputs().len() != tx.witnesses().len() {
            return Err(format!(
                "Invalid witnesses length: {}, expected: {}",
                tx.witnesses().len(),
                tx.inputs().len(),
            ));
        }
        // TODO: check all deps can be found
        // TODO: check all inputs can be found
        // TODO: check all output can be found
        let key_bytes = tx.hash().to_vec();
        let value_bytes = bincode::serialize(tx).unwrap();
        self.db.put_cf(self.cf, key_bytes, value_bytes)?;
        Ok(())
    }

    pub fn set_witness(
        &self,
        hash: &H256,
        input_index: usize,
        witness: Witness,
    ) -> Result<Transaction, String> {
        let tx = self.get(hash)?;
        if input_index >= tx.inputs().len() {
            return Err(format!("input index out of bound"));
        }
        let mut witnesses = tx.witnesses().to_vec();
        witnesses[input_index] = witness;
        let tx_new = TransactionBuilder::from_transaction(tx)
            .witnesses(witnesses)
            .build();
        assert_eq!(
            hash,
            tx_new.hash(),
            "Transaction hash must not changed just update witness"
        );
        self.add(&tx_new)?;
        Ok(tx_new)
    }

    // TODO: set witnesses by given secp256k1 private keys
    pub fn set_witnesses_by_keys(
        &self,
        hash: &H256,
        keys: &[SecpKey],
        rpc_client: &mut HttpRpcClient,
    ) -> Result<Transaction, String> {
        let tx = self.get(hash)?;
        let tx_hash = tx.hash();
        let key_pairs = keys
            .iter()
            .filter_map(|key| key.privkey.as_ref())
            .map(|privkey| {
                let pubkey = privkey.pubkey().unwrap();
                let hash = H160::from_slice(&blake2b_256(pubkey.serialize())[0..20])
                    .expect("Generate hash(H160) from pubkey failed");
                (hash, privkey)
            })
            .collect::<HashMap<_, _>>();
        let mut witnesses = tx.witnesses().to_vec();
        let cell_manager = CellManager::new(self.db);
        for (idx, input) in tx.inputs().iter().enumerate() {
            let cell_out_point = input.previous_output.cell.as_ref().unwrap();
            let cell_output = from_local_cell_out_point(cell_out_point)
                .and_then(|name| cell_manager.get(&name))
                .or_else(|_| {
                    let out_point = OutPoint {
                        cell: Some(cell_out_point.clone()),
                        block_hash: None,
                    };
                    rpc_client
                        .get_live_cell(out_point.into())
                        .call()
                        .unwrap()
                        .cell
                        .map(Into::into)
                        .ok_or_else(|| format!("Input not found or dead"))
                })?;

            let lock = cell_output.lock;
            if lock.code_hash == SECP_CODE_HASH {
                if let Some(privkey) = lock
                    .args
                    .get(0)
                    .and_then(|bytes| H160::from_slice(bytes).ok())
                    .and_then(|hash| key_pairs.get(&hash))
                {
                    witnesses[idx] = build_witness(privkey, tx_hash);
                } else {
                    log::warn!("Can not find key for secp arg: {:?}", lock.args.get(0));
                }
            } else {
                log::info!("Input with a non-secp lock: code_hash={}", lock.code_hash);
            }
        }
        Ok(tx)
    }

    pub fn remove(&self, hash: &H256) -> Result<(), String> {
        if self.db.get_cf(self.cf, hash.as_bytes())?.is_some() {
            self.db.delete_cf(self.cf, hash.as_bytes())?;
            Ok(())
        } else {
            Err("key not exists".to_owned())
        }
    }

    pub fn get(&self, hash: &H256) -> Result<Transaction, String> {
        match self.db.get_cf(self.cf, hash.as_bytes())? {
            Some(db_vec) => Ok(bincode::deserialize(&db_vec).unwrap()),
            None => Err("key not found".to_owned()),
        }
    }

    pub fn list(&self) -> Result<Vec<Transaction>, String> {
        let mut txs = Vec::new();
        for (key_bytes, value_bytes) in self.db.iterator_cf(self.cf, IteratorMode::Start)? {
            let key = H256::from_slice(&key_bytes).unwrap();
            let tx: Transaction = bincode::deserialize(&value_bytes).unwrap();
            assert_eq!(
                &key,
                tx.hash(),
                "Transaction hash not match the transaction"
            );
            txs.push(tx);
        }
        Ok(txs)
    }

    pub fn verify(
        &self,
        hash: &H256,
        max_cycle: Cycle,
        rpc_client: &mut HttpRpcClient,
    ) -> Result<VerifyResult, String> {
        let tx = self.get(hash)?;
        let cell_manager = CellManager::new(self.db);
        let resource = Resource::from_both(&tx, &cell_manager, rpc_client)?;
        let rtx = {
            let mut seen_inputs = FnvHashSet::default();
            resolve_transaction(&tx, &mut seen_inputs, &resource, &resource)
                .map_err(|err| format!("Resolve transaction error: {:?}", err))?
        };

        let script_config = ScriptConfig::default();
        let store = Arc::new(resource);
        let verifier = TransactionScriptsVerifier::new(&rtx, store, &script_config);
        let cycle = verifier
            .verify(max_cycle)
            .map_err(|err| format!("Verify script error: {:?}", err))?;
        Ok(VerifyResult { cycle })
    }
}

pub struct VerifyResult {
    pub cycle: Cycle,
    // debug_logs: Vec<String>,
}

struct Resource {
    out_point_blocks: HashMap<CellOutPoint, H256>,
    required_cells: HashMap<CellOutPoint, CellMeta>,
    required_headers: HashMap<H256, Header>,
}

impl Resource {
    fn from_both(
        tx: &Transaction,
        cell_manager: &CellManager,
        rpc_client: &mut HttpRpcClient,
    ) -> Result<Resource, String> {
        let mut out_point_blocks = HashMap::default();
        let mut required_headers = HashMap::default();
        let mut required_cells = HashMap::default();
        for out_point in tx
            .deps()
            .iter()
            .chain(tx.inputs().iter().map(|input| &input.previous_output))
        {
            let cell_out_point = out_point.cell.clone().unwrap();
            let mut block_info = None;
            if let Some(ref hash) = out_point.block_hash {
                let block_view = rpc_client
                    .get_block(hash.clone())
                    .call()
                    .unwrap()
                    .0
                    .unwrap();
                let header: Header = block_view.header.inner.into();
                block_info = Some(BlockInfo {
                    number: header.number(),
                    epoch: header.epoch(),
                });
                required_headers.insert(hash.clone(), header);
                out_point_blocks.insert(cell_out_point.clone(), hash.clone());
            }

            match cell_manager.get_by_cell_out_point(&cell_out_point) {
                Ok(cell_output) => {
                    let cell_meta =
                        cell_output_to_meta(cell_out_point.clone(), cell_output, block_info);
                    required_cells.insert(cell_out_point, cell_meta);
                }
                Err(_) => {
                    // TODO: we should cache genesis block here
                    let cell_output = rpc_client
                        .get_live_cell(out_point.clone().into())
                        .call()
                        .unwrap()
                        .cell
                        .unwrap()
                        .into();
                    let cell_meta =
                        cell_output_to_meta(cell_out_point.clone(), cell_output, block_info);
                    required_cells.insert(cell_out_point, cell_meta);
                }
            }
        }
        Ok(Resource {
            out_point_blocks,
            required_cells,
            required_headers,
        })
    }
}

fn cell_output_to_meta(
    cell_out_point: CellOutPoint,
    cell_output: CellOutput,
    block_info: Option<BlockInfo>,
) -> CellMeta {
    let data_hash = cell_output.data_hash();
    let mut cell_meta_builder = CellMetaBuilder::from_cell_output(cell_output)
        .out_point(cell_out_point.clone())
        .data_hash(data_hash);
    if let Some(block_info) = block_info {
        cell_meta_builder = cell_meta_builder.block_info(block_info);
    }
    cell_meta_builder.build()
}

impl<'a> HeaderProvider for Resource {
    fn header(&self, out_point: &OutPoint) -> HeaderStatus {
        out_point
            .block_hash
            .as_ref()
            .map(|block_hash| {
                if let Some(block_hash) = out_point.block_hash.as_ref() {
                    let cell_out_point = out_point.cell.as_ref().unwrap();
                    if let Some(saved_block_hash) = self.out_point_blocks.get(cell_out_point) {
                        if block_hash != saved_block_hash {
                            return HeaderStatus::InclusionFaliure;
                        }
                    }
                }
                self.required_headers
                    .get(block_hash)
                    .cloned()
                    .map(|header| {
                        // TODO: query index db ensure cell_out_point match the block_hash
                        HeaderStatus::live_header(header)
                    })
                    .unwrap_or(HeaderStatus::Unknown)
            })
            .unwrap_or(HeaderStatus::Unspecified)
    }
}

impl CellProvider for Resource {
    fn cell(&self, out_point: &OutPoint) -> CellStatus {
        self.required_cells
            .get(out_point.cell.as_ref().unwrap())
            .cloned()
            .map(|cell_meta| CellStatus::live_cell(cell_meta))
            .unwrap_or(CellStatus::Unknown)
    }
}

struct DummyStoreBatch;

impl StoreBatch for DummyStoreBatch {
    fn insert_block(&mut self, _block: &Block) -> Result<(), CkbDbError> {
        unimplemented!();
    }
    fn insert_block_ext(&mut self, _block_hash: &H256, _ext: &BlockExt) -> Result<(), CkbDbError> {
        unimplemented!();
    }
    fn insert_tip_header(&mut self, _header: &Header) -> Result<(), CkbDbError> {
        unimplemented!();
    }
    fn insert_current_epoch_ext(&mut self, _epoch: &EpochExt) -> Result<(), CkbDbError> {
        unimplemented!();
    }
    fn insert_block_epoch_index(
        &mut self,
        _block_hash: &H256,
        _epoch_hash: &H256,
    ) -> Result<(), CkbDbError> {
        unimplemented!();
    }
    fn insert_epoch_ext(&mut self, _hash: &H256, _epoch: &EpochExt) -> Result<(), CkbDbError> {
        unimplemented!();
    }

    fn attach_block(&mut self, _block: &Block) -> Result<(), CkbDbError> {
        unimplemented!();
    }
    fn detach_block(&mut self, _block: &Block) -> Result<(), CkbDbError> {
        unimplemented!();
    }

    fn commit(self) -> Result<(), CkbDbError> {
        unimplemented!();
    }
}

impl ChainStore for Resource {
    /// Batch handle
    type Batch = DummyStoreBatch;
    /// New a store batch handle
    fn new_batch(&self) -> Result<Self::Batch, CkbDbError> {
        unimplemented!();
    }

    /// Get block by block header hash
    fn get_block(&self, _block_hash: &H256) -> Option<Block> {
        unimplemented!();
    }
    /// Get header by block header hash
    fn get_header(&self, _block_hash: &H256) -> Option<Header> {
        unimplemented!();
    }
    /// Get block body by block header hash
    fn get_block_body(&self, _block_hash: &H256) -> Option<Vec<Transaction>> {
        unimplemented!();
    }
    /// Get proposal short id by block header hash
    fn get_block_proposal_txs_ids(&self, _h: &H256) -> Option<Vec<ProposalShortId>> {
        unimplemented!();
    }
    /// Get block uncles by block header hash
    fn get_block_uncles(&self, _block_hash: &H256) -> Option<Vec<UncleBlock>> {
        unimplemented!();
    }
    /// Get block ext by block header hash
    fn get_block_ext(&self, _block_hash: &H256) -> Option<BlockExt> {
        unimplemented!();
    }

    fn init(&self, _consensus: &Consensus) -> Result<(), CkbDbError> {
        unimplemented!();
    }
    /// Get block header hash by block number
    fn get_block_hash(&self, _number: BlockNumber) -> Option<H256> {
        unimplemented!();
    }
    /// Get block number by block header hash
    fn get_block_number(&self, _hash: &H256) -> Option<BlockNumber> {
        unimplemented!();
    }
    /// Get the tip(highest) header
    fn get_tip_header(&self) -> Option<Header> {
        unimplemented!();
    }
    /// Get commit transaction and block hash by it's hash
    fn get_transaction(&self, _h: &H256) -> Option<(Transaction, H256)> {
        unimplemented!();
    }
    fn get_transaction_address(&self, _hash: &H256) -> Option<TransactionAddress> {
        unimplemented!();
    }
    fn get_cell_meta(&self, tx_hash: &H256, index: u32) -> Option<CellMeta> {
        let cell_out_point = CellOutPoint {
            tx_hash: tx_hash.clone(),
            index,
        };
        self.required_cells.get(&cell_out_point).cloned()
    }
    fn get_cell_output(&self, tx_hash: &H256, index: u32) -> Option<CellOutput> {
        let cell_out_point = CellOutPoint {
            tx_hash: tx_hash.clone(),
            index,
        };
        self.required_cells
            .get(&cell_out_point)
            .and_then(|cell_meta| cell_meta.cell_output.clone())
    }
    // Get current epoch ext
    fn get_current_epoch_ext(&self) -> Option<EpochExt> {
        unimplemented!();
    }
    // Get epoch ext by epoch index
    fn get_epoch_ext(&self, _hash: &H256) -> Option<EpochExt> {
        unimplemented!();
    }
    // Get epoch index by epoch number
    fn get_epoch_index(&self, _number: EpochNumber) -> Option<H256> {
        unimplemented!();
    }
    // Get epoch index by block hash
    fn get_block_epoch_index(&self, _h256: &H256) -> Option<H256> {
        unimplemented!();
    }
}
