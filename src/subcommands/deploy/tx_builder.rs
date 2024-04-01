use std::collections::HashMap;

use anyhow::{anyhow, Result};
use ckb_sdk::{
    constants::{MULTISIG_TYPE_HASH, SIGHASH_TYPE_HASH},
    traits::{
        CellCollector, CellQueryOptions, DefaultCellCollector, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider, OffchainTransactionDependencyProvider, Signer,
        SignerError, TransactionDependencyError, TransactionDependencyProvider, ValueRangeOption,
    },
    tx_builder::{balance_tx_capacity, fill_placeholder_witnesses, CapacityBalancer},
    unlock::{
        MultisigConfig, ScriptUnlocker, SecpMultisigScriptSigner, SecpMultisigUnlocker,
        SecpSighashUnlocker,
    },
    Address, CkbRpcClient, ScriptId,
};
use ckb_types::{
    bytes::Bytes,
    core::{HeaderView, TransactionBuilder, TransactionView},
    packed::{self, Byte32, CellOutput, OutPoint},
    prelude::*,
    H256,
};

use super::state_change::ChangeInfo;
use crate::utils::genesis_info::GenesisInfo;

// build balanced transaction
pub fn build_tx<T: ChangeInfo>(
    (from_address, fee_rate): (&Address, u64),
    multisig_config: Option<&MultisigConfig>,
    lock_script: &packed::Script,
    infos: &[T],
    pending_tx: Option<packed::Transaction>,
    genesis_info: &GenesisInfo,
    ckb_rpc: &str,
) -> Result<Option<packed::Transaction>> {
    let to_capacity: u64 = infos
        .iter()
        .filter(|info| info.has_new_output())
        .map(|info| info.occupied_capacity(lock_script))
        .sum();
    if to_capacity == 0 {
        return Ok(None);
    }

    let mut cell_collector = DefaultCellCollector::new(ckb_rpc);
    if let Some(pending_tx) = pending_tx.as_ref() {
        let ckb_client = CkbRpcClient::new(ckb_rpc);
        let tip_num = ckb_client.get_tip_block_number().unwrap().value();
        cell_collector.apply_tx(pending_tx.clone(), tip_num)?;
    }

    let from_script = packed::Script::from(from_address.payload());
    let (mut inputs, mut input_capacities): (Vec<_>, Vec<_>) =
        infos.iter().filter_map(|info| info.build_input()).unzip();
    if inputs.is_empty() {
        let mut query = CellQueryOptions::new_lock(from_script.clone());
        query.secondary_script_len_range = Some(ValueRangeOption::new_exact(0));
        query.data_len_range = Some(ValueRangeOption::new_exact(0));
        let (more_infos, more_capacity) = cell_collector.collect_live_cells(&query, true)?;
        if more_infos.is_empty() {
            return Err(anyhow!("No live cell found from address: {}", from_address));
        }
        inputs.push(packed::CellInput::new(more_infos[0].out_point.clone(), 0));
        input_capacities.push(more_capacity);
    }
    if inputs.is_empty() {
        return Err(anyhow!(
            "Capacity(mature) not enough from {}, require more than {}",
            from_address,
            to_capacity,
        ));
    }

    let first_cell_input = &inputs[0];
    let (outputs, outputs_data): (Vec<_>, Vec<_>) = infos
        .iter()
        .filter_map(|info| info.build_cell_output(lock_script, first_cell_input))
        .unzip();
    let mut cell_deps = vec![genesis_info.sighash_dep()];
    if multisig_config.is_some() {
        cell_deps.push(genesis_info.multisig_dep());
    }
    let mut unlockers = HashMap::new();
    let signer = DummySigner {
        args: vec![from_address.payload().args()],
    };
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer.clone()) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    unlockers.insert(
        sighash_script_id,
        Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
    );
    if let Some(cfg) = multisig_config {
        let multisig_signer = SecpMultisigScriptSigner::new(Box::new(signer), cfg.clone());
        let multisig_unlocker = SecpMultisigUnlocker::new(multisig_signer);
        let multisig_script_id = ScriptId::new_type(MULTISIG_TYPE_HASH.clone());
        unlockers.insert(
            multisig_script_id,
            Box::new(multisig_unlocker) as Box<dyn ScriptUnlocker>,
        );
    }

    let placeholder_witness = packed::WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer = CapacityBalancer::new_simple(from_script, placeholder_witness, fee_rate);

    let header_dep_resolver = DefaultHeaderDepResolver::new(ckb_rpc);
    let tx_dep_provider = {
        let inner = DefaultTransactionDependencyProvider::new(ckb_rpc, 0);
        let mut offchain = OffchainTransactionDependencyProvider::default();
        if let Some(pending_tx) = pending_tx {
            let tx_view = pending_tx.into_view();
            let tx_hash: H256 = tx_view.hash().unpack();
            offchain.txs.insert(tx_hash.clone(), tx_view.clone());
            for (output_idx, (output, output_data)) in tx_view.outputs_with_data_iter().enumerate()
            {
                offchain
                    .cells
                    .insert((tx_hash.clone(), output_idx as u32), (output, output_data));
            }
        }
        TxDepProviderWrapper { inner, offchain }
    };

    let base_tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.into_iter().map(|data| data.pack()))
        .build();

    let (tx_filled_witnesses, _) =
        fill_placeholder_witnesses(base_tx, &tx_dep_provider, &unlockers)?;
    let balanced_tx = balance_tx_capacity(
        &tx_filled_witnesses,
        &balancer,
        &mut cell_collector,
        &tx_dep_provider,
        &genesis_info.cell_dep_resolver,
        &header_dep_resolver,
    )?;
    Ok(Some(balanced_tx.data()))
}

#[derive(Clone)]
struct DummySigner {
    args: Vec<Bytes>,
}
impl Signer for DummySigner {
    fn match_id(&self, id: &[u8]) -> bool {
        self.args.iter().any(|arg| arg.as_ref() == id)
    }
    fn sign(&self, _: &[u8], _: &[u8], _: bool, _: &TransactionView) -> Result<Bytes, SignerError> {
        unreachable!()
    }
}

struct TxDepProviderWrapper {
    inner: DefaultTransactionDependencyProvider,
    offchain: OffchainTransactionDependencyProvider,
}

impl TransactionDependencyProvider for TxDepProviderWrapper {
    fn get_transaction(
        &self,
        tx_hash: &Byte32,
    ) -> Result<TransactionView, TransactionDependencyError> {
        self.offchain
            .get_transaction(tx_hash)
            .or_else(|_| self.inner.get_transaction(tx_hash))
    }
    fn get_cell(&self, out_point: &OutPoint) -> Result<CellOutput, TransactionDependencyError> {
        self.offchain
            .get_cell(out_point)
            .or_else(|_| self.inner.get_cell(out_point))
    }
    fn get_cell_data(&self, out_point: &OutPoint) -> Result<Bytes, TransactionDependencyError> {
        self.offchain
            .get_cell_data(out_point)
            .or_else(|_| self.inner.get_cell_data(out_point))
    }
    fn get_header(&self, block_hash: &Byte32) -> Result<HeaderView, TransactionDependencyError> {
        self.offchain
            .get_header(block_hash)
            .or_else(|_| self.inner.get_header(block_hash))
    }

    fn get_block_extension(
        &self,
        _block_hash: &Byte32,
    ) -> std::result::Result<Option<packed::Bytes>, TransactionDependencyError> {
        Err(TransactionDependencyError::NotFound(
            "get_block_extension not supported".to_string(),
        ))
    }
}
