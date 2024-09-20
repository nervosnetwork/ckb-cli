use std::convert::TryInto;

use ckb_jsonrpc_types::{
    Alert, BlockNumber, CellWithStatus, EpochNumber, EpochNumberWithFraction, JsonBytes,
    OutputsValidator, Uint32,
};
pub use ckb_sdk::{
    rpc::ckb_indexer::{Order, Pagination, SearchKey},
    CkbRpcClient as RawHttpRpcClient,
};
use ckb_types::{packed, H256};

use super::primitive;
use super::types;

pub struct HttpRpcClient {
    url: String,
    client: RawHttpRpcClient,
}

impl HttpRpcClient {
    pub fn new(url: String) -> HttpRpcClient {
        let client = RawHttpRpcClient::new(url.as_str());
        HttpRpcClient { url, client }
    }

    pub fn url(&self) -> &str {
        self.url.as_str()
    }
    pub fn client(&mut self) -> &mut RawHttpRpcClient {
        &mut self.client
    }
}

impl HttpRpcClient {
    // Chain
    pub fn get_packed_block(&mut self, hash: H256) -> Result<Option<types::JsonBytes>, String> {
        self.client
            .get_packed_block(hash)
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_block(&mut self, hash: H256) -> Result<Option<types::BlockView>, String> {
        self.client
            .get_block(hash)
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_packed_block_with_cycles(
        &mut self,
        hash: H256,
    ) -> Result<Option<types::PackedBlockResponse>, String> {
        self.client
            .get_packed_block_with_cycles(hash)
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_block_with_cycles(
        &mut self,
        hash: H256,
    ) -> Result<Option<types::BlockResponse>, String> {
        self.client
            .get_block_with_cycles(hash)
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_packed_block_by_number(
        &mut self,
        number: u64,
    ) -> Result<Option<types::JsonBytes>, String> {
        self.client
            .get_packed_block_by_number(BlockNumber::from(number))
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_block_by_number(&mut self, number: u64) -> Result<Option<types::BlockView>, String> {
        self.client
            .get_block_by_number(BlockNumber::from(number))
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_packed_block_by_number_with_cycles(
        &mut self,
        number: u64,
    ) -> Result<Option<types::PackedBlockResponse>, String> {
        self.client
            .get_packed_block_by_number_with_cycles(BlockNumber::from(number))
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_block_by_number_with_cycles(
        &mut self,
        number: u64,
    ) -> Result<Option<types::BlockResponse>, String> {
        self.client
            .get_block_by_number_with_cycles(BlockNumber::from(number))
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_block_hash(&mut self, number: u64) -> Result<Option<H256>, String> {
        self.client
            .get_block_hash(BlockNumber::from(number))
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_current_epoch(&mut self) -> Result<types::EpochView, String> {
        self.client
            .get_current_epoch()
            .map(Into::into)
            .map_err(|err| err.to_string())
    }
    pub fn get_epoch_by_number(&mut self, number: u64) -> Result<Option<types::EpochView>, String> {
        self.client
            .get_epoch_by_number(EpochNumber::from(number))
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_header(&mut self, hash: H256) -> Result<Option<types::HeaderView>, String> {
        self.client
            .get_header(hash)
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_packed_header(&mut self, hash: H256) -> Result<Option<types::JsonBytes>, String> {
        self.client
            .get_packed_header(hash)
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_header_by_number(
        &mut self,
        number: u64,
    ) -> Result<Option<types::HeaderView>, String> {
        self.client
            .get_header_by_number(BlockNumber::from(number))
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_packed_header_by_number(
        &mut self,
        number: u64,
    ) -> Result<Option<types::JsonBytes>, String> {
        self.client
            .get_packed_header_by_number(BlockNumber::from(number))
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    // TODO: Make `cell::CellData` public
    pub fn get_live_cell(
        &mut self,
        out_point: packed::OutPoint,
        with_data: bool,
        include_tx_pool: Option<bool>,
    ) -> Result<CellWithStatus, String> {
        match include_tx_pool {
            Some(include_tx_pool) => self
                .client
                .get_live_cell_with_include_tx_pool(out_point.into(), with_data, include_tx_pool)
                .map_err(|err| err.to_string()),
            None => self
                .client
                .get_live_cell(out_point.into(), with_data)
                .map_err(|err| err.to_string()),
        }
    }
    pub fn get_tip_block_number(&mut self) -> Result<u64, String> {
        self.client
            .get_tip_block_number()
            .map(Into::into)
            .map_err(|err| err.to_string())
    }
    pub fn get_tip_header(&mut self) -> Result<types::HeaderView, String> {
        self.client
            .get_tip_header()
            .map(Into::into)
            .map_err(|err| err.to_string())
    }
    pub fn get_packed_tip_header(&mut self) -> Result<types::JsonBytes, String> {
        self.client
            .get_packed_tip_header()
            .map(Into::into)
            .map_err(|err| err.to_string())
    }
    pub fn get_transaction(
        &mut self,
        hash: H256,
    ) -> Result<Option<types::TransactionWithStatus>, String> {
        self.client
            .get_transaction(hash)
            .map(|opt| opt.map(TryInto::try_into))
            .map_err(|err| err.to_string())?
            .transpose()
    }
    pub fn get_packed_transaction(
        &mut self,
        hash: H256,
    ) -> Result<types::PackedTransactionWithStatus, String> {
        self.client
            .get_packed_transaction(hash)
            .map(TryInto::try_into)
            .map_err(|err| err.to_string())?
    }
    pub fn get_transaction_proof(
        &mut self,
        tx_hashes: Vec<H256>,
        block_hash: Option<H256>,
    ) -> Result<types::TransactionProof, String> {
        self.client
            .get_transaction_proof(tx_hashes, block_hash)
            .map(Into::into)
            .map_err(|err| err.to_string())
    }
    pub fn verify_transaction_proof(
        &mut self,
        tx_proof: types::TransactionProof,
    ) -> Result<Vec<H256>, String> {
        self.client
            .verify_transaction_proof(tx_proof.into())
            .map_err(|err| err.to_string())
    }

    pub fn verify_transaction_and_witness_proof(
        &mut self,
        tx_and_witness_proof: types::TransactionAndWitnessProof,
    ) -> Result<Vec<H256>, String> {
        self.client
            .verify_transaction_and_witness_proof(tx_and_witness_proof.into())
            .map_err(|err| err.to_string())
    }

    pub fn get_transaction_and_witness_proof(
        &mut self,
        tx_hashes: Vec<H256>,
        block_hash: Option<H256>,
    ) -> Result<types::TransactionAndWitnessProof, String> {
        self.client
            .get_transaction_and_witness_proof(tx_hashes, block_hash)
            .map(Into::into)
            .map_err(|err| err.to_string())
    }

    pub fn get_fork_block(&mut self, block_hash: H256) -> Result<Option<types::BlockView>, String> {
        self.client
            .get_fork_block(block_hash)
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_consensus(&mut self) -> Result<types::Consensus, String> {
        self.client
            .get_consensus()
            .map(Into::into)
            .map_err(|err| err.to_string())
    }
    pub fn get_block_median_time(
        &mut self,
        hash: H256,
    ) -> Result<Option<primitive::Timestamp>, String> {
        self.client
            .get_block_median_time(hash)
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_block_economic_state(
        &mut self,
        block_hash: H256,
    ) -> Result<Option<types::BlockEconomicState>, String> {
        self.client
            .get_block_economic_state(block_hash)
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }

    pub fn estimate_cycles(
        &mut self,
        tx: packed::Transaction,
    ) -> Result<types::EstimateCycles, String> {
        self.client
            .estimate_cycles(tx.into())
            .map(Into::into)
            .map_err(|err| err.to_string())
    }
    pub fn get_fee_rate_statistics(
        &mut self,
        target: Option<u64>,
    ) -> Result<Option<types::FeeRateStatistics>, String> {
        self.client
            .get_fee_rate_statics(target.map(Into::into))
            .map(|fee_rate_statistics| fee_rate_statistics.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_deployments_info(&mut self) -> Result<types::DeploymentsInfo, String> {
        self.client
            .get_deployments_info()
            .map(Into::into)
            .map_err(|err| err.to_string())
    }
    // Net
    pub fn get_banned_addresses(&mut self) -> Result<Vec<types::BannedAddr>, String> {
        self.client
            .get_banned_addresses()
            .map(|vec| vec.into_iter().map(Into::into).collect())
            .map_err(|err| err.to_string())
    }
    pub fn get_peers(&mut self) -> Result<Vec<types::RemoteNode>, String> {
        self.client
            .get_peers()
            .map(|vec| vec.into_iter().map(Into::into).collect())
            .map_err(|err| err.to_string())
    }
    pub fn local_node_info(&mut self) -> Result<types::LocalNode, String> {
        self.client
            .local_node_info()
            .map(Into::into)
            .map_err(|err| err.to_string())
    }
    pub fn set_ban(
        &mut self,
        address: String,
        command: String,
        ban_time: Option<u64>,
        absolute: Option<bool>,
        reason: Option<String>,
    ) -> Result<(), String> {
        self.client
            .set_ban(address, command, ban_time.map(Into::into), absolute, reason)
            .map_err(|err| err.to_string())
    }
    pub fn sync_state(&mut self) -> Result<types::SyncState, String> {
        self.client
            .sync_state()
            .map(Into::into)
            .map_err(|err| err.to_string())
    }
    pub fn set_network_active(&mut self, state: bool) -> Result<(), String> {
        self.client
            .set_network_active(state)
            .map_err(|err| err.to_string())
    }
    pub fn add_node(&mut self, peer_id: String, address: String) -> Result<(), String> {
        self.client
            .add_node(peer_id, address)
            .map_err(|err| err.to_string())
    }
    pub fn remove_node(&mut self, peer_id: String) -> Result<(), String> {
        self.client
            .remove_node(peer_id)
            .map_err(|err| err.to_string())
    }
    pub fn clear_banned_addresses(&mut self) -> Result<(), String> {
        self.client
            .clear_banned_addresses()
            .map_err(|err| err.to_string())
    }
    pub fn ping_peers(&mut self) -> Result<(), String> {
        self.client.ping_peers().map_err(|err| err.to_string())
    }

    // Pool
    pub fn send_transaction(
        &mut self,
        tx: packed::Transaction,
        outputs_validator: Option<OutputsValidator>,
    ) -> Result<H256, String> {
        self.client
            .send_transaction(tx.into(), outputs_validator)
            .map_err(|err| err.to_string())
    }
    pub fn remove_transaction(&mut self, tx_hash: H256) -> Result<bool, String> {
        self.client
            .remove_transaction(tx_hash)
            .map_err(|err| err.to_string())
    }
    pub fn tx_pool_info(&mut self) -> Result<types::TxPoolInfo, String> {
        self.client
            .tx_pool_info()
            .map(Into::into)
            .map_err(|err| err.to_string())
    }
    pub fn clear_tx_verify_queue(&mut self) -> Result<(), String> {
        self.client
            .clear_tx_verify_queue()
            .map(Into::into)
            .map_err(|err| err.to_string())
    }

    pub fn test_tx_pool_accept(
        &mut self,
        tx: packed::Transaction,
        outputs_validator: Option<OutputsValidator>,
    ) -> Result<types::EntryCompleted, String> {
        self.client
            .test_tx_pool_accept(tx.into(), outputs_validator)
            .map(Into::into)
            .map_err(|err| err.to_string())
    }
    pub fn clear_tx_pool(&mut self) -> Result<(), String> {
        self.client.clear_tx_pool().map_err(|err| err.to_string())
    }
    pub fn get_raw_tx_pool(&mut self, verbose: Option<bool>) -> Result<types::RawTxPool, String> {
        self.client
            .get_raw_tx_pool(verbose)
            .map(Into::into)
            .map_err(|err| err.to_string())
    }
    pub fn tx_pool_ready(&mut self) -> Result<bool, String> {
        self.client.tx_pool_ready().map_err(|err| err.to_string())
    }

    // Stats
    pub fn get_blockchain_info(&mut self) -> Result<types::ChainInfo, String> {
        self.client
            .get_blockchain_info()
            .map(Into::into)
            .map_err(|err| err.to_string())
    }

    // Alert
    pub fn send_alert(&mut self, alert: Alert) -> Result<(), String> {
        self.client.send_alert(alert).map_err(|err| err.to_string())
    }

    // IntegrationTest
    pub fn truncate(&mut self, target_tip_hash: H256) -> Result<(), String> {
        self.client
            .truncate(target_tip_hash)
            .map_err(|err| err.to_string())
    }
    pub fn generate_block(&mut self) -> Result<H256, String> {
        self.client.generate_block().map_err(|err| err.to_string())
    }

    pub fn generate_epochs(&mut self, num_epochs: u64) -> Result<EpochNumberWithFraction, String> {
        self.client
            .generate_epochs(EpochNumberWithFraction::from(num_epochs))
            .map_err(|err| err.to_string())
    }
    pub fn notify_transaction(&mut self, tx: packed::Transaction) -> Result<H256, String> {
        self.client
            .notify_transaction(tx.into())
            .map_err(|err| err.to_string())
    }

    // Indexer
    pub fn get_indexer_tip(&mut self) -> Result<Option<types::IndexerTip>, String> {
        self.client
            .get_indexer_tip()
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }

    pub fn get_cells(
        &mut self,
        search_key: SearchKey,
        order: Order,
        limit: Uint32,
        after: Option<JsonBytes>,
    ) -> Result<Pagination<types::Cell>, String> {
        self.client
            .get_cells(search_key, order, limit, after)
            .map(|p| Pagination {
                objects: p.objects.into_iter().map(Into::into).collect(),
                last_cursor: p.last_cursor,
            })
            .map_err(|err| err.to_string())
    }

    pub fn get_transactions(
        &mut self,
        search_key: SearchKey,
        order: Order,
        limit: Uint32,
        after: Option<JsonBytes>,
    ) -> Result<Pagination<types::Tx>, String> {
        self.client
            .get_transactions(search_key, order, limit, after)
            .map(|p| Pagination {
                objects: p.objects.into_iter().map(Into::into).collect(),
                last_cursor: p.last_cursor,
            })
            .map_err(|err| err.to_string())
    }

    pub fn get_cells_capacity(
        &mut self,
        search_key: SearchKey,
    ) -> Result<Option<types::CellsCapacity>, String> {
        self.client
            .get_cells_capacity(search_key)
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
}
