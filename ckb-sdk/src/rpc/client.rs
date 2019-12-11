use ckb_jsonrpc_types::{
    BannedAddr, BlockNumber, BlockReward, BlockView, CellOutputWithOutPoint, CellTransaction,
    CellWithStatus, ChainInfo, EpochNumber, EpochView, HeaderView, LiveCell, LockHashIndexState,
    Node, OutPoint, PeerState, Timestamp, Transaction, TransactionWithStatus, TxPoolInfo, Uint64,
};
use jsonrpc_client_core::{expand_params, jsonrpc_client};
use jsonrpc_client_http::{HttpHandle, HttpTransport};

use super::types;
use ckb_types::{packed, H256};

jsonrpc_client!(pub struct RawRpcClient {
    // Chain
    pub fn get_block(&mut self, hash: H256) -> RpcRequest<Option<BlockView>>;
    pub fn get_block_by_number(&mut self, number: BlockNumber) -> RpcRequest<Option<BlockView>>;
    pub fn get_block_hash(&mut self, number: BlockNumber) -> RpcRequest<Option<H256>>;
    pub fn get_cellbase_output_capacity_details(&mut self, hash: H256) -> RpcRequest<Option<BlockReward>>;
    pub fn get_cells_by_lock_hash(&mut self, lock_hash: H256, from: BlockNumber, to: BlockNumber) -> RpcRequest<Vec<CellOutputWithOutPoint>>;
    pub fn get_current_epoch(&mut self) -> RpcRequest<EpochView>;
    pub fn get_epoch_by_number(&mut self, number: EpochNumber) -> RpcRequest<Option<EpochView>>;
    pub fn get_header(&mut self, hash: H256) -> RpcRequest<Option<HeaderView>>;
    pub fn get_header_by_number(&mut self, number: BlockNumber) -> RpcRequest<Option<HeaderView>>;
    pub fn get_live_cell(&mut self, out_point: OutPoint, with_data: bool) -> RpcRequest<CellWithStatus>;
    pub fn get_tip_block_number(&mut self) -> RpcRequest<BlockNumber>;
    pub fn get_tip_header(&mut self) -> RpcRequest<HeaderView>;
    pub fn get_transaction(&mut self, hash: H256) -> RpcRequest<Option<TransactionWithStatus>>;

    // Indexer
    pub fn deindex_lock_hash(&mut self, lock_hash: H256) -> RpcRequest<()>;
    pub fn get_live_cells_by_lock_hash(
        &mut self,
        lock_hash: H256,
        page: Uint64,
        per_page: Uint64,
        reverse_order: Option<bool>
    ) -> RpcRequest<Vec<LiveCell>>;
    pub fn get_transactions_by_lock_hash(
        &mut self,
        lock_hash: H256,
        page: Uint64,
        per_page: Uint64,
        reverse_order: Option<bool>
    ) -> RpcRequest<Vec<CellTransaction>>;
    pub fn index_lock_hash(
        &mut self,
        lock_hash: H256,
        index_from: Option<BlockNumber>
    ) -> RpcRequest<LockHashIndexState>;

    // Net
    pub fn get_banned_addresses(&mut self) -> RpcRequest<Vec<BannedAddr>>;
    pub fn get_peers(&mut self) -> RpcRequest<Vec<Node>>;
    pub fn local_node_info(&mut self) -> RpcRequest<Node>;
    pub fn set_ban(
        &mut self,
        address: String,
        command: String,
        ban_time: Option<Timestamp>,
        absolute: Option<bool>,
        reason: Option<String>
    ) -> RpcRequest<()>;

    // Pool
    pub fn send_transaction(&mut self, tx: Transaction) -> RpcRequest<H256>;
    pub fn tx_pool_info(&mut self) -> RpcRequest<TxPoolInfo>;

    // Stats
    pub fn get_blockchain_info(&mut self) -> RpcRequest<ChainInfo>;
    pub fn get_peers_state(&mut self) -> RpcRequest<Vec<PeerState>>;

    // IntegrationTest
    pub fn add_node(&mut self, peer_id: String, address: String) -> RpcRequest<()>;
    pub fn remove_node(&mut self, peer_id: String) -> RpcRequest<()>;
    pub fn broadcast_transaction(&mut self, tx: Transaction) -> RpcRequest<H256>;
});

impl RawRpcClient<HttpHandle> {
    pub fn from_uri(server: &str) -> RawRpcClient<HttpHandle> {
        let transport = HttpTransport::new().standalone().unwrap();
        let transport_handle = transport.handle(server).unwrap();
        RawRpcClient::new(transport_handle)
    }
}

pub type RawHttpRpcClient = RawRpcClient<HttpHandle>;

pub struct HttpRpcClient {
    url: String,
    client: RawHttpRpcClient,
}

impl HttpRpcClient {
    pub fn new(url: String) -> HttpRpcClient {
        let client = RawHttpRpcClient::from_uri(url.as_str());
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
    pub fn get_block(&mut self, hash: H256) -> Result<Option<types::BlockView>, String> {
        self.client
            .get_block(hash)
            .call()
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_block_by_number(&mut self, number: u64) -> Result<Option<types::BlockView>, String> {
        self.client
            .get_block_by_number(BlockNumber::from(number))
            .call()
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_block_hash(&mut self, number: u64) -> Result<Option<H256>, String> {
        self.client
            .get_block_hash(BlockNumber::from(number))
            .call()
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_cellbase_output_capacity_details(
        &mut self,
        hash: H256,
    ) -> Result<Option<types::BlockReward>, String> {
        self.client
            .get_cellbase_output_capacity_details(hash)
            .call()
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_cells_by_lock_hash(
        &mut self,
        lock_hash: H256,
        from: u64,
        to: u64,
    ) -> Result<Vec<types::CellOutputWithOutPoint>, String> {
        self.client
            .get_cells_by_lock_hash(lock_hash, BlockNumber::from(from), BlockNumber::from(to))
            .call()
            .map(|vec| vec.into_iter().map(Into::into).collect())
            .map_err(|err| err.to_string())
    }
    pub fn get_current_epoch(&mut self) -> Result<types::EpochView, String> {
        self.client
            .get_current_epoch()
            .call()
            .map(Into::into)
            .map_err(|err| err.to_string())
    }
    pub fn get_epoch_by_number(&mut self, number: u64) -> Result<Option<types::EpochView>, String> {
        self.client
            .get_epoch_by_number(EpochNumber::from(number))
            .call()
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_header(&mut self, hash: H256) -> Result<Option<types::HeaderView>, String> {
        self.client
            .get_header(hash)
            .call()
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_header_by_number(
        &mut self,
        number: u64,
    ) -> Result<Option<types::HeaderView>, String> {
        self.client
            .get_header_by_number(BlockNumber::from(number))
            .call()
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    // TODO: Make `cell::CellData` public
    pub fn get_live_cell(
        &mut self,
        out_point: packed::OutPoint,
        with_data: bool,
    ) -> Result<CellWithStatus, String> {
        self.client
            .get_live_cell(out_point.into(), with_data)
            .call()
            .map_err(|err| err.to_string())
    }
    pub fn get_tip_block_number(&mut self) -> Result<u64, String> {
        self.client
            .get_tip_block_number()
            .call()
            .map(Into::into)
            .map_err(|err| err.to_string())
    }
    pub fn get_tip_header(&mut self) -> Result<types::HeaderView, String> {
        self.client
            .get_tip_header()
            .call()
            .map(Into::into)
            .map_err(|err| err.to_string())
    }
    pub fn get_transaction(
        &mut self,
        hash: H256,
    ) -> Result<Option<types::TransactionWithStatus>, String> {
        self.client
            .get_transaction(hash)
            .call()
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }

    // Indexer
    pub fn deindex_lock_hash(&mut self, lock_hash: H256) -> Result<(), String> {
        self.client
            .deindex_lock_hash(lock_hash)
            .call()
            .map_err(|err| err.to_string())
    }
    pub fn get_live_cells_by_lock_hash(
        &mut self,
        lock_hash: H256,
        page: u64,
        per_page: u64,
        reverse_order: Option<bool>,
    ) -> Result<Vec<types::LiveCell>, String> {
        self.client
            .get_live_cells_by_lock_hash(
                lock_hash,
                Uint64::from(page),
                Uint64::from(per_page),
                reverse_order,
            )
            .call()
            .map(|vec| vec.into_iter().map(Into::into).collect())
            .map_err(|err| err.to_string())
    }
    pub fn get_transactions_by_lock_hash(
        &mut self,
        lock_hash: H256,
        page: u64,
        per_page: u64,
        reverse_order: Option<bool>,
    ) -> Result<Vec<types::CellTransaction>, String> {
        self.client
            .get_transactions_by_lock_hash(
                lock_hash,
                Uint64::from(page),
                Uint64::from(per_page),
                reverse_order,
            )
            .call()
            .map(|vec| vec.into_iter().map(Into::into).collect())
            .map_err(|err| err.to_string())
    }
    pub fn index_lock_hash(
        &mut self,
        lock_hash: H256,
        index_from: Option<u64>,
    ) -> Result<types::LockHashIndexState, String> {
        self.client
            .index_lock_hash(lock_hash, index_from.map(BlockNumber::from))
            .call()
            .map(Into::into)
            .map_err(|err| err.to_string())
    }

    // Net
    pub fn get_banned_addresses(&mut self) -> Result<Vec<types::BannedAddr>, String> {
        self.client
            .get_banned_addresses()
            .call()
            .map(|vec| vec.into_iter().map(Into::into).collect())
            .map_err(|err| err.to_string())
    }
    pub fn get_peers(&mut self) -> Result<Vec<types::Node>, String> {
        self.client
            .get_peers()
            .call()
            .map(|vec| vec.into_iter().map(Into::into).collect())
            .map_err(|err| err.to_string())
    }
    pub fn local_node_info(&mut self) -> Result<types::Node, String> {
        self.client
            .local_node_info()
            .call()
            .map(Into::into)
            .map_err(|err| err.description().to_string())
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
            .call()
            .map_err(|err| err.description().to_string())
    }

    // Pool
    pub fn send_transaction(&mut self, tx: packed::Transaction) -> Result<H256, String> {
        self.client
            .send_transaction(tx.into())
            .call()
            .map_err(|err| err.to_string())
    }
    pub fn tx_pool_info(&mut self) -> Result<types::TxPoolInfo, String> {
        self.client
            .tx_pool_info()
            .call()
            .map(Into::into)
            .map_err(|err| err.to_string())
    }

    // Stats
    pub fn get_blockchain_info(&mut self) -> Result<types::ChainInfo, String> {
        self.client
            .get_blockchain_info()
            .call()
            .map(Into::into)
            .map_err(|err| err.to_string())
    }
    pub fn get_peers_state(&mut self) -> Result<Vec<PeerState>, String> {
        self.client
            .get_peers_state()
            .call()
            .map_err(|err| err.to_string())
    }

    // IntegrationTest
    pub fn add_node(&mut self, peer_id: String, address: String) -> Result<(), String> {
        self.client
            .add_node(peer_id, address)
            .call()
            .map_err(|err| err.to_string())
    }
    pub fn remove_node(&mut self, peer_id: String) -> Result<(), String> {
        self.client
            .remove_node(peer_id)
            .call()
            .map_err(|err| err.to_string())
    }
    pub fn broadcast_transaction(&mut self, tx: packed::Transaction) -> Result<H256, String> {
        self.client
            .broadcast_transaction(tx.into())
            .call()
            .map_err(|err| err.to_string())
    }
}
