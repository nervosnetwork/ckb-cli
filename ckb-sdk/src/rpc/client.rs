use ckb_jsonrpc_types::{
    BannedAddr, BlockNumber, BlockReward, BlockView, CellOutputWithOutPoint, CellTransaction,
    CellWithStatus, ChainInfo, EpochNumber, EpochView, HeaderView, LiveCell, LockHashIndexState,
    Node, OutPoint, PeerState, Timestamp, Transaction, TransactionWithStatus, TxPoolInfo, Uint64,
};
use jsonrpc_client_core::{expand_params, jsonrpc_client};
use jsonrpc_client_http::{HttpHandle, HttpTransport};
use serde_derive::{Deserialize, Serialize};

use ckb_types::H256;

#[derive(Serialize, Deserialize)]
pub struct Nodes(pub Vec<Node>);

#[derive(Serialize, Deserialize)]
pub struct OptionTransactionWithStatus(pub Option<TransactionWithStatus>);

#[derive(Serialize, Deserialize)]
pub struct CellOutputWithOutPoints(pub Vec<CellOutputWithOutPoint>);

#[derive(Serialize, Deserialize)]
pub struct OptionBlockView(pub Option<BlockView>);

#[derive(Serialize, Deserialize)]
pub struct OptionHeaderView(pub Option<HeaderView>);

#[derive(Serialize, Deserialize)]
pub struct OptionH256(pub Option<H256>);

#[derive(Serialize, Deserialize)]
pub struct OptionEpochView(pub Option<EpochView>);

#[derive(Serialize, Deserialize)]
pub struct PeerStates(pub Vec<PeerState>);

#[derive(Serialize, Deserialize)]
pub struct BannedAddres(pub Vec<BannedAddr>);

#[derive(Serialize, Deserialize)]
pub struct OptionBlockReward(pub Option<BlockReward>);

#[derive(Serialize, Deserialize)]
pub struct LiveCells(pub Vec<LiveCell>);

#[derive(Serialize, Deserialize)]
pub struct CellTransactions(pub Vec<CellTransaction>);

jsonrpc_client!(pub struct RpcClient {
    // Chain
    pub fn get_block(&mut self, hash: H256) -> RpcRequest<OptionBlockView>;
    pub fn get_block_by_number(&mut self, number: BlockNumber) -> RpcRequest<OptionBlockView>;
    pub fn get_block_hash(&mut self, number: BlockNumber) -> RpcRequest<OptionH256>;
    pub fn get_cellbase_output_capacity_details(&mut self, hash: H256) -> RpcRequest<OptionBlockReward>;
    pub fn get_cells_by_lock_hash(&mut self, lock_hash: H256, from: BlockNumber, to: BlockNumber) -> RpcRequest<CellOutputWithOutPoints>;
    pub fn get_current_epoch(&mut self) -> RpcRequest<EpochView>;
    pub fn get_epoch_by_number(&mut self, number: EpochNumber) -> RpcRequest<OptionEpochView>;
    pub fn get_header(&mut self, hash: H256) -> RpcRequest<OptionHeaderView>;
    pub fn get_header_by_number(&mut self, number: BlockNumber) -> RpcRequest<OptionHeaderView>;
    pub fn get_live_cell(&mut self, out_point: OutPoint, with_data: bool) -> RpcRequest<CellWithStatus>;
    pub fn get_tip_block_number(&mut self) -> RpcRequest<BlockNumber>;
    pub fn get_tip_header(&mut self) -> RpcRequest<HeaderView>;
    pub fn get_transaction(&mut self, hash: H256) -> RpcRequest<OptionTransactionWithStatus>;

    // Indexer
    pub fn deindex_lock_hash(&mut self, lock_hash: H256) -> RpcRequest<()>;
    pub fn get_live_cells_by_lock_hash(
        &mut self,
        lock_hash: H256,
        page: Uint64,
        per_page: Uint64,
        reverse_order: Option<bool>
    ) -> RpcRequest<LiveCells>;
    pub fn get_transactions_by_lock_hash(
        &mut self,
        lock_hash: H256,
        page: Uint64,
        per_page: Uint64,
        reverse_order: Option<bool>
    ) -> RpcRequest<CellTransactions>;
    pub fn index_lock_hash(
        &mut self,
        lock_hash: H256,
        index_from: Option<BlockNumber>
    ) -> RpcRequest<LockHashIndexState>;

    // Net
    pub fn get_banned_addresses(&mut self) -> RpcRequest<BannedAddres>;
    pub fn get_peers(&mut self) -> RpcRequest<Nodes>;
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
    pub fn get_peers_state(&mut self) -> RpcRequest<PeerStates>;

    // IntegrationTest
    pub fn add_node(&mut self, peer_id: String, address: String) -> RpcRequest<()>;
    pub fn remove_node(&mut self, peer_id: String) -> RpcRequest<()>;
    pub fn broadcast_transaction(&mut self, tx: Transaction) -> RpcRequest<H256>;
});

impl RpcClient<HttpHandle> {
    pub fn from_uri(server: &str) -> RpcClient<HttpHandle> {
        let transport = HttpTransport::new().standalone().unwrap();
        let transport_handle = transport.handle(server).unwrap();
        RpcClient::new(transport_handle)
    }
}

pub type HttpRpcClient = RpcClient<HttpHandle>;
