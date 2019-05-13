
use jsonrpc_client_core::{expand_params, jsonrpc_client};
use jsonrpc_types::{
    BlockView, HeaderView, Node, Transaction, TransactionWithStatus,
    TxPoolInfo, EpochExt,
    BlockNumber,
    CellWithStatus,
    OutPoint,
    CellOutputWithOutPoint,
};
use jsonrpc_client_http::{HttpHandle, HttpTransport};

use numext_fixed_hash::H256;

jsonrpc_client!(pub struct RpcClient {
    pub fn local_node_info(&mut self) -> RpcRequest<Node>;
    pub fn get_peers(&mut self) -> RpcRequest<Vec<Node>>;
    pub fn add_node(&mut self, peer_id: String, address: String) -> RpcRequest<()>;

    pub fn tx_pool_info(&mut self) -> RpcRequest<TxPoolInfo>;

    pub fn send_transaction(&mut self, tx: Transaction) -> RpcRequest<H256>;
    pub fn get_transaction(&mut self, hash: H256) -> RpcRequest<Option<TransactionWithStatus>>;
    pub fn get_cells_by_lock_hash(&mut self, lock_hash: H256, from: BlockNumber, to: BlockNumber) -> RpcRequest<Vec<CellOutputWithOutPoint>>;
    pub fn get_live_cell(&mut self, out_point: OutPoint) -> RpcRequest<CellWithStatus>;

    pub fn get_tip_header(&mut self) -> RpcRequest<HeaderView>;
    pub fn get_current_epoch(&mut self) -> RpcRequest<EpochExt>;
    pub fn get_block(&mut self, hash: H256) -> RpcRequest<Option<BlockView>>;
    pub fn get_block_hash(&mut self, number: BlockNumber) -> RpcRequest<Option<H256>>;
    pub fn get_tip_block_number(&mut self) -> RpcRequest<String>;
});

impl RpcClient<HttpHandle> {
    pub fn from_uri(server: &str) -> RpcClient<HttpHandle> {
        let transport = HttpTransport::new().standalone().unwrap();
        let transport_handle = transport
            .handle(server)
            .unwrap();
        RpcClient::new(transport_handle)
    }
}
