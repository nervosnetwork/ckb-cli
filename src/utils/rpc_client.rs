
use jsonrpc_client_core::{expand_params, jsonrpc_client};
pub use jsonrpc_types::{
    BlockView, HeaderView, Node, Transaction, TransactionWithStatus,
    TxPoolInfo, EpochExt,
    BlockNumber,
    CellWithStatus,
    OutPoint,
    CellOutputWithOutPoint,
};
use jsonrpc_client_http::{HttpHandle, HttpTransport};
use serde_derive::{Deserialize, Serialize};

use numext_fixed_hash::H256;

#[derive(Serialize, Deserialize)]
pub struct Nodes(Vec<Node>);

#[derive(Serialize, Deserialize)]
pub struct OptionTransactionWithStatus(Option<TransactionWithStatus>);

#[derive(Serialize, Deserialize)]
pub struct CellOutputWithOutPoints(Vec<CellOutputWithOutPoint>);

#[derive(Serialize, Deserialize)]
pub struct OptionBlockView(Option<BlockView>);

#[derive(Serialize, Deserialize)]
pub struct OptionH256(Option<H256>);

jsonrpc_client!(pub struct RpcClient {
    pub fn local_node_info(&mut self) -> RpcRequest<Node>;
    pub fn get_peers(&mut self) -> RpcRequest<Nodes>;
    pub fn add_node(&mut self, peer_id: String, address: String) -> RpcRequest<()>;

    pub fn tx_pool_info(&mut self) -> RpcRequest<TxPoolInfo>;

    pub fn send_transaction(&mut self, tx: Transaction) -> RpcRequest<H256>;
    pub fn get_transaction(&mut self, hash: H256) -> RpcRequest<OptionTransactionWithStatus>;
    pub fn get_cells_by_lock_hash(&mut self, lock_hash: H256, from: BlockNumber, to: BlockNumber) -> RpcRequest<CellOutputWithOutPoints>;
    pub fn get_live_cell(&mut self, out_point: OutPoint) -> RpcRequest<CellWithStatus>;

    pub fn get_tip_header(&mut self) -> RpcRequest<HeaderView>;
    pub fn get_current_epoch(&mut self) -> RpcRequest<EpochExt>;
    pub fn get_block(&mut self, hash: H256) -> RpcRequest<OptionBlockView>;
    pub fn get_block_hash(&mut self, number: BlockNumber) -> RpcRequest<OptionH256>;
    pub fn get_block_by_number(&mut self, number: BlockNumber) -> RpcRequest<OptionBlockView>;
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

pub type HttpRpcClient = RpcClient<HttpHandle>;
