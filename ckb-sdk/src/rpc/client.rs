use ckb_jsonrpc_types::{
    Alert, BannedAddr, Block, BlockEconomicState, BlockNumber, BlockTemplate, BlockView,
    CellWithStatus, ChainInfo, Consensus, EpochNumber, EpochView, ExtraLoggerConfig, HeaderView,
    JsonBytes, LocalNode, MainLoggerConfig, OutPoint, OutputsValidator, RawTxPool, RemoteNode,
    Script, Timestamp, Transaction, TransactionProof, TransactionWithStatus, TxPoolInfo, Uint64,
    Version,
};

use super::primitive;
use super::types;
use ckb_types::{packed, H256};

macro_rules! jsonrpc {
    (
        $(#[$struct_attr:meta])*
        pub struct $struct_name:ident {$(
            $(#[$attr:meta])*
            pub fn $method:ident(&mut $selff:ident $(, $arg_name:ident: $arg_ty:ty)*)
                -> $return_ty:ty;
        )*}
    ) => (
        $(#[$struct_attr])*
        pub struct $struct_name {
            pub client: reqwest::blocking::Client,
            pub url: reqwest::Url,
            pub id: u64,
        }

        impl $struct_name {
            pub fn new(uri: &str) -> Self {
                let url = reqwest::Url::parse(uri).expect("ckb uri, e.g. \"http://127.0.0.1:8114\"");
                $struct_name { url, id: 0, client: reqwest::blocking::Client::new(), }
            }

            $(
                $(#[$attr])*
                pub fn $method(&mut $selff $(, $arg_name: $arg_ty)*) -> Result<$return_ty, failure::Error> {
                    let method = String::from(stringify!($method));
                    let params = serialize_parameters!($($arg_name,)*);
                    $selff.id += 1;

                    let mut req_json = serde_json::Map::new();
                    req_json.insert("id".to_owned(), serde_json::json!($selff.id));
                    req_json.insert("jsonrpc".to_owned(), serde_json::json!("2.0"));
                    req_json.insert("method".to_owned(), serde_json::json!(method));
                    req_json.insert("params".to_owned(), params);

                    let resp = $selff.client.post($selff.url.clone()).json(&req_json).send()?;
                    let output = resp.json::<jsonrpc_core::response::Output>()?;
                    match output {
                        jsonrpc_core::response::Output::Success(success) => {
                            serde_json::from_value(success.result).map_err(Into::into)
                        },
                        jsonrpc_core::response::Output::Failure(failure) => {
                            Err(failure.error.into())
                        }
                    }
                }
            )*
        }
    )
}

macro_rules! serialize_parameters {
    () => ( serde_json::Value::Null );
    ($($arg_name:ident,)+) => ( serde_json::to_value(($($arg_name,)+))?)
}

jsonrpc!(pub struct RawHttpRpcClient {
    // Chain
    pub fn get_block(&mut self, hash: H256) -> Option<BlockView>;
    pub fn get_block_by_number(&mut self, number: BlockNumber) -> Option<BlockView>;
    pub fn get_block_hash(&mut self, number: BlockNumber) -> Option<H256>;
    pub fn get_current_epoch(&mut self) -> EpochView;
    pub fn get_epoch_by_number(&mut self, number: EpochNumber) -> Option<EpochView>;
    pub fn get_header(&mut self, hash: H256) -> Option<HeaderView>;
    pub fn get_header_by_number(&mut self, number: BlockNumber) -> Option<HeaderView>;
    pub fn get_live_cell(&mut self, out_point: OutPoint, with_data: bool) -> CellWithStatus;
    pub fn get_tip_block_number(&mut self) -> BlockNumber;
    pub fn get_tip_header(&mut self) -> HeaderView;
    pub fn get_transaction(&mut self, hash: H256) -> Option<TransactionWithStatus>;
    pub fn get_transaction_proof(
        &mut self,
        tx_hashes: Vec<H256>,
        block_hash: Option<H256>
    ) -> TransactionProof;
    pub fn verify_transaction_proof(&mut self, tx_proof: TransactionProof) -> Vec<H256>;
    pub fn get_fork_block(&mut self, block_hash: H256) -> Option<BlockView>;
    pub fn get_consensus(&mut self) -> Consensus;
    pub fn get_block_median_time(&mut self, block_hash: H256) -> Option<Timestamp>;
    pub fn get_block_economic_state(&mut self, block_hash: H256) -> Option<BlockEconomicState>;

    // Net
    pub fn get_banned_addresses(&mut self) -> Vec<BannedAddr>;
    pub fn get_peers(&mut self) -> Vec<RemoteNode>;
    pub fn local_node_info(&mut self) -> LocalNode;
    pub fn set_ban(
        &mut self,
        address: String,
        command: String,
        ban_time: Option<Timestamp>,
        absolute: Option<bool>,
        reason: Option<String>
    ) -> ();
    pub fn sync_state(&mut self) -> types::PeerSyncState;
    pub fn set_network_active(&mut self, state: bool) -> ();
    pub fn add_node(&mut self, peer_id: String, address: String) -> ();
    pub fn remove_node(&mut self, peer_id: String) -> ();
    pub fn clear_banned_addresses(&mut self) -> ();
    pub fn ping_peers(&mut self) -> ();

    // Pool
    pub fn send_transaction(&mut self, tx: Transaction, outputs_validator: Option<OutputsValidator>) -> H256;
    pub fn remove_transaction(&mut self, tx_hash: H256) -> bool;
    pub fn tx_pool_info(&mut self) -> TxPoolInfo;
    pub fn clear_tx_pool(&mut self) -> ();
    pub fn get_raw_tx_pool(&mut self, verbose: Option<bool>) -> RawTxPool;
    pub fn tx_pool_ready(&mut self) -> bool;

    // Stats
    pub fn get_blockchain_info(&mut self) -> ChainInfo;

    // Miner
    pub fn get_block_template(&mut self, bytes_limit: Option<Uint64>, proposals_limit: Option<Uint64>, max_version: Option<Version>) -> BlockTemplate;
    pub fn submit_block(&mut self, _work_id: String, _data: Block) -> H256;

    // Alert
    pub fn send_alert(&mut self, alert: Alert) -> ();

    // IntegrationTest
    pub fn process_block_without_verify(&mut self, data: Block, broadcast: bool) -> Option<H256>;
    pub fn truncate(&mut self, target_tip_hash: H256) -> ();
    pub fn generate_block(&mut self, block_assembler_script: Option<Script>, block_assembler_message: Option<JsonBytes>) -> H256;
    pub fn notify_transaction(&mut self, tx: Transaction) -> H256;

    // Debug
    pub fn jemalloc_profiling_dump(&mut self) -> String;
    pub fn update_main_logger(&mut self, config: MainLoggerConfig) -> ();
    pub fn set_extra_logger(&mut self, name: String, config_opt: Option<ExtraLoggerConfig>) -> ();
});

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
    pub fn get_block(&mut self, hash: H256) -> Result<Option<types::BlockView>, String> {
        self.client
            .get_block(hash)
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
    }
    pub fn get_block_by_number(&mut self, number: u64) -> Result<Option<types::BlockView>, String> {
        self.client
            .get_block_by_number(BlockNumber::from(number))
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
    pub fn get_header_by_number(
        &mut self,
        number: u64,
    ) -> Result<Option<types::HeaderView>, String> {
        self.client
            .get_header_by_number(BlockNumber::from(number))
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
            .map_err(|err| err.to_string())
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
    pub fn get_transaction(
        &mut self,
        hash: H256,
    ) -> Result<Option<types::TransactionWithStatus>, String> {
        self.client
            .get_transaction(hash)
            .map(|opt| opt.map(Into::into))
            .map_err(|err| err.to_string())
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
    pub fn sync_state(&mut self) -> Result<types::PeerSyncState, String> {
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

    // Miner
    pub fn get_block_template(
        &mut self,
        bytes_limit: Option<u64>,
        proposals_limit: Option<u64>,
        max_version: Option<u32>,
    ) -> Result<BlockTemplate, String> {
        self.client
            .get_block_template(
                bytes_limit.map(Into::into),
                proposals_limit.map(Into::into),
                max_version.map(Into::into),
            )
            .map_err(|err| err.to_string())
    }
    pub fn submit_block(&mut self, work_id: String, data: packed::Block) -> Result<H256, String> {
        self.client
            .submit_block(work_id, data.into())
            .map_err(|err| err.to_string())
    }

    // Alert
    pub fn send_alert(&mut self, alert: Alert) -> Result<(), String> {
        self.client.send_alert(alert).map_err(|err| err.to_string())
    }

    // IntegrationTest
    pub fn process_block_without_verify(
        &mut self,
        data: Block,
        broadcast: bool,
    ) -> Result<Option<H256>, String> {
        self.client
            .process_block_without_verify(data, broadcast)
            .map_err(|err| err.to_string())
    }
    pub fn truncate(&mut self, target_tip_hash: H256) -> Result<(), String> {
        self.client
            .truncate(target_tip_hash)
            .map_err(|err| err.to_string())
    }
    pub fn generate_block(
        &mut self,
        block_assembler_script: Option<Script>,
        block_assembler_message: Option<JsonBytes>,
    ) -> Result<H256, String> {
        self.client
            .generate_block(block_assembler_script, block_assembler_message)
            .map_err(|err| err.to_string())
    }
    pub fn notify_transaction(&mut self, tx: packed::Transaction) -> Result<H256, String> {
        self.client
            .notify_transaction(tx.into())
            .map_err(|err| err.to_string())
    }

    // Debug
    pub fn jemalloc_profiling_dump(&mut self) -> Result<String, String> {
        self.client
            .jemalloc_profiling_dump()
            .map_err(|err| err.to_string())
    }
    pub fn update_main_logger(&mut self, config: MainLoggerConfig) -> Result<(), String> {
        self.client
            .update_main_logger(config)
            .map_err(|err| err.to_string())
    }
    pub fn set_extra_logger(
        &mut self,
        name: String,
        config_opt: Option<ExtraLoggerConfig>,
    ) -> Result<(), String> {
        self.client
            .set_extra_logger(name, config_opt)
            .map_err(|err| err.to_string())
    }
}
