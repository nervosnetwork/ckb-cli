use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ckb_crypto::secp::SECP256K1;
use ckb_sdk::{
    AcpConfig, Address, AddressPayload, GenesisInfo, HttpRpcClient, HumanCapacity, NetworkType,
    ReprAcpConfig,
};
use ckb_types::{
    bytes::Bytes,
    core::{service::Request, BlockView},
    prelude::*,
    H256,
};
use clap::{App, Arg, ArgMatches};
use jsonrpc_core::{Error as RpcError, ErrorCode as RpcErrorCode, IoHandler, Result as RpcResult};
use jsonrpc_derive::rpc;
use jsonrpc_http_server::{Server, ServerBuilder};
use jsonrpc_server_utils::cors::AccessControlAllowOrigin;
use jsonrpc_server_utils::hosts::DomainsValidation;
use serde::{Deserialize, Serialize};

use super::{CliSubCommand, LiveCells, Output, TransferArgs, WalletSubCommand};
use crate::plugin::PluginManager;
use crate::utils::{
    arg,
    arg_parser::{AddressParser, ArgParser, FromStrParser, PrivkeyPathParser, PrivkeyWrapper},
    index::{IndexController, IndexRequest},
    other::get_network_type,
};

pub struct ApiServerSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    plugin_mgr: Option<PluginManager>,
    genesis_info: Option<GenesisInfo>,
    index_dir: PathBuf,
    index_controller: IndexController,
}

impl<'a> ApiServerSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        plugin_mgr: PluginManager,
        genesis_info: Option<GenesisInfo>,
        index_dir: PathBuf,
        index_controller: IndexController,
    ) -> ApiServerSubCommand<'a> {
        ApiServerSubCommand {
            rpc_client,
            plugin_mgr: Some(plugin_mgr),
            genesis_info,
            index_dir,
            index_controller,
        }
    }

    pub fn subcommand(name: &'static str) -> App<'static> {
        App::new(name)
            .about("Start advanced API server")
            .arg(
                Arg::with_name("listen")
                    .long("listen")
                    .takes_value(true)
                    .required(true)
                    .default_value("127.0.0.1:3000")
                    .validator(|input| FromStrParser::<SocketAddr>::new().validate(input))
                    .about("Rpc server listen address (when --privkey-path is given ip MUST be 127.0.0.1)"),
            )
            .arg(
                arg::privkey_path()
                 .about("Private key file path (only read first line)")
            )
    }
}

impl<'a> CliSubCommand for ApiServerSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches, _debug: bool) -> Result<Output, String> {
        let listen_addr: SocketAddr =
            FromStrParser::<SocketAddr>::new().from_matches(matches, "listen")?;
        let privkey_path: Option<String> = matches.value_of("privkey-path").map(Into::into);

        let network_result = get_network_type(self.rpc_client);
        if privkey_path.is_some() && listen_addr.ip() != IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)) {
            return Err(format!(
                "When privkey-path is given, listen ip MUST be 127.0.0.1, current ip: {}",
                listen_addr.ip()
            ));
        }
        let privkey_opt: Option<PrivkeyWrapper> = privkey_path
            .clone()
            .map(|input| PrivkeyPathParser.parse(&input))
            .transpose()?;
        let network = match network_result {
            Ok(network) => network,
            Err(ref err) if privkey_opt.is_some() => {
                return Err(format!("Get network type failed: {}", err))
            }
            Err(_) => NetworkType::Mainnet,
        };
        let address_opt = privkey_opt.map(|privkey| {
            let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &privkey);
            let payload = AddressPayload::from_pubkey(&pubkey);
            Address::new(network, payload).to_string()
        });

        Request::call(self.index_controller.sender(), IndexRequest::Kick);

        let mut io_handler = IoHandler::new();
        let handler = ApiRpcImpl {
            rpc_client: Arc::new(Mutex::new(HttpRpcClient::new(
                self.rpc_client.url().to_string(),
            ))),
            plugin_mgr: Arc::new(Mutex::new(self.plugin_mgr.take().unwrap())),
            genesis_info: Arc::new(Mutex::new(self.genesis_info.clone())),
            privkey_path,
            index_dir: self.index_dir.clone(),
            index_controller: self.index_controller.clone(),
        };
        io_handler.extend_with(handler.to_delegate());

        thread::sleep(Duration::from_millis(200));
        log::info!("Node rpc server: {}", self.rpc_client.url());
        log::info!("Network: {:?}", network_result);
        log::info!("Index database directory: {:?}", self.index_dir);
        log::info!(
            "Index database state: {}",
            *self.index_controller.state().read()
        );
        log::info!("Wallet address: {:?}", address_opt);
        log::info!("Listen on {}", listen_addr);
        RpcServer::start(&listen_addr, io_handler).wait();
        Ok(Output::new_error(serde_json::json!({
            "status": "stopped",
        })))
    }
}

struct RpcServer {
    server: Server,
}

impl RpcServer {
    fn start(listen_addr: &SocketAddr, io_handler: IoHandler) -> RpcServer {
        let server = ServerBuilder::new(io_handler)
            .cors(DomainsValidation::AllowOnly(vec![
                AccessControlAllowOrigin::Null,
                AccessControlAllowOrigin::Any,
            ]))
            .threads(2)
            .max_request_body_size(50 * 1024 * 1024)
            .start_http(listen_addr)
            .expect("Jsonrpc initialize");
        RpcServer { server }
    }

    fn wait(self) {
        self.server.wait()
    }
}

#[rpc]
pub trait ApiRpc {
    #[rpc(name = "transfer")]
    fn transfer(&self, _args: HttpTransferArgs) -> RpcResult<H256>;

    #[rpc(name = "get_capacity_by_address")]
    fn get_capacity_by_address(
        &self,
        _address: String,
        _acp_config: Option<ReprAcpConfig>,
    ) -> RpcResult<GetCapacityResponse>;

    #[rpc(name = "get_capacity_by_lock_hash")]
    fn get_capacity_by_lock_hash(&self, _lock_hash: H256) -> RpcResult<GetCapacityResponse>;

    #[rpc(name = "get_live_cells_by_address")]
    fn get_live_cells_by_address(
        &self,
        _address: String,
        _acp_config: Option<ReprAcpConfig>,
        _from_number_opt: Option<u64>,
        _to_number_opt: Option<u64>,
        _limit: usize,
    ) -> RpcResult<LiveCells>;

    #[rpc(name = "get_live_cells_by_lock_hash")]
    fn get_live_cells_by_lock_hash(
        &self,
        _lock_hash: H256,
        _from_number_opt: Option<u64>,
        _to_number_opt: Option<u64>,
        _limit: usize,
    ) -> RpcResult<LiveCells>;

    #[rpc(name = "get_live_cells_by_type_hash")]
    fn get_live_cells_by_type_hash(
        &self,
        _type_hash: H256,
        _from_number_opt: Option<u64>,
        _to_number_opt: Option<u64>,
        _limit: usize,
    ) -> RpcResult<LiveCells>;

    #[rpc(name = "get_live_cells_by_code_hash")]
    fn get_live_cells_by_code_hash(
        &self,
        _code_hash: H256,
        _from_number_opt: Option<u64>,
        _to_number_opt: Option<u64>,
        _limit: usize,
    ) -> RpcResult<LiveCells>;
}

struct ApiRpcImpl {
    rpc_client: Arc<Mutex<HttpRpcClient>>,
    plugin_mgr: Arc<Mutex<PluginManager>>,
    genesis_info: Arc<Mutex<Option<GenesisInfo>>>,
    privkey_path: Option<String>,
    index_dir: PathBuf,
    index_controller: IndexController,
}

impl ApiRpcImpl {
    fn genesis_info(&self) -> Result<GenesisInfo, String> {
        let mut genesis_info = self.genesis_info.lock().unwrap();
        if genesis_info.is_none() {
            let genesis_block: BlockView = self
                .rpc_client
                .lock()
                .unwrap()
                .get_block_by_number(0)?
                .expect("Can not get genesis block?")
                .into();
            *genesis_info = Some(GenesisInfo::from_block(&genesis_block)?);
        }
        Ok(genesis_info.clone().unwrap())
    }

    fn with_wallet<T, F: FnOnce(&mut WalletSubCommand) -> Result<T, RpcError>>(
        &self,
        func: F,
    ) -> Result<T, RpcError> {
        let genesis_info = self.genesis_info().map_err(internal_err)?;
        let mut rpc_client = self.rpc_client.lock().unwrap();
        let mut plugin_mgr = self.plugin_mgr.lock().unwrap();
        func(&mut WalletSubCommand::new(
            &mut rpc_client,
            &mut plugin_mgr,
            Some(genesis_info),
            self.index_dir.clone(),
            self.index_controller.clone(),
            true,
        ))
    }
}

impl ApiRpc for ApiRpcImpl {
    fn transfer(&self, args: HttpTransferArgs) -> RpcResult<H256> {
        log::info!("[call]: tranfer({:?})", args);
        if let Some(privkey_path) = self.privkey_path.clone() {
            self.with_wallet(|cmd| {
                cmd.transfer(args.into_full_args(privkey_path), false)
                    .map_err(RpcError::invalid_params)
            })
            .map(|tx| tx.hash().unpack())
        } else {
            Err(internal_err(
                "Please give privkey-path argument to enable transfer api".to_string(),
            ))
        }
    }

    fn get_capacity_by_address(
        &self,
        address: String,
        acp_config: Option<ReprAcpConfig>,
    ) -> RpcResult<GetCapacityResponse> {
        log::info!(
            "[call]: get_capacity_by_address({}, acp_config: {:?})",
            address,
            acp_config
        );
        let network = {
            let mut rpc_client = self.rpc_client.lock().unwrap();
            get_network_type(&mut rpc_client).map_err(internal_err)?
        };
        let address = AddressParser::default()
            .set_network(network)
            .parse(&address)
            .map_err(RpcError::invalid_params)?;
        let acp_config = acp_config.map(AcpConfig::from);
        let acp_config = AcpConfig::from_network(network, acp_config.as_ref());
        let lock_hash: H256 = address
            .payload()
            .try_to_script(acp_config.as_ref())
            .map_err(RpcError::invalid_params)?
            .calc_script_hash()
            .unpack();
        self.get_capacity_by_lock_hash(lock_hash)
    }

    fn get_capacity_by_lock_hash(&self, lock_hash: H256) -> RpcResult<GetCapacityResponse> {
        log::info!("[call]: get_capacity_by_lock_hash({:#x})", lock_hash);
        let lock_hashes = vec![lock_hash.pack()];
        self.with_wallet(|cmd| {
            cmd.get_capacity(lock_hashes)
                .map(|(total, immature, dao)| GetCapacityResponse {
                    total,
                    immature,
                    dao,
                })
                .map_err(RpcError::invalid_params)
        })
    }

    fn get_live_cells_by_address(
        &self,
        address: String,
        acp_config: Option<ReprAcpConfig>,
        from_number_opt: Option<u64>,
        to_number_opt: Option<u64>,
        limit: usize,
    ) -> RpcResult<LiveCells> {
        log::info!(
            "[call]: get_live_cells_by_address({}, {:?}, {:?}, {})",
            address,
            from_number_opt,
            to_number_opt,
            limit,
        );
        let network = {
            let mut rpc_client = self.rpc_client.lock().unwrap();
            get_network_type(&mut rpc_client).map_err(internal_err)?
        };
        let address = AddressParser::default()
            .set_network(network)
            .parse(&address)
            .map_err(RpcError::invalid_params)?;
        let acp_config = acp_config.map(AcpConfig::from);
        let acp_config = AcpConfig::from_network(network, acp_config.as_ref());
        let lock_hash: H256 = address
            .payload()
            .try_to_script(acp_config.as_ref())
            .map_err(RpcError::invalid_params)?
            .calc_script_hash()
            .unpack();
        self.get_live_cells_by_lock_hash(lock_hash, from_number_opt, to_number_opt, limit)
    }

    fn get_live_cells_by_lock_hash(
        &self,
        lock_hash: H256,
        from_number_opt: Option<u64>,
        to_number_opt: Option<u64>,
        limit: usize,
    ) -> RpcResult<LiveCells> {
        log::info!(
            "[call]: get_live_cells_by_lock_hash({:#x}, {:?}, {:?}, {})",
            lock_hash,
            from_number_opt,
            to_number_opt,
            limit,
        );
        let to_number = to_number_opt.unwrap_or(std::u64::MAX);
        self.with_wallet(|cmd| {
            cmd.get_live_cells(
                to_number,
                limit,
                |db, terminator| {
                    db.get_live_cells_by_lock(lock_hash.pack(), from_number_opt, terminator)
                },
                true,
            )
            .map(|result| result.0)
            .map_err(RpcError::invalid_params)
        })
    }

    fn get_live_cells_by_type_hash(
        &self,
        type_hash: H256,
        from_number_opt: Option<u64>,
        to_number_opt: Option<u64>,
        limit: usize,
    ) -> RpcResult<LiveCells> {
        log::info!(
            "[call]: get_live_cells_by_type_hash({:#x}, {:?}, {:?}, {})",
            type_hash,
            from_number_opt,
            to_number_opt,
            limit,
        );
        let to_number = to_number_opt.unwrap_or(std::u64::MAX);
        self.with_wallet(|cmd| {
            cmd.get_live_cells(
                to_number,
                limit,
                |db, terminator| {
                    db.get_live_cells_by_type(type_hash.pack(), from_number_opt, terminator)
                },
                true,
            )
            .map(|result| result.0)
            .map_err(RpcError::invalid_params)
        })
    }

    fn get_live_cells_by_code_hash(
        &self,
        code_hash: H256,
        from_number_opt: Option<u64>,
        to_number_opt: Option<u64>,
        limit: usize,
    ) -> RpcResult<LiveCells> {
        log::info!(
            "[call]: get_live_cells_by_code_hash({:#x}, {:?}, {:?}, {})",
            code_hash,
            from_number_opt,
            to_number_opt,
            limit,
        );
        let to_number = to_number_opt.unwrap_or(std::u64::MAX);
        self.with_wallet(|cmd| {
            cmd.get_live_cells(
                to_number,
                limit,
                |db, terminator| {
                    db.get_live_cells_by_code(code_hash.pack(), from_number_opt, terminator)
                },
                true,
            )
            .map(|result| result.0)
            .map_err(RpcError::invalid_params)
        })
    }
}

fn internal_err(message: String) -> RpcError {
    RpcError {
        code: RpcErrorCode::InternalError,
        message,
        data: None,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpTransferArgs {
    pub capacity: u64,
    pub tx_fee: u64,
    pub to_address: String,
    pub from_locked_address: Option<String>,
    pub to_data: Option<Bytes>,
    pub acp_config: Option<ReprAcpConfig>,
}

impl HttpTransferArgs {
    pub fn into_full_args(self, privkey_path: String) -> TransferArgs {
        let capacity = HumanCapacity::from(self.capacity).to_string();
        let tx_fee = HumanCapacity::from(self.tx_fee).to_string();
        TransferArgs {
            acp_config: self.acp_config.map(Into::into),
            privkey_path: Some(privkey_path),
            from_account: None,
            from_locked_address: self.from_locked_address,
            password: None,
            derive_receiving_address_length: None,
            derive_change_address: None,
            capacity,
            tx_fee,
            to_address: self.to_address,
            to_data: self.to_data,
            is_type_id: false,
            skip_check_to_address: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetCapacityResponse {
    pub total: u64,
    pub immature: u64,
    pub dao: u64,
}
