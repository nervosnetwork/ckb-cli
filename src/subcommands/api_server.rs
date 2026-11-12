use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ckb_crypto::secp::SECP256K1;
use ckb_sdk::{Address, AddressPayload, HumanCapacity, NetworkType};
use ckb_types::{bytes::Bytes, packed::Script, prelude::*, H256};
use clap::{App, Arg, ArgMatches};
use jsonrpc_core::{Error as RpcError, ErrorCode as RpcErrorCode, IoHandler, Result as RpcResult};
use jsonrpc_derive::rpc;
use jsonrpc_http_server::hyper::{self, header, Body, Method, StatusCode};
use jsonrpc_http_server::{RequestMiddleware, RequestMiddlewareAction, Server, ServerBuilder};
use jsonrpc_server_utils::cors::AccessControlAllowOrigin;
use jsonrpc_server_utils::hosts::DomainsValidation;
use serde::{Deserialize, Serialize};

use super::{CliSubCommand, Output, TransferArgs, WalletSubCommand};
use crate::plugin::PluginManager;
use crate::utils::{
    arg,
    arg_parser::{AddressParser, ArgParser, FromStrParser, PrivkeyPathParser, PrivkeyWrapper},
    genesis_info::GenesisInfo,
    other::{get_genesis_info, get_network_type},
    rpc::HttpRpcClient,
};

pub struct ApiServerSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    plugin_mgr: Option<PluginManager>,
    genesis_info: Option<GenesisInfo>,
}

impl<'a> ApiServerSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        plugin_mgr: PluginManager,
        genesis_info: Option<GenesisInfo>,
    ) -> ApiServerSubCommand<'a> {
        ApiServerSubCommand {
            rpc_client,
            plugin_mgr: Some(plugin_mgr),
            genesis_info,
        }
    }

    pub fn subcommand(name: &'static str) -> App<'static> {
        App::new(name)
            .about("Start advanced API server")
            .arg(
                Arg::with_name("listen")
                    .long("listen")
                    .takes_value(true)
                    .default_value("127.0.0.1:3000")
                    .validator(|input| FromStrParser::<SocketAddr>::new().validate(input))
                    .about("Rpc server listen address (when --privkey-path is given ip MUST be 127.0.0.1)"),
            )
            .arg(
                arg::privkey_path()
                 .about("Private key file path (only read first line)")
            )
            .arg(
                Arg::with_name("auth-token")
                    .long("auth-token")
                    .takes_value(true)
                    .required(true)
                    .validator(validate_auth_token)
                    .about("Token that clients must send in the `Authorization: Bearer <token>` header"),
            )
    }
}

impl CliSubCommand for ApiServerSubCommand<'_> {
    fn process(&mut self, matches: &ArgMatches, _debug: bool) -> Result<Output, String> {
        let listen_addr: SocketAddr =
            FromStrParser::<SocketAddr>::new().from_matches(matches, "listen")?;
        let privkey_path: Option<String> = matches.value_of("privkey-path").map(Into::into);
        let auth_token = matches.value_of("auth-token").unwrap();

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
            Address::new(network, payload, false).to_string()
        });

        let mut io_handler = IoHandler::new();
        let handler = ApiRpcImpl {
            rpc_client: Arc::new(Mutex::new(HttpRpcClient::new(
                self.rpc_client.url().to_string(),
            ))),
            plugin_mgr: Arc::new(Mutex::new(self.plugin_mgr.take().unwrap())),
            genesis_info: Arc::new(Mutex::new(self.genesis_info.clone())),
            privkey_path,
        };
        io_handler.extend_with(handler.to_delegate());

        thread::sleep(Duration::from_millis(200));
        log::info!("Node rpc server: {}", self.rpc_client.url());
        log::info!("Network: {:?}", network_result);
        log::info!("Wallet address: {:?}", address_opt);
        log::info!("Listen on {}", listen_addr);
        RpcServer::start(&listen_addr, io_handler, auth_token).wait();
        Ok(Output::new_error(serde_json::json!({
            "status": "stopped",
        })))
    }
}

struct RpcServer {
    server: Server,
}

impl RpcServer {
    fn start(listen_addr: &SocketAddr, io_handler: IoHandler, auth_token: &str) -> RpcServer {
        let server = ServerBuilder::new(io_handler)
            .cors(DomainsValidation::AllowOnly(vec![
                AccessControlAllowOrigin::Null,
                AccessControlAllowOrigin::Any,
            ]))
            .threads(2)
            .max_request_body_size(50 * 1024 * 1024)
            .request_middleware(AuthTokenMiddleware::new(auth_token))
            .start_http(listen_addr)
            .expect("Jsonrpc initialize");
        RpcServer { server }
    }

    fn wait(self) {
        self.server.wait()
    }
}

fn validate_auth_token(token: &str) -> Result<(), String> {
    if !token.is_empty() && token.bytes().all(|byte| byte.is_ascii_graphic()) {
        Ok(())
    } else {
        Err("auth-token must be non-empty printable ASCII without spaces".to_string())
    }
}

/// Rejects requests without the expected `Authorization: Bearer <token>` header.
///
/// Browsers send CORS preflight requests without this header, and these requests don't run any
/// RPC method, so `OPTIONS` requests are passed through.
struct AuthTokenMiddleware {
    expected_header: Vec<u8>,
}

impl AuthTokenMiddleware {
    fn new(token: &str) -> Self {
        Self {
            expected_header: format!("Bearer {}", token).into_bytes(),
        }
    }

    fn is_authorized(&self, request: &hyper::Request<Body>) -> bool {
        request
            .headers()
            .get(header::AUTHORIZATION)
            .is_some_and(|value| constant_time_eq(value.as_bytes(), &self.expected_header))
    }
}

impl RequestMiddleware for AuthTokenMiddleware {
    fn on_request(&self, request: hyper::Request<Body>) -> RequestMiddlewareAction {
        if request.method() == Method::OPTIONS || self.is_authorized(&request) {
            return request.into();
        }
        hyper::Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "Bearer")
            .body(Body::from("Invalid or missing auth token\n"))
            .expect("valid response")
            .into()
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0, |diff, (left, right)| diff | (left ^ right))
            == 0
}

#[rpc]
pub trait ApiRpc {
    #[rpc(name = "transfer")]
    fn transfer(&self, _args: HttpTransferArgs) -> RpcResult<H256>;

    #[rpc(name = "get_capacity_by_address")]
    fn get_capacity_by_address(&self, _address: String) -> RpcResult<GetCapacityResponse>;

    // #[rpc(name = "get_live_cells_by_address")]
    // fn get_live_cells_by_address(
    //     &self,
    //     _address: String,
    //     _from_number_opt: Option<u64>,
    //     _to_number_opt: Option<u64>,
    //     _limit: usize,
    // ) -> RpcResult<LiveCells>;

    // #[rpc(name = "get_live_cells_by_lock_hash")]
    // fn get_live_cells_by_lock_hash(
    //     &self,
    //     _lock_hash: H256,
    //     _from_number_opt: Option<u64>,
    //     _to_number_opt: Option<u64>,
    //     _limit: usize,
    // ) -> RpcResult<LiveCells>;

    // #[rpc(name = "get_live_cells_by_type_hash")]
    // fn get_live_cells_by_type_hash(
    //     &self,
    //     _type_hash: H256,
    //     _from_number_opt: Option<u64>,
    //     _to_number_opt: Option<u64>,
    //     _limit: usize,
    // ) -> RpcResult<LiveCells>;

    // #[rpc(name = "get_live_cells_by_code_hash")]
    // fn get_live_cells_by_code_hash(
    //     &self,
    //     _code_hash: H256,
    //     _from_number_opt: Option<u64>,
    //     _to_number_opt: Option<u64>,
    //     _limit: usize,
    // ) -> RpcResult<LiveCells>;
}

struct ApiRpcImpl {
    rpc_client: Arc<Mutex<HttpRpcClient>>,
    plugin_mgr: Arc<Mutex<PluginManager>>,
    genesis_info: Arc<Mutex<Option<GenesisInfo>>>,
    privkey_path: Option<String>,
}

impl ApiRpcImpl {
    fn genesis_info(&self) -> Result<GenesisInfo, String> {
        let mut genesis_info = self.genesis_info.lock().unwrap();
        *genesis_info = Some(get_genesis_info(
            &genesis_info,
            &mut self.rpc_client.lock().unwrap(),
        )?);
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

    fn get_capacity_by_address(&self, address: String) -> RpcResult<GetCapacityResponse> {
        log::info!("[call]: get_capacity_by_address({})", address);
        let network = {
            let mut rpc_client = self.rpc_client.lock().unwrap();
            get_network_type(&mut rpc_client).map_err(internal_err)?
        };
        let address = AddressParser::default()
            .set_network(network)
            .parse(&address)
            .map_err(RpcError::invalid_params)?;
        self.with_wallet(|cmd| {
            cmd.get_capacity(vec![Script::from(address.payload())])
                .map(|(total, immature, dao)| GetCapacityResponse {
                    total,
                    immature,
                    dao,
                })
                .map_err(RpcError::invalid_params)
        })
    }

    // fn get_live_cells_by_address(
    //     &self,
    //     address: String,
    //     from_number_opt: Option<u64>,
    //     to_number_opt: Option<u64>,
    //     limit: usize,
    // ) -> RpcResult<LiveCells> {
    //     log::info!(
    //         "[call]: get_live_cells_by_address({}, {:?}, {:?}, {})",
    //         address,
    //         from_number_opt,
    //         to_number_opt,
    //         limit,
    //     );
    //     let network = {
    //         let mut rpc_client = self.rpc_client.lock().unwrap();
    //         get_network_type(&mut rpc_client).map_err(internal_err)?
    //     };
    //     let address = AddressParser::default()
    //         .set_network(network)
    //         .parse(&address)
    //         .map_err(RpcError::invalid_params)?;
    //     let lock_hash: H256 = Script::from(address.payload()).calc_script_hash().unpack();
    //     self.get_live_cells_by_lock_hash(lock_hash, from_number_opt, to_number_opt, limit)
    // }

    // fn get_live_cells_by_lock_hash(
    //     &self,
    //     lock_hash: H256,
    //     from_number_opt: Option<u64>,
    //     to_number_opt: Option<u64>,
    //     limit: usize,
    // ) -> RpcResult<LiveCells> {
    //     log::info!(
    //         "[call]: get_live_cells_by_lock_hash({:#x}, {:?}, {:?}, {})",
    //         lock_hash,
    //         from_number_opt,
    //         to_number_opt,
    //         limit,
    //     );
    //     let to_number = to_number_opt.unwrap_or(std::u64::MAX);
    //     self.with_wallet(|cmd| {
    //         cmd.get_live_cells(
    //             to_number,
    //             limit,
    //             |db, terminator| {
    //                 db.get_live_cells_by_lock(lock_hash.pack(), from_number_opt, terminator)
    //             },
    //             true,
    //         )
    //         .map(|result| result.0)
    //         .map_err(RpcError::invalid_params)
    //     })
    // }

    // fn get_live_cells_by_type_hash(
    //     &self,
    //     type_hash: H256,
    //     from_number_opt: Option<u64>,
    //     to_number_opt: Option<u64>,
    //     limit: usize,
    // ) -> RpcResult<LiveCells> {
    //     log::info!(
    //         "[call]: get_live_cells_by_type_hash({:#x}, {:?}, {:?}, {})",
    //         type_hash,
    //         from_number_opt,
    //         to_number_opt,
    //         limit,
    //     );
    //     let to_number = to_number_opt.unwrap_or(std::u64::MAX);
    //     self.with_wallet(|cmd| {
    //         cmd.get_live_cells(
    //             to_number,
    //             limit,
    //             |db, terminator| {
    //                 db.get_live_cells_by_type(type_hash.pack(), from_number_opt, terminator)
    //             },
    //             true,
    //         )
    //         .map(|result| result.0)
    //         .map_err(RpcError::invalid_params)
    //     })
    // }

    // fn get_live_cells_by_code_hash(
    //     &self,
    //     code_hash: H256,
    //     from_number_opt: Option<u64>,
    //     to_number_opt: Option<u64>,
    //     limit: usize,
    // ) -> RpcResult<LiveCells> {
    //     log::info!(
    //         "[call]: get_live_cells_by_code_hash({:#x}, {:?}, {:?}, {})",
    //         code_hash,
    //         from_number_opt,
    //         to_number_opt,
    //         limit,
    //     );
    //     let to_number = to_number_opt.unwrap_or(std::u64::MAX);
    //     self.with_wallet(|cmd| {
    //         cmd.get_live_cells(
    //             to_number,
    //             limit,
    //             |db, terminator| {
    //                 db.get_live_cells_by_code(code_hash.pack(), from_number_opt, terminator)
    //             },
    //             true,
    //         )
    //         .map(|result| result.0)
    //         .map_err(RpcError::invalid_params)
    //     })
    // }
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
    pub fee_rate: u64,
    pub to_address: String,
    pub from_locked_address: Option<String>,
    pub to_data: Option<Bytes>,
    pub force_small_change_as_fee: Option<String>,
}

impl HttpTransferArgs {
    pub fn into_full_args(self, privkey_path: String) -> TransferArgs {
        let capacity = HumanCapacity::from(self.capacity).to_string();
        let fee_rate = self.fee_rate.to_string();
        TransferArgs {
            privkey_path: Some(privkey_path),
            from_account: None,
            from_locked_address: self.from_locked_address,
            password: None,
            derive_receiving_address_length: None,
            derive_change_address: None,
            capacity,
            fee_rate,
            force_small_change_as_fee: self.force_small_change_as_fee,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TOKEN: &str = "test-token";

    // Starts a server whose `transfer` method counts its calls
    fn start_server() -> (RpcServer, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut io_handler = IoHandler::new();
        let method_calls = Arc::clone(&calls);
        io_handler.add_sync_method("transfer", move |_| {
            method_calls.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::Value::Null)
        });
        let server = RpcServer::start(&"127.0.0.1:0".parse().unwrap(), io_handler, TOKEN);
        (server, calls)
    }

    // Sends a request and returns the HTTP status code
    fn send(server: &RpcServer, method: &str, extra_headers: &[&str]) -> u16 {
        let addr = server.server.address();
        let body = r#"{"jsonrpc":"2.0","method":"transfer","params":[],"id":1}"#;
        let mut request = format!(
            "{} / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            method,
            addr,
            body.len()
        );
        for extra_header in extra_headers {
            request.push_str(extra_header);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        request.push_str(body);

        let mut stream = TcpStream::connect(addr).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response.split_whitespace().nth(1).unwrap().parse().unwrap()
    }

    #[test]
    fn test_request_without_valid_token_is_rejected() {
        let (server, calls) = start_server();

        for headers in [
            vec![],
            vec!["Authorization: Bearer wrong-token"],
            vec!["Authorization: Bearer test-token-suffix"],
            vec!["Authorization: test-token"],
            // A request from another website doesn't get through because of its origin
            vec!["Origin: https://example.com"],
            vec!["Origin: null"],
        ] {
            assert_eq!(send(&server, "POST", &headers), 401, "{:?}", headers);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_request_with_valid_token_is_processed() {
        let (server, calls) = start_server();

        assert_eq!(
            send(&server, "POST", &["Authorization: Bearer test-token"]),
            200
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_preflight_does_not_run_any_method() {
        let (server, calls) = start_server();

        assert_eq!(
            send(&server, "OPTIONS", &["Origin: https://example.com"]),
            200
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_validate_auth_token() {
        assert!(validate_auth_token(TOKEN).is_ok());
        assert!(validate_auth_token("").is_err());
        assert!(validate_auth_token("with space").is_err());
        assert!(validate_auth_token("line\nbreak").is_err());
    }

    #[test]
    fn test_auth_token_argument_is_required() {
        let without_token =
            ApiServerSubCommand::subcommand("server").try_get_matches_from(vec!["server"]);
        assert_eq!(
            without_token.unwrap_err().kind,
            clap::ErrorKind::MissingRequiredArgument
        );

        let with_token = ApiServerSubCommand::subcommand("server")
            .try_get_matches_from(vec!["server", "--auth-token", TOKEN])
            .unwrap();
        assert_eq!(with_token.value_of("auth-token"), Some(TOKEN));
        // `--listen` is optional and falls back to its default
        assert_eq!(with_token.value_of("listen"), Some("127.0.0.1:3000"));
    }
}
