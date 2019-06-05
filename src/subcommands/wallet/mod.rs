pub mod index;

use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use byteorder::{LittleEndian, WriteBytesExt};
use bytes::Bytes;
use ckb_core::{
    header::Header as CoreHeader,
    service::Request,
    transaction::{
        CellOutput as CoreCellOutput, OutPoint as CoreOutPoint,
        TransactionBuilder as CoreTransactionBuilder,
    },
    Capacity,
};
use ckb_util::RwLock;
use clap::{App, Arg, ArgMatches, SubCommand};
use crossbeam_channel::{Receiver, Sender};
use crypto::secp::{Generator, Privkey};
use faster_hex::{hex_decode, hex_string};
use hash::blake2b_256;
use jsonrpc_types::{BlockNumber, BlockView, CellOutPoint, HeaderView, Transaction, Unsigned};
use numext_fixed_hash::H256;
use secp256k1::key;
use serde_derive::{Deserialize, Serialize};
use serde_json::json;

use super::{from_matches, CliSubCommand};
use crate::utils::printer::Printable;
use crate::utils::rpc_client::HttpRpcClient;

pub use index::{
    Address, AddressFormat, IndexError, LiveCellDatabase, LiveCellInfo, NetworkType, SECP_CODE_HASH,
};

const ONE_CKB: u64 = 10000_0000;
const MIN_SECP_CELL_CAPACITY: u64 = 60 * ONE_CKB;

pub struct WalletSubCommand<'a> {
    #[allow(dead_code)]
    rpc_client: &'a mut HttpRpcClient,
    index_sender: Sender<Request<IndexRequest, IndexResponse>>,
    genesis_info: Option<GenesisInfo>,
}

impl<'a> WalletSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        index_sender: Sender<Request<IndexRequest, IndexResponse>>,
    ) -> WalletSubCommand<'a> {
        WalletSubCommand {
            rpc_client,
            index_sender,
            genesis_info: None,
        }
    }

    pub fn genesis_info(&mut self) -> &GenesisInfo {
        if self.genesis_info.is_none() {
            let genesis_block = self
                .rpc_client
                .get_block_by_number(BlockNumber(0))
                .call()
                .unwrap()
                .0
                .unwrap();
            self.genesis_info =
                Some(GenesisInfo::from_block(genesis_block).expect("Build genesis info failed"));
        }
        self.genesis_info.as_ref().unwrap()
    }

    pub fn subcommand() -> App<'static, 'static> {
        let arg_privkey = Arg::with_name("privkey-path")
            .long("privkey-path")
            .takes_value(true)
            .help("Private key file path (only read first line)");
        let arg_address = Arg::with_name("address")
            .long("address")
            .takes_value(true)
            .required(true)
            .help("Target address (see: https://github.com/nervosnetwork/ckb/wiki/Common-Address-Format)");
        SubCommand::with_name("wallet")
            .about("tranfer / query balance(with local index) / key utils")
            .subcommands(vec![
                SubCommand::with_name("transfer")
                    .about("Transfer capacity to a address (can have data)")
                    .arg(arg_privkey.clone().required(true))
                    .arg(
                        Arg::with_name("to-address")
                            .long("to-address")
                            .takes_value(true)
                            .required(true)
                            .help("Target address"),
                    )
                    .arg(
                        Arg::with_name("to-data")
                            .long("to-data")
                            .takes_value(true)
                            .help("Hex data store in target cell (optional)"),
                    )
                    .arg(
                        Arg::with_name("capacity")
                            .long("capacity")
                            .takes_value(true)
                            .required(true)
                            .help("The capacity (default unit: CKB)"),
                    )
                    .arg(
                        Arg::with_name("unit")
                            .long("unit")
                            .takes_value(true)
                            .possible_values(&["CKB", "shannon"])
                            .default_value("CKB")
                            .help("Capacity unit, 1CKB = 10^8 shanon"),
                    ),
                SubCommand::with_name("generate-key")
                    .about("Generate a random secp256k1 privkey and save to file (print block_assembler config)")
                    .arg(
                        Arg::with_name("print-privkey")
                            .long("print-privkey")
                            .help("Print privkey key (default: no)"),
                    )
                    .arg(
                        Arg::with_name("privkey-path")
                            .long("privkey-path")
                            .takes_value(true)
                            .required(true)
                            .help("Output privkey file path (content = privkey + address)"),
                    ),
                SubCommand::with_name("key-info")
                    .about("Show public information of a secp256k1 private key (file)")
                    .arg(arg_privkey.clone())
                    .arg(
                        Arg::with_name("pubkey")
                            .long("pubkey")
                            .takes_value(true)
                            .required_if("privkey-path", "")
                            .help("Public key (hex string, compressed format)"),
                    ),
                SubCommand::with_name("get-capacity")
                    .about("Get capacity by lock script hash")
                    .arg(
                        Arg::with_name("lock-hash")
                            .long("lock-hash")
                            .takes_value(true)
                            .required(true)
                            .help("Lock hash"),
                    ),
                SubCommand::with_name("get-balance")
                    .about("Get balance by address (balance is capacity)")
                    .arg(arg_address.clone()),
                SubCommand::with_name("top")
                    .about("Show top n capacity owned by lock script hash")
                    .arg(
                        Arg::with_name("number")
                            .short("n")
                            .long("number")
                            .validator(|s| {
                                let n = s.parse::<usize>().map_err(|err| err.to_string())?;
                                if n < 1 {
                                    return Err("number should large than 0".to_owned());
                                }
                                Ok(())
                            })
                            .default_value("10")
                            .takes_value(true)
                            .help("Get top n capacity addresses (default: 10)"),
                    ),
            ])
    }
}

impl<'a> CliSubCommand for WalletSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches) -> Result<Box<dyn Printable>, String> {
        match matches.subcommand() {
            ("transfer", Some(m)) => {
                let privkey_path: String = from_matches(m, "privkey-path");
                let to_address: String = from_matches(m, "to-address");
                let to_data = m.value_of("to-data");
                let mut capacity: u64 = m.value_of("capacity").unwrap().parse().unwrap();
                let unit: String = from_matches(m, "unit");

                let to_address = Address::from_input(NetworkType::TestNet, to_address.as_str())?;
                let to_data = to_data
                    .map(|data| {
                        let data_hex = if data.starts_with("0x") || data.starts_with("0X") {
                            &data[2..]
                        } else {
                            data
                        };
                        let mut data_bytes = vec![0; data_hex.len() / 2];
                        hex_decode(data_hex.as_bytes(), &mut data_bytes)
                            .map_err(|err| format!("parse to-data failed: {:?}", err))?;
                        if data_bytes.len() as u64 > capacity {
                            return Err(format!(
                                "data size exceed capacity: {} > {}",
                                data_bytes.len(),
                                capacity,
                            ));
                        }
                        Ok(Bytes::from(data_bytes))
                    })
                    .unwrap_or_else(|| Ok(Bytes::default()))?;

                if unit == "CKB" {
                    capacity *= ONE_CKB;
                }
                if capacity < MIN_SECP_CELL_CAPACITY {
                    return Err(format!(
                        "Capacity can not less than {} shannons",
                        MIN_SECP_CELL_CAPACITY
                    ));
                }
                if capacity < MIN_SECP_CELL_CAPACITY + to_data.len() as u64 {
                    return Err(format!(
                        "Capacity can not hold {} bytes of data",
                        to_data.len()
                    ));
                }

                let from_privkey = privkey_from_file(privkey_path.as_str())?;
                let from_pubkey = from_privkey.pubkey().unwrap();
                let from_address = Address::from_pubkey(AddressFormat::default(), &from_pubkey)?;

                let request = IndexRequest::GetLiveCellInfos {
                    address: from_address.clone(),
                    total_capacity: capacity,
                };
                match Request::call(&self.index_sender, request).unwrap() {
                    IndexResponse::LiveCellInfos {
                        infos,
                        total_capacity,
                        ..
                    } => {
                        if total_capacity < capacity {
                            return Err(format!(
                                "Capacity not enough: {} => {}",
                                from_address.to_string(NetworkType::TestNet),
                                total_capacity,
                            ));
                        }
                        let tx_args = TransactionArgs {
                            from_privkey: &from_privkey,
                            from_address: &from_address,
                            from_capacity: total_capacity,
                            to_data: &to_data,
                            to_address: &to_address,
                            to_capacity: capacity,
                        };
                        let tx = tx_args.build(infos, self.genesis_info().secp_dep());
                        // TODO: print when debug
                        // println!(
                        //     "[Send Transaction]:\n{}",
                        //     serde_json::to_string_pretty(&tx).unwrap()
                        // );
                        let resp = self
                            .rpc_client
                            .send_transaction(tx)
                            .call()
                            .map_err(|err| format!("Send transaction error: {:?}", err))?;
                        Ok(Box::new(serde_json::to_string(&resp).unwrap()))
                    }
                    resp => {
                        panic!("Invalid response from index db: {:?}", resp);
                    }
                }
            }
            ("generate-key", Some(m)) => {
                let (privkey, pubkey) = Generator::new()
                    .random_keypair()
                    .expect("generate random key error");
                let print_privkey = m.is_present("print-privkey");
                let privkey_path = m.value_of("privkey-path").unwrap();
                let pubkey_string = hex_string(&pubkey.serialize()).expect("encode pubkey failed");
                let address = Address::from_pubkey(AddressFormat::default(), &pubkey)?;
                let address_string = address.to_string(NetworkType::TestNet);

                if Path::new(privkey_path).exists() {
                    return Err(format!(
                        "ERROR: output path ( {} ) already exists",
                        privkey_path
                    ));
                }
                let mut file = fs::File::create(privkey_path).map_err(|err| err.to_string())?;
                file.write(format!("{}\n", privkey.to_string()).as_bytes())
                    .map_err(|err| err.to_string())?;
                file.write(format!("{}\n", address_string).as_bytes())
                    .map_err(|err| err.to_string())?;

                println!(
                    r#"Put this config in < ckb.toml >:

[block_assembler]
code_hash = "{:#x}"
args = ["{:#x}"]
"#,
                    SECP_CODE_HASH,
                    address.hash()
                );

                let mut resp = json!({
                    "pubkey": pubkey_string,
                    "address": address_string,
                    "lock_hash": address.lock_script().hash(),
                });
                if print_privkey {
                    resp.as_object_mut()
                        .unwrap()
                        .insert("privkey".to_owned(), privkey.to_string().into());
                }
                Ok(Box::new(serde_json::to_string(&resp).unwrap()))
            }
            ("key-info", Some(m)) => {
                let pubkey = m
                    .value_of("privkey-path")
                    .map(|path| {
                        privkey_from_file(path).and_then(|privkey| {
                            privkey
                                .pubkey()
                                .map_err(|err| format!("get pubkey from privkey failed, {:?}", err))
                        })
                    })
                    .unwrap_or_else(|| {
                        let mut pubkey_hex = m
                            .value_of("pubkey")
                            .ok_or_else(|| "privkey-path or pubkey not given".to_string())?;
                        if pubkey_hex.starts_with("0x") || pubkey_hex.starts_with("0X") {
                            pubkey_hex = &pubkey_hex[2..];
                        }
                        let mut pubkey_bytes = [0u8; 33];
                        hex_decode(pubkey_hex.as_bytes(), &mut pubkey_bytes)
                            .map_err(|err| format!("parse pubkey failed: {:?}", err))?;
                        key::PublicKey::from_slice(&pubkey_bytes)
                            .map(Into::into)
                            .map_err(|err| err.to_string())
                    })?;
                let pubkey_string = hex_string(&pubkey.serialize()).expect("encode pubkey failed");
                let address = Address::from_pubkey(AddressFormat::default(), &pubkey)?;
                let address_string = address.to_string(NetworkType::TestNet);

                println!(
                    r#"Put this config in < ckb.toml >:

[block_assembler]
code_hash = "{:#x}"
args = ["{:#x}"]
"#,
                    SECP_CODE_HASH,
                    address.hash()
                );

                let resp = json!({
                    "pubkey": pubkey_string,
                    "address": address_string,
                    "lock_hash": address.lock_script().hash(),
                });
                Ok(Box::new(serde_json::to_string(&resp).unwrap()))
            }
            ("get-capacity", Some(m)) => {
                let lock_hash: H256 = from_matches(m, "lock-hash");
                let resp = Request::call(&self.index_sender, IndexRequest::GetCapacity(lock_hash))
                    .unwrap();
                Ok(Box::new(serde_json::to_string(&resp).unwrap()))
            }
            ("get-balance", Some(m)) => {
                let address_string: String = from_matches(m, "address");
                let address = Address::from_input(NetworkType::TestNet, address_string.as_str())?;
                let resp =
                    Request::call(&self.index_sender, IndexRequest::GetBalance(address)).unwrap();
                Ok(Box::new(serde_json::to_string(&resp).unwrap()))
            }
            ("top", Some(m)) => {
                let n: usize = m
                    .value_of("number")
                    .map(|n_str| n_str.parse().unwrap())
                    .unwrap();
                let resp = Request::call(&self.index_sender, IndexRequest::GetTopLocks(n)).unwrap();
                Ok(Box::new(serde_json::to_string(&resp).unwrap()))
            }
            _ => Err(matches.usage().to_owned()),
        }
    }
}

pub struct GenesisInfo {
    // header: HeaderView,
    out_points: Vec<Vec<CellOutPoint>>,
}

impl GenesisInfo {
    pub fn from_block(genesis_block: BlockView) -> Result<GenesisInfo, String> {
        let mut error = None;
        let out_points = genesis_block
            .transactions
            .iter()
            .enumerate()
            .map(|(tx_index, tx)| {
                tx.inner
                    .outputs
                    .iter()
                    .enumerate()
                    .map(|(index, output)| {
                        if tx_index == 0 && index == 1 {
                            let code_hash = H256::from_slice(&blake2b_256(output.data.as_bytes()))
                                .expect("Convert to H256 error");
                            if code_hash != SECP_CODE_HASH {
                                error = Some(format!(
                                    "System secp script code hash error! found: {}, expected: {}",
                                    code_hash, SECP_CODE_HASH,
                                ));
                            }
                        }
                        CellOutPoint {
                            tx_hash: tx.hash.clone(),
                            index: Unsigned(index as u64),
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        if let Some(err) = error {
            Err(err)
        } else {
            Ok(GenesisInfo { out_points })
        }
    }

    pub fn secp_dep(&self) -> CoreOutPoint {
        CoreOutPoint {
            cell: Some(self.out_points[0][1].clone().into()),
            block_hash: None,
        }
    }
}

fn privkey_from_file(path: &str) -> Result<Privkey, String> {
    let mut content = String::new();
    let mut file = fs::File::open(path).map_err(|err| err.to_string())?;
    file.read_to_string(&mut content)
        .map_err(|err| err.to_string())?;
    let privkey_string: String = content
        .split_whitespace()
        .next()
        .map(|s| s.to_owned())
        .ok_or_else(|| "File is empty".to_string())?;
    let privkey_str = if privkey_string.starts_with("0x") || privkey_string.starts_with("0X") {
        &privkey_string[2..]
    } else {
        privkey_string.as_str()
    };
    Privkey::from_str(privkey_str.trim()).map_err(|err| err.to_string())
}

#[derive(Debug)]
pub struct TransactionArgs<'a> {
    from_privkey: &'a Privkey,
    from_address: &'a Address,
    from_capacity: u64,
    to_data: &'a Bytes,
    to_address: &'a Address,
    to_capacity: u64,
}

impl<'a> TransactionArgs<'a> {
    fn build(&self, input_infos: Vec<LiveCellInfo>, secp_dep: CoreOutPoint) -> Transaction {
        assert!(self.from_capacity >= self.to_capacity);

        let inputs = input_infos
            .iter()
            .map(|info| info.core_input())
            .collect::<Vec<_>>();

        // TODO: calculate transaction fee
        // Send to user
        let mut from_capacity = self.from_capacity;
        let mut outputs = vec![CoreCellOutput {
            capacity: Capacity::shannons(self.to_capacity),
            data: self.to_data.clone(),
            lock: self.to_address.lock_script(),
            type_: None,
        }];
        from_capacity -= self.to_capacity;

        if from_capacity > MIN_SECP_CELL_CAPACITY {
            // The rest send back to sender
            outputs.push(CoreCellOutput {
                capacity: Capacity::shannons(from_capacity),
                data: Bytes::default(),
                lock: self.from_address.lock_script(),
                type_: None,
            });
        }

        let core_tx = CoreTransactionBuilder::default()
            .inputs(inputs.clone())
            .outputs(outputs.clone())
            .dep(secp_dep.clone())
            .build();

        let pubkey = self.from_privkey.pubkey().unwrap().serialize();
        let signature = self.from_privkey.sign_recoverable(&core_tx.hash()).unwrap();
        let signature_der = signature.serialize_der();
        let mut signature_size = vec![];
        signature_size
            .write_u64::<LittleEndian>(signature_der.len() as u64)
            .unwrap();

        let witnesses = inputs
            .iter()
            .map(|_| {
                vec![
                    Bytes::from(pubkey.clone()),
                    Bytes::from(signature_der.clone()),
                    Bytes::from(signature_size.clone()),
                ]
            })
            .collect::<Vec<_>>();
        (&CoreTransactionBuilder::default()
            .inputs(inputs)
            .outputs(outputs)
            .dep(secp_dep)
            .witnesses(witnesses)
            .build())
            .into()
    }
}

pub enum IndexRequest {
    UpdateUrl(String),
    GetLiveCellInfos {
        address: Address,
        total_capacity: u64,
    },
    GetTopLocks(usize),
    GetCapacity(H256),
    GetBalance(Address),
    // GetLastHeader,
    // RebuildIndex,
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityResult {
    pub lock_hash: H256,
    pub address: Option<String>,
    pub capacity: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleBlockInfo {
    epoch: u64,
    number: u64,
    hash: H256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndexResponse {
    LiveCellInfos {
        infos: Vec<LiveCellInfo>,
        total_capacity: u64,
        last_block: SimpleBlockInfo,
    },
    TopLocks {
        capacity_list: Vec<CapacityResult>,
        last_block: SimpleBlockInfo,
    },
    Capacity {
        capacity: Option<u64>,
        // live_cell_count: Option<usize>,
        last_block: SimpleBlockInfo,
    },
    LastHeader(CoreHeader),
    Ok,
}

impl From<CoreHeader> for SimpleBlockInfo {
    fn from(header: CoreHeader) -> SimpleBlockInfo {
        SimpleBlockInfo {
            number: header.number(),
            epoch: header.epoch(),
            hash: header.hash().clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum IndexThreadState {
    // wait first request to start
    WaitToStart,
    // Started init db
    StartInit,
    // Process after init db
    Processing(SimpleBlockInfo),
    // Thread exit
    Stopped,
}

impl IndexThreadState {
    fn start_init(&mut self) {
        *self = IndexThreadState::StartInit;
    }
    fn processing(&mut self, header: CoreHeader) {
        *self = IndexThreadState::Processing(header.into());
    }
    fn stop(&mut self) {
        *self = IndexThreadState::Stopped;
    }
    pub fn is_stopped(&self) -> bool {
        match self {
            IndexThreadState::Stopped => true,
            _ => false,
        }
    }
    pub fn is_processing(&self) -> bool {
        match self {
            IndexThreadState::Processing(_) => true,
            _ => false,
        }
    }
}

impl fmt::Display for IndexThreadState {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let output = match self {
            IndexThreadState::WaitToStart => "waiting for first query".to_owned(),
            IndexThreadState::StartInit => "initializating".to_owned(),
            IndexThreadState::Processing(SimpleBlockInfo { number, .. }) => {
                format!("processed block#{}", number)
            }
            IndexThreadState::Stopped => "stopped".to_owned(),
        };
        write!(f, "{}", output)
    }
}

impl Default for IndexThreadState {
    fn default() -> IndexThreadState {
        IndexThreadState::WaitToStart
    }
}

pub struct IndexController {
    state: Arc<RwLock<IndexThreadState>>,
    sender: Sender<Request<IndexRequest, IndexResponse>>,
}

impl Clone for IndexController {
    fn clone(&self) -> IndexController {
        IndexController {
            state: Arc::clone(&self.state),
            sender: self.sender.clone(),
        }
    }
}

impl IndexController {
    pub fn state(&self) -> &Arc<RwLock<IndexThreadState>> {
        &self.state
    }
    pub fn sender(&self) -> &Sender<Request<IndexRequest, IndexResponse>> {
        &self.sender
    }
    pub fn shutdown(&self) {
        let start_time = Instant::now();
        let _ = Request::call(&self.sender, IndexRequest::Shutdown);
        while !self.state().read().is_stopped() {
            if start_time.elapsed() < Duration::from_secs(10) {
                thread::sleep(Duration::from_millis(50));
            } else {
                eprintln!("Stop index thread timeout, give up");
                return;
            }
        }
    }
}

pub fn start_index_thread(
    url: &str,
    index_dir: PathBuf,
    state: Arc<RwLock<IndexThreadState>>,
) -> IndexController {
    let mut rpc_url = url.to_owned();
    let (sender, receiver) = crossbeam_channel::bounded::<Request<IndexRequest, IndexResponse>>(1);
    let state_clone = Arc::clone(&state);

    thread::spawn(move || {
        let mut first_request = match receiver.recv() {
            Ok(request) => match request.arguments {
                IndexRequest::UpdateUrl(ref url) => {
                    rpc_url = url.clone();
                    if let Err(err) = request.responder.send(IndexResponse::Ok) {
                        log::debug!("response first change url failed {:?}", err);
                        return;
                    };
                    None
                }
                IndexRequest::Shutdown => {
                    state.write().stop();
                    return;
                }
                _ => Some(request),
            },
            Err(err) => {
                log::debug!("index db receiver error: {:?}", err);
                None
            }
        };
        state.write().start_init();
        let mut rpc_client = HttpRpcClient::from_uri(rpc_url.as_str());
        let genesis_block = rpc_client
            .get_block_by_number(BlockNumber(0))
            .call()
            .unwrap()
            .0
            .unwrap();
        let mut db =
            LiveCellDatabase::from_path(NetworkType::TestNet, &genesis_block, index_dir.clone())
                .unwrap();

        let mut last_get_tip = Instant::now();
        let mut tip_header = rpc_client.get_tip_header().call().unwrap();
        db.update_tip(tip_header.clone());

        loop {
            if last_get_tip.elapsed() > Duration::from_secs(2) {
                last_get_tip = Instant::now();
                tip_header = rpc_client.get_tip_header().call().unwrap();
                db.update_tip(tip_header.clone());
                log::debug!("Update to tip {}", tip_header.inner.number.0);
            }

            while tip_header.inner.number.0.saturating_sub(4) > db.last_number() {
                if state.read().is_processing() {
                    if try_recv(
                        &receiver,
                        &mut db,
                        &index_dir,
                        &mut tip_header,
                        &mut rpc_client,
                    ) {
                        state.write().stop();
                        break;
                    }
                }
                let next_block = rpc_client
                    .get_block_by_number(db.next_number())
                    .call()
                    .unwrap()
                    .0
                    .unwrap();
                db.apply_next_block(&next_block).expect("Add block failed");
            }

            if first_request
                .take()
                .map(|request| {
                    process_request(
                        request,
                        &mut db,
                        &index_dir,
                        &mut tip_header,
                        &mut rpc_client,
                    )
                })
                .unwrap_or(false)
            {
                break;
            }
            if try_recv(
                &receiver,
                &mut db,
                &index_dir,
                &mut tip_header,
                &mut rpc_client,
            ) {
                break;
            }
            if state.read().is_stopped() {
                break;
            } else {
                state.write().processing(db.last_header().clone());
            }

            thread::sleep(Duration::from_millis(100));
        }

        state.write().stop();
        log::info!("Index database thread stopped");
    });

    IndexController {
        state: state_clone,
        sender,
    }
}

fn try_recv(
    receiver: &Receiver<Request<IndexRequest, IndexResponse>>,
    db: &mut LiveCellDatabase,
    index_dir: &PathBuf,
    tip_header: &mut HeaderView,
    rpc_client: &mut HttpRpcClient,
) -> bool {
    match receiver.try_recv() {
        Ok(request) => process_request(request, db, index_dir, tip_header, rpc_client),
        Err(err) => {
            if err.is_disconnected() {
                log::info!("Sender dropped, exit index thread");
                true
            } else {
                false
            }
        }
    }
}

fn process_request(
    request: Request<IndexRequest, IndexResponse>,
    db: &mut LiveCellDatabase,
    index_dir: &PathBuf,
    tip_header: &mut HeaderView,
    rpc_client: &mut HttpRpcClient,
) -> bool {
    let Request {
        responder,
        arguments,
    } = request;
    match arguments {
        IndexRequest::UpdateUrl(url) => {
            *rpc_client = HttpRpcClient::from_uri(url.as_str());
            let genesis_block = rpc_client
                .get_block_by_number(BlockNumber(0))
                .call()
                .unwrap()
                .0
                .unwrap();
            *db = LiveCellDatabase::from_path(
                NetworkType::TestNet,
                &genesis_block,
                index_dir.clone(),
            )
            .unwrap();
            *tip_header = rpc_client.get_tip_header().call().unwrap();
            db.update_tip(tip_header.clone());
            responder.send(IndexResponse::Ok).is_err()
        }
        IndexRequest::GetLiveCellInfos {
            address,
            total_capacity,
        } => {
            let lock_hash = address.lock_script().hash();
            let (infos, total_capacity) = db.get_live_cell_infos(lock_hash, total_capacity);
            responder
                .send(IndexResponse::LiveCellInfos {
                    infos,
                    total_capacity,
                    last_block: db.last_header().clone().into(),
                })
                .is_err()
        }
        IndexRequest::GetTopLocks(n) => responder
            .send(IndexResponse::TopLocks {
                capacity_list: db
                    .get_top_n(n)
                    .into_iter()
                    .map(|(lock_hash, address, capacity)| {
                        let address = address.map(|addr| addr.to_string(NetworkType::TestNet));
                        CapacityResult {
                            lock_hash,
                            address,
                            capacity,
                        }
                    })
                    .collect::<Vec<_>>(),
                last_block: db.last_header().clone().into(),
            })
            .is_err(),

        IndexRequest::GetCapacity(lock_hash) => {
            responder
                .send(IndexResponse::Capacity {
                    capacity: db.get_capacity(lock_hash),
                    // live_cell_count: result.map(|value| value.1),
                    last_block: db.last_header().clone().into(),
                })
                .is_err()
        }
        IndexRequest::GetBalance(address) => {
            let lock_hash = address.lock_script().hash();
            responder
                .send(IndexResponse::Capacity {
                    capacity: db.get_capacity(lock_hash),
                    // live_cell_count: result.map(|value| value.1),
                    last_block: db.last_header().clone().into(),
                })
                .is_err()
        }

        // IndexRequest::GetLastHeader => responder
        //     .send(IndexResponse::LastHeader(db.last_header().clone()))
        //     .is_err(),
        // IndexRequest::RebuildIndex => responder.send(IndexResponse::Ok).is_err(),
        IndexRequest::Shutdown => {
            let _ = responder.send(IndexResponse::Ok);
            log::info!("Received shutdown message");
            true
        }
    }
}
