pub mod index;

use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use byteorder::{LittleEndian, WriteBytesExt};
use bytes::Bytes;
use ckb_core::{
    service::Request,
    transaction::{
        CellOutput as CoreCellOutput, OutPoint as CoreOutPoint,
        TransactionBuilder as CoreTransactionBuilder,
    },
    Capacity,
};
use clap::{App, Arg, ArgMatches, SubCommand};
use crossbeam_channel::{Receiver, Sender};
use crypto::secp::Privkey;
use hash::blake2b_256;
use jsonrpc_types::{BlockNumber, BlockView, CellOutPoint, HeaderView, Transaction, Unsigned};
use numext_fixed_hash::H256;
use serde_derive::{Deserialize, Serialize};

use super::{from_matches, CliSubCommand};
use crate::utils::printer::Printable;
use crate::utils::rpc_client::HttpRpcClient;

pub use index::{
    Address, AddressFormat, IndexError, NetworkType, SecpUtxoInfo, UtxoDatabase, SECP_CODE_HASH,
};

const ONE_CKB: u64 = 10 ^ 8;
const MIN_CELL_CAPACITY: u64 = 40 * ONE_CKB;

pub struct WalletSubCommand<'a> {
    #[allow(dead_code)]
    rpc_client: &'a mut HttpRpcClient,
    index_sender: &'a Sender<Request<IndexRequest, IndexResponse>>,
    genesis_info: Option<GenesisInfo>,
}

impl<'a> WalletSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        index_sender: &'a Sender<Request<IndexRequest, IndexResponse>>,
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
        let arg_address = Arg::with_name("address")
            .long("address")
            .takes_value(true)
            .required(true)
            .help("Target address");
        SubCommand::with_name("wallet").subcommands(vec![
            SubCommand::with_name("transfer")
                .arg(
                    Arg::with_name("privkey")
                        .long("privkey")
                        .takes_value(true)
                        .required(true)
                        .help("Private key file path"),
                )
                .arg(
                    Arg::with_name("to-address")
                        .long("to-address")
                        .takes_value(true)
                        .required(true)
                        .help("Target address"),
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
            SubCommand::with_name("get-balance").arg(arg_address.clone()),
            SubCommand::with_name("top").arg(
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
                let privkey_path: String = from_matches(m, "privkey");
                let to_address: String = from_matches(m, "to-address");
                let mut capacity: u64 = m.value_of("capacity").unwrap().parse().unwrap();
                let unit: String = from_matches(m, "unit");

                let mut privkey_string = String::new();
                let mut file = fs::File::open(privkey_path).map_err(|err| err.to_string())?;
                file.read_to_string(&mut privkey_string)
                    .map_err(|err| err.to_string())?;
                let from_privkey =
                    Privkey::from_str(privkey_string.trim()).map_err(|err| err.to_string())?;
                let to_address = Address::from_input(NetworkType::TestNet, to_address.as_str())?;

                if unit == "CKB" {
                    capacity *= ONE_CKB;
                }

                let from_pubkey = from_privkey.pubkey().unwrap();
                let from_address = Address::from_pubkey(AddressFormat::default(), &from_pubkey)?;

                let request = IndexRequest::GetUtxoInfos {
                    address: from_address.clone(),
                    total_capacity: capacity + MIN_CELL_CAPACITY,
                };
                match Request::call(&self.index_sender, request).unwrap() {
                    IndexResponse::UtxoInfos {
                        infos,
                        total_capacity,
                        ..
                    } => {
                        println!("Got infos: {:?}", infos);
                        let total_capacity = total_capacity.unwrap_or(0);
                        if total_capacity < capacity + MIN_CELL_CAPACITY {
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
                            to_address: &to_address,
                            to_capacity: capacity,
                        };
                        let tx = tx_args.build(infos, self.genesis_info().secp_dep());
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
                let resp =
                    Request::call(&self.index_sender, IndexRequest::GetTopAddresses(n)).unwrap();
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

pub struct TransactionArgs<'a> {
    from_privkey: &'a Privkey,
    from_address: &'a Address,
    from_capacity: u64,
    to_address: &'a Address,
    to_capacity: u64,
}

impl<'a> TransactionArgs<'a> {
    fn build(&self, input_infos: Vec<Arc<SecpUtxoInfo>>, secp_dep: CoreOutPoint) -> Transaction {
        assert!(self.from_capacity >= self.to_capacity + MIN_CELL_CAPACITY);

        let inputs = input_infos
            .iter()
            .map(|info| info.core_input())
            .collect::<Vec<_>>();

        // TODO: calculate transaction fee
        // Send to user
        let mut from_capacity = self.from_capacity;
        let mut outputs = vec![CoreCellOutput {
            capacity: Capacity::shannons(self.to_capacity),
            data: Bytes::default(),
            lock: self.to_address.lock_script(),
            type_: None,
        }];
        from_capacity -= self.to_capacity;
        from_capacity -= MIN_CELL_CAPACITY;

        if from_capacity > MIN_CELL_CAPACITY {
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
    GetUtxoInfos {
        address: Address,
        total_capacity: u64,
    },
    GetTopAddresses(usize),
    GetBalance(Address),
    GetLastHeader,
    RebuildIndex,
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndexResponse {
    UtxoInfos {
        infos: Vec<Arc<SecpUtxoInfo>>,
        total_capacity: Option<u64>,
        last_header: HeaderView,
    },
    TopAddresses {
        capacity_list: Vec<(Address, u64)>,
        last_header: HeaderView,
    },
    Balance {
        capacity: Option<u64>,
        utxo_count: Option<usize>,
        last_header: HeaderView,
    },
    LastHeader(HeaderView),
    Ok,
}

impl IndexResponse {
    fn is_ok(&self) -> bool {
        match self {
            IndexResponse::Ok => true,
            _ => false,
        }
    }
}

pub fn start_index_thread(
    url: &str,
    index_file: PathBuf,
    db_ready: Arc<AtomicBool>,
) -> Sender<Request<IndexRequest, IndexResponse>> {
    let url = url.to_owned();
    let (sender, receiver) = crossbeam_channel::bounded(1);

    thread::spawn(move || {
        let mut rpc_client = HttpRpcClient::from_uri(url.as_str());
        let genesis_block = rpc_client
            .get_block_by_number(BlockNumber(0))
            .call()
            .unwrap()
            .0
            .unwrap();
        let mut db = if index_file.as_path().exists() {
            match UtxoDatabase::from_file(&index_file, &genesis_block) {
                Ok(db) => db,
                Err(err) => {
                    log::info!("Index database broken: {:?}", err);
                    UtxoDatabase::from_fresh(NetworkType::TestNet, &genesis_block)
                }
            }
        } else {
            UtxoDatabase::from_fresh(NetworkType::TestNet, &genesis_block)
        };

        let mut removed_in_loop = 0;
        let mut added_in_loop = 0;
        let mut last_get_tip = Instant::now();
        let mut last_saved_number = db.last_number();
        let mut tip_header = rpc_client.get_tip_header().call().unwrap();
        db.update_tip(tip_header.clone());

        loop {
            if last_get_tip.elapsed() > Duration::from_secs(2) {
                last_get_tip = Instant::now();
                tip_header = rpc_client.get_tip_header().call().unwrap();
                db.update_tip(tip_header.clone());
                log::debug!("Update to tip {}", tip_header.inner.number.0);
            }

            while tip_header.inner.number.0 - 4 > db.last_number() {
                if try_recv(&receiver, &mut db) {
                    break;
                }
                let next_block = rpc_client
                    .get_block_by_number(db.next_number())
                    .call()
                    .unwrap()
                    .0
                    .unwrap();
                let (removed_in_block, added_in_block) =
                    db.apply_next_block(&next_block).expect("Add block failed");
                removed_in_loop += removed_in_block;
                added_in_loop += added_in_block;
            }
            db_ready.store(true, Ordering::SeqCst);
            if try_recv(&receiver, &mut db) {
                break;
            }

            // TODO: the saving logic is wrong
            log::debug!("> Height not enought, waiting...");
            if tip_header.inner.number.0 - last_saved_number > 100 {
                log::info!(
                    "{} utxo removed, {} utxo added, saving to file",
                    removed_in_loop,
                    added_in_loop,
                );

                db.save_to_file(&index_file).unwrap();

                removed_in_loop = 0;
                added_in_loop = 0;
                last_saved_number = db.last_number();
                log::info!("saving index finished");
            }
            thread::sleep(Duration::from_millis(100));
        }
        log::info!("Index database thread stopped");
    });
    sender
}

fn try_recv(
    receiver: &Receiver<Request<IndexRequest, IndexResponse>>,
    db: &mut UtxoDatabase,
) -> bool {
    match receiver.try_recv() {
        Ok(Request {
            responder,
            arguments,
        }) => match arguments {
            IndexRequest::GetUtxoInfos {
                address,
                total_capacity,
            } => {
                let (infos, total_capacity_opt) = db.get_utxo_infos(&address, total_capacity);
                responder
                    .send(IndexResponse::UtxoInfos {
                        infos,
                        total_capacity: total_capacity_opt,
                        last_header: db.last_header().clone(),
                    })
                    .is_err()
            }
            IndexRequest::GetTopAddresses(n) => responder
                .send(IndexResponse::TopAddresses {
                    capacity_list: db.get_top_n(n),
                    last_header: db.last_header().clone(),
                })
                .is_err(),
            IndexRequest::GetBalance(address) => {
                let result = db.get_balance(&address);
                responder
                    .send(IndexResponse::Balance {
                        capacity: result.map(|value| value.0),
                        utxo_count: result.map(|value| value.1),
                        last_header: db.last_header().clone(),
                    })
                    .is_err()
            }
            IndexRequest::GetLastHeader => responder
                .send(IndexResponse::LastHeader(db.last_header().clone()))
                .is_err(),
            IndexRequest::RebuildIndex => responder.send(IndexResponse::Ok).is_err(),
            IndexRequest::Shutdown => {
                let _ = responder.send(IndexResponse::Ok);
                log::info!("Received shutdown message");
                true
            }
        },
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
