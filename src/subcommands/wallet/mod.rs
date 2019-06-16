mod index;
mod util;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use bytes::Bytes;
use ckb_core::{block::Block, service::Request};
use ckb_sdk::{Address, AddressFormat, NetworkType, SECP_CODE_HASH};
use clap::{App, Arg, ArgMatches, SubCommand};
use crypto::secp::Generator;
use faster_hex::{hex_decode, hex_string};
use jsonrpc_types::BlockNumber;
use numext_fixed_hash::H256;
use secp256k1::key;
use serde_json::json;

use super::{from_matches, CliSubCommand};
use crate::utils::printer::Printable;
use ckb_sdk::{
    GenesisInfo, HttpRpcClient, LiveCellDatabase, TransferTransactionBuilder, LMDB_EXTRA_MAP_SIZE,
    MIN_SECP_CELL_CAPACITY, ONE_CKB,
};
pub use index::{
    start_index_thread, CapacityResult, IndexController, IndexRequest, IndexResponse,
    IndexThreadState, SimpleBlockInfo,
};
use util::privkey_from_file;

pub struct WalletSubCommand<'a> {
    #[allow(dead_code)]
    rpc_client: &'a mut HttpRpcClient,
    genesis_info: Option<GenesisInfo>,
    index_dir: PathBuf,
    index_controller: IndexController,
    interactive: bool,
}

impl<'a> WalletSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        genesis_info: Option<GenesisInfo>,
        index_dir: PathBuf,
        index_controller: IndexController,
        interactive: bool,
    ) -> WalletSubCommand<'a> {
        WalletSubCommand {
            rpc_client,
            genesis_info,
            index_dir,
            index_controller,
            interactive,
        }
    }

    fn genesis_info(&mut self) -> Result<GenesisInfo, String> {
        if self.genesis_info.is_none() {
            let genesis_block: Block = self
                .rpc_client
                .get_block_by_number(BlockNumber(0))
                .call()
                .map_err(|err| err.to_string())?
                .0
                .expect("Can not get genesis block?")
                .into();
            self.genesis_info = Some(GenesisInfo::from_block(&genesis_block)?);
        }
        Ok(self.genesis_info.clone().unwrap())
    }

    fn get_db(&mut self) -> Result<LiveCellDatabase, String> {
        if !self.interactive {
            Request::call(self.index_controller.sender(), IndexRequest::Kick);
            for _ in 0..600 {
                let state = self.index_controller.state().read();
                if state.is_error() || state.is_stopped() {
                    break;
                } else if !state.is_synced() {
                    thread::sleep(Duration::from_millis(100));
                }
            }
            if !self.index_controller.state().read().is_synced() {
                return Err(format!(
                    "Index database not synced({}), please try again",
                    self.index_controller.state().read().to_string(),
                ));
            }
        }
        LiveCellDatabase::from_path(
            NetworkType::TestNet,
            self.genesis_info()?.header(),
            self.index_dir.clone(),
            LMDB_EXTRA_MAP_SIZE,
        )
        .map_err(|err| err.to_string())
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
                    .about("Transfer capacity to an address (can have data)")
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
                            .help("Capacity unit, 1CKB = 10^8 shannon"),
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
                    .about("Show public information of a secp256k1 private key (from file) or public key")
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
                            .help("Get top n capacity addresses"),
                    ),
                SubCommand::with_name("db-metrics")
                    .about("Show index database metrics"),
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

                let (infos, total_capacity) = self
                    .get_db()?
                    .get_live_cell_infos(from_address.lock_script().hash().clone(), capacity);
                if total_capacity < capacity {
                    return Err(format!(
                        "Capacity not enough: {} => {}",
                        from_address.to_string(NetworkType::TestNet),
                        total_capacity,
                    ));
                }
                let tx_args = TransferTransactionBuilder {
                    from_privkey: &from_privkey,
                    from_address: &from_address,
                    from_capacity: total_capacity,
                    to_data: &to_data,
                    to_address: &to_address,
                    to_capacity: capacity,
                };
                let tx = tx_args.build(infos, self.genesis_info()?.secp_dep());
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
                let resp = serde_json::json!({
                    "capacity": self.get_db()?.get_capacity(lock_hash)
                });
                Ok(Box::new(serde_json::to_string(&resp).unwrap()))
            }
            ("get-balance", Some(m)) => {
                let address_string: String = from_matches(m, "address");
                let address = Address::from_input(NetworkType::TestNet, address_string.as_str())?;
                let lock_hash = address.lock_script().hash().clone();
                let resp = serde_json::json!({
                    "capacity": self.get_db()?.get_capacity(lock_hash)
                });
                Ok(Box::new(serde_json::to_string(&resp).unwrap()))
            }
            ("top", Some(m)) => {
                let n: usize = m
                    .value_of("number")
                    .map(|n_str| n_str.parse().unwrap())
                    .unwrap();
                let resp = serde_json::to_value(self.get_db()?.get_top_n(n))
                    .map_err(|err| err.to_string())?;
                Ok(Box::new(serde_json::to_string(&resp).unwrap()))
            }
            ("db-metrics", _) => {
                let resp = serde_json::to_value(self.get_db()?.get_metrics(None))
                    .map_err(|err| err.to_string())?;
                Ok(Box::new(serde_json::to_string(&resp).unwrap()))
            }
            _ => Err(matches.usage().to_owned()),
        }
    }
}
