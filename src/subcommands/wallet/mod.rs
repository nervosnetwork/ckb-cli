mod index;

use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use bytes::Bytes;
use ckb_core::{block::Block, service::Request};
use clap::{App, Arg, ArgMatches, SubCommand};
use crypto::secp::SECP256K1;
use faster_hex::hex_string;
use hash::blake2b_256;
use jsonrpc_types::BlockNumber;
use numext_fixed_hash::{H160, H256};
use serde_json::json;

use super::CliSubCommand;
use crate::utils::{
    arg_parser::{
        AddressParser, ArgParser, CapacityParser, FilePathParser, FixedHashParser, FromStrParser,
        HexParser, PrivkeyPathParser, PubkeyHexParser,
    },
    other::read_password,
    printer::{OutputFormat, Printable},
};
use ckb_sdk::{
    build_witness_with_key, serialize_signature,
    wallet::{KeyStore, KeyStoreError},
    with_index_db, Address, AddressFormat, GenesisInfo, HttpRpcClient, IndexDatabase, LiveCellInfo,
    NetworkType, TransferTransactionBuilder, MIN_SECP_CELL_CAPACITY, ONE_CKB,
};
pub use index::{
    start_index_thread, CapacityResult, IndexController, IndexRequest, IndexResponse,
    IndexThreadState, SimpleBlockInfo,
};

pub struct WalletSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    key_store: &'a mut KeyStore,
    genesis_info: Option<GenesisInfo>,
    index_dir: PathBuf,
    index_controller: IndexController,
    interactive: bool,
}

impl<'a> WalletSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        key_store: &'a mut KeyStore,
        genesis_info: Option<GenesisInfo>,
        index_dir: PathBuf,
        index_controller: IndexController,
        interactive: bool,
    ) -> WalletSubCommand<'a> {
        WalletSubCommand {
            rpc_client,
            key_store,
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

    fn with_db<F, T>(&mut self, func: F) -> Result<T, String>
    where
        F: FnOnce(IndexDatabase) -> T,
    {
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

        let genesis_info = self.genesis_info()?;
        let genesis_hash = genesis_info.header().hash().clone();
        with_index_db(&self.index_dir, genesis_hash, |backend, cf| {
            let db =
                IndexDatabase::from_db(backend, cf, NetworkType::TestNet, genesis_info, false)?;
            Ok(func(db))
        })
        .map_err(|err| err.to_string())
    }

    pub fn subcommand() -> App<'static, 'static> {
        let arg_privkey = Arg::with_name("privkey-path")
            .long("privkey-path")
            .takes_value(true)
            .validator(|input| PrivkeyPathParser.validate(input))
            .help("Private key file path (only read first line)");
        let arg_pubkey = Arg::with_name("pubkey")
            .long("pubkey")
            .takes_value(true)
            .validator(|input| PubkeyHexParser.validate(input))
            .help("Public key (hex string, compressed format)");
        let arg_address = Arg::with_name("address")
            .long("address")
            .takes_value(true)
            .validator(|input| AddressParser.validate(input))
            .required(true)
            .help("Target address (see: https://github.com/nervosnetwork/ckb/wiki/Common-Address-Format)");
        let arg_lock_hash = Arg::with_name("lock-hash")
            .long("lock-hash")
            .takes_value(true)
            .validator(|input| FixedHashParser::<H256>::default().validate(input))
            .required(true)
            .help("Lock hash");
        let arg_lock_arg = Arg::with_name("lock-arg")
            .long("lock-arg")
            .takes_value(true)
            .validator(|input| FixedHashParser::<H160>::default().validate(input))
            .help("Lock argument (account identifier, blake2b(pubkey)[0..20])");
        SubCommand::with_name("wallet")
            .about("tranfer / query balance(with local index) / key utils")
            .subcommands(vec![
                SubCommand::with_name("transfer")
                    .about("Transfer capacity to an address (can have data)")
                    .arg(arg_privkey.clone().required_unless("from-account"))
                    .arg(
                        Arg::with_name("from-account")
                            .long("from-account")
                            .required_unless("privkey-path")
                            .takes_value(true)
                            .validator(|input| FixedHashParser::<H160>::default().validate(input))
                            .help("The account's lock-arg (transfer from this account)")
                    )
                    .arg(
                        Arg::with_name("to-address")
                            .long("to-address")
                            .takes_value(true)
                            .validator(|input| AddressParser.validate(input))
                            .required(true)
                            .help("Target address"),
                    )
                    .arg(
                        Arg::with_name("to-data")
                            .long("to-data")
                            .takes_value(true)
                            .validator(|input| HexParser.validate(input))
                            .help("Hex data store in target cell (optional)"),
                    )
                    .arg(
                        Arg::with_name("to-data-path")
                            .long("to-data-path")
                            .takes_value(true)
                            .validator(|input| FilePathParser::new(true).validate(input))
                            .help("Data binary file path store in target cell (optional)"),
                    )
                    .arg(
                        Arg::with_name("capacity")
                            .long("capacity")
                            .takes_value(true)
                            .validator(|input| CapacityParser.validate(input))
                            .required(true)
                            .help("The capacity (unit: CKB, format: 123.335)"),
                    )
                    .arg(
                        Arg::with_name("with-password")
                            .long("with-password")
                            .help("Input password to unlock keystore account just for current transfer transaction")
                    )
                    ,
                SubCommand::with_name("key-info")
                    .about("Show public information of a secp256k1 private key (from file) or public key")
                    .arg(arg_privkey.clone().conflicts_with("pubkey"))
                    .arg(arg_pubkey.clone().required(false))
                    .arg(arg_address.clone().required(false))
                    .arg(arg_lock_arg.clone()),
                SubCommand::with_name("get-capacity")
                    .about("Get capacity by lock script hash or address or lock arg or pubkey")
                    .arg(arg_lock_hash.clone().required(false))
                    .arg(arg_address.clone().required(false))
                    .arg(arg_pubkey.clone())
                    .arg(arg_lock_arg.clone()),
                SubCommand::with_name("get-live-cells")
                    .about("Get live cells by lock/type/code  hash")
                    .arg(arg_lock_hash.clone().required(false))
                    .arg(
                        Arg::with_name("type-hash")
                            .long("type-hash")
                            .takes_value(true)
                            .validator(|input| FixedHashParser::<H256>::default().validate(input))
                            .help("The type script hash")
                    )
                    .arg(
                        Arg::with_name("code-hash")
                            .long("code-hash")
                            .takes_value(true)
                            .validator(|input| FixedHashParser::<H256>::default().validate(input))
                            .help("The type script's code hash")
                    )
                    .arg(
                        Arg::with_name("limit")
                            .long("limit")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<usize>::default().validate(input))
                            .default_value("15")
                            .help("Get live cells <= limit")
                    )
                    .arg(
                        Arg::with_name("from")
                            .long("from")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<u64>::default().validate(input))
                            .help("From block number"),
                    )
                    .arg(
                        Arg::with_name("to")
                            .long("to")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<u64>::default().validate(input))
                            .help("To block number"),
                    ),
                // Move to index subcommand
                SubCommand::with_name("get-lock-by-address")
                    .about("Get lock script (include hash) by address")
                    .arg(arg_address.clone()),
                // Move to index subcommand
                SubCommand::with_name("db-metrics")
                    .about("Show index database metrics"),
                SubCommand::with_name("top-capacity")
                    .about("Show top n capacity owned by lock script hash")
                    .arg(
                        Arg::with_name("number")
                            .short("n")
                            .long("number")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<u32>::default().validate(input))
                            .default_value("10")
                            .help("Get top n capacity addresses"),
                    ),
            ])
    }
}

impl<'a> CliSubCommand for WalletSubCommand<'a> {
    fn process(
        &mut self,
        matches: &ArgMatches,
        format: OutputFormat,
        color: bool,
    ) -> Result<String, String> {
        fn get_address(m: &ArgMatches) -> Result<Address, String> {
            let address: Option<Address> = AddressParser.from_matches_opt(m, "address", false)?;
            let pubkey: Option<secp256k1::PublicKey> =
                PubkeyHexParser.from_matches_opt(m, "pubkey", false)?;
            let lock_arg: Option<H160> =
                FixedHashParser::<H160>::default().from_matches_opt(m, "lock-arg", false)?;
            let address = address
                .or_else(|| {
                    pubkey.map(|pubkey| {
                        Address::from_pubkey(AddressFormat::default(), &pubkey.into()).unwrap()
                    })
                })
                .or_else(|| lock_arg.map(|lock_arg| Address::from_lock_arg(&lock_arg[..]).unwrap()))
                .ok_or_else(|| "Please give one argument".to_owned())?;
            Ok(address)
        }

        match matches.subcommand() {
            ("transfer", Some(m)) => {
                let from_privkey: Option<secp256k1::SecretKey> =
                    PrivkeyPathParser.from_matches_opt(m, "privkey-path", false)?;
                let from_account: Option<H160> = FixedHashParser::<H160>::default()
                    .from_matches_opt(m, "from-account", false)?;
                let to_address: Address = AddressParser.from_matches(m, "to-address")?;
                let to_data_opt: Option<Bytes> = HexParser.from_matches_opt(m, "to-data", false)?;
                let capacity: u64 = CapacityParser.from_matches(m, "capacity")?;

                let to_data = match to_data_opt {
                    Some(data) => data,
                    None => {
                        if let Some(path) = m.value_of("to-data-path") {
                            let mut content = Vec::new();
                            let mut file = fs::File::open(path).map_err(|err| err.to_string())?;
                            file.read_to_end(&mut content)
                                .map_err(|err| err.to_string())?;
                            Bytes::from(content)
                        } else {
                            Bytes::new()
                        }
                    }
                };

                if capacity < MIN_SECP_CELL_CAPACITY {
                    return Err(format!(
                        "Capacity can not less than {} shannons",
                        MIN_SECP_CELL_CAPACITY
                    ));
                }
                if capacity < MIN_SECP_CELL_CAPACITY + (to_data.len() as u64 * ONE_CKB) {
                    return Err(format!(
                        "Capacity can not hold {} bytes of data",
                        to_data.len()
                    ));
                }

                let from_address = if let Some(from_privkey) = from_privkey {
                    let from_pubkey =
                        secp256k1::PublicKey::from_secret_key(&SECP256K1, &from_privkey);
                    let pubkey_hash = blake2b_256(&from_pubkey.serialize()[..]);
                    Address::from_lock_arg(&pubkey_hash[0..20])?
                } else {
                    Address::from_lock_arg(&from_account.as_ref().unwrap()[..])?
                };

                let genesis_info = self.genesis_info()?;
                let secp_code_hash = genesis_info.secp_code_hash();
                let (infos, total_capacity): (Vec<LiveCellInfo>, u64) = self.with_db(|db| {
                    let mut total_capacity = 0;
                    let infos = db.get_live_cells_by_lock(
                        from_address
                            .lock_script(secp_code_hash.clone())
                            .hash()
                            .clone(),
                        None,
                        |_, info| {
                            total_capacity += info.capacity;
                            let stop = total_capacity >= capacity;
                            (stop, true)
                        },
                    );
                    (infos, total_capacity)
                })?;
                if total_capacity < capacity {
                    return Err(format!(
                        "Capacity not enough: {} => {}",
                        from_address.to_string(NetworkType::TestNet),
                        total_capacity,
                    ));
                }
                let tx_args = TransferTransactionBuilder {
                    from_address: &from_address,
                    from_capacity: total_capacity,
                    to_data: &to_data,
                    to_address: &to_address,
                    to_capacity: capacity,
                };
                let tx = if let Some(privkey) = from_privkey {
                    tx_args.build(infos, &genesis_info, |tx_hash| {
                        Ok(build_witness_with_key(&privkey, tx_hash))
                    })?
                } else {
                    let lock_arg = from_account.as_ref().unwrap();
                    tx_args.build(infos, &genesis_info, |tx_hash| {
                        let sign_hash = H256::from_slice(&blake2b_256(tx_hash))
                            .expect("Tx hash convert to H256 failed");
                        let signature_result = if self.interactive && !m.is_present("with-password") {
                            self.key_store
                                .sign_recoverable(lock_arg, &sign_hash)
                                .map_err(|err| {
                                    match err {
                                        KeyStoreError::AccountLocked(lock_arg) => {
                                            format!("Account(lock_arg={:x}) locked or not exists, your may use `account unlock` to unlock it or use --with-password", lock_arg)
                                        }
                                        err => err.to_string(),
                                    }
                                })
                        } else {
                            let password = read_password(false, None)?;
                            self.key_store
                                .sign_recoverable_with_password(lock_arg, &sign_hash, password.as_bytes())
                                .map_err(|err| err.to_string())
                        };
                        signature_result.map(|signature| serialize_signature(&signature))
                    })?
                };
                // let tx_view: TransactionView = (&Into::<Transaction>::into(tx.clone())).into();
                // println!("[Send Transaction]:\n{}", tx_view.render(format, color));
                let resp = self
                    .rpc_client
                    .send_transaction(tx)
                    .call()
                    .map_err(|err| format!("Send transaction error: {}", err))?;
                Ok(resp.render(format, color))
            }
            ("key-info", Some(m)) => {
                let privkey_opt: Option<secp256k1::SecretKey> =
                    PrivkeyPathParser.from_matches_opt(m, "privkey-path", false)?;
                let pubkey_opt: Option<secp256k1::PublicKey> =
                    PubkeyHexParser.from_matches_opt(m, "pubkey", false)?;
                let pubkey_opt = privkey_opt
                    .map(|privkey| secp256k1::PublicKey::from_secret_key(&SECP256K1, &privkey))
                    .or_else(|| pubkey_opt);
                let pubkey_string_opt = pubkey_opt.as_ref().map(|pubkey| {
                    hex_string(&pubkey.serialize()[..]).expect("encode pubkey failed")
                });
                let address = match pubkey_opt {
                    Some(pubkey) => {
                        let pubkey_hash = blake2b_256(&pubkey.serialize()[..]);
                        Address::from_lock_arg(&pubkey_hash[0..20])?
                    }
                    None => get_address(m)?,
                };

                let genesis_info = self.genesis_info()?;
                let secp_code_hash = genesis_info.secp_code_hash();
                println!(
                    r#"Put this config in < ckb.toml >:

[block_assembler]
code_hash = "{:#x}"
args = ["{:#x}"]
"#,
                    secp_code_hash,
                    address.hash()
                );

                let resp = json!({
                    "pubkey": pubkey_string_opt,
                    "address": {
                        "testnet": address.to_string(NetworkType::TestNet),
                        "mainnet": address.to_string(NetworkType::MainNet),
                    },
                    "lock_arg": format!("{:x}", address.hash()),
                    "lock_hash": address.lock_script(secp_code_hash.clone()).hash(),
                });
                Ok(resp.render(format, color))
            }
            ("get-capacity", Some(m)) => {
                let lock_hash_opt: Option<H256> =
                    FixedHashParser::<H256>::default().from_matches_opt(m, "lock-hash", false)?;
                let lock_hash = if let Some(lock_hash) = lock_hash_opt {
                    lock_hash
                } else {
                    let secp_code_hash = self.genesis_info()?.secp_code_hash().clone();
                    let address = get_address(m)?;
                    address.lock_script(secp_code_hash).hash().clone()
                };
                let capacity = self.with_db(|db| db.get_capacity(lock_hash))?;
                let resp = serde_json::json!({
                    "capacity": capacity,
                });
                Ok(resp.render(format, color))
            }
            ("get-live-cells", Some(m)) => {
                let lock_hash_opt: Option<H256> =
                    FixedHashParser::<H256>::default().from_matches_opt(m, "lock-hash", false)?;
                let type_hash_opt: Option<H256> =
                    FixedHashParser::<H256>::default().from_matches_opt(m, "type-hash", false)?;
                let code_hash_opt: Option<H256> =
                    FixedHashParser::<H256>::default().from_matches_opt(m, "code-hash", false)?;
                let limit: usize = FromStrParser::<usize>::default().from_matches(m, "limit")?;
                let from_number_opt: Option<u64> =
                    FromStrParser::<u64>::default().from_matches_opt(m, "from", false)?;
                let to_number_opt: Option<u64> =
                    FromStrParser::<u64>::default().from_matches_opt(m, "to", false)?;

                if lock_hash_opt.is_none() && type_hash_opt.is_none() && code_hash_opt.is_none() {
                    return Err("lock-hash or type-hash or code-hash is required".to_owned());
                }

                let to_number = to_number_opt.unwrap_or(std::u64::MAX);
                let (infos, total_capacity) = self.with_db(|db| {
                    let mut total_capacity = 0;
                    let terminator = |idx, info: &LiveCellInfo| {
                        let stop = idx >= limit || info.number > to_number;
                        let push_info = !stop;
                        if push_info {
                            total_capacity += info.capacity;
                        }
                        (stop, push_info)
                    };
                    let infos = if let Some(lock_hash) = lock_hash_opt {
                        db.get_live_cells_by_lock(lock_hash.clone(), from_number_opt, terminator)
                    } else if let Some(type_hash) = type_hash_opt {
                        db.get_live_cells_by_type(type_hash.clone(), from_number_opt, terminator)
                    } else {
                        db.get_live_cells_by_code(
                            code_hash_opt.clone().unwrap(),
                            from_number_opt,
                            terminator,
                        )
                    };
                    (infos, total_capacity)
                })?;
                let resp = serde_json::json!({
                    "live_cells": infos.into_iter().map(|info| {
                        serde_json::to_value(&info).unwrap()
                    }).collect::<Vec<_>>(),
                    "total_capacity": total_capacity,
                });
                Ok(resp.render(format, color))
            }
            ("get-lock-by-address", Some(m)) => {
                let address: Address = AddressParser.from_matches(m, "address")?;
                let lock_script = self.with_db(|db| {
                    db.get_lock_hash_by_address(address)
                        .and_then(|lock_hash| db.get_lock_script_by_hash(lock_hash))
                        .map(|lock_script| {
                            let args = lock_script
                                .args
                                .iter()
                                .map(|arg| hex_string(arg).unwrap())
                                .collect::<Vec<_>>();
                            serde_json::json!({
                                "hash": lock_script.hash(),
                                "script": {
                                    "code_hash": lock_script.code_hash,
                                    "args": args,
                                }
                            })
                        })
                })?;
                Ok(lock_script.render(format, color))
            }
            ("top-capacity", Some(m)) => {
                let n: usize = m
                    .value_of("number")
                    .map(|n_str| n_str.parse().unwrap())
                    .unwrap();
                let resp = self.with_db(|db| {
                    db.get_top_n(n)
                        .into_iter()
                        .map(|(lock_hash, address, capacity)| {
                            serde_json::json!({
                                "lock_hash": format!("{:#x}", lock_hash),
                                "address": address.map(|addr| addr.to_string(NetworkType::TestNet)),
                                "capacity": capacity,
                            })
                        })
                        .collect::<Vec<_>>()
                })?;
                Ok(resp.render(format, color))
            }
            ("db-metrics", _) => {
                let metrcis = self.with_db(|db| db.get_metrics(None))?;
                let resp = serde_json::to_value(metrcis).map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            _ => Err(matches.usage().to_owned()),
        }
    }
}
