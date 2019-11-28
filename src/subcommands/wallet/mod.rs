mod index;

use std::fs;
use std::io::Read;
use std::path::PathBuf;

use ckb_jsonrpc_types::{BlockNumber, CellWithStatus, EpochNumber};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, EpochNumberWithFraction, TransactionView},
    packed::Script,
    prelude::*,
    H160, H256,
};
use clap::{App, ArgMatches, SubCommand};

use super::CliSubCommand;
use crate::utils::{
    arg,
    arg_parser::{
        AddressParser, ArgParser, CapacityParser, FixedHashParser, FromStrParser, HexParser,
        PrivkeyPathParser, PrivkeyWrapper,
    },
    other::{get_address, get_network_type, read_password},
    printer::{OutputFormat, Printable},
};
use ckb_index::{with_index_db, IndexDatabase, LiveCellInfo};
use ckb_sdk::{
    blake2b_args, build_witness_with_key, calc_max_mature_number,
    constants::{CELLBASE_MATURITY, MIN_SECP_CELL_CAPACITY, ONE_CKB},
    serialize_signature,
    wallet::{KeyStore, KeyStoreError},
    Address, AddressPayload, CodeHashIndex, GenesisInfo, HttpRpcClient, HumanCapacity,
    TransferTransactionBuilder, SECP256K1,
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
            let genesis_block: BlockView = self
                .rpc_client
                .get_block_by_number(BlockNumber::from(0))
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
            return Err("ERROR: This is an interactive mode only sub-command".to_string());
        }

        let network_type = get_network_type(self.rpc_client)?;
        let genesis_info = self.genesis_info()?;
        let genesis_hash: H256 = genesis_info.header().hash().unpack();
        with_index_db(&self.index_dir, genesis_hash, |backend, cf| {
            let db = IndexDatabase::from_db(backend, cf, network_type, genesis_info, false)?;
            Ok(func(db))
        })
        .map_err(|_err| {
            format!(
                "index database may not ready, sync process: {}",
                self.index_controller.state().read().to_string()
            )
        })
    }

    pub fn subcommand() -> App<'static, 'static> {
        SubCommand::with_name("wallet")
            .about("Transfer / query balance (with local index) / key utils")
            .subcommands(vec![
                SubCommand::with_name("transfer")
                    .about("Transfer capacity to an address (can have data)")
                    .arg(arg::privkey_path().required_unless(arg::from_account().b.name))
                    .arg(arg::from_account().required_unless(arg::privkey_path().b.name))
                    .arg(arg::to_address().required(true))
                    .arg(arg::to_data())
                    .arg(arg::to_data_path())
                    .arg(arg::capacity().required(true))
                    .arg(arg::tx_fee().required(true))
                    .arg(arg::with_password()),
                SubCommand::with_name("get-capacity")
                    .about("Get capacity by lock script hash or address or lock arg or pubkey")
                    .arg(arg::lock_hash())
                    .arg(arg::address())
                    .arg(arg::pubkey())
                    .arg(arg::lock_arg()),
                SubCommand::with_name("get-live-cells")
                    .about("Get live cells by lock/type/code  hash")
                    .arg(arg::lock_hash())
                    .arg(arg::type_hash())
                    .arg(arg::code_hash())
                    .arg(arg::live_cells_limit())
                    .arg(arg::from_block_number())
                    .arg(arg::to_block_number()),
                // Move to index subcommand
                SubCommand::with_name("db-metrics").about("Show index database metrics"),
                SubCommand::with_name("top-capacity")
                    .about("Show top n capacity owned by lock script hash")
                    .arg(arg::top_n()),
            ])
    }

    pub fn transfer(
        &mut self,
        m: &ArgMatches,
        format: OutputFormat,
        color: bool,
        debug: bool,
    ) -> Result<String, String> {
        let from_privkey: Option<PrivkeyWrapper> =
            PrivkeyPathParser.from_matches_opt(m, "privkey-path", false)?;
        let from_account: Option<H160> =
            FixedHashParser::<H160>::default().from_matches_opt(m, "from-account", false)?;
        let capacity: u64 = CapacityParser.from_matches(m, "capacity")?;
        let tx_fee: u64 = CapacityParser.from_matches(m, "tx-fee")?;

        let network_type = get_network_type(self.rpc_client)?;
        let from_address_payload = if let Some(from_privkey) = from_privkey.as_ref() {
            let from_pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, from_privkey);
            AddressPayload::from_pubkey(&from_pubkey)
        } else {
            AddressPayload::from_pubkey_hash(from_account.clone().unwrap())
        };
        let from_address = Address::new(network_type, from_address_payload.clone());

        let to_address: Address = AddressParser::default()
            .set_network(network_type)
            .set_short(CodeHashIndex::Sighash)
            .from_matches(m, "to-address")?;
        let to_data = to_data(m)?;
        let with_password = m.is_present("with-password");

        check_capacity(capacity, to_data.len())?;
        let genesis_info = self.genesis_info()?;

        // For check index database is ready
        self.with_db(|_| ())?;
        let index_dir = self.index_dir.clone();
        let genesis_hash = genesis_info.header().hash();
        let genesis_info_clone = genesis_info.clone();
        let max_mature_number = get_max_mature_number(self.rpc_client)?;
        let mut total_capacity = 0;
        let terminator = |_, info: &LiveCellInfo| {
            let out_point = info.out_point();
            let resp: CellWithStatus = self
                .rpc_client
                .get_live_cell(out_point.into(), true)
                .call()
                .expect("get_live_cell by RPC call failed");
            if is_live_cell(&resp) && is_secp_cell(&resp) && is_mature(info, max_mature_number) {
                total_capacity += info.capacity;
                (total_capacity >= capacity + tx_fee, true)
            } else {
                (false, false)
            }
        };
        let infos: Vec<LiveCellInfo> =
            with_index_db(&index_dir, genesis_hash.unpack(), |backend, cf| {
                let db =
                    IndexDatabase::from_db(backend, cf, network_type, genesis_info_clone, false)?;
                Ok(db.get_live_cells_by_lock(
                    Script::from(&from_address_payload).calc_script_hash(),
                    None,
                    terminator,
                ))
            })
            .map_err(|_err| {
                format!(
                    "index database may not ready, sync process: {}",
                    self.index_controller.state().read().to_string()
                )
            })?;

        if total_capacity < capacity + tx_fee {
            return Err(format!(
                "Capacity(mature) not enough: {} => {}",
                from_address, total_capacity,
            ));
        }
        let inputs = infos.iter().map(LiveCellInfo::input).collect::<Vec<_>>();
        let mut tx_args = TransferTransactionBuilder::new(
            &from_address,
            total_capacity,
            &to_data,
            &to_address,
            capacity,
            tx_fee,
            inputs,
        );
        let transaction = if let Some(privkey) = from_privkey.as_ref() {
            tx_args.transfer(&genesis_info, |args| {
                Ok(build_witness_with_key(privkey, args))
            })
        } else {
            let lock_arg = from_account.as_ref().unwrap();
            let password = if with_password {
                Some(read_password(false, None)?)
            } else {
                None
            };
            tx_args.transfer(&genesis_info, |args| {
                self.build_witness_with_keystore(lock_arg, args, &password)
            })
        }?;
        self.send_transaction(transaction, format, color, debug)
    }

    fn build_witness_with_keystore(
        &mut self,
        lock_arg: &H160,
        args: &[Vec<u8>],
        password: &Option<String>,
    ) -> Result<Bytes, String> {
        let sign_hash = H256::from_slice(&blake2b_args(args))
            .expect("converting digest of [u8; 32] to H256 should be ok");
        let signature_result = if self.interactive && password.is_none() {
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
        } else if let Some(password) = password {
            self.key_store
                .sign_recoverable_with_password(lock_arg, &sign_hash, password.as_bytes())
                .map_err(|err| err.to_string())
        } else {
            return Err("Password required to unlock the keystore".to_owned());
        };
        signature_result.map(|signature| serialize_signature(&signature))
    }

    fn send_transaction(
        &mut self,
        transaction: TransactionView,
        format: OutputFormat,
        color: bool,
        debug: bool,
    ) -> Result<String, String> {
        let transaction_view: ckb_jsonrpc_types::TransactionView = transaction.clone().into();
        if debug {
            println!(
                "[Send Transaction]:\n{}",
                transaction_view.render(format, color)
            );
        }

        let resp = self
            .rpc_client
            .send_transaction(transaction.data().into())
            .call()
            .map_err(|err| format!("Send transaction error: {}", err))?;
        Ok(resp.render(format, color))
    }
}

impl<'a> CliSubCommand for WalletSubCommand<'a> {
    fn process(
        &mut self,
        matches: &ArgMatches,
        format: OutputFormat,
        color: bool,
        debug: bool,
    ) -> Result<String, String> {
        match matches.subcommand() {
            ("transfer", Some(m)) => self.transfer(m, format, color, debug),
            ("get-capacity", Some(m)) => {
                let lock_hash_opt: Option<H256> =
                    FixedHashParser::<H256>::default().from_matches_opt(m, "lock-hash", false)?;
                let lock_hash = if let Some(lock_hash) = lock_hash_opt {
                    lock_hash.pack()
                } else {
                    let network_type = get_network_type(self.rpc_client)?;
                    let address_payload = get_address(Some(network_type), m)?;
                    Script::from(&address_payload).calc_script_hash()
                };

                let max_mature_number = get_max_mature_number(self.rpc_client)?;
                let (total_capacity, immature_capacity) = self.with_db(|db| {
                    let mut total_capacity = 0;
                    let mut immature_capacity = 0;
                    let terminator = |_idx: usize, info: &LiveCellInfo| {
                        if !is_mature(info, max_mature_number) {
                            immature_capacity += info.capacity;
                        }
                        total_capacity += info.capacity;
                        (false, false)
                    };
                    let _ = db.get_live_cells_by_lock(lock_hash, None, terminator);
                    (total_capacity, immature_capacity)
                })?;

                let resp = if immature_capacity > 0 {
                    serde_json::json!({
                        "total_capacity": format!("{:#}", HumanCapacity::from(total_capacity)),
                        "immature_capacity": format!("{:#}", HumanCapacity::from(immature_capacity)),
                    })
                } else {
                    serde_json::json!({
                        "total_capacity": format!("{:#}", HumanCapacity::from(total_capacity)),
                    })
                };
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
                let (infos, total_count, total_capacity, current_count, current_capacity) = self
                    .with_db(|db| {
                        let mut total_count: u32 = 0;
                        let mut total_capacity: u64 = 0;
                        let mut current_count: u32 = 0;
                        let mut current_capacity: u64 = 0;
                        let terminator = |idx, info: &LiveCellInfo| {
                            let stop = idx >= limit || info.number > to_number;
                            let push_info = !stop;
                            total_count += 1;
                            total_capacity += info.capacity;
                            if push_info {
                                current_count += 1;
                                current_capacity += info.capacity;
                            }
                            (false, push_info)
                        };
                        let infos = if let Some(lock_hash) = lock_hash_opt {
                            db.get_live_cells_by_lock(
                                lock_hash.clone().pack(),
                                from_number_opt,
                                terminator,
                            )
                        } else if let Some(type_hash) = type_hash_opt {
                            db.get_live_cells_by_type(
                                type_hash.clone().pack(),
                                from_number_opt,
                                terminator,
                            )
                        } else {
                            db.get_live_cells_by_code(
                                code_hash_opt.clone().unwrap().pack(),
                                from_number_opt,
                                terminator,
                            )
                        };
                        (
                            infos,
                            total_count,
                            total_capacity,
                            current_count,
                            current_capacity,
                        )
                    })?;
                let max_mature_number = get_max_mature_number(self.rpc_client)?;
                let resp = serde_json::json!({
                    "live_cells": infos.into_iter().map(|info| {
                        let mut value = serde_json::to_value(&info).unwrap();
                        let mature = serde_json::Value::Bool(is_mature(&info, max_mature_number));
                        let capacity_string = serde_json::Value::String(format!("{:#}", HumanCapacity::from(info.capacity)));
                        let map = value.as_object_mut().unwrap();
                        map.insert("capacity".to_string(), capacity_string);
                        map.insert("mature".to_string(), mature);
                        value
                    }).collect::<Vec<_>>(),
                    "total_capacity": format!("{:#}", HumanCapacity::from(total_capacity)),
                    "current_capacity": format!("{:#}", HumanCapacity::from(current_capacity)),
                    "total_count": total_count,
                    "current_count": current_count,
                });
                Ok(resp.render(format, color))
            }
            ("top-capacity", Some(m)) => {
                let n: usize = m
                    .value_of("number")
                    .map(|n_str| n_str.parse().unwrap())
                    .unwrap();
                let network_type = get_network_type(self.rpc_client)?;
                let resp = self.with_db(|db| {
                    db.get_top_n(n)
                        .into_iter()
                        .map(|(lock_hash, payload_opt, capacity)| {
                            serde_json::json!({
                                "lock_hash": format!("{:#x}", lock_hash),
                                "address": payload_opt.map(|payload| Address::new(network_type, payload).to_string()),
                                "capacity": format!("{:#}", HumanCapacity::from(capacity)),
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

fn check_capacity(capacity: u64, to_data_len: usize) -> Result<(), String> {
    if capacity < MIN_SECP_CELL_CAPACITY {
        return Err(format!(
            "Capacity can not less than {} shannons",
            MIN_SECP_CELL_CAPACITY
        ));
    }
    if capacity < MIN_SECP_CELL_CAPACITY + (to_data_len as u64 * ONE_CKB) {
        return Err(format!(
            "Capacity can not hold {} bytes of data",
            to_data_len
        ));
    }
    Ok(())
}

// Get max mature block number
fn get_max_mature_number(client: &mut HttpRpcClient) -> Result<u64, String> {
    let tip_epoch = client
        .get_tip_header()
        .call()
        .map(|header| EpochNumberWithFraction::from_full_value(header.inner.epoch.value()))
        .map_err(|err| err.to_string())?;
    let tip_epoch_number = tip_epoch.number();
    if tip_epoch_number < 4 {
        // No cellbase live cell is mature
        Ok(0)
    } else {
        let max_mature_epoch = client
            .get_epoch_by_number(EpochNumber::from(tip_epoch_number - 4))
            .call()
            .map_err(|err| err.to_string())?
            .0
            .ok_or_else(|| "Can not get epoch less than current epoch number".to_string())?;
        let start_number = max_mature_epoch.start_number.value();
        let length = max_mature_epoch.length.value();
        Ok(calc_max_mature_number(
            tip_epoch,
            Some((start_number, length)),
            CELLBASE_MATURITY,
        ))
    }
}

fn is_mature(info: &LiveCellInfo, max_mature_number: u64) -> bool {
    // Not cellbase cell
    info.index.tx_index > 0
        // Live cells in genesis are all mature
        || info.number == 0
        || info.number <= max_mature_number
}

fn is_live_cell(cell: &CellWithStatus) -> bool {
    if cell.status != "live" {
        eprintln!(
            "[ERROR]: Not live cell({:?}) status: {}",
            cell.cell.as_ref().map(|info| &info.output),
            cell.status
        );
        return false;
    }

    if cell.cell.is_none() {
        eprintln!(
            "[ERROR]: No output found for cell: {:?}",
            cell.cell.as_ref().map(|info| &info.output)
        );
        return false;
    }

    true
}

fn is_secp_cell(cell: &CellWithStatus) -> bool {
    if let Some(ref info) = cell.cell {
        // FIXME Check if output.data.is_empty()
        if info.output.type_.is_none() {
            return true;
        } else {
            log::info!(
                "Ignore live cell({:?}) which data is not empty or type is not empty.",
                info.output
            );
        }
    }

    false
}

fn to_data(m: &ArgMatches) -> Result<Bytes, String> {
    let to_data_opt: Option<Bytes> = HexParser.from_matches_opt(m, "to-data", false)?;
    match to_data_opt {
        Some(data) => Ok(data),
        None => {
            if let Some(path) = m.value_of("to-data-path") {
                let mut content = Vec::new();
                let mut file = fs::File::open(path).map_err(|err| err.to_string())?;
                file.read_to_end(&mut content)
                    .map_err(|err| err.to_string())?;
                Ok(Bytes::from(content))
            } else {
                Ok(Bytes::new())
            }
        }
    }
}
