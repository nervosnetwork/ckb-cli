mod index;

use std::fs;
use std::io::Read;
use std::path::PathBuf;

use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::{BlockNumber, CellWithStatus, HeaderView, TransactionWithStatus};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, TransactionView},
    packed::{Byte32, CellInput, Script},
    prelude::*,
    H160, H256,
};
use clap::{App, ArgMatches, SubCommand};
use faster_hex::hex_string;

use super::CliSubCommand;
use crate::utils::{
    arg,
    arg_parser::{
        AddressParser, ArgParser, CapacityParser, FixedHashParser, FromStrParser, HexParser,
        PrivkeyPathParser, PrivkeyWrapper,
    },
    other::{check_address_prefix, get_address, get_network_type, read_password},
    printer::{OutputFormat, Printable},
};
use ckb_index::{with_index_db, IndexDatabase, LiveCellInfo};
use ckb_sdk::{
    blake2b_args, build_witness_with_key, serialize_signature,
    wallet::{KeyStore, KeyStoreError},
    Address, GenesisInfo, HttpRpcClient, TransferTransactionBuilder, MIN_SECP_CELL_CAPACITY,
    ONE_CKB, SECP256K1,
};
pub use index::{
    start_index_thread, CapacityResult, IndexController, IndexRequest, IndexResponse,
    IndexThreadState, SimpleBlockInfo,
};
use std::collections::HashSet;

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
                SubCommand::with_name("deposit-dao")
                    .about("Deposit capacity into NervosDAO(can have data)")
                    .arg(arg::privkey_path().required_unless(arg::from_account().b.name))
                    .arg(arg::from_account().required_unless(arg::privkey_path().b.name))
                    .arg(arg::to_address())
                    .arg(arg::to_data())
                    .arg(arg::to_data_path())
                    .arg(arg::capacity().required(true))
                    .arg(arg::tx_fee().required(true))
                    .arg(arg::with_password()),
                SubCommand::with_name("withdraw-dao")
                    .about("Withdraw capacity from NervosDAO(can have data)")
                    .arg(arg::privkey_path().required_unless(arg::from_account().b.name))
                    .arg(arg::from_account().required_unless(arg::privkey_path().b.name))
                    .arg(arg::to_address())
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
                SubCommand::with_name("get-dao-capacity")
                    .about("Get NervosDAO deposited capacity by lock script hash or address or lock arg or pubkey")
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
                SubCommand::with_name("get-lock-by-address")
                    .about("Get lock script (include hash) by address")
                    .arg(arg::address().required(true)),
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
        let from_address = if let Some(from_privkey) = from_privkey.as_ref() {
            let from_pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, from_privkey);
            let pubkey_hash = blake2b_256(&from_pubkey.serialize()[..]);
            Address::from_lock_arg(&pubkey_hash[0..20])?
        } else {
            Address::from_lock_arg(from_account.as_ref().unwrap().as_bytes())?
        };
        let to_address: Address = AddressParser.from_matches(m, "to-address")?;
        let to_data = to_data(m)?;
        let with_password = m.is_present("with-password");

        check_capacity(capacity, to_data.len())?;
        let network_type = get_network_type(self.rpc_client)?;
        let genesis_info = self.genesis_info()?;
        let secp_type_hash = genesis_info.secp_type_hash();

        check_address_prefix(m.value_of("to-address").unwrap(), network_type)?;
        // For check index database is ready
        self.with_db(|_| ())?;
        let index_dir = self.index_dir.clone();
        let genesis_hash = genesis_info.header().hash();
        let genesis_info_clone = genesis_info.clone();
        let mut total_capacity = 0;
        let terminator = |_, info: &LiveCellInfo| {
            let out_point = info.out_point();
            let resp: CellWithStatus = self
                .rpc_client
                .get_live_cell(out_point.into(), true)
                .call()
                .expect("get_live_cell by RPC call failed");
            if is_live_cell(&resp) && is_secp_cell(&resp) {
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
                    from_address
                        .lock_script(secp_type_hash.clone())
                        .calc_script_hash(),
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
                "Capacity not enough: {} => {}",
                from_address.to_string(network_type),
                total_capacity,
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

    pub fn deposit_dao(
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
        let from_address = if let Some(from_privkey) = from_privkey.as_ref() {
            let from_pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, from_privkey);
            let pubkey_hash = blake2b_256(&from_pubkey.serialize()[..]);
            Address::from_lock_arg(&pubkey_hash[0..20])?
        } else {
            Address::from_lock_arg(from_account.as_ref().unwrap().as_bytes())?
        };
        let to_address: Address = AddressParser
            .from_matches_opt(m, "to-address", false)?
            .unwrap_or_else(|| from_address.clone());
        let to_data = to_data(m)?;
        let with_password = m.is_present("with-password");

        check_capacity(capacity, to_data.len())?;
        let network_type = get_network_type(self.rpc_client)?;
        let genesis_info = self.genesis_info()?;
        let secp_type_hash = genesis_info.secp_type_hash();

        if let Some(address) = m.value_of("to-address") {
            check_address_prefix(address, network_type)?;
        }
        // For check index database is ready
        self.with_db(|_| ())?;
        let index_dir = self.index_dir.clone();
        let genesis_hash = genesis_info.header().hash();
        let genesis_info_clone = genesis_info.clone();
        let mut total_capacity = 0;
        let terminator = |_, info: &LiveCellInfo| {
            let out_point = info.out_point();
            let resp: CellWithStatus = self
                .rpc_client
                .get_live_cell(out_point.into(), true)
                .call()
                .expect("get_live_cell by RPC call failed");
            if is_live_cell(&resp) && is_secp_cell(&resp) {
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
                    from_address
                        .lock_script(secp_type_hash.clone())
                        .calc_script_hash(),
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
                "Capacity not enough: {} => {}",
                from_address.to_string(network_type),
                total_capacity,
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
            tx_args.deposit_dao(&genesis_info, |args| {
                Ok(build_witness_with_key(privkey, args))
            })
        } else {
            let lock_arg = from_account.as_ref().unwrap();
            let password = if with_password {
                Some(read_password(false, None)?)
            } else {
                None
            };
            tx_args.deposit_dao(&genesis_info, |args| {
                self.build_witness_with_keystore(lock_arg, args, &password)
            })
        }?;
        self.send_transaction(transaction, format, color, debug)
    }

    pub fn withdraw_dao(
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
        let from_address = if let Some(from_privkey) = from_privkey.as_ref() {
            let from_pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, from_privkey);
            let pubkey_hash = blake2b_256(&from_pubkey.serialize()[..]);
            Address::from_lock_arg(&pubkey_hash[0..20])?
        } else {
            Address::from_lock_arg(from_account.as_ref().unwrap().as_bytes())?
        };
        let to_address: Address = AddressParser
            .from_matches_opt(m, "to-address", false)?
            .unwrap_or_else(|| from_address.clone());
        let to_data = to_data(m)?;
        let with_password = m.is_present("with-password");

        check_capacity(capacity, to_data.len())?;
        let network_type = get_network_type(self.rpc_client)?;
        let genesis_info = self.genesis_info()?;
        let secp_type_hash = genesis_info.secp_type_hash();

        if let Some(address) = m.value_of("to-address") {
            check_address_prefix(address, network_type)?;
        }
        // For check index database is ready
        self.with_db(|_| ())?;
        let index_dir = self.index_dir.clone();
        let genesis_hash = genesis_info.header().hash();
        let genesis_info_clone = genesis_info.clone();
        let mut total_capacity = 0;
        let terminator = |_, info: &LiveCellInfo| {
            let out_point = info.out_point();
            let resp: CellWithStatus = self
                .rpc_client
                .get_live_cell(out_point.into(), true)
                .call()
                .expect("get_live_cell by RPC call failed");
            if is_live_cell(&resp) && is_dao_cell(&resp, genesis_info.dao_type_hash()) {
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
                    from_address
                        .lock_script(secp_type_hash.clone())
                        .calc_script_hash(),
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
                "Capacity not enough: {} => {}",
                from_address.to_string(network_type),
                total_capacity,
            ));
        }

        let inputs_and_header_hashes = build_dao_inputs(&mut self.rpc_client, infos)?;
        let (inputs, input_header_hashes) = inputs_and_header_hashes.into_iter().unzip();
        let withdraw_header_hash = build_dao_withdraw_hash(&mut self.rpc_client)?;
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
            tx_args.withdraw_dao(
                withdraw_header_hash,
                input_header_hashes,
                &genesis_info,
                |args| Ok(build_witness_with_key(privkey, args)),
            )
        } else {
            let lock_arg = from_account.as_ref().unwrap();
            let password = if with_password {
                Some(read_password(false, None)?)
            } else {
                None
            };
            tx_args.withdraw_dao(
                withdraw_header_hash,
                input_header_hashes,
                &genesis_info,
                |args| self.build_witness_with_keystore(lock_arg, args, &password),
            )
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
            ("deposit-dao", Some(m)) => self.deposit_dao(m, format, color, debug),
            ("withdraw-dao", Some(m)) => self.withdraw_dao(m, format, color, debug),
            ("get-capacity", Some(m)) => {
                let lock_hash_opt: Option<H256> =
                    FixedHashParser::<H256>::default().from_matches_opt(m, "lock-hash", false)?;
                let lock_hash = if let Some(lock_hash) = lock_hash_opt {
                    lock_hash.pack()
                } else {
                    let secp_type_hash = self.genesis_info()?.secp_type_hash().clone();
                    let address = get_address(m)?;
                    address.lock_script(secp_type_hash).calc_script_hash()
                };
                let capacity = self.with_db(|db| db.get_capacity(lock_hash))?;
                let resp = serde_json::json!({
                    "capacity": capacity,
                });
                Ok(resp.render(format, color))
            }
            ("get-dao-capacity", Some(m)) => {
                let secp_type_hash = self.genesis_info()?.secp_type_hash().clone();
                let dao_type_hash = self.genesis_info()?.dao_type_hash().clone();
                let lock_hash_opt: Option<H256> =
                    FixedHashParser::<H256>::default().from_matches_opt(m, "lock-hash", false)?;
                let lock_hash = if let Some(lock_hash) = lock_hash_opt {
                    lock_hash.pack()
                } else {
                    let address = get_address(m)?;
                    address.lock_script(secp_type_hash).calc_script_hash()
                };
                let capacity = self.with_db(|db| {
                    let infos_by_lock = db
                        .get_live_cells_by_lock(lock_hash, Some(0), |_, _| (false, true))
                        .into_iter()
                        .collect::<HashSet<_>>();
                    let infos_by_code = db
                        .get_live_cells_by_code(dao_type_hash, Some(0), |_, _| (false, true))
                        .into_iter()
                        .collect::<HashSet<_>>();
                    infos_by_lock
                        .intersection(&infos_by_code)
                        .map(|info| info.capacity)
                        .sum::<u64>()
                })?;
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
                            let args = hex_string(&lock_script.args().raw_data()).unwrap();
                            let script_hash: H256 = lock_script.calc_script_hash().unpack();
                            let code_hash: H256 = lock_script.code_hash().unpack();
                            serde_json::json!({
                                "hash": script_hash,
                                "script": {
                                    "code_hash": code_hash,
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
                let network_type = get_network_type(self.rpc_client)?;
                let resp = self.with_db(|db| {
                    db.get_top_n(n)
                        .into_iter()
                        .map(|(lock_hash, address, capacity)| {
                            serde_json::json!({
                                "lock_hash": format!("{:#x}", lock_hash),
                                "address": address.map(|addr| addr.to_string(network_type)),
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

fn check_capacity(capacity: u64, to_data_len: usize) -> Result<(), String> {
    if capacity < *MIN_SECP_CELL_CAPACITY {
        return Err(format!(
            "Capacity can not less than {} shannons",
            *MIN_SECP_CELL_CAPACITY
        ));
    }
    if capacity < *MIN_SECP_CELL_CAPACITY + (to_data_len as u64 * ONE_CKB) {
        return Err(format!(
            "Capacity can not hold {} bytes of data",
            to_data_len
        ));
    }
    Ok(())
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

fn is_dao_cell(cell: &CellWithStatus, dao_type_hash: &Byte32) -> bool {
    if let Some(ref info) = cell.cell {
        return info
            .output
            .type_
            .as_ref()
            .map(|script| {
                let type_hash = Into::<Script>::into(script.to_owned()).calc_script_hash();
                &type_hash == dao_type_hash
            })
            .unwrap_or(false);
    }

    false
}

fn build_dao_inputs(
    rpc_client: &mut HttpRpcClient,
    infos: Vec<LiveCellInfo>,
) -> Result<Vec<(CellInput, H256)>, String> {
    // NOTE: We assume here tip_number > input.number + DAO_MATURITY(10)
    let dao_minimal_since = {
        let tip_header: HeaderView = rpc_client
            .get_tip_header()
            .call()
            .map_err(|err| format!("Send get_tip_header error: {}", err))?;
        tip_header.inner.number.value()
    };

    let mut inputs = Vec::with_capacity(infos.len());
    for info in infos.iter() {
        let previous_tx_hash = info.tx_hash.to_owned();
        let previous_tx: TransactionWithStatus = rpc_client
            .get_transaction(previous_tx_hash)
            .call()
            .map_err(|err| format!("Send get_transaction error: {}", err))?
            .0
            .expect("transaction of a live cell exist");
        let input_block_hash = previous_tx
            .tx_status
            .block_hash
            .expect("live cell's block_hash should exist");

        let live_cell_info = {
            let live_cell_info = LiveCellInfo::input(info);
            live_cell_info
                .as_builder()
                .since(dao_minimal_since.pack())
                .build()
        };
        inputs.push((live_cell_info, input_block_hash));
    }
    Ok(inputs)
}

fn build_dao_withdraw_hash(rpc_client: &mut HttpRpcClient) -> Result<H256, String> {
    const DAO_MATURITY: u64 = 10;

    let tip_header: HeaderView = rpc_client
        .get_tip_header()
        .call()
        .map_err(|err| format!("Send get_tip_header error: {}", err))?;
    let dao_withdraw_number = tip_header.inner.number.value() - DAO_MATURITY;
    let dao_withdraw_hash = rpc_client
        .get_header_by_number(BlockNumber::from(dao_withdraw_number))
        .call()
        .map_err(|err| format!("Send get_header_by_number error: {}", err))?
        .0
        .expect("old block exist")
        .hash;
    Ok(dao_withdraw_hash)
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
