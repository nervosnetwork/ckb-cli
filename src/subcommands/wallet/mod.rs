mod index;

use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use ckb_crypto::secp::SECP256K1;
use ckb_hash::blake2b_256;
use ckb_types::{
    bytes::Bytes,
    core::{service::Request, BlockView, TransactionView},
    prelude::*,
    H160, H256,
};
use clap::{App, Arg, ArgMatches, SubCommand};
use ckb_jsonrpc_types::{BlockNumber, HeaderView, TransactionView, TransactionWithStatus};
use clap::{App, ArgMatches, SubCommand};
use faster_hex::hex_string;

use super::CliSubCommand;
use crate::utils::{
    arg,
    arg_parser::{
        AddressParser, ArgParser, CapacityParser, FixedHashParser, FromStrParser, HexParser,
        PrivkeyPathParser,
    },
    other::{get_address, read_password},
    printer::{OutputFormat, Printable},
};
use ckb_index::{with_index_db, IndexDatabase, LiveCellInfo};
use ckb_sdk::{
    blake2b_args,
    build_witness_with_key, serialize_signature,
    wallet::{KeyStore, KeyStoreError},
    Address, GenesisInfo, HttpRpcClient, NetworkType, TransferTransactionBuilder,
    MIN_SECP_CELL_CAPACITY, ONE_CKB,
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
        let genesis_hash: H256 = genesis_info.header().hash().unpack();
        with_index_db(&self.index_dir, genesis_hash, |backend, cf| {
            let db =
                IndexDatabase::from_db(backend, cf, NetworkType::TestNet, genesis_info, false)?;
            Ok(func(db))
        })
        .map_err(|err| err.to_string())
    }

    pub fn subcommand() -> App<'static, 'static> {
        SubCommand::with_name("wallet")
            .about("Tranfer / query balance(with local index) / key utils")
            .subcommands(vec![
                SubCommand::with_name("transfer")
                    .about("Transfer capacity to an address (can have data)")
                    .arg(arg::privkey_path().required_unless(arg::from_account().b.name))
                    .arg(arg::from_account().required_unless(arg::privkey_path().b.name))
                    .arg(arg::to_address().required(true))
                    .arg(arg::to_data())
                    .arg(arg::to_data_path())
                    .arg(arg::capacity().required(true))
                    .arg(arg::with_password()),
                SubCommand::with_name("deposit-dao")
                    .about("Deposit capacity into NervosDAO(can have data)")
                    .arg(arg::privkey_path().required_unless(arg::from_account().b.name))
                    .arg(arg::from_account().required_unless(arg::privkey_path().b.name))
                    .arg(arg::to_address())
                    .arg(arg::to_data())
                    .arg(arg::to_data_path())
                    .arg(arg::capacity().required(true))
                    .arg(arg::with_password()),
                SubCommand::with_name("withdraw-dao")
                    .about("Withdraw capacity from NervosDAO(can have data)")
                    .arg(arg::privkey_path().required_unless(arg::from_account().b.name))
                    .arg(arg::from_account().required_unless(arg::privkey_path().b.name))
                    .arg(arg::to_address())
                    .arg(arg::to_data())
                    .arg(arg::to_data_path())
                    .arg(arg::capacity().required(true))
                    .arg(arg::with_password()),
                SubCommand::with_name("get-dao-capacity")
                    .about("Get deposited capacity in NervosDAO by lock script hash or address or lock arg or pubkey")
                    .arg(arg::lock_hash())
                    .arg(arg::address())
                    .arg(arg::pubkey())
                    .arg(arg::lock_arg()),
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
    ) -> Result<String, String> {
        let from_privkey: Option<secp256k1::SecretKey> =
            PrivkeyPathParser.from_matches_opt(m, "privkey-path", false)?;
        let from_account: Option<H160> =
            FixedHashParser::<H160>::default().from_matches_opt(m, "from-account", false)?;
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
            let from_pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &from_privkey);
            let pubkey_hash = blake2b_256(&from_pubkey.serialize()[..]);
            Address::from_lock_arg(&pubkey_hash[0..20])?
        } else {
            Address::from_lock_arg(&from_account.as_ref().unwrap()[..])?
        };

        let genesis_info = self.genesis_info()?;
        let secp_code_hash = genesis_info.secp_code_hash();

        // For check index database is ready
        self.with_db(|_| ())?;
        let index_dir = self.index_dir.clone();
        let genesis_hash = genesis_info.header().hash().clone();
        let genesis_info_clone = genesis_info.clone();
        let mut total_capacity = 0;
        let terminator = |_, info: &LiveCellInfo| {
            let out_point = OutPoint {
                cell: Some(info.out_point.clone()),
                block_hash: None,
            };
            let push_cell = match self.rpc_client.get_live_cell(out_point.into()).call() {
                Ok(resp) => {
                    if resp.status != "live" {
                        eprintln!(
                            "[ERROR]: Invalid cell({:?}) status: {}",
                            info.out_point, resp.status,
                        );
                        return (false, false);
                    }
                    if let Some(output) = resp.cell {
                        let free_cell = output.data.is_empty() && output.type_.is_none();
                        if !free_cell {
                            log::info!(
                                "Ignore live cell({:?}) which data is not empty or type is not empty.",
                                info.out_point
                            );
                        }
                        free_cell
                    } else {
                        eprintln!("[ERROR]: No output found for cell: {:?}", info.out_point,);
                        return (false, false);
                    }
                }
                Err(err) => {
                    eprintln!("[ERROR]: get_live_cell by RPC call failed: {:?}", err);
                    return (false, false);
                }
            };
            if push_cell {
                total_capacity += info.capacity;
            }
            let stop = total_capacity >= capacity;
            (stop, push_cell)
        };
        let infos: Vec<LiveCellInfo> = with_index_db(&index_dir, genesis_hash, |backend, cf| {
            let db = IndexDatabase::from_db(
                backend,
                cf,
                NetworkType::TestNet,
                genesis_info_clone,
                false,
            )?;

            let infos = db.get_live_cells_by_lock(
                from_address
                    .lock_script(secp_code_hash.clone())
                    .hash()
                    .clone(),
                None,
                terminator,
            );
            Ok(infos)
        })
        .map_err(|err| err.to_string())?;

        if total_capacity < capacity {
            return Err(format!(
                "Capacity not enough: {} => {}",
                from_address.to_string(NetworkType::TestNet),
                total_capacity,
            ));
        }
        let mut tx_args = TransferTransactionBuilder::new(
            &from_address,
            total_capacity,
            &to_data,
            &to_address,
            capacity,
        );
        let inputs = infos
            .iter()
            .map(LiveCellInfo::core_input)
            .collect::<Vec<_>>();
        let tx = if let Some(ref privkey) = from_privkey {
            tx_args.transfer(inputs, &genesis_info, |args| {
                Ok(build_witness_with_key(privkey, args))
            })?
        } else {
            let lock_arg = from_account.as_ref().unwrap();
            tx_args.transfer(inputs, &genesis_info, |args| {
                let sign_hash = H256::from_slice(&blake2b_args(args))
                    .expect("converting digest of [u8; 32] to H256 should be ok");
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
        let tx_view: TransactionView = (&Into::<Transaction>::into(tx.clone())).into();
        println!("[Send Transaction]:\n{}", tx_view.render(format, color));
        let resp = self
            .rpc_client
            .send_transaction((&tx).into())
            .call()
            .map_err(|err| format!("Send transaction error: {}", err))?;
        Ok(resp.render(format, color))
    }

    pub fn deposit_dao(
        &mut self,
        m: &ArgMatches,
        format: OutputFormat,
        color: bool,
    ) -> Result<String, String> {
        let from_privkey: Option<secp256k1::SecretKey> =
            PrivkeyPathParser.from_matches_opt(m, "privkey-path", false)?;
        let from_account: Option<H160> =
            FixedHashParser::<H160>::default().from_matches_opt(m, "from-account", false)?;
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
            let from_pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &from_privkey);
            let pubkey_hash = blake2b_256(&from_pubkey.serialize()[..]);
            Address::from_lock_arg(&pubkey_hash[0..20])?
        } else {
            Address::from_lock_arg(&from_account.as_ref().unwrap()[..])?
        };

        let genesis_info = self.genesis_info()?;
        let secp_code_hash = genesis_info.secp_code_hash();

        // For check index database is ready
        self.with_db(|_| ())?;
        let index_dir = self.index_dir.clone();
        let genesis_hash = genesis_info.header().hash().clone();
        let genesis_info_clone = genesis_info.clone();
        let mut total_capacity = 0;
        let terminator = |_, info: &LiveCellInfo| {
            let out_point = OutPoint {
                cell: Some(info.out_point.clone()),
                block_hash: None,
            };
            let push_cell = match self.rpc_client.get_live_cell(out_point.into()).call() {
                Ok(resp) => {
                    if resp.status != "live" {
                        eprintln!(
                            "[ERROR]: Invalid cell({:?}) status: {}",
                            info.out_point, resp.status,
                        );
                        return (false, false);
                    }
                    if let Some(output) = resp.cell {
                        let free_cell = output.data.is_empty() && output.type_.is_none();
                        if !free_cell {
                            log::info!(
                                "Ignore live cell({:?}) which data is not empty or type is not empty.",
                                info.out_point
                            );
                        }
                        free_cell
                    } else {
                        eprintln!("[ERROR]: No output found for cell: {:?}", info.out_point,);
                        return (false, false);
                    }
                }
                Err(err) => {
                    eprintln!("[ERROR]: get_live_cell by RPC call failed: {:?}", err);
                    return (false, false);
                }
            };
            if push_cell {
                total_capacity += info.capacity;
            }
            let stop = total_capacity >= capacity;
            (stop, push_cell)
        };
        let infos: Vec<LiveCellInfo> = with_index_db(&index_dir, genesis_hash, |backend, cf| {
            let db = IndexDatabase::from_db(
                backend,
                cf,
                NetworkType::TestNet,
                genesis_info_clone,
                false,
            )?;

            let infos = db.get_live_cells_by_lock(
                from_address
                    .lock_script(secp_code_hash.clone())
                    .hash()
                    .clone(),
                None,
                terminator,
            );
            Ok(infos)
        })
        .map_err(|err| err.to_string())?;

        if total_capacity < capacity {
            return Err(format!(
                "Capacity not enough: {} => {}",
                from_address.to_string(NetworkType::TestNet),
                total_capacity,
            ));
        }
        let mut tx_args = TransferTransactionBuilder::new(
            &from_address,
            total_capacity,
            &to_data,
            &to_address,
            capacity,
        );
        let inputs = infos
            .iter()
            .map(LiveCellInfo::core_input)
            .collect::<Vec<_>>();
        let tx = if let Some(ref privkey) = from_privkey {
            tx_args.deposit_dao(inputs, &genesis_info, |args| {
                Ok(build_witness_with_key(privkey, args))
            })?
        } else {
            let lock_arg = from_account.as_ref().unwrap();
            tx_args.deposit_dao(inputs, &genesis_info, |args| {
                let sign_hash = H256::from_slice(&blake2b_args(args))
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
        let tx_view: TransactionView = (&Into::<Transaction>::into(tx.clone())).into();
        println!("[Send Transaction]:\n{}", tx_view.render(format, color));
        let resp = self
            .rpc_client
            .send_transaction((&tx).into())
            .call()
            .map_err(|err| format!("Send transaction error: {}", err))?;
        Ok(resp.render(format, color))
    }

    pub fn withdraw_dao(
        &mut self,
        m: &ArgMatches,
        format: OutputFormat,
        color: bool,
    ) -> Result<String, String> {
        let from_privkey: Option<secp256k1::SecretKey> =
            PrivkeyPathParser.from_matches_opt(m, "privkey-path", false)?;
        let from_account: Option<H160> =
            FixedHashParser::<H160>::default().from_matches_opt(m, "from-account", false)?;
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
            let from_pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &from_privkey);
            let pubkey_hash = blake2b_256(&from_pubkey.serialize()[..]);
            Address::from_lock_arg(&pubkey_hash[0..20])?
        } else {
            Address::from_lock_arg(&from_account.as_ref().unwrap()[..])?
        };

        let genesis_info = self.genesis_info()?;
        let secp_code_hash = genesis_info.secp_code_hash();

        // For check index database is ready
        self.with_db(|_| ())?;
        let index_dir = self.index_dir.clone();
        let genesis_hash = genesis_info.header().hash().clone();
        let genesis_info_clone = genesis_info.clone();
        let mut total_capacity = 0;
        let terminator = |_, info: &LiveCellInfo| {
            let out_point = OutPoint {
                cell: Some(info.out_point.clone()),
                block_hash: None,
            };
            let push_cell = match self.rpc_client.get_live_cell(out_point.into()).call() {
                Ok(resp) => {
                    if resp.status != "live" {
                        eprintln!(
                            "[ERROR]: Invalid cell({:?}) status: {}",
                            info.out_point, resp.status,
                        );
                        return (false, false);
                    }

                    if let Some(output) = resp.cell {
                        let deposited_cell = output
                            .type_
                            .map(|script| script.code_hash == DAO_CODE_HASH)
                            .unwrap_or(false);
                        if !deposited_cell {
                            log::info!(
                                "Ignore live cell({:?}) which type is not matched with NervosDAO type script.",
                                info.out_point
                            );
                        }
                        deposited_cell
                    } else {
                        eprintln!("[ERROR]: No output found for cell: {:?}", info.out_point,);
                        return (false, false);
                    }
                }
                Err(err) => {
                    eprintln!("[ERROR]: get_live_cell by RPC call failed: {:?}", err);
                    return (false, false);
                }
            };
            if push_cell {
                total_capacity += info.capacity;
            }
            let stop = total_capacity >= capacity;
            (stop, push_cell)
        };
        let infos: Vec<LiveCellInfo> = with_index_db(&index_dir, genesis_hash, |backend, cf| {
            let db = IndexDatabase::from_db(
                backend,
                cf,
                NetworkType::TestNet,
                genesis_info_clone,
                false,
            )?;

            let infos = db.get_live_cells_by_lock(
                from_address
                    .lock_script(secp_code_hash.clone())
                    .hash()
                    .clone(),
                None,
                terminator,
            );
            Ok(infos)
        })
        .map_err(|err| err.to_string())?;

        if total_capacity < capacity {
            return Err(format!(
                "Capacity not enough: {} => {}",
                from_address.to_string(NetworkType::TestNet),
                total_capacity,
            ));
        }
        let mut tx_args = TransferTransactionBuilder::new(
            &from_address,
            total_capacity,
            &to_data,
            &to_address,
            capacity,
        );
        let tip_header: HeaderView = self
            .rpc_client
            .get_tip_header()
            .call()
            .map_err(|err| format!("Send get_tip_header error: {}", err))?;
        let inputs = {
            let mut inputs = Vec::with_capacity(infos.len());
            for info in infos.iter() {
                let previous_tx_hash = info.out_point.tx_hash.to_owned();
                let previous_tx: TransactionWithStatus = self
                    .rpc_client
                    .get_transaction(previous_tx_hash.to_owned())
                    .call()
                    .map_err(|err| format!("Send get_transaction error: {}", err))?
                    .0
                    .expect("transaction of a live cell exist");

                let mut live_cell_info = LiveCellInfo::core_input(info);
                // NOTE: We assume here tip_number > input.number + DAO_MATURITY(10)
                live_cell_info.since = tip_header.inner.number.0;
                live_cell_info.previous_output.block_hash = previous_tx.tx_status.block_hash;
                inputs.push(live_cell_info);
            }
            inputs
        };
        let withdraw_header_hash = {
            const DAO_MATURITY: u64 = 10;
            self.rpc_client
                .get_header_by_number(BlockNumber(tip_header.inner.number.0 - DAO_MATURITY))
                .call()
                .map_err(|err| format!("Send get_tip_header error: {}", err))?
                .0
                .expect("old block exist")
                .hash
        };

        let tx = if let Some(ref privkey) = from_privkey {
            tx_args.withdraw_dao(inputs, withdraw_header_hash, &genesis_info, |args| {
                Ok(build_witness_with_key(privkey, args))
            })?
        } else {
            let lock_arg = from_account.as_ref().unwrap();
            tx_args.withdraw_dao(inputs, withdraw_header_hash, &genesis_info, |args| {
                let sign_hash = H256::from_slice(&blake2b_args(args)).expect("Tx hash convert to H256 failed");
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
        let tx_view: TransactionView = (&Into::<Transaction>::into(tx.clone())).into();
        println!("[Send Transaction]:\n{}", tx_view.render(format, color));
        let resp = self
            .rpc_client
            .send_transaction((&tx).into())
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
    ) -> Result<String, String> {
        match matches.subcommand() {
            ("transfer", Some(m)) => self.transfer(m, format, color),
            ("deposit-dao", Some(m)) => self.deposit_dao(m, format, color),
            ("withdraw-dao", Some(m)) => self.withdraw_dao(m, format, color),
            ("get-capacity", Some(m)) => {
                let lock_hash_opt: Option<H256> =
                    FixedHashParser::<H256>::default().from_matches_opt(m, "lock-hash", false)?;
                let lock_hash = if let Some(lock_hash) = lock_hash_opt {
                    lock_hash
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
                                .args()
                                .into_iter()
                                .map(|arg| hex_string(&arg.raw_data()).unwrap())
                                .collect::<Vec<_>>();
                            let script_hash = lock_script.calc_script_hash();
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
