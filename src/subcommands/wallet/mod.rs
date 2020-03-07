mod index;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use either::Either;
pub use index::start_index_thread;

use super::account::AccountId;
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, Capacity, ScriptHashType, TransactionView},
    packed::{Byte32, CellOutput, OutPoint, Script},
    prelude::*,
    H160, H256,
};
use clap::{App, ArgMatches, SubCommand};

use super::CliSubCommand;
use crate::utils::{
    arg,
    arg_parser::{AddressParser, ArgParser, CapacityParser, FixedHashParser, FromStrParser},
    index::IndexController,
    other::{
        check_capacity, get_address, get_live_cell_with_cache, get_master_key_signer_raw,
        get_max_mature_number, get_network_type, get_privkey_signer, get_to_data, is_mature,
        make_address_payload_and_master_key_cap, privkey_or_from_account, read_password,
        serialize_signature_bytes,
    },
    printer::{OutputFormat, Printable},
};
use ckb_index::{with_index_db, IndexDatabase, LiveCellInfo};
use ckb_ledger::LedgerKeyStore;
use ckb_sdk::{
    constants::{
        DAO_TYPE_HASH, MIN_SECP_CELL_CAPACITY, MULTISIG_TYPE_HASH, ONE_CKB, SIGHASH_TYPE_HASH,
    },
    rpc::Transaction,
    wallet::{AbstractMasterPrivKey, AbstractPrivKey, DerivationPath, KeyStore},
    Address, AddressPayload, GenesisInfo, HttpRpcClient, HumanCapacity, MultisigConfig,
    NetworkType, SignerClosureHelper, SignerFnTrait, Since, SinceType, TxHelper,
};

pub struct WalletSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    key_store: &'a mut KeyStore,
    ledger_key_store: &'a mut LedgerKeyStore,
    genesis_info: Option<GenesisInfo>,
    index_dir: PathBuf,
    index_controller: IndexController,
}

impl<'a> WalletSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        key_store: &'a mut KeyStore,
        ledger_key_store: &'a mut LedgerKeyStore,
        genesis_info: Option<GenesisInfo>,
        index_dir: PathBuf,
        index_controller: IndexController,
    ) -> WalletSubCommand<'a> {
        WalletSubCommand {
            rpc_client,
            key_store,
            ledger_key_store,
            genesis_info,
            index_dir,
            index_controller,
        }
    }

    fn genesis_info(&mut self) -> Result<GenesisInfo, String> {
        if self.genesis_info.is_none() {
            let genesis_block: BlockView = self
                .rpc_client
                .get_block_by_number(0)?
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
        let network_type = get_network_type(self.rpc_client)?;
        let genesis_info = self.genesis_info()?;
        let genesis_hash: H256 = genesis_info.header().hash().unpack();
        with_index_db(&self.index_dir, genesis_hash, |backend, cf| {
            let db = IndexDatabase::from_db(backend, cf, network_type, genesis_info, false)?;
            Ok(func(db))
        })
        .map_err(|_err| {
            format!(
                "Index database may not ready, sync process: {}",
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
                    .arg(
                        arg::from_account()
                            .required_unless(arg::privkey_path().b.name)
                            .conflicts_with(arg::privkey_path().b.name),
                    )
                    .arg(arg::from_locked_address())
                    .arg(arg::to_address().required(true))
                    .arg(arg::to_data())
                    .arg(arg::to_data_path())
                    .arg(arg::capacity().required(true))
                    .arg(arg::tx_fee().required(true))
                    .arg(arg::derive_receiving_address_length())
                    .arg(arg::derive_change_address_length())
                    .arg(arg::derive_change_address().conflicts_with(arg::privkey_path().b.name)),
                SubCommand::with_name("get-capacity")
                    .about("Get capacity by lock script hash or address or lock arg or pubkey")
                    .arg(arg::lock_hash())
                    .arg(arg::address())
                    .arg(arg::pubkey())
                    .arg(arg::lock_arg())
                    .arg(arg::derive_receiving_address_length())
                    .arg(arg::derive_change_address_length())
                    .arg(arg::derived().conflicts_with(arg::lock_hash().b.name)),
                SubCommand::with_name("get-live-cells")
                    .about("Get live cells by lock/type/code hash")
                    .arg(arg::lock_hash())
                    .arg(arg::type_hash())
                    .arg(arg::code_hash())
                    .arg(arg::address())
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
        let from_account = privkey_or_from_account(m)?;

        let (from_address_payload_opt, master_key_cap_opt) =
            make_address_payload_and_master_key_cap(
                &from_account,
                self.key_store,
                self.ledger_key_store,
            )?;
        let from_address_info_opt: Option<(AddressPayload, H160)> =
            from_address_payload_opt.map(|payload| {
                let hash160 = H160::from_slice(payload.args().as_ref()).unwrap();
                (payload, hash160)
            });

        let network_type = get_network_type(self.rpc_client)?;

        let to_address: Address = AddressParser::default()
            .set_network(network_type)
            .from_matches(m, "to-address")?;

        let to_capacity: u64 = CapacityParser.from_matches(m, "capacity")?;
        let tx_fee: u64 = CapacityParser.from_matches(m, "tx-fee")?;

        let from_locked_address_opt: Option<Address> = AddressParser::default()
            .set_network(network_type)
            .set_full_type(MULTISIG_TYPE_HASH.clone())
            .from_matches_opt(m, "from-locked-address", false)?;
        if let Some(ref from_locked_address) = from_locked_address_opt {
            let args = from_locked_address.payload().args();
            let err_prefix = "Invalid from-locked-address's args";
            if args.len() != 28 {
                return Err(format!("{}: invalid {}", err_prefix, args.len()));
            }
            let mut since_bytes = [0u8; 8];
            since_bytes.copy_from_slice(&args[20..]);
            let since = Since::from_raw_value(u64::from_le_bytes(since_bytes));
            if !since.flags_is_valid() {
                return Err(format!("{}: invalid since flags", err_prefix));
            }
            if !since.is_absolute() {
                return Err(format!("{}: only support absolute since value", err_prefix));
            }
            if since.extract_metric().map(|(ty, _)| ty) != Some(SinceType::EpochNumberWithFraction)
            {
                return Err(format!("{}: only support epoch since value", err_prefix));
            }
        }

        // The lock hashes for search live cells
        let mut lock_hashes = Vec::new();
        let mut path_map: HashMap<H160, DerivationPath> = Default::default();

        if let Some((ref underived_payload, ref underived_hash)) = from_address_info_opt {
            // Remember underived keypair's script hash
            lock_hashes.push(Script::from(underived_payload).calc_script_hash());
            // Remember underived pub key hash
            path_map.insert(underived_hash.clone(), DerivationPath::empty());
        }

        let last_change_address_opt: Option<Address> = AddressParser::default()
            .set_network(network_type)
            .from_matches_opt(m, "derive-change-address", false)?;
        let change_address_payload = if let Some(last_change_address) = last_change_address_opt {
            let key_cap = master_key_cap_opt.as_ref().expect(
                "Shouldn't be allowed to pass --derive-change-address with --privkey-path.",
            );
            // Behave like HD wallet
            let change_last =
                H160::from_slice(last_change_address.payload().args().as_ref()).unwrap();
            let receiving_address_length: u32 = FromStrParser::<u32>::default()
                .from_matches(m, "derive-receiving-address-length")?;
            let change_address_length: u32 =
                FromStrParser::<u32>::default().from_matches(m, "derive-change-address-length")?;
            let key_set = key_cap
                .derived_key_set(
                    receiving_address_length,
                    &change_last,
                    change_address_length,
                )
                .map_err(|e| match e {
                    Either::Left(e) => e.to_string(),
                    Either::Right(e) => e.to_string(),
                })?;
            //.map_err(|err: K::Err| err.to_string())?;
            for (path, hash160) in key_set.external.iter().chain(key_set.change.iter()) {
                path_map.insert(hash160.clone(), path.clone());
                let payload = AddressPayload::from_pubkey_hash(hash160.clone());
                lock_hashes.push(Script::from(&payload).calc_script_hash());
            }
            last_change_address.payload().clone()
        } else if let Some((ref from_address_payload, _)) = from_address_info_opt {
            from_address_payload.clone()
        } else {
            return Err(
                "Need to pass --derive-change-address when using hardware wallet".to_string(),
            );
        };

        let multisig_config_opt =
            if let Some(from_locked_address) = from_locked_address_opt.as_ref() {
                lock_hashes.insert(
                    0,
                    Script::from(from_locked_address.payload()).calc_script_hash(),
                );
                let mut lock_args = path_map.keys();
                Some(loop {
                    let lock_arg =
                        match lock_args.next() {
                            Some(la) => la,
                            None => return Err(String::from(
                                "from-locked-address is not created from the key or derived keys",
                            )),
                        };
                    let mut sighash_addresses = Vec::default();
                    sighash_addresses.push(AddressPayload::from_pubkey_hash(lock_arg.clone()));
                    let require_first_n = 0;
                    let threshold = 1;
                    let cfg =
                        MultisigConfig::new_with(sighash_addresses, require_first_n, threshold)?;
                    if cfg.hash160().as_bytes() == &from_locked_address.payload().args()[0..20] {
                        break cfg;
                    }
                })
            } else {
                None
            };

        let to_data = get_to_data(m)?;

        let is_ledger = if let Either::Right(account) = from_account.clone() {
            match account {
                AccountId::SoftwareMasterKey(_) => false,
                AccountId::LedgerId(_) => true,
            }
        } else {
            false
        };

        let payload_opt = from_address_info_opt.map(|(x, _y)| x);
        if let Either::Left(from_privkey) = from_account {
            let signer = get_privkey_signer(from_privkey)?;
            self.transfer_impl(
                network_type,
                payload_opt,
                change_address_payload,
                to_address,
                to_capacity,
                to_data,
                tx_fee,
                lock_hashes,
                signer,
                false,
                multisig_config_opt,
                format,
                color,
                debug,
            )
        } else if let Some(key_cap) = master_key_cap_opt {
            let signer = get_keystore_signer(key_cap, path_map);
            self.transfer_impl(
                network_type,
                payload_opt,
                change_address_payload,
                to_address,
                to_capacity,
                to_data,
                tx_fee,
                lock_hashes,
                signer,
                is_ledger,
                multisig_config_opt,
                format,
                color,
                debug,
            )
        } else {
            unreachable!("If didn't pass privkey path, should have master key cap")
        }
    }

    fn transfer_impl(
        &mut self,
        network_type: NetworkType,
        from_address_payload_opt: Option<AddressPayload>,
        change_address_payload: AddressPayload,
        to_address: Address,
        to_capacity: u64,
        to_data: Bytes,
        tx_fee: u64,
        lock_hashes: Vec<Byte32>,
        signer: impl SignerFnTrait,
        is_ledger: bool,
        multisig_config_opt: Option<MultisigConfig>,
        format: OutputFormat,
        color: bool,
        debug: bool,
    ) -> Result<String, String> {
        let from_address = from_address_payload_opt.map(|x| Address::new(network_type, x.clone()));

        let to_address_hash_type = to_address.payload().hash_type();
        let to_address_code_hash: H256 = to_address.payload().code_hash().unpack();
        let to_address_args_len = to_address.payload().args().len();
        if !(to_address_hash_type == ScriptHashType::Type
            && to_address_code_hash == SIGHASH_TYPE_HASH
            && to_address_args_len == 20)
            && !(to_address_hash_type == ScriptHashType::Type
                && to_address_code_hash == MULTISIG_TYPE_HASH
                && (to_address_args_len == 20 || to_address_args_len == 28))
        {
            return Err(format!("Invalid to-address: {}", to_address));
        }

        check_capacity(to_capacity, to_data.len())?;

        let max_mature_number = get_max_mature_number(self.rpc_client)?;
        let mut from_capacity = 0;
        let mut infos: Vec<LiveCellInfo> = Default::default();
        let mut terminator = |_, info: &LiveCellInfo| {
            if from_capacity >= to_capacity + tx_fee {
                (true, false)
            } else if info.type_hashes.is_none()
                && info.data_bytes == 0
                && is_mature(info, max_mature_number)
            {
                from_capacity += info.capacity;
                infos.push(info.clone());
                (from_capacity >= to_capacity + tx_fee, false)
            } else {
                (false, false)
            }
        };

        let genesis_info = self.genesis_info()?;
        let genesis_hash = genesis_info.header().hash();
        let genesis_info_clone = genesis_info.clone();

        // For check index database is ready
        self.with_db(|_| ())?;
        let index_dir = self.index_dir.clone();

        if let Err(err) = with_index_db(&index_dir, genesis_hash.unpack(), |backend, cf| {
            IndexDatabase::from_db(backend, cf, network_type, genesis_info_clone, false)
                .map(|db| {
                    for lock_hash in lock_hashes {
                        db.get_live_cells_by_lock(lock_hash, None, &mut terminator);
                    }
                })
                .map_err(Into::into)
        }) {
            return Err(format!(
                "Index database may not ready, sync process: {}, error: {}",
                self.index_controller.state().read().to_string(),
                err.to_string(),
            ));
        }

        if tx_fee > ONE_CKB {
            return Err("Transaction fee can not be more than 1.0 CKB".to_string());
        }
        if to_capacity + tx_fee > from_capacity {
            let rendered_from_address = match from_address {
                Some(ref x) => format!("{}", x),
                None => "<hardware wallet>".to_string(),
            };
            return Err(format!(
                "Capacity(mature) not enough: {} => {}",
                rendered_from_address, from_capacity,
            ));
        }

        let rest_capacity = from_capacity - to_capacity - tx_fee;
        if rest_capacity < MIN_SECP_CELL_CAPACITY && tx_fee + rest_capacity > ONE_CKB {
            return Err("Transaction fee can not be more than 1.0 CKB, please change to-capacity value to adjust".to_string());
        }

        let mut helper = TxHelper::default();
        if let Some(multisig_config) = multisig_config_opt {
            helper.add_multisig_config(multisig_config)
        }

        let mut live_cell_cache: HashMap<(OutPoint, bool), ((CellOutput, Transaction), Bytes)> =
            Default::default();
        let mut get_live_cell_fn = |out_point: OutPoint, with_data: bool| {
            get_live_cell_with_cache(&mut live_cell_cache, self.rpc_client, out_point, with_data)
                .map(|(output, _)| output)
        };
        for info in &infos {
            helper.add_input(info.out_point(), None, &mut get_live_cell_fn, &genesis_info)?;
        }
        let to_output = CellOutput::new_builder()
            .capacity(Capacity::shannons(to_capacity).pack())
            .lock(to_address.payload().into())
            .build();
        helper.add_output(to_output, to_data);
        if rest_capacity >= MIN_SECP_CELL_CAPACITY {
            let change_output = CellOutput::new_builder()
                .capacity(Capacity::shannons(rest_capacity).pack())
                .lock((&change_address_payload).into())
                .build();
            helper.add_output(change_output, Bytes::default());
        }

        for (ref lock_arg, ref signature) in
            helper.sign_inputs(signer, &mut get_live_cell_fn, is_ledger)?
        {
            helper.add_signature(lock_arg.clone(), serialize_signature_bytes(signature))?;
        }
        let tx = helper.build_tx(&mut get_live_cell_fn)?;
        self.send_transaction(tx, format, color, debug)
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
            .send_transaction(transaction.data())
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
                let lock_hashes = if let Some(lock_hash) = lock_hash_opt {
                    vec![lock_hash.pack()]
                } else {
                    let network_type = get_network_type(self.rpc_client)?;

                    let receiving_address_length: u32 = FromStrParser::<u32>::default()
                        .from_matches(m, "derive-receiving-address-length")?;
                    let change_address_length: u32 = FromStrParser::<u32>::default()
                        .from_matches(m, "derive-change-address-length")?;
                    let address_payload = if let Some(address_str) = m.value_of("address") {
                        AddressParser::default()
                            .set_network(network_type)
                            .parse(address_str)?
                            .payload()
                            .clone()
                    } else {
                        get_address(Some(network_type), m)?
                    };
                    let mut lock_hashes = vec![Script::from(&address_payload).calc_script_hash()];
                    if m.is_present("derived") {
                        let password = read_password(false, None)?;
                        let lock_arg = H160::from_slice(address_payload.args().as_ref()).unwrap();
                        let key_set = self
                            .key_store
                            .derived_key_set_by_index_with_password(
                                &lock_arg,
                                password.as_bytes(),
                                0,
                                receiving_address_length,
                                0,
                                change_address_length,
                            )
                            .map_err(|err| err.to_string())?;
                        for (_, hash160) in key_set.external.iter().chain(key_set.change.iter()) {
                            let payload = AddressPayload::from_pubkey_hash(hash160.clone());
                            lock_hashes.push(Script::from(&payload).calc_script_hash());
                        }
                    }
                    lock_hashes
                };

                let max_mature_number = get_max_mature_number(self.rpc_client)?;
                let (total_capacity, immature_capacity, free_capacity, dao_capacity) = self
                    .with_db(|db| {
                        let mut total_capacity = 0;
                        let mut free_capacity = 0;
                        let mut dao_capacity = 0;
                        let mut immature_capacity = 0;
                        let mut terminator = |_idx: usize, info: &LiveCellInfo| {
                            if !is_mature(info, max_mature_number) {
                                immature_capacity += info.capacity;
                            }
                            if info
                                .type_hashes
                                .as_ref()
                                .filter(|(code_hash, _)| code_hash == &DAO_TYPE_HASH)
                                .is_some()
                            {
                                dao_capacity += info.capacity;
                            } else {
                                free_capacity += info.capacity;
                            }
                            total_capacity += info.capacity;
                            (false, false)
                        };
                        for lock_hash in lock_hashes {
                            let _ = db.get_live_cells_by_lock(lock_hash, None, &mut terminator);
                        }
                        (
                            total_capacity,
                            immature_capacity,
                            free_capacity,
                            dao_capacity,
                        )
                    })?;

                let mut resp = serde_json::json!({
                    "total": format!("{:#}", HumanCapacity::from(total_capacity))
                });
                if immature_capacity > 0 {
                    resp["immature"] =
                        serde_json::json!(format!("{:#}", HumanCapacity::from(immature_capacity)));
                }
                if dao_capacity > 0 {
                    resp["dao"] =
                        serde_json::json!(format!("{:#}", HumanCapacity::from(dao_capacity)));
                    resp["free"] =
                        serde_json::json!(format!("{:#}", HumanCapacity::from(free_capacity)));
                }
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

                let network_type = get_network_type(self.rpc_client)?;
                let lock_hash_opt = if lock_hash_opt.is_none() {
                    let address_opt: Option<Address> = AddressParser::default()
                        .set_network_opt(Some(network_type))
                        .from_matches_opt(m, "address", false)?;
                    address_opt
                        .map(|address| Script::from(address.payload()).calc_script_hash().unpack())
                } else {
                    lock_hash_opt
                };

                if lock_hash_opt.is_none() && type_hash_opt.is_none() && code_hash_opt.is_none() {
                    return Err(
                        "lock-hash or type-hash or code-hash or address is required".to_owned()
                    );
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

fn get_keystore_signer<K>(key: K, path_map: HashMap<H160, DerivationPath>) -> impl SignerFnTrait
where
    K: AbstractMasterPrivKey + Clone,
    K::Privkey: Clone,
    <K as AbstractMasterPrivKey>::Err: ToString,
    <K::Privkey as AbstractPrivKey>::Err: ToString,
{
    SignerClosureHelper(move |lock_args: &HashSet<H160>| {
        let path = match lock_args.iter().find_map(|lock_arg| path_map.get(lock_arg)) {
            None => return Ok(None),
            Some(path) => path.clone(),
        };
        get_master_key_signer_raw(key.clone(), path)?.new_signature_builder(lock_args)
    })
}
