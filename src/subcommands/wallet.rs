use std::{collections::HashMap, fs, str::FromStr};

use bitcoin::bip32::DerivationPath;
use clap::{ArgMatches, Args, Command, CommandFactory, FromArgMatches, Parser, Subcommand};
use serde::{Deserialize, Serialize};

use ckb_chain_spec::consensus::TYPE_ID_CODE_HASH;
use ckb_hash::new_blake2b;
use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    constants::{MultisigScript, DAO_TYPE_HASH, SIGHASH_TYPE_HASH},
    traits::{
        CellCollector, CellQueryOptions, DefaultCellCollector, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider, MaturityOption, PrimaryScriptType, Signer,
        ValueRangeOption,
    },
    tx_builder::{
        transfer::CapacityTransferBuilder, unlock_tx, BalanceTxCapacityError, CapacityBalancer,
        CapacityProvider, SinceSource, TxBuilder, TxBuilderError,
    },
    types::ScriptId,
    unlock::{
        MultisigConfig, ScriptUnlocker, SecpMultisigScriptSigner, SecpMultisigUnlocker,
        SecpSighashScriptSigner, SecpSighashUnlocker,
    },
    util::{get_max_mature_number, is_mature},
    Address, AddressPayload, HumanCapacity, Since, SinceType, SECP256K1,
};
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, FeeRate, ScriptHashType, TransactionView},
    packed::{CellOutput, Script, WitnessArgs},
    prelude::*,
    H160, H256,
};
use plugin_protocol::LiveCellInfo;

use super::{CliSubCommand, Output};
use crate::plugin::PluginManager;
use crate::utils::{
    arg_parser::{
        AddressParser, ArgParser, CapacityParser, FilePathParser, FixedHashParser, FromStrParser,
        HexParser, PrivkeyPathParser, PrivkeyWrapper, PubkeyHexParser,
    },
    genesis_info::GenesisInfo,
    other::{
        check_capacity, get_genesis_info, get_network_type, map_tx_builder_error_2_str,
        read_password, to_live_cell_info,
    },
    rpc::HttpRpcClient,
    signer::KeyStoreHandlerSigner,
};

fn parse_privkey_path(input: &str) -> Result<String, String> {
    PrivkeyPathParser.validate(input).map(|_| input.to_string())
}

fn parse_address(input: &str) -> Result<String, String> {
    AddressParser::default()
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_lock_arg(input: &str) -> Result<String, String> {
    FixedHashParser::<H160>::default()
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_from_account(input: &str) -> Result<String, String> {
    FixedHashParser::<H160>::default()
        .validate(input)
        .or_else(|err| {
            AddressParser::default()
                .validate(input)
                .and_then(|()| AddressParser::new_sighash().validate(input))
                .map_err(|_| err)
        })
        .map(|_| input.to_string())
}

fn parse_capacity(input: &str) -> Result<String, String> {
    CapacityParser.validate(input).map(|_| input.to_string())
}

fn parse_u64(input: &str) -> Result<String, String> {
    FromStrParser::<u64>::default()
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_hex(input: &str) -> Result<String, String> {
    HexParser.validate(input).map(|_| input.to_string())
}

fn parse_file_path(input: &str) -> Result<String, String> {
    FilePathParser::new(true)
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_u32(input: &str) -> Result<String, String> {
    FromStrParser::<u32>::default()
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_usize(input: &str) -> Result<String, String> {
    FromStrParser::<usize>::default()
        .validate(input)
        .map(|_| input.to_string())
}

#[derive(Parser, Debug)]
#[command(
    name = "wallet",
    about = "Transfer / query balance (with local index) / key utils"
)]
pub struct WalletCmd {
    #[command(subcommand)]
    pub command: WalletSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum WalletSubcommands {
    /// Transfer capacity to an address (can have data)
    Transfer(WalletTransferArgs),
    /// Get capacity address or lock arg or pubkey
    GetCapacity(WalletGetCapacityArgs),
    /// Get live cells by address
    GetLiveCells(WalletGetLiveCellsArgs),
}

#[derive(Args, Debug)]
pub struct WalletTransferArgs {
    #[arg(long = "privkey-path", id = "privkey-path", required_unless_present = "from-account", value_parser = parse_privkey_path)]
    pub privkey_path: Option<String>,
    #[arg(long = "from-account", id = "from-account", required_unless_present = "privkey-path", conflicts_with = "privkey-path", value_parser = parse_from_account)]
    pub from_account: Option<String>,
    #[arg(long = "from-locked-address", id = "from-locked-address", value_parser = parse_address)]
    pub from_locked_address: Option<String>,
    #[arg(long = "to-address", id = "to-address", value_parser = parse_address)]
    pub to_address: String,
    #[arg(long = "to-data", id = "to-data", value_parser = parse_hex)]
    pub to_data: Option<String>,
    #[arg(long = "to-data-path", id = "to-data-path", value_parser = parse_file_path)]
    pub to_data_path: Option<String>,
    #[arg(long = "capacity", id = "capacity", value_parser = parse_capacity)]
    pub capacity: String,
    #[arg(long = "fee-rate", id = "fee-rate", default_value = "1000", value_parser = parse_u64)]
    pub fee_rate: String,
    #[arg(long = "max-tx-fee", id = "max-tx-fee", value_parser = parse_capacity)]
    pub max_tx_fee: Option<String>,
    #[arg(long = "derive-receiving-address-length", id = "derive-receiving-address-length", default_value = "1000", value_parser = parse_u32)]
    pub derive_receiving_address_length: String,
    #[arg(long = "derive-change-address", id = "derive-change-address", conflicts_with = "privkey-path", value_parser = parse_address)]
    pub derive_change_address: Option<String>,
    #[arg(long = "skip-check-to-address", id = "skip-check-to-address")]
    pub skip_check_to_address: bool,
    #[arg(long = "type-id", id = "type-id")]
    pub type_id: bool,
}

#[derive(Args, Debug)]
pub struct WalletGetCapacityArgs {
    #[arg(long, value_parser = parse_address)]
    pub address: Option<String>,
    #[arg(long = "pubkey", id = "pubkey")]
    pub pubkey: Option<String>,
    #[arg(long = "lock-arg", id = "lock-arg", value_parser = parse_lock_arg)]
    pub lock_arg: Option<String>,
    #[arg(long = "derive-receiving-address-length", id = "derive-receiving-address-length", default_value = "1000", value_parser = parse_u32)]
    pub derive_receiving_address_length: String,
    #[arg(long = "derive-change-address-length", id = "derive-change-address-length", default_value = "1000", value_parser = parse_u32)]
    pub derive_change_address_length: String,
    #[arg(long = "derived", id = "derived")]
    pub derived: bool,
}

#[derive(Args, Debug)]
pub struct WalletGetLiveCellsArgs {
    #[arg(long, value_parser = parse_address)]
    pub address: String,
    #[arg(long = "limit", id = "limit", default_value = "15", value_parser = parse_usize)]
    pub limit: String,
    #[arg(long = "from", id = "from", value_parser = parse_u64)]
    pub from: Option<String>,
    #[arg(long = "to", id = "to", value_parser = parse_u64)]
    pub to: Option<String>,
}

// Max derived change address to search
const DERIVE_CHANGE_ADDRESS_MAX_LEN: u32 = 10000;

pub struct WalletSubCommand<'a> {
    plugin_mgr: &'a mut PluginManager,
    rpc_client: &'a mut HttpRpcClient,
    genesis_info: Option<GenesisInfo>,
}

impl<'a> WalletSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        plugin_mgr: &'a mut PluginManager,
        genesis_info: Option<GenesisInfo>,
    ) -> WalletSubCommand<'a> {
        WalletSubCommand {
            rpc_client,
            plugin_mgr,
            genesis_info,
        }
    }

    fn genesis_info(&mut self) -> Result<GenesisInfo, String> {
        self.genesis_info = Some(get_genesis_info(&self.genesis_info, self.rpc_client)?);
        Ok(self.genesis_info.clone().unwrap())
    }

    pub fn subcommand() -> Command {
        WalletCmd::command()
    }

    pub fn transfer(
        &mut self,
        args: TransferArgs,
        skip_check: bool,
    ) -> Result<TransactionView, String> {
        let TransferArgs {
            privkey_path,
            from_account,
            from_locked_address,
            password,
            derive_receiving_address_length,
            derive_change_address,
            capacity,
            fee_rate,
            force_small_change_as_fee,
            to_address,
            to_data,
            is_type_id,
            skip_check_to_address,
        } = args;

        let network_type = get_network_type(self.rpc_client)?;
        let from_privkey: Option<PrivkeyWrapper> = privkey_path
            .map(|input| PrivkeyPathParser.parse(&input))
            .transpose()?;
        let from_account: Option<H160> = from_account
            .map(|input| {
                FixedHashParser::<H160>::default()
                    .parse(&input)
                    .or_else(|err| {
                        let result: Result<Address, String> = AddressParser::new_sighash()
                            .set_network(network_type)
                            .parse(&input);
                        result
                            .map(|address| H160::from_slice(&address.payload().args()).unwrap())
                            .map_err(|_| err)
                    })
            })
            .transpose()?;
        let from_locked_address: Option<Address> = from_locked_address
            .map(|input| {
                AddressParser::new_multisig(MultisigScript::Legacy)
                    .set_network(network_type)
                    .parse(&input)
                    .or(AddressParser::new_multisig(MultisigScript::V2)
                        .set_network(network_type)
                        .parse(&input))
            })
            .transpose()?;
        let to_capacity: u64 = CapacityParser.parse(&capacity)?.into();
        let fee_rate: u64 = FromStrParser::<u64>::default().parse(&fee_rate)?;
        let force_small_change_as_fee: Option<u64> =
            force_small_change_as_fee.map(|s| CapacityParser.parse(&s).unwrap().into());
        let receiving_address_length: u32 = derive_receiving_address_length
            .map(|input| FromStrParser::<u32>::default().parse(&input))
            .transpose()?
            .unwrap_or(1000);
        let last_change_address_opt: Option<Address> = derive_change_address
            .map(|input| {
                AddressParser::default()
                    .set_network(network_type)
                    .parse(&input)
            })
            .transpose()?;
        let to_address: Address = AddressParser::default()
            .set_network(network_type)
            .parse(&to_address)?;
        let to_data = to_data.unwrap_or_default();

        let (from_address_payload, password) = if let Some(from_privkey) = from_privkey.as_ref() {
            let from_pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, from_privkey);
            (AddressPayload::from_pubkey(&from_pubkey), None)
        } else {
            let password = if let Some(password) = password {
                Some(password)
            } else if self.plugin_mgr.keystore_require_password() {
                Some(read_password(false, None)?)
            } else {
                None
            };
            (
                AddressPayload::from_pubkey_hash(from_account.unwrap()),
                password,
            )
        };
        let from_address = Address::new(network_type, from_address_payload.clone(), false);

        if let Some(from_locked_address) = from_locked_address.as_ref() {
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

        let to_address_hash_type = to_address.payload().hash_type();
        let to_address_code_hash: H256 = to_address
            .payload()
            .code_hash(Some(to_address.network()))
            .unpack();
        let to_address_args_len = to_address.payload().args().len();
        if !(skip_check_to_address
            || (to_address_hash_type == ScriptHashType::Type
                && to_address_code_hash == SIGHASH_TYPE_HASH
                && to_address_args_len == 20)
            || (to_address_hash_type == MultisigScript::V2.script_id().hash_type
                && to_address_code_hash == MultisigScript::V2.script_id().code_hash
                && (to_address_args_len == 20 || to_address_args_len == 28))
            || (to_address_hash_type == MultisigScript::Legacy.script_id().hash_type
                && to_address_code_hash == MultisigScript::Legacy.script_id().code_hash
                && (to_address_args_len == 20 || to_address_args_len == 28)))
        {
            return Err(format!(
                "Invalid to-address: {}\n[Hint]: Add `--skip-check-to-address` flag to transfer to any address",
                to_address
            ));
        }
        check_capacity(to_capacity, to_data.len())?;

        let genesis_info = self.genesis_info()?;

        // The lock scripts for search live cells
        let sighash_placeholder_witness = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(vec![0u8; 65])).pack())
            .build();
        let mut lock_scripts = vec![(
            Script::from(&from_address_payload),
            sighash_placeholder_witness.clone(),
            SinceSource::default(),
        )];

        let from_lock_arg = H160::from_slice(from_address.payload().args().as_ref()).unwrap();
        let mut path_map: HashMap<H160, DerivationPath> = Default::default();
        let (change_address_payload, change_path) =
            if let Some(last_change_address) = last_change_address_opt.as_ref() {
                // Behave like HD wallet
                let change_last =
                    H160::from_slice(last_change_address.payload().args().as_ref()).unwrap();
                let key_set = self.plugin_mgr.keystore_handler().derived_key_set(
                    from_lock_arg.clone(),
                    receiving_address_length,
                    change_last.clone(),
                    DERIVE_CHANGE_ADDRESS_MAX_LEN,
                    None,
                )?;
                let mut change_path_opt = None;
                for (path, hash160) in key_set.external.into_iter().chain(key_set.change) {
                    if hash160 == change_last {
                        change_path_opt = Some(path.clone());
                    }
                    path_map.insert(hash160.clone(), path);
                    let payload = AddressPayload::from_pubkey_hash(hash160);
                    lock_scripts.push((
                        Script::from(&payload),
                        sighash_placeholder_witness.clone(),
                        Default::default(),
                    ));
                }
                (
                    last_change_address.payload().clone(),
                    change_path_opt.expect("change path not exists"),
                )
            } else {
                (
                    from_address.payload().clone(),
                    self.plugin_mgr.root_key_path(from_lock_arg.clone())?,
                )
            };

        let get_signer = || -> Result<Box<dyn Signer>, String> {
            if let Some(privkey) = from_privkey.as_ref() {
                Ok(Box::new(privkey.clone()))
            } else {
                let mut signer = KeyStoreHandlerSigner::new(
                    self.plugin_mgr.keystore_handler(),
                    Box::new(DefaultTransactionDependencyProvider::new(
                        self.rpc_client.url(),
                        0,
                    )),
                );
                if let Some(password) = password.as_ref() {
                    signer.set_password(from_lock_arg.clone(), password.clone());
                }
                if let Some(last_change_address) = last_change_address_opt.as_ref() {
                    let change_last =
                        H160::from_slice(last_change_address.payload().args().as_ref()).unwrap();
                    signer.cache_key_set(
                        from_lock_arg.clone(),
                        receiving_address_length,
                        change_last,
                        DERIVE_CHANGE_ADDRESS_MAX_LEN,
                    )?;
                }
                signer.set_change_path(from_lock_arg.clone(), change_path.to_string());
                Ok(Box::new(signer))
            }
        };
        let mut unlockers: HashMap<_, Box<dyn ScriptUnlocker>> = HashMap::new();
        let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
        let sighash_unlocker = {
            let signer = get_signer()?;
            SecpSighashUnlocker::new(SecpSighashScriptSigner::new(signer))
        };
        unlockers.insert(sighash_script_id, Box::new(sighash_unlocker));

        if let Some(from_locked_address) = from_locked_address.as_ref() {
            let mut found_lock_arg = false;
            for lock_arg in std::iter::once(&from_lock_arg).chain(path_map.keys()) {
                let sighash_addresses = vec![lock_arg.clone()];
                let require_first_n = 0;
                let threshold = 1;

                let mut matched_multisig_config = None;
                for multisig_script in [MultisigScript::V2, MultisigScript::Legacy] {
                    let config = MultisigConfig::new_with(
                        multisig_script,
                        sighash_addresses.clone(),
                        require_first_n,
                        threshold,
                    )
                    .map_err(|err| err.to_string())?;
                    if config.hash160().as_bytes() == &from_locked_address.payload().args()[0..20]
                        && config
                            .lock_code_hash()
                            .pack()
                            .eq(&from_locked_address.payload().code_hash(Some(network_type)))
                        && config
                            .lock_hash_type()
                            .eq(&from_locked_address.payload().hash_type().into())
                    {
                        matched_multisig_config = Some(config);
                        break;
                    }
                }

                if let Some(matched_multisig_config) = matched_multisig_config {
                    found_lock_arg = true;
                    let lock_script = Script::from(from_locked_address.payload());
                    let placeholder_witness = matched_multisig_config.placeholder_witness();
                    lock_scripts.insert(
                        0,
                        (lock_script, placeholder_witness, SinceSource::LockArgs(20)),
                    );
                    let multisig_script_id =
                        MultisigScript::try_from(matched_multisig_config.lock_code_hash())
                            .unwrap_or_else(|_| {
                                panic!(
                                    "must get multisig script by {}",
                                    matched_multisig_config.lock_code_hash()
                                )
                            })
                            .script_id();
                    let multisig_unlocker = {
                        let signer = get_signer()?;
                        SecpMultisigUnlocker::new(SecpMultisigScriptSigner::new(
                            signer,
                            matched_multisig_config,
                        ))
                    };
                    unlockers.insert(multisig_script_id, Box::new(multisig_unlocker));
                    break;
                };
            }
            if !found_lock_arg {
                return Err(String::from(
                    "from-locked-address is not created from the key or derived keys",
                ));
            }
        }

        let balancer = CapacityBalancer {
            fee_rate: FeeRate::from_u64(fee_rate),
            change_lock_script: Some(Script::from(&change_address_payload)),
            capacity_provider: CapacityProvider::new(lock_scripts),
            force_small_change_as_fee,
        };
        let tx_dep_provider = DefaultTransactionDependencyProvider::new(self.rpc_client.url(), 10);
        let mut cell_collector = DefaultCellCollector::new(self.rpc_client.url());
        let header_dep_resolver = DefaultHeaderDepResolver::new(self.rpc_client.url());

        // Add outputs
        let placeholder_type_script = if is_type_id {
            Some(
                Script::new_builder()
                    .code_hash(TYPE_ID_CODE_HASH.pack())
                    .hash_type(ScriptHashType::Type)
                    .args(Bytes::from(vec![0u8; 32]).pack())
                    .build(),
            )
        } else {
            None
        };
        let to_output = CellOutput::new_builder()
            .capacity(Capacity::shannons(to_capacity).pack())
            .lock(to_address.payload())
            .type_(placeholder_type_script.pack())
            .build();
        let builder = CapacityTransferBuilder::new(vec![(to_output, to_data)]);
        let mut tx = builder
            .build_balanced(
                &mut cell_collector,
                &genesis_info.cell_dep_resolver,
                &header_dep_resolver,
                &tx_dep_provider,
                &balancer,
                &unlockers,
            )
            .map_err(|err| {
                if balancer.force_small_change_as_fee.is_none() {
                    if let TxBuilderError::BalanceCapacity(BalanceTxCapacityError::CapacityNotEnough(ref msg)) =
                        err
                    {
                        let prefix = "can not create change cell, left capacity=";
                        if msg.contains(prefix) {
                            let left_capacity = HumanCapacity::from_str(&msg[prefix.len()..]);
                            if let Ok(left_capacity) = left_capacity {
                                let suggest_capacity = HumanCapacity(left_capacity.0 + to_capacity);

                                return format!("{}, try to transfer {} or try parameter `--max-tx-fee` to make small left capacity as transaction fee", err, suggest_capacity);
                            }
                        }
                    }
                }
                map_tx_builder_error_2_str(balancer.force_small_change_as_fee.is_none(), err)
            })?;
        if is_type_id {
            let mut blake2b = new_blake2b();
            let first_cell_input = tx.inputs().into_iter().next().expect("inputs empty");
            blake2b.update(first_cell_input.as_slice());
            blake2b.update(&0u64.to_le_bytes());
            let mut ret = [0; 32];
            blake2b.finalize(&mut ret);
            let type_script = Script::new_builder()
                .code_hash(TYPE_ID_CODE_HASH.pack())
                .hash_type(ScriptHashType::Type)
                .args(Bytes::from(ret.to_vec()).pack())
                .build();
            let mut outputs = tx.outputs().into_iter().collect::<Vec<_>>();
            outputs[0] = tx
                .output(0)
                .expect("first output")
                .as_builder()
                .type_(Some(type_script).pack())
                .build();
            tx = tx.as_advanced_builder().set_outputs(outputs).build();
        }
        let (tx, still_locked_groups) =
            unlock_tx(tx, &tx_dep_provider, &unlockers).map_err(|err| err.to_string())?;
        assert!(still_locked_groups.is_empty());

        let outputs_validator = if is_type_id || skip_check || skip_check_to_address {
            Some(json_types::OutputsValidator::Passthrough)
        } else {
            None
        };

        let tx_hash = self
            .rpc_client
            .send_transaction(tx.data(), outputs_validator)
            .map_err(|err| format!("Send transaction error: {}", err))?;
        assert_eq!(tx.hash(), tx_hash.pack());
        Ok(tx)
    }

    pub fn get_capacity(&mut self, lock_scripts: Vec<Script>) -> Result<(u64, u64, u64), String> {
        let mut cell_collector = DefaultCellCollector::new(self.rpc_client.url());
        let max_mature_number = get_max_mature_number(self.rpc_client.client())?;
        let mut total_all = 0;
        let mut total_immature = 0;
        let mut total_dao = 0;
        for script in lock_scripts {
            let mut query = CellQueryOptions::new_lock(script);
            query.maturity = MaturityOption::Both;
            query.min_total_capacity = u64::MAX;
            let (cells, total_capacity) = cell_collector
                .collect_live_cells(&query, false)
                .map_err(|err| err.to_string())?;
            total_all += total_capacity;
            for cell in &cells {
                let capacity: u64 = cell.output.capacity().unpack();
                if !is_mature(cell, max_mature_number) {
                    total_immature += capacity;
                }
                if cell
                    .output
                    .type_()
                    .to_opt()
                    .map(|script| script.code_hash().as_slice() == DAO_TYPE_HASH.as_bytes())
                    .unwrap_or(false)
                {
                    total_dao += capacity;
                }
            }
        }
        Ok((total_all, total_immature, total_dao))
    }

    pub fn get_live_cells(
        &mut self,
        script: Script,
        script_type: PrimaryScriptType,
        from_number: u64,
        to_number: u64,
        limit: u32,
    ) -> Result<Vec<LiveCell>, String> {
        let mut cell_collector = DefaultCellCollector::new(self.rpc_client.url());

        let mut query = CellQueryOptions::new(script, script_type);
        query.maturity = MaturityOption::Both;
        query.min_total_capacity = u64::MAX;
        query.limit = Some(limit);
        query.block_range = Some(ValueRangeOption::new(from_number, to_number));
        let (cells, _total_capacity) = cell_collector
            .collect_live_cells(&query, false)
            .map_err(|err| err.to_string())?;

        let max_mature_number = get_max_mature_number(self.rpc_client.client())?;
        let live_cells = cells
            .into_iter()
            .map(|cell| {
                let mature = is_mature(&cell, max_mature_number);
                LiveCell {
                    info: to_live_cell_info(&cell),
                    mature,
                }
            })
            .collect::<Vec<_>>();
        Ok(live_cells)
    }
}

impl CliSubCommand for WalletSubCommand<'_> {
    fn process(&mut self, matches: &ArgMatches, debug: bool) -> Result<Output, String> {
        let cmd = WalletCmd::from_arg_matches(matches).map_err(|err| err.to_string())?;
        match cmd.command {
            WalletSubcommands::Transfer(args) => {
                let to_data = if let Some(hex) = args.to_data.as_ref() {
                    Bytes::from(HexParser.parse(hex)?)
                } else if let Some(path) = args.to_data_path.as_ref() {
                    let content = fs::read(path).map_err(|err| err.to_string())?;
                    Bytes::from(content)
                } else {
                    Bytes::new()
                };
                let args = TransferArgs {
                    privkey_path: args.privkey_path.clone(),
                    from_account: args.from_account.clone(),
                    from_locked_address: args.from_locked_address.clone(),
                    password: None,
                    capacity: args.capacity.clone(),
                    fee_rate: args.fee_rate.clone(),
                    force_small_change_as_fee: args.max_tx_fee.clone(),
                    derive_receiving_address_length: Some(
                        args.derive_receiving_address_length.clone(),
                    ),
                    derive_change_address: args.derive_change_address.clone(),
                    to_address: args.to_address.clone(),
                    to_data: Some(to_data),
                    is_type_id: args.type_id,
                    skip_check_to_address: args.skip_check_to_address,
                };
                let tx = self.transfer(args, false)?;
                if debug {
                    let rpc_tx_view = json_types::TransactionView::from(tx);
                    Ok(Output::new_output(rpc_tx_view))
                } else {
                    let tx_hash: H256 = tx.hash().unpack();
                    Ok(Output::new_output(tx_hash))
                }
            }
            WalletSubcommands::GetCapacity(args) => {
                let network_type = get_network_type(self.rpc_client)?;

                let receiving_address_length: u32 =
                    FromStrParser::<u32>::default().parse(&args.derive_receiving_address_length)?;
                let change_address_length: u32 =
                    FromStrParser::<u32>::default().parse(&args.derive_change_address_length)?;
                let address_payload = if let Some(address_str) = args.address.as_ref() {
                    AddressParser::default()
                        .set_network(network_type)
                        .parse(address_str)?
                        .payload()
                        .clone()
                } else if let Some(pubkey_str) = args.pubkey.as_ref() {
                    let pubkey = PubkeyHexParser.parse(pubkey_str)?;
                    AddressPayload::from_pubkey(&pubkey)
                } else if let Some(lock_arg_str) = args.lock_arg.as_ref() {
                    let lock_arg: H160 = FixedHashParser::<H160>::default().parse(lock_arg_str)?;
                    AddressPayload::from_pubkey_hash(lock_arg)
                } else {
                    return Err("Please give one argument".to_string());
                };
                let mut lock_scripts = vec![Script::from(&address_payload)];
                if args.derived {
                    let lock_arg = H160::from_slice(address_payload.args().as_ref()).unwrap();

                    let key_set = self
                        .plugin_mgr
                        .keystore_handler()
                        .derived_key_set_by_index(
                            lock_arg,
                            0,
                            receiving_address_length,
                            0,
                            change_address_length,
                            None,
                        )?;
                    for (_, hash160) in key_set.external.iter().chain(key_set.change.iter()) {
                        let payload = AddressPayload::from_pubkey_hash(hash160.clone());
                        lock_scripts.push(Script::from(&payload));
                    }
                }

                let (total, immature, dao) = self.get_capacity(lock_scripts)?;

                let mut resp =
                    serde_json::json!({ "total": format!("{:#}", HumanCapacity::from(total)) });
                if immature > 0 {
                    resp["immature"] =
                        serde_json::json!(format!("{:#}", HumanCapacity::from(immature)));
                }
                if dao > 0 {
                    let free = total - dao;
                    resp["dao"] = serde_json::json!(format!("{:#}", HumanCapacity::from(dao)));
                    resp["free"] = serde_json::json!(format!("{:#}", HumanCapacity::from(free)));
                }
                Ok(Output::new_output(resp))
            }
            WalletSubcommands::GetLiveCells(args) => {
                let limit: u32 = FromStrParser::<u32>::default().parse(&args.limit)?;
                let from_number_opt: Option<u64> = args
                    .from
                    .as_ref()
                    .map(|value| FromStrParser::<u64>::default().parse(value))
                    .transpose()?;
                let to_number_opt: Option<u64> = args
                    .to
                    .as_ref()
                    .map(|value| FromStrParser::<u64>::default().parse(value))
                    .transpose()?;

                let network_type = get_network_type(self.rpc_client)?;
                let address: Address = AddressParser::default()
                    .set_network(network_type)
                    .parse(&args.address)?;
                let lock_script = Script::from(address.payload());
                let live_cells = self.get_live_cells(
                    lock_script,
                    PrimaryScriptType::Lock,
                    from_number_opt.unwrap_or(0),
                    to_number_opt.unwrap_or(u64::MAX),
                    limit,
                )?;

                let resp = serde_json::json!({
                    "live_cells": live_cells.into_iter().map(|live_cell| {
                        let LiveCell{ info, mature } = live_cell;
                        let mut value = serde_json::to_value(&info).unwrap();
                        let mature = serde_json::Value::Bool(mature);
                        let capacity_string = serde_json::Value::String(format!("{:#}", HumanCapacity::from(info.capacity)));
                        let map = value.as_object_mut().unwrap();
                        map.insert("capacity".to_string(), capacity_string);
                        map.insert("mature".to_string(), mature);
                        value
                    }).collect::<Vec<_>>(),
                });

                Ok(Output::new_output(resp))
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct TransferArgs {
    pub privkey_path: Option<String>,
    pub from_account: Option<String>,
    pub from_locked_address: Option<String>,
    pub password: Option<String>,
    pub derive_receiving_address_length: Option<String>,
    pub derive_change_address: Option<String>,
    pub capacity: String,
    pub fee_rate: String,
    pub force_small_change_as_fee: Option<String>,
    pub to_address: String,
    pub to_data: Option<Bytes>,
    pub is_type_id: bool,
    pub skip_check_to_address: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiveCell {
    pub info: LiveCellInfo,
    pub mature: bool,
}
