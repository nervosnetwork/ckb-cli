use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Error, Result};
use chrono::prelude::*;
use ckb_chain_spec::consensus::TYPE_ID_CODE_HASH;
use ckb_hash::blake2b_256;
use ckb_index::{CellIndex, IndexDatabase, LiveCellInfo};
use ckb_jsonrpc_types as json_types;
use ckb_jsonrpc_types::JsonBytes;
use ckb_sdk::{
    constants::{MIN_SECP_CELL_CAPACITY, ONE_CKB},
    Address, GenesisInfo, HttpRpcClient, HumanCapacity, MultisigConfig, NetworkType, SignerFn,
    TxHelper,
};
use ckb_sdk_types::{
    deployment::{
        Cell, CellLocation, CellRecipe, DepGroup, DepGroupRecipe, Deployment, DeploymentRecipe,
    },
    tx_helper::{ReprMultisigConfig, ReprTxHelper},
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, Capacity, ScriptHashType, TransactionBuilder},
    packed,
    prelude::*,
    H160, H256,
};
use clap::{App, Arg, ArgMatches};
use serde_derive::{Deserialize, Serialize};

use super::{CliSubCommand, Output};
use crate::plugin::PluginManager;
use crate::utils::{
    arg,
    arg_parser::{
        AddressParser, ArgParser, CapacityParser, DirPathParser, FilePathParser, FixedHashParser,
        PrivkeyPathParser, PrivkeyWrapper,
    },
    index::{with_db, IndexController},
    other::{
        calculate_type_id, enough_capacity, get_keystore_signer, get_live_cell_with_cache,
        get_max_mature_number, get_network_type, get_privkey_signer, is_mature, read_password,
    },
};

const DEPLOYMENT_TOML: &str = include_str!("../deployment.toml");

// Features:
//  * DONE Support sighash/multisig lock
//  * DONE Support type id
//  * DONE Support dep group
//  * DONE Support migration
//  * DONE Support outpoint/file as data source
//  * DONE Support offline sign
pub struct DeploySubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    plugin_mgr: &'a mut PluginManager,
    genesis_info: Option<GenesisInfo>,
    index_dir: PathBuf,
    index_controller: IndexController,
    wait_for_sync: bool,
}

impl<'a> DeploySubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        plugin_mgr: &'a mut PluginManager,
        genesis_info: Option<GenesisInfo>,
        index_dir: PathBuf,
        index_controller: IndexController,
        wait_for_sync: bool,
    ) -> DeploySubCommand<'a> {
        DeploySubCommand {
            rpc_client,
            plugin_mgr,
            genesis_info,
            index_dir,
            index_controller,
            wait_for_sync,
        }
    }

    fn genesis_info(&mut self) -> std::result::Result<GenesisInfo, String> {
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

    pub fn subcommand(name: &'static str) -> App<'static> {
        let arg_info_file = Arg::with_name("info-file")
            .long("info-file")
            .required(true)
            .takes_value(true)
            .validator(|input| FilePathParser::new(true).validate(input))
            .about("File path for saving deploy cell/dep_group transactions and metadata (format: json)");
        let arg_migration_dir = Arg::with_name("migration-dir")
            .long("migration-dir")
            .required(true)
            .takes_value(true)
            .validator(|input| DirPathParser::new(true).validate(input))
            .about("Migration directory for saving json format migration files");
        let arg_deployment = Arg::with_name("deployment-config")
            .long("deployment-config")
            .required(true)
            .takes_value(true)
            .validator(|input| FilePathParser::new(true).validate(input))
            .about("deployment config file path (.toml)");
        App::new(name)
            .about("Deploy contract binaries")
            .subcommands(vec![
                App::new("gen-txs")
                    .about("Generate cell/dep_group deploy transaction, then use `ckb-cli tx` sub-command to sign mutlsig inputs and send the transaction")
                    .arg(
                        Arg::with_name("from-address")
                            .long("from-address")
                            .required(true)
                            .takes_value(true)
                            .validator(|input| AddressParser::new_sighash().validate(input))
                            .about("Collect cells from this address (short sighash address)")
                    )
                    .arg(arg::tx_fee().required(true))
                    .arg(arg_deployment.clone())
                    .arg(arg_info_file.clone().validator(|input| FilePathParser::new(false).validate(input)))
                    .arg(arg_migration_dir.clone())
                    .arg(
                        Arg::with_name("sign-now")
                            .long("sign-now")
                            .about("Sign the cell/dep_group transaction add signatures to info-file now"),
                    ),
                App::new("sign-txs")
                    .arg(arg::privkey_path().required_unless(arg::from_account().get_name()))
                    .arg(arg::from_account().required_unless(arg::privkey_path().get_name()))
                    .arg(arg_info_file.clone())
                    .arg(
                        Arg::with_name("add-signatures")
                            .long("add-signatures")
                            .about("Sign and add signatures"),
                    )
                    .about("Sign cell/dep_group transactions (support offline sign)"),
                App::new("explain-txs")
                    .arg(arg_info_file.clone())
                    .about("Explain cell transaction and dep_group transaction"),
                App::new("apply-txs")
                    .arg(arg_info_file.clone())
                    .arg(arg_migration_dir)
                    .about("Send cell/dep_group and write results to migration directory"),
                App::new("init-config")
                    .arg(arg_deployment.validator(|input| FilePathParser::new(false).validate(input)))
                    .about("Initialize default deployment config (format: toml)")
            ])
    }
}

impl<'a> CliSubCommand for DeploySubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches, _debug: bool) -> Result<Output, String> {
        match matches.subcommand() {
            ("gen-txs", Some(m)) => {
                let network = get_network_type(self.rpc_client)?;
                let from_address: Address = AddressParser::new_sighash()
                    .set_network(network)
                    .from_matches(m, "from-address")?;
                let tx_fee: u64 = CapacityParser.from_matches(m, "tx-fee")?;
                let deployment_config: PathBuf =
                    FilePathParser::new(true).from_matches(m, "deployment-config")?;
                let migration_dir: PathBuf =
                    DirPathParser::new(true).from_matches(m, "migration-dir")?;
                let info_file: PathBuf = FilePathParser::new(false).from_matches(m, "info-file")?;

                if info_file.exists() {
                    return Err(format!("Output info-file already exists: {:?}", info_file));
                }

                let genesis_info = self.genesis_info()?;
                let max_mature_number = get_max_mature_number(self.rpc_client)?;

                // * Load deployment config
                let deployment =
                    load_deployment(&deployment_config).map_err(|err| err.to_string())?;
                let lock_script = packed::Script::from(deployment.lock.clone());

                // * Load last receipt
                let last_recipe =
                    load_last_snapshot(&migration_dir).map_err(|err| err.to_string())?;

                // * Load needed cells
                let cell_changes = load_cells(
                    self.rpc_client,
                    &deployment.cells,
                    last_recipe.as_ref().map(|recipe| &recipe.cell_recipes[..]),
                )
                .map_err(|err| err.to_string())?;

                let mut cell_deps = vec![genesis_info.sighash_dep()];
                if !deployment.multisig_config.sighash_addresses.is_empty() {
                    cell_deps.push(genesis_info.multisig_dep());
                }
                // * Build new cell transaction
                let cell_tx_opt = {
                    let mut collector = CellCollector::new(
                        self.rpc_client,
                        &genesis_info,
                        &self.index_dir,
                        self.index_controller.clone(),
                        self.wait_for_sync,
                        max_mature_number,
                    );
                    build_tx(
                        &from_address,
                        &mut collector,
                        tx_fee,
                        cell_deps.clone(),
                        &lock_script,
                        &cell_changes,
                    )
                    .map_err(|err| err.to_string())?
                };

                // * Build new cell recipes
                let new_cell_recipes =
                    build_new_cell_recipes(&lock_script, cell_tx_opt.as_ref(), &cell_changes)
                        .map_err(|err| err.to_string())?;

                // * Load needed dep groups
                let dep_group_changes = load_dep_groups(
                    self.rpc_client,
                    &deployment.dep_groups,
                    last_recipe
                        .as_ref()
                        .map(|recipe| &recipe.dep_group_recipes[..]),
                    &new_cell_recipes,
                )
                .map_err(|err| err.to_string())?;

                // * Build new dep_group transaction
                let dep_group_tx_opt = {
                    let mut collector = CellCollector::new(
                        self.rpc_client,
                        &genesis_info,
                        &self.index_dir,
                        self.index_controller.clone(),
                        self.wait_for_sync,
                        max_mature_number,
                    );
                    if let Some(cell_tx) = cell_tx_opt.as_ref() {
                        collector.apply_tx(cell_tx.clone())
                    }
                    build_tx(
                        &from_address,
                        &mut collector,
                        tx_fee,
                        cell_deps,
                        &lock_script,
                        &dep_group_changes,
                    )
                    .map_err(|err| err.to_string())?
                };
                if cell_tx_opt.is_none() && dep_group_tx_opt.is_none() {
                    return Err("No cells/dep_groups need update".to_string());
                }

                // * Load input transactions
                let mut used_input_txs = HashMap::default();
                if let Some(tx) = cell_tx_opt.as_ref() {
                    load_input_txs(&mut used_input_txs, self.rpc_client, tx)
                        .map_err(|err| err.to_string())?;
                    let tx_hash = tx.calc_tx_hash().unpack();
                    used_input_txs.insert(tx_hash, json_types::Transaction::from(tx.clone()));
                }
                if let Some(tx) = dep_group_tx_opt.as_ref() {
                    load_input_txs(&mut used_input_txs, self.rpc_client, tx)
                        .map_err(|err| err.to_string())?;
                }

                // * Build new dep_group recipes
                let new_dep_group_recipes = build_new_dep_group_recipes(
                    &lock_script,
                    dep_group_tx_opt.as_ref(),
                    &dep_group_changes,
                );

                // * Explain transactions
                let repr_cell_changes: Vec<_> = cell_changes
                    .iter()
                    .map(|change| change.to_repr(&lock_script))
                    .collect();
                let repr_dep_group_changes: Vec<_> = dep_group_changes
                    .iter()
                    .map(|change| change.to_repr(&lock_script))
                    .collect();
                let new_recipe = DeploymentRecipe {
                    cell_recipes: new_cell_recipes,
                    dep_group_recipes: new_dep_group_recipes,
                };
                let mut info = IntermediumInfo {
                    deployment,
                    last_recipe,
                    new_recipe,
                    used_input_txs,
                    cell_tx: cell_tx_opt.map(Into::into),
                    cell_tx_signatures: HashMap::default(),
                    cell_changes: repr_cell_changes,
                    dep_group_tx: dep_group_tx_opt.map(Into::into),
                    dep_group_tx_signatures: HashMap::default(),
                    dep_group_changes: repr_dep_group_changes,
                };
                explain_txs(&info).map_err(|err| err.to_string())?;

                // Sign if required
                if m.is_present("sign-now") {
                    let mut signer = {
                        let password = if self.plugin_mgr.keystore_require_password() {
                            Some(read_password(false, None)?)
                        } else {
                            None
                        };
                        if !from_address.payload().is_sighash() {
                            return Err(format!(
                                "Can not sign now, from-address is not a sighash address: {}",
                                from_address
                            ));
                        }
                        let account =
                            H160::from_slice(from_address.payload().args().as_ref()).expect("H160");
                        let keystore = self.plugin_mgr.keystore_handler();
                        let new_client = HttpRpcClient::new(self.rpc_client.url().to_owned());
                        get_keystore_signer(keystore, new_client, Vec::new(), account, password)
                    };
                    let _ = sign_info(&mut info, self.rpc_client, &mut signer, true)
                        .map_err(|err| err.to_string())?;
                }

                let mut file = fs::File::create(&info_file).map_err(|err| err.to_string())?;
                let content = serde_json::to_string_pretty(&info).map_err(|err| err.to_string())?;
                file.write_all(content.as_bytes())
                    .map_err(|err| err.to_string())?;
                Ok(Output::new_success())
            }
            ("sign-txs", Some(m)) => {
                let info_file: PathBuf = FilePathParser::new(true).from_matches(m, "info-file")?;
                let privkey_opt: Option<PrivkeyWrapper> =
                    PrivkeyPathParser.from_matches_opt(m, "privkey-path", false)?;
                let account_opt: Option<H160> = m
                    .value_of("from-account")
                    .map(|input| {
                        FixedHashParser::<H160>::default()
                            .parse(&input)
                            .or_else(|err| {
                                let mut parser = AddressParser::new_sighash();
                                match get_network_type(self.rpc_client) {
                                    Ok(network) => {
                                        parser.set_network(network);
                                    }
                                    Err(err) => {
                                        eprintln!("WARNING: get network type failed: {}", err);
                                    }
                                }
                                let result: Result<Address, String> = parser.parse(&input);
                                result
                                    .map(|address| {
                                        H160::from_slice(&address.payload().args()).unwrap()
                                    })
                                    .map_err(|_| err)
                            })
                    })
                    .transpose()?;

                let all_signatures = modify_info_file(&info_file, |info: &mut IntermediumInfo| {
                    let mut signer = if let Some(privkey) = privkey_opt {
                        get_privkey_signer(privkey)
                    } else {
                        let password = if self.plugin_mgr.keystore_require_password() {
                            Some(read_password(false, None).map_err(Error::msg)?)
                        } else {
                            None
                        };
                        let account = account_opt.unwrap();
                        let keystore = self.plugin_mgr.keystore_handler();
                        let new_client = HttpRpcClient::new(self.rpc_client.url().to_owned());
                        let used_input_txs: Vec<_> =
                            info.used_input_txs.values().cloned().collect();
                        get_keystore_signer(keystore, new_client, used_input_txs, account, password)
                    };

                    sign_info(
                        info,
                        self.rpc_client,
                        &mut signer,
                        m.is_present("add-signatures"),
                    )
                })
                .map_err(|err| err.to_string())?;
                Ok(Output::new_output(all_signatures))
            }
            ("explain-txs", Some(m)) => {
                // * Report cell transaction summary
                // * Report dep_group transaction summary
                let info_file: PathBuf = FilePathParser::new(false).from_matches(m, "info-file")?;

                let file = fs::File::open(info_file).map_err(|err| err.to_string())?;
                let info: IntermediumInfo =
                    serde_json::from_reader(&file).map_err(|err| err.to_string())?;

                explain_txs(&info).map_err(|err| err.to_string())?;

                Ok(Output::new_success())
            }
            ("apply-txs", Some(m)) => {
                let info_file: PathBuf = FilePathParser::new(false).from_matches(m, "info-file")?;
                let migration_dir: PathBuf =
                    DirPathParser::new(true).from_matches(m, "migration-dir")?;

                let file = fs::File::open(info_file).map_err(|err| err.to_string())?;
                let info: IntermediumInfo =
                    serde_json::from_reader(&file).map_err(|err| err.to_string())?;
                let skip_check = false;

                let (cell_tx_opt, dep_group_tx_opt) = {
                    let mut live_cell_cache: HashMap<
                        packed::OutPoint,
                        (packed::CellOutput, Bytes),
                    > = Default::default();
                    if let Some(cell_tx) = info.cell_tx.as_ref() {
                        let cell_tx = packed::Transaction::from(cell_tx.clone()).into_view();
                        let tx_hash = cell_tx.hash();
                        for (output_index, (output, data)) in
                            cell_tx.outputs_with_data_iter().enumerate()
                        {
                            let out_point =
                                packed::OutPoint::new(tx_hash.clone(), output_index as u32);
                            live_cell_cache.insert(out_point, (output, data));
                        }
                    }
                    let mut get_live_cell = |out_point: packed::OutPoint, with_data: bool| {
                        get_live_cell_with_cache(
                            &mut live_cell_cache,
                            self.rpc_client,
                            out_point,
                            with_data,
                        )
                        .map(|(output, _)| output)
                    };
                    let cell_tx_opt = info
                        .cell_tx_helper()
                        .map_err(|err| err.to_string())?
                        .map(|helper| {
                            let _ = helper.check_tx(&mut get_live_cell)?;
                            helper.build_tx(&mut get_live_cell, skip_check)
                        })
                        .transpose()?;
                    let dep_group_tx_opt = info
                        .dep_group_tx_helper()
                        .map_err(|err| err.to_string())?
                        .map(|helper| {
                            let _ = helper.check_tx(&mut get_live_cell)?;
                            helper.build_tx(&mut get_live_cell, skip_check)
                        })
                        .transpose()?;
                    (cell_tx_opt, dep_group_tx_opt)
                };

                let cell_tx_hash = if let Some(tx) = cell_tx_opt {
                    let calculated_tx_hash: H256 = tx.hash().unpack();
                    println!("> [send cell transaction]: {:#x}", calculated_tx_hash);
                    let tx_hash = self
                        .rpc_client
                        .send_transaction(tx.data(), None)
                        .map_err(|err| format!("Send transaction error: {}", err))?;
                    Some(tx_hash)
                } else {
                    None
                };

                let dep_group_tx_hash = if let Some(tx) = dep_group_tx_opt {
                    let calculated_tx_hash: H256 = tx.hash().unpack();
                    println!("> [send dep group transaction]: {:#x}", calculated_tx_hash);
                    let tx_hash = self
                        .rpc_client
                        .send_transaction(tx.data(), None)
                        .map_err(|err| format!("Send transaction error: {}", err))?;
                    Some(tx_hash)
                } else {
                    None
                };

                let mut path = migration_dir;
                path.push(snapshot_name());
                snapshot_recipe(&path, &info.new_recipe).map_err(|err| err.to_string())?;

                let resp = serde_json::json!({
                    "cell_tx": cell_tx_hash,
                    "dep_group_tx": dep_group_tx_hash,
                });
                Ok(Output::new_output(resp))
            }
            ("init-config", Some(m)) => {
                let deployment_config: PathBuf =
                    FilePathParser::new(false).from_matches(m, "deployment-config")?;

                if deployment_config.exists() {
                    return Err(format!(
                        "deployment-config already exists: {:?}",
                        deployment_config
                    ));
                }
                let _deployment: Deployment =
                    toml::from_str(DEPLOYMENT_TOML).map_err(|err| err.to_string())?;
                let mut file =
                    fs::File::create(&deployment_config).map_err(|err| err.to_string())?;
                file.write_all(DEPLOYMENT_TOML.as_bytes())
                    .map_err(|err| err.to_string())?;
                Ok(Output::new_success())
            }
            _ => Err(Self::subcommand("deploy").generate_usage()),
        }
    }
}

fn load_deployment(file_path: &Path) -> Result<Deployment> {
    let mut file = fs::File::open(file_path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let deployment = toml::from_slice(&buf)?;
    Ok(deployment)
}

fn load_snapshot(migration_dir: &Path, snapshot_name: String) -> Result<DeploymentRecipe> {
    let mut path = migration_dir.to_path_buf();
    path.push(snapshot_name);
    let file = fs::File::open(path)?;
    let recipe = serde_json::from_reader(&file)?;
    Ok(recipe)
}

fn snapshot_name() -> String {
    let now: DateTime<Utc> = Utc::now();
    now.format("%Y-%m-%d-%H%M%S.json").to_string()
}

fn snapshot_recipe(path: &PathBuf, recipe: &DeploymentRecipe) -> Result<()> {
    let content = serde_json::to_vec_pretty(recipe)?;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?
        .write_all(&content)?;
    Ok(())
}

fn load_last_snapshot(migration_dir: &Path) -> Result<Option<DeploymentRecipe>> {
    let re = regex::Regex::new(r"^\d{4}-\d{2}-\d{2}-\d{6}\.json$").unwrap();
    fs::read_dir(migration_dir)?
        .map(|d| d.map(|d| d.file_name()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|filename| filename.into_string().unwrap())
        .filter(|filename| re.is_match(filename))
        .max()
        .map(|last_filename| load_snapshot(migration_dir, last_filename))
        .transpose()
}

fn sign_info(
    info: &mut IntermediumInfo,
    rpc_client: &mut HttpRpcClient,
    signer: &mut SignerFn,
    add_signatures: bool,
) -> Result<HashMap<String, HashMap<JsonBytes, JsonBytes>>> {
    let skip_check = false;
    let mut live_cell_cache: HashMap<packed::OutPoint, (packed::CellOutput, Bytes)> =
        Default::default();
    for input_tx in info.used_input_txs.values() {
        let cell_tx = packed::Transaction::from(input_tx.clone()).into_view();
        // For security reason, we must calculate transaction hash from transaction.
        let tx_hash = cell_tx.hash();
        for (output_index, (output, data)) in cell_tx.outputs_with_data_iter().enumerate() {
            let out_point = packed::OutPoint::new(tx_hash.clone(), output_index as u32);
            live_cell_cache.insert(out_point, (output, data));
        }
    }
    let mut get_live_cell = |out_point: packed::OutPoint, with_data: bool| {
        get_live_cell_with_cache(&mut live_cell_cache, rpc_client, out_point, with_data)
            .map(|(output, _)| output)
    };

    let mut all_signatures: HashMap<String, HashMap<_, _>> = Default::default();
    if let Some(helper) = info.cell_tx_helper()? {
        let _ = helper.check_tx(&mut get_live_cell).map_err(Error::msg)?;
        let signatures: HashMap<_, _> = helper
            .sign_inputs(signer, &mut get_live_cell, skip_check)
            .map_err(Error::msg)?
            .into_iter()
            .map(|(k, v)| (JsonBytes::from_bytes(k), JsonBytes::from_bytes(v)))
            .collect();
        if add_signatures {
            let mut cell_tx_signatures: HashMap<JsonBytes, HashSet<JsonBytes>> = info
                .cell_tx_signatures
                .clone()
                .into_iter()
                .map(|(lock_arg, sigs)| (lock_arg, sigs.into_iter().collect()))
                .collect();
            for (lock_arg, signature) in signatures.clone() {
                cell_tx_signatures
                    .entry(lock_arg)
                    .or_default()
                    .insert(signature);
            }
            info.cell_tx_signatures = cell_tx_signatures
                .into_iter()
                .map(|(lock_arg, sigs)| (lock_arg, sigs.into_iter().collect()))
                .collect();
        }
        all_signatures.insert("cell_tx_signatures".to_string(), signatures);
    }

    if let Some(helper) = info.dep_group_tx_helper()? {
        let _ = helper.check_tx(&mut get_live_cell).map_err(Error::msg)?;
        let signatures: HashMap<_, _> = helper
            .sign_inputs(signer, &mut get_live_cell, skip_check)
            .map_err(Error::msg)?
            .into_iter()
            .map(|(k, v)| (JsonBytes::from_bytes(k), JsonBytes::from_bytes(v)))
            .collect();
        if add_signatures {
            let mut dep_group_tx_signatures: HashMap<JsonBytes, HashSet<JsonBytes>> = info
                .dep_group_tx_signatures
                .clone()
                .into_iter()
                .map(|(lock_arg, sigs)| (lock_arg, sigs.into_iter().collect()))
                .collect();
            for (lock_arg, signature) in signatures.clone() {
                dep_group_tx_signatures
                    .entry(lock_arg)
                    .or_default()
                    .insert(signature);
            }
            info.dep_group_tx_signatures = dep_group_tx_signatures
                .into_iter()
                .map(|(lock_arg, sigs)| (lock_arg, sigs.into_iter().collect()))
                .collect();
        }
        all_signatures.insert("dep_group_tx_signatures".to_string(), signatures);
    }
    Ok(all_signatures)
}

fn load_cells(
    rpc_client: &mut HttpRpcClient,
    cells: &[Cell],
    cell_recipes_opt: Option<&[CellRecipe]>,
) -> Result<Vec<CellChange>> {
    let mut cell_recipes_map: HashMap<&String, (&CellRecipe, bool)> =
        if let Some(cell_recipes) = cell_recipes_opt {
            cell_recipes
                .iter()
                .map(|recipe| (&recipe.name, (recipe, true)))
                .collect()
        } else {
            HashMap::default()
        };
    let mut cell_changes = Vec::new();

    let mut output_index = 0;
    for cell in cells {
        let (data_hash, data) = match &cell.location {
            CellLocation::File { file } => {
                let mut buf = Vec::new();
                fs::File::open(file)?.read_to_end(&mut buf)?;
                let data = Bytes::from(buf);
                let data_hash = H256::from(blake2b_256(data.as_ref()));
                (data_hash, data)
            }
            CellLocation::OutPoint { tx_hash, index } => {
                load_cell_data(rpc_client, tx_hash, *index)?
            }
        };
        let config = cell.clone();
        let change = if let Some((old_recipe, removed)) = cell_recipes_map.get_mut(&cell.name) {
            let old_recipe = old_recipe.clone();
            *removed = false;
            let data_unchanged = data_hash == old_recipe.data_hash;
            let type_id_unchanged = old_recipe.type_id.is_some() == config.enable_type_id;
            // NOTE: we trust `old_recipe.data_hash` here
            if data_unchanged && type_id_unchanged {
                StateChange::Unchanged {
                    data,
                    data_hash,
                    config,
                    old_recipe,
                }
            } else {
                StateChange::Changed {
                    data,
                    data_hash,
                    config,
                    old_recipe,
                    output_index,
                }
            }
        } else {
            StateChange::NewAdded {
                data,
                data_hash,
                config,
                output_index,
            }
        };
        if change.has_new_output() {
            output_index += 1;
        }
        cell_changes.push(change);
    }

    for (old_recipe, removed) in cell_recipes_map.values() {
        if *removed {
            cell_changes.push(StateChange::Removed {
                old_recipe: (*old_recipe).clone(),
            });
        }
    }
    Ok(cell_changes)
}

fn load_cell_data(
    rpc_client: &mut HttpRpcClient,
    tx_hash: &H256,
    index: u32,
) -> Result<(H256, Bytes)> {
    let out_point = packed::OutPoint::new_builder()
        .tx_hash(tx_hash.pack())
        .index(index.pack())
        .build();
    let cell_with_status = rpc_client
        .get_live_cell(out_point, true)
        .map_err(Error::msg)?;
    if cell_with_status.status != "live" {
        return Err(anyhow!(
            "Load cell by location failed: tx_hash: {:#x}, index: {} is not live cell",
            tx_hash,
            index
        ));
    }
    let data = cell_with_status
        .cell
        .expect("cell.info")
        .data
        .expect("info.data");
    Ok((data.hash, data.content.into_bytes()))
}

fn load_dep_groups(
    rpc_client: &mut HttpRpcClient,
    dep_groups: &[DepGroup],
    dep_group_recipes_opt: Option<&[DepGroupRecipe]>,
    new_cell_recipes: &[CellRecipe],
) -> Result<Vec<DepGroupChange>> {
    let mut dep_group_recipes_map: HashMap<&String, (&DepGroupRecipe, bool)> =
        if let Some(dep_group_recipes) = dep_group_recipes_opt {
            dep_group_recipes
                .iter()
                .map(|recipe| (&recipe.name, (recipe, true)))
                .collect()
        } else {
            HashMap::default()
        };
    let new_cell_recipes_map: HashMap<&String, &CellRecipe> = new_cell_recipes
        .iter()
        .map(|recipe| (&recipe.name, recipe))
        .collect();
    let mut dep_group_changes = Vec::new();
    let mut output_index: u64 = 0;
    for dep_group in dep_groups {
        let out_points: Vec<_> = dep_group
            .cells
            .iter()
            .map(|cell_name| {
                new_cell_recipes_map
                    .get(cell_name)
                    .map(|cell_recipe| {
                        packed::OutPoint::new_builder()
                            .tx_hash(cell_recipe.tx_hash.pack())
                            .index(cell_recipe.index.pack())
                            .build()
                    })
                    .ok_or_else(|| {
                        anyhow!(
                            "Can not find cell by name: {} in dep_group: {}",
                            cell_name,
                            dep_group.name
                        )
                    })
            })
            .collect::<Result<_, _>>()?;
        let out_points_vec: packed::OutPointVec = out_points.pack();
        let data = out_points_vec.as_bytes();
        let data_hash = H256::from(blake2b_256(data.as_ref()));
        let config = (*dep_group).clone();
        let change =
            if let Some((old_recipe, removed)) = dep_group_recipes_map.get_mut(&dep_group.name) {
                let old_recipe = old_recipe.clone();
                *removed = false;
                let old_data_hash = if old_recipe.data_hash == H256::default() {
                    load_cell_data(rpc_client, &old_recipe.tx_hash, old_recipe.index)?.0
                } else {
                    old_recipe.data_hash.clone()
                };
                if data_hash == old_data_hash {
                    StateChange::Unchanged {
                        data,
                        data_hash,
                        config,
                        old_recipe,
                    }
                } else {
                    StateChange::Changed {
                        data,
                        data_hash,
                        config,
                        old_recipe,
                        output_index,
                    }
                }
            } else {
                StateChange::NewAdded {
                    data,
                    data_hash,
                    config,
                    output_index,
                }
            };
        if change.has_new_output() {
            output_index += 1;
        }
        dep_group_changes.push(change);
    }

    for (old_recipe, removed) in dep_group_recipes_map.values() {
        if *removed {
            dep_group_changes.push(StateChange::Removed {
                old_recipe: (*old_recipe).clone(),
            });
        }
    }
    Ok(dep_group_changes)
}

fn build_new_cell_recipes(
    lock_script: &packed::Script,
    cell_tx_opt: Option<&packed::Transaction>,
    cell_changes: &[CellChange],
) -> Result<Vec<CellRecipe>> {
    let (new_tx_hash, first_cell_input): (H256, packed::CellInput) = cell_tx_opt
        .map::<Result<(H256, packed::CellInput), Error>, _>(|cell_tx| {
            let new_tx_hash: H256 = cell_tx.calc_tx_hash().unpack();
            let first_cell_input = cell_tx
                .raw()
                .inputs()
                .get(0)
                .ok_or_else(|| anyhow!("cell transaction has no inputs"))?;
            Ok((new_tx_hash, first_cell_input))
        })
        .transpose()?
        .unwrap_or_default();
    let new_recipes: Vec<_> = cell_changes
        .iter()
        .filter(|info| info.has_new_recipe())
        .map(|info| {
            info.build_new_recipe(lock_script, &first_cell_input, &new_tx_hash)
                .expect("to new cell recipe")
        })
        .collect();
    Ok(new_recipes)
}

fn build_new_dep_group_recipes(
    lock_script: &packed::Script,
    dep_group_tx_opt: Option<&packed::Transaction>,
    dep_group_changes: &[DepGroupChange],
) -> Vec<DepGroupRecipe> {
    let new_tx_hash: H256 = dep_group_tx_opt
        .map(|dep_group_tx| dep_group_tx.calc_tx_hash().unpack())
        .unwrap_or_default();
    dep_group_changes
        .iter()
        .filter(|info| info.has_new_recipe())
        .map(|info| {
            info.build_new_recipe(lock_script, new_tx_hash.clone())
                .expect("to new dep_group recipe")
        })
        .collect()
}

fn explain_txs(info: &IntermediumInfo) -> Result<()> {
    fn print_total_change(changes: &[ReprStateChange]) {
        let (old_capacities, new_capacities): (Vec<_>, Vec<_>) = changes
            .iter()
            .filter(|change| change.kind != "Removed")
            .map(|change| (change.old_capacity, change.new_capacity))
            .unzip();
        let old_total: u64 = old_capacities.iter().sum();
        let new_total: u64 = new_capacities.iter().sum();
        println!(
            "> old total capacity: {:#} (removed items not included)",
            HumanCapacity(old_total)
        );
        println!("> new total capacity: {:#}", HumanCapacity(new_total));
    }
    fn print_item(tag: &str, max_width: usize, change: &ReprStateChange) {
        println!(
            "[{}] {:<9} name: {:>width$}, old-capacity: {:>7}, new-capacity: {:>7}",
            tag,
            change.kind,
            change.name,
            HumanCapacity(change.old_capacity).to_string(),
            HumanCapacity(change.new_capacity).to_string(),
            width = max_width
        );
    }

    println!("==== Cell transaction ====");
    let max_width: usize = info
        .cell_changes
        .iter()
        .map(|change| change.name.len())
        .max()
        .unwrap_or_default();
    for change in &info.cell_changes {
        print_item("cell", max_width, change);
    }
    print_total_change(&info.cell_changes);
    println!("==== DepGroup transaction ====");
    let max_width: usize = info
        .dep_group_changes
        .iter()
        .map(|change| change.name.len())
        .max()
        .unwrap_or_default();
    for change in &info.dep_group_changes {
        print_item("dep_group", max_width, change);
    }
    print_total_change(&info.dep_group_changes);
    Ok(())
}

fn build_tx<T: DeployInfo>(
    from_address: &Address,
    collector: &mut CellCollector,
    tx_fee: u64,
    cell_deps: Vec<packed::CellDep>,
    lock_script: &packed::Script,
    infos: &[T],
) -> Result<Option<packed::Transaction>> {
    let to_capacity: u64 = infos
        .iter()
        .filter_map(|info| {
            if info.has_new_output() {
                Some(info.occupied_capacity(lock_script))
            } else {
                None
            }
        })
        .sum();
    if to_capacity == 0 {
        return Ok(None);
    }

    let from_lock_hash: H256 = packed::Script::from(from_address.payload())
        .calc_script_hash()
        .unpack();
    let (mut inputs, input_capacities): (Vec<_>, Vec<_>) =
        infos.iter().filter_map(|info| info.build_input()).unzip();

    let mut from_capacity: u64 = input_capacities.into_iter().sum();
    if !enough_capacity(from_capacity, to_capacity, tx_fee) {
        let needed_capacity = if to_capacity > from_capacity {
            to_capacity - from_capacity
        } else {
            // may need one more cell to fit the tx_fee
            0
        };
        let (more_infos, more_capacity) =
            collector.collect_live_cells(from_lock_hash, needed_capacity, tx_fee)?;
        inputs.extend(more_infos.into_iter().map(|info| info.input()));
        from_capacity += more_capacity;
    }
    if to_capacity + tx_fee > from_capacity {
        return Err(anyhow!(
            "Capacity(mature) not enough: {} => {}",
            from_address,
            from_capacity,
        ));
    }

    let first_cell_input = &inputs[0];
    let (mut outputs, mut outputs_data): (Vec<_>, Vec<_>) = infos
        .iter()
        .filter_map(|info| info.build_cell_output(lock_script, first_cell_input))
        .unzip();

    let rest_capacity = from_capacity - to_capacity - tx_fee;
    if rest_capacity >= MIN_SECP_CELL_CAPACITY {
        let change_output = packed::CellOutput::new_builder()
            .capacity(Capacity::shannons(rest_capacity).pack())
            .lock(from_address.payload().into())
            .build();
        outputs.push(change_output);
        outputs_data.push(Bytes::default());
    }

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.into_iter().map(|data| data.pack()))
        .build();
    Ok(Some(tx.data()))
}

fn load_input_txs(
    input_txs: &mut HashMap<H256, json_types::Transaction>,
    rpc_client: &mut HttpRpcClient,
    tx: &packed::Transaction,
) -> Result<()> {
    for input in tx.raw().inputs().into_iter() {
        let tx_hash: H256 = input.previous_output().tx_hash().unpack();
        if input_txs.contains_key(&tx_hash) {
            continue;
        }
        let input_tx = rpc_client
            .get_transaction(tx_hash.clone())
            .map_err(Error::msg)?
            .and_then(|tx_with_status| {
                if tx_with_status.tx_status.status == json_types::Status::Committed {
                    Some(json_types::Transaction::from(packed::Transaction::from(
                        tx_with_status.transaction.inner,
                    )))
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow!("Can not load input transaction {:#x}", tx_hash))?;
        input_txs.insert(tx_hash, input_tx);
    }
    Ok(())
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
struct IntermediumInfo {
    deployment: Deployment,
    last_recipe: Option<DeploymentRecipe>,
    new_recipe: DeploymentRecipe,
    // For offline sign (should verify the tx hash)
    used_input_txs: HashMap<H256, json_types::Transaction>,
    cell_tx: Option<json_types::Transaction>,
    cell_tx_signatures: HashMap<JsonBytes, Vec<JsonBytes>>,
    cell_changes: Vec<ReprStateChange>,
    dep_group_tx: Option<json_types::Transaction>,
    dep_group_tx_signatures: HashMap<JsonBytes, Vec<JsonBytes>>,
    dep_group_changes: Vec<ReprStateChange>,
}

impl IntermediumInfo {
    fn multisig_configs(&self) -> Result<HashMap<H160, ReprMultisigConfig>> {
        // NOTE: we don't care the NetworkType here.
        let network = NetworkType::Testnet;
        let mut multisig_configs = HashMap::default();
        if !self.deployment.multisig_config.sighash_addresses.is_empty() {
            let config = MultisigConfig::try_from(self.deployment.multisig_config.clone())
                .map_err(Error::msg)?;
            multisig_configs.insert(config.hash160(), config.into_repr(network));
        }
        Ok(multisig_configs)
    }

    fn cell_tx_helper(&self) -> Result<Option<TxHelper>> {
        if let Some(cell_tx) = self.cell_tx.as_ref() {
            let repr = ReprTxHelper {
                transaction: cell_tx.clone(),
                multisig_configs: self.multisig_configs()?,
                signatures: self.cell_tx_signatures.clone(),
            };
            let helper = TxHelper::try_from(repr).map_err(Error::msg)?;
            Ok(Some(helper))
        } else {
            Ok(None)
        }
    }

    fn dep_group_tx_helper(&self) -> Result<Option<TxHelper>> {
        if let Some(dep_group_tx) = self.dep_group_tx.as_ref() {
            let repr = ReprTxHelper {
                transaction: dep_group_tx.clone(),
                multisig_configs: self.multisig_configs()?,
                signatures: self.dep_group_tx_signatures.clone(),
            };
            let helper = TxHelper::try_from(repr).map_err(Error::msg)?;
            Ok(Some(helper))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
enum StateChange<C, R> {
    Changed {
        // New data
        data: Bytes,
        data_hash: H256,
        config: C,
        old_recipe: R,
        output_index: u64,
    },
    NewAdded {
        data: Bytes,
        data_hash: H256,
        config: C,
        output_index: u64,
    },
    Unchanged {
        data: Bytes,
        data_hash: H256,
        config: C,
        old_recipe: R,
    },
    Removed {
        old_recipe: R,
    },
}

impl<C, R> StateChange<C, R> {
    fn has_new_output(&self) -> bool {
        match self {
            StateChange::Changed { .. } => true,
            StateChange::NewAdded { .. } => true,
            StateChange::Removed { .. } => false,
            StateChange::Unchanged { .. } => false,
        }
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
struct ReprStateChange {
    name: String,
    kind: String,
    old_capacity: u64,
    new_capacity: u64,
}

type CellChange = StateChange<Cell, CellRecipe>;
type DepGroupChange = StateChange<DepGroup, DepGroupRecipe>;

trait DeployInfo {
    fn name(&self) -> &String;
    fn to_repr(&self, lock_script: &packed::Script) -> ReprStateChange;
    fn has_new_output(&self) -> bool;
    fn has_new_recipe(&self) -> bool;
    fn occupied_capacity(&self, lock_script: &packed::Script) -> u64;
    fn build_input(&self) -> Option<(packed::CellInput, u64)>;
    fn build_cell_output(
        &self,
        lock_script: &packed::Script,
        first_cell_input: &packed::CellInput,
    ) -> Option<(packed::CellOutput, Bytes)>;
}

impl DeployInfo for CellChange {
    fn name(&self) -> &String {
        match self {
            StateChange::Changed { config, .. } => &config.name,
            StateChange::NewAdded { config, .. } => &config.name,
            StateChange::Unchanged { config, .. } => &config.name,
            StateChange::Removed { old_recipe } => &old_recipe.name,
        }
    }

    fn to_repr(&self, lock_script: &packed::Script) -> ReprStateChange {
        let new_capacity = self.occupied_capacity(lock_script);
        let (kind, old_capacity) = match self {
            StateChange::Changed { old_recipe, .. } => ("Changed", old_recipe.occupied_capacity),
            StateChange::NewAdded { .. } => ("NewAdded", 0),
            StateChange::Unchanged { .. } => ("Unchanged", new_capacity),
            StateChange::Removed { old_recipe } => ("Removed", old_recipe.occupied_capacity),
        };
        ReprStateChange {
            name: self.name().clone(),
            kind: kind.to_string(),
            old_capacity,
            new_capacity,
        }
    }

    fn has_new_output(&self) -> bool {
        StateChange::has_new_output(self)
    }

    fn has_new_recipe(&self) -> bool {
        match self {
            StateChange::Removed { .. } => false,
            _ => true,
        }
    }

    fn occupied_capacity(&self, lock_script: &packed::Script) -> u64 {
        let (data, config) = match self {
            StateChange::Removed { .. } => return 0,
            StateChange::Changed { data, config, .. } => (data, config),
            StateChange::Unchanged { data, config, .. } => (data, config),
            StateChange::NewAdded { data, config, .. } => (data, config),
        };
        let data_size = data.len() as u64;
        let type_script_size: u64 = if config.enable_type_id {
            32 + 1 + 32
        } else {
            0
        };
        lock_script.occupied_capacity().expect("capacity").as_u64()
            + (type_script_size + data_size + 8) * ONE_CKB
    }

    fn build_input(&self) -> Option<(packed::CellInput, u64)> {
        match self {
            StateChange::Changed { old_recipe, .. } => {
                let out_point = packed::OutPoint::new(old_recipe.tx_hash.pack(), old_recipe.index);
                let input = packed::CellInput::new(out_point, 0);
                Some((input, old_recipe.occupied_capacity))
            }
            _ => None,
        }
    }

    fn build_cell_output(
        &self,
        lock_script: &packed::Script,
        first_cell_input: &packed::CellInput,
    ) -> Option<(packed::CellOutput, Bytes)> {
        let (data, config, output_index, old_type_id) = match self {
            StateChange::Removed { .. } => {
                return None;
            }
            StateChange::Unchanged { .. } => {
                return None;
            }
            StateChange::Changed {
                data,
                config,
                old_recipe,
                output_index,
                ..
            } => (data, config, *output_index, old_recipe.type_id.clone()),
            StateChange::NewAdded {
                data,
                config,
                output_index,
                ..
            } => (data, config, *output_index, None),
        };
        let type_id = if config.enable_type_id {
            old_type_id.or_else(|| {
                Some(H256::from(calculate_type_id(
                    first_cell_input,
                    output_index,
                )))
            })
        } else {
            None
        };
        let occupied_capacity = self.occupied_capacity(lock_script);
        let type_script_opt = type_id.map(|type_id_args| {
            packed::Script::new_builder()
                .code_hash(TYPE_ID_CODE_HASH.pack())
                .hash_type(ScriptHashType::Type.into())
                .args(Bytes::from(type_id_args.as_bytes().to_vec()).pack())
                .build()
        });
        let output = packed::CellOutput::new_builder()
            .capacity(Capacity::shannons(occupied_capacity).pack())
            .lock(lock_script.clone())
            .type_(
                packed::ScriptOpt::new_builder()
                    .set(type_script_opt)
                    .build(),
            )
            .build();
        Some((output, data.clone()))
    }
}

impl CellChange {
    fn build_new_recipe(
        &self,
        lock_script: &packed::Script,
        first_cell_input: &packed::CellInput,
        new_tx_hash: &H256,
    ) -> Option<CellRecipe> {
        let (tx_hash, index, data_hash, config, old_type_id) = match self {
            StateChange::Removed { .. } => {
                return None;
            }
            StateChange::Changed {
                data_hash,
                config,
                old_recipe,
                output_index,
                ..
            } => (
                new_tx_hash.clone(),
                *output_index as u32,
                data_hash.clone(),
                config,
                old_recipe.type_id.clone(),
            ),
            StateChange::Unchanged {
                data_hash,
                config,
                old_recipe,
                ..
            } => (
                old_recipe.tx_hash.clone(),
                old_recipe.index,
                data_hash.clone(),
                config,
                old_recipe.type_id.clone(),
            ),
            StateChange::NewAdded {
                data_hash,
                config,
                output_index,
                ..
            } => (
                new_tx_hash.clone(),
                *output_index as u32,
                data_hash.clone(),
                config,
                None,
            ),
        };
        let type_id = if config.enable_type_id {
            old_type_id.or_else(|| {
                Some(H256::from(calculate_type_id(
                    first_cell_input,
                    index as u64,
                )))
            })
        } else {
            None
        };
        Some(CellRecipe {
            name: self.name().clone(),
            // To be replaced with final transaction hash
            tx_hash,
            index,
            occupied_capacity: self.occupied_capacity(lock_script),
            data_hash,
            type_id,
        })
    }
}

impl DeployInfo for DepGroupChange {
    fn name(&self) -> &String {
        match self {
            StateChange::Changed { config, .. } => &config.name,
            StateChange::NewAdded { config, .. } => &config.name,
            StateChange::Unchanged { config, .. } => &config.name,
            StateChange::Removed { old_recipe } => &old_recipe.name,
        }
    }

    fn to_repr(&self, lock_script: &packed::Script) -> ReprStateChange {
        let new_capacity = self.occupied_capacity(lock_script);
        let (kind, old_capacity) = match self {
            StateChange::Changed { old_recipe, .. } => ("Changed", old_recipe.occupied_capacity),
            StateChange::NewAdded { .. } => ("NewAdded", 0),
            StateChange::Unchanged { .. } => ("Unchanged", new_capacity),
            StateChange::Removed { old_recipe } => ("Removed", old_recipe.occupied_capacity),
        };
        ReprStateChange {
            name: self.name().clone(),
            kind: kind.to_string(),
            old_capacity,
            new_capacity,
        }
    }

    fn has_new_output(&self) -> bool {
        StateChange::has_new_output(self)
    }

    fn has_new_recipe(&self) -> bool {
        match self {
            StateChange::Removed { .. } => false,
            _ => true,
        }
    }

    fn occupied_capacity(&self, lock_script: &packed::Script) -> u64 {
        let data = match self {
            StateChange::Removed { .. } => return 0,
            StateChange::Changed { data, .. } => data,
            StateChange::Unchanged { data, .. } => data,
            StateChange::NewAdded { data, .. } => data,
        };
        let data_size = data.len() as u64;
        lock_script.occupied_capacity().expect("capacity").as_u64() + (data_size + 8) * ONE_CKB
    }

    fn build_input(&self) -> Option<(packed::CellInput, u64)> {
        match self {
            StateChange::Changed { old_recipe, .. } => {
                let out_point = packed::OutPoint::new(old_recipe.tx_hash.pack(), old_recipe.index);
                let input = packed::CellInput::new(out_point, 0);
                Some((input, old_recipe.occupied_capacity))
            }
            _ => None,
        }
    }

    fn build_cell_output(
        &self,
        lock_script: &packed::Script,
        _first_cell_input: &packed::CellInput,
    ) -> Option<(packed::CellOutput, Bytes)> {
        let data = match self {
            StateChange::Removed { .. } => {
                return None;
            }
            StateChange::Unchanged { .. } => {
                return None;
            }
            StateChange::Changed { data, .. } => data,
            StateChange::NewAdded { data, .. } => data,
        };
        let occupied_capacity = self.occupied_capacity(lock_script);
        let output = packed::CellOutput::new_builder()
            .capacity(Capacity::shannons(occupied_capacity).pack())
            .lock(lock_script.clone())
            .build();
        Some((output, data.clone()))
    }
}

impl DepGroupChange {
    fn build_new_recipe(
        &self,
        lock_script: &packed::Script,
        new_tx_hash: H256,
    ) -> Option<DepGroupRecipe> {
        let (tx_hash, index, data_hash) = match self {
            StateChange::Removed { .. } => {
                return None;
            }
            StateChange::Changed {
                data_hash,
                output_index,
                ..
            } => (new_tx_hash, *output_index as u32, data_hash.clone()),
            StateChange::Unchanged {
                data_hash,
                old_recipe,
                ..
            } => (
                old_recipe.tx_hash.clone(),
                old_recipe.index,
                data_hash.clone(),
            ),
            StateChange::NewAdded {
                data_hash,
                output_index,
                ..
            } => (new_tx_hash, *output_index as u32, data_hash.clone()),
        };
        Some(DepGroupRecipe {
            name: self.name().clone(),
            // To be replaced with final transaction hash
            tx_hash,
            index,
            data_hash,
            occupied_capacity: self.occupied_capacity(lock_script),
        })
    }
}

struct CellCollector<'a> {
    rpc_client: &'a mut HttpRpcClient,
    genesis_info: &'a GenesisInfo,
    index_dir: &'a PathBuf,
    index_controller: IndexController,
    wait_for_sync: bool,
    max_mature_number: u64,
    locked_cells: HashSet<(H256, u32)>,
    // lock_hash => live cell
    offchain_live_cells: Vec<LiveCellInfo>,
}

impl<'a> CellCollector<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        genesis_info: &'a GenesisInfo,
        index_dir: &'a PathBuf,
        index_controller: IndexController,
        wait_for_sync: bool,
        max_mature_number: u64,
    ) -> CellCollector<'a> {
        CellCollector {
            rpc_client,
            genesis_info,
            index_dir,
            index_controller,
            wait_for_sync,
            max_mature_number,
            locked_cells: Default::default(),
            offchain_live_cells: Default::default(),
        }
    }

    pub fn lock_cell(&mut self, tx_hash: H256, index: u32) {
        self.locked_cells.insert((tx_hash, index));
    }
    pub fn apply_tx(&mut self, tx: packed::Transaction) {
        let tx_view = tx.into_view();
        let tx_hash: H256 = tx_view.hash().unpack();
        for out_point in tx_view.input_pts_iter() {
            self.lock_cell(out_point.tx_hash().unpack(), out_point.index().unpack());
        }
        for (output_index, (output, data)) in tx_view.outputs_with_data_iter().enumerate() {
            let type_hashes = output.type_().to_opt().map(|_| Default::default());
            let info = LiveCellInfo {
                tx_hash: tx_hash.clone(),
                output_index: output_index as u32,
                data_bytes: data.len() as u64,
                type_hashes,
                lock_hash: output.lock().calc_script_hash().unpack(),
                capacity: output.capacity().unpack(),
                number: Default::default(),
                index: CellIndex {
                    tx_index: Default::default(),
                    output_index: output_index as u32,
                },
            };
            self.offchain_live_cells.push(info);
        }
    }

    pub fn collect_live_cells(
        &mut self,
        lock_hash: H256,
        capacity: u64,
        tx_fee: u64,
    ) -> Result<(Vec<LiveCellInfo>, u64)> {
        let mut collected_capacity = 0;
        let (mut infos, rest_infos): (Vec<_>, Vec<_>) = self
            .offchain_live_cells
            .split_off(0)
            .into_iter()
            .partition(|info| {
                if enough_capacity(collected_capacity, capacity, tx_fee) {
                    false
                } else if info.lock_hash == lock_hash
                    && info.type_hashes.is_none()
                    && info.data_bytes == 0
                {
                    collected_capacity += info.capacity;
                    true
                } else {
                    false
                }
            });
        self.offchain_live_cells = rest_infos;
        if enough_capacity(collected_capacity, capacity, tx_fee) {
            return Ok((infos, collected_capacity));
        }

        let max_mature_number: u64 = self.max_mature_number;
        let locked_cells = self.locked_cells.clone();
        let mut terminator = |_, info: &LiveCellInfo| {
            if enough_capacity(collected_capacity, capacity, tx_fee) {
                (true, false)
            } else if info.type_hashes.is_none()
                && info.data_bytes == 0
                && is_mature(info, max_mature_number)
                && !locked_cells.contains(&(info.tx_hash.clone(), info.output_index))
            {
                collected_capacity += info.capacity;
                (enough_capacity(collected_capacity, capacity, tx_fee), true)
            } else {
                (false, false)
            }
        };

        let func =
            |db: IndexDatabase| db.get_live_cells_by_lock(lock_hash.pack(), None, &mut terminator);
        let more_infos = with_db(
            func,
            self.rpc_client,
            self.genesis_info.clone(),
            self.index_dir,
            self.index_controller.clone(),
            self.wait_for_sync,
        )
        .map_err(Error::msg)?;
        infos.extend(more_infos);
        Ok((infos, collected_capacity))
    }
}

fn modify_info_file<T, F: FnOnce(&mut IntermediumInfo) -> Result<T>>(
    path: &PathBuf,
    func: F,
) -> Result<T> {
    let file = fs::File::open(path)?;
    let mut info: IntermediumInfo = serde_json::from_reader(&file)?;
    let result = func(&mut info)?;
    let mut file = fs::File::create(path)?;
    let content = serde_json::to_string_pretty(&info)?;
    file.write_all(content.as_bytes())?;
    Ok(result)
}
