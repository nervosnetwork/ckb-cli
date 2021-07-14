use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    constants::{MULTISIG_TYPE_HASH, SECP_SIGNATURE_SIZE},
    Address, AddressPayload, CodeHashIndex, GenesisInfo, HttpRpcClient, HumanCapacity,
    MultisigConfig, NetworkType, TxHelper,
};
use ckb_sdk_types::tx_helper::ReprTxHelper;
use ckb_types::{
    bytes::Bytes,
    core::Capacity,
    packed::{self, CellOutput, OutPoint, Script},
    prelude::*,
    H160, H256,
};
use clap::{App, Arg, ArgMatches};
use faster_hex::hex_string;

use super::{CliSubCommand, Output};
use crate::plugin::PluginManager;
use crate::utils::{
    arg,
    arg_parser::{
        AddressParser, ArgParser, CapacityParser, FilePathParser, FixedHashParser, FromStrParser,
        HexParser, PrivkeyPathParser, PrivkeyWrapper,
    },
    other::{
        check_capacity, get_genesis_info, get_keystore_signer, get_live_cell,
        get_live_cell_with_cache, get_network_type, get_privkey_signer, get_to_data, read_password,
    },
};

pub struct TxSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    plugin_mgr: &'a mut PluginManager,
    genesis_info: Option<GenesisInfo>,
}

impl<'a> TxSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        plugin_mgr: &'a mut PluginManager,
        genesis_info: Option<GenesisInfo>,
    ) -> TxSubCommand<'a> {
        TxSubCommand {
            rpc_client,
            plugin_mgr,
            genesis_info,
        }
    }

    pub fn subcommand(name: &'static str) -> App<'static> {
        let arg_tx_file = Arg::with_name("tx-file")
            .long("tx-file")
            .takes_value(true)
            .validator(|input| FilePathParser::new(false).validate(input))
            .required(true)
            .about("Multisig transaction data file (format: json)");
        let arg_sighash_address = Arg::with_name("sighash-address")
            .long("sighash-address")
            .takes_value(true)
            .multiple(true)
            .required(true)
            .validator(|input| AddressParser::new_sighash().validate(input))
            .about("Normal sighash address");
        let arg_require_first_n = Arg::with_name("require-first-n")
            .long("require-first-n")
            .takes_value(true)
            .default_value("0")
            .validator(|input| FromStrParser::<u8>::default().validate(input))
            .about("Require first n signatures of corresponding pubkey");
        let arg_threshold = Arg::with_name("threshold")
            .long("threshold")
            .takes_value(true)
            .default_value("1")
            .validator(|input| FromStrParser::<u8>::default().validate(input))
            .about("Multisig threshold");
        let arg_since_absolute_epoch = Arg::with_name("since-absolute-epoch")
            .long("since-absolute-epoch")
            .takes_value(true)
            .validator(|input| FromStrParser::<u64>::default().validate(input))
            .about("Since absolute epoch number");
        let arg_skip_check = Arg::with_name("skip-check")
            .long("skip-check")
            .about("Send transaction without any check, be cautious to use this flag");

        App::new(name)
            .about("Handle common sighash/multisig transaction")
            .subcommands(vec![
                App::new("init")
                    .about("Init a common (sighash/multisig) transaction")
                    .arg(arg_tx_file.clone()),
                App::new("add-multisig-config")
                    .about("Add multisig config")
                    .arg(arg_sighash_address.clone())
                    .arg(arg_require_first_n.clone())
                    .arg(arg_threshold.clone())
                    .arg(arg_tx_file.clone()),
                App::new("clear-field")
                    .about("Remove all field items in transaction")
                    .arg(
                        Arg::with_name("field")
                            .long("field")
                            .takes_value(true)
                            .required(true)
                            .possible_values(&["inputs", "outputs", "signatures"])
                            .about("The transaction field"),
                    )
                    .arg(arg_tx_file.clone()),
                App::new("add-input")
                    .about("Add cell input (with secp/multisig lock)")
                    .arg(
                        Arg::with_name("tx-hash")
                            .long("tx-hash")
                            .takes_value(true)
                            .validator(|input| FixedHashParser::<H256>::default().validate(input))
                            .required(true)
                            .about("Transaction hash"),
                    )
                    .arg(
                        Arg::with_name("index")
                            .long("index")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<u32>::default().validate(input))
                            .required(true)
                            .about("Transaction output index"),
                    )
                    .arg(arg_since_absolute_epoch.clone())
                    .arg(arg_tx_file.clone())
                    .arg(arg_skip_check.clone()),
                App::new("add-output")
                    .about("Add cell output")
                    .arg(
                        Arg::with_name("to-sighash-address")
                            .long("to-sighash-address")
                            .conflicts_with_all(&[
                                "to-short-multisig-address",
                                "to-long-multisig-address",
                            ])
                            .takes_value(true)
                            .validator(|input| AddressParser::new_sighash().validate(input))
                            .about("To normal sighash address"),
                    )
                    .arg(
                        Arg::with_name("to-short-multisig-address")
                            .long("to-short-multisig-address")
                            .conflicts_with("to-long-multisig-address")
                            .takes_value(true)
                            .validator(|input| AddressParser::new_multisig().validate(input))
                            .about("To short multisig address"),
                    )
                    .arg(
                        Arg::with_name("to-long-multisig-address")
                            .long("to-long-multisig-address")
                            .takes_value(true)
                            .validator(|input| {
                                AddressParser::default()
                                    .set_full_type(MULTISIG_TYPE_HASH)
                                    .validate(input)
                            })
                            .about("To long multisig address (special case, include since)"),
                    )
                    .arg(arg::capacity().required(true))
                    .arg(arg::to_data())
                    .arg(arg::to_data_path())
                    .arg(arg_tx_file.clone()),
                App::new("add-signature")
                    .about("Add signature")
                    .arg(
                        Arg::with_name("lock-arg")
                            .long("lock-arg")
                            .takes_value(true)
                            .required(true)
                            .validator(|input| match HexParser.parse(&input) {
                                Ok(ref data) if data.len() == 20 || data.len() == 28 => Ok(()),
                                Ok(ref data) => Err(format!("invalid data length: {}", data.len())),
                                Err(err) => Err(err),
                            })
                            .about("The lock_arg of input lock script (20 bytes or 28 bytes)"),
                    )
                    .arg(
                        Arg::with_name("signature")
                            .long("signature")
                            .takes_value(true)
                            .required(true)
                            .validator(|input| match HexParser.parse(&input) {
                                Ok(ref data) if data.len() == SECP_SIGNATURE_SIZE => Ok(()),
                                Ok(ref data) => Err(format!("invalid data length: {}", data.len())),
                                Err(err) => Err(err),
                            })
                            .about("The signature"),
                    )
                    .arg(arg_tx_file.clone()),
                App::new("info")
                    .about("Show detail of this multisig transaction (capacity, tx-fee, etc.)")
                    .arg(arg_tx_file.clone()),
                App::new("sign-inputs")
                    .about("Sign all sighash/multisig inputs in this transaction")
                    .arg(arg::privkey_path().required_unless(arg::from_account().get_name()))
                    .arg(arg::from_account().required_unless(arg::privkey_path().get_name()))
                    .arg(arg_tx_file.clone())
                    .arg(
                        Arg::with_name("add-signatures")
                            .long("add-signatures")
                            .about("Sign and add signatures"),
                    )
                    .arg(arg_skip_check.clone()),
                App::new("send")
                    .about("Send multisig transaction")
                    .arg(arg_tx_file.clone())
                    .arg(
                        Arg::with_name("max-tx-fee")
                            .long("max-tx-fee")
                            .takes_value(true)
                            .default_value("1.0")
                            .validator(|input| CapacityParser.validate(input))
                            .about("Max transaction fee (unit: CKB)"),
                    )
                    .arg(arg_skip_check),
                App::new("build-multisig-address")
                    .about(
                        "Build multisig address with multisig config and since(optional) argument",
                    )
                    .arg(arg_sighash_address.clone())
                    .arg(arg_require_first_n.clone())
                    .arg(arg_threshold.clone())
                    .arg(arg_since_absolute_epoch.clone()),
            ])
    }
}

impl<'a> CliSubCommand for TxSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches, debug: bool) -> Result<Output, String> {
        let network = get_network_type(self.rpc_client)?;

        match matches.subcommand() {
            ("init", Some(m)) => {
                let tx_file_opt: Option<PathBuf> =
                    FilePathParser::new(false).from_matches_opt(m, "tx-file", false)?;
                let helper = TxHelper::default();
                let repr = helper.into_repr(network);

                if let Some(tx_file) = tx_file_opt {
                    let mut file = fs::File::create(&tx_file).map_err(|err| err.to_string())?;
                    let content =
                        serde_json::to_string_pretty(&repr).map_err(|err| err.to_string())?;
                    file.write_all(content.as_bytes())
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_success())
                } else {
                    Ok(Output::new_output(repr))
                }
            }
            ("clear-field", Some(m)) => {
                let tx_file: PathBuf = FilePathParser::new(true).from_matches(m, "tx-file")?;
                let field = m.value_of("field").unwrap();
                modify_tx_file(&tx_file, network, |helper| {
                    match field {
                        "inputs" => helper.clear_inputs(),
                        "outputs" => helper.clear_outputs(),
                        "signatures" => helper.clear_signatures(),
                        _ => panic!("Invalid clear field: {}", field),
                    }
                    Ok(())
                })?;
                Ok(Output::new_success())
            }
            ("add-input", Some(m)) => {
                let tx_file: PathBuf = FilePathParser::new(true).from_matches(m, "tx-file")?;
                let tx_hash: H256 =
                    FixedHashParser::<H256>::default().from_matches(m, "tx-hash")?;
                let index: u32 = FromStrParser::<u32>::default().from_matches(m, "index")?;
                let since_absolute_epoch_opt: Option<u64> = FromStrParser::<u64>::default()
                    .from_matches_opt(m, "since-absolute-epoch", false)?;

                let skip_check: bool = m.is_present("skip-check");
                let genesis_info = get_genesis_info(&self.genesis_info, self.rpc_client)?;
                let out_point = OutPoint::new_builder()
                    .tx_hash(tx_hash.pack())
                    .index(index.pack())
                    .build();
                let get_live_cell = |out_point, with_data| {
                    get_live_cell(self.rpc_client, out_point, with_data).map(|(output, _)| output)
                };
                modify_tx_file(&tx_file, network, |helper| {
                    helper.add_input(
                        out_point,
                        since_absolute_epoch_opt,
                        get_live_cell,
                        &genesis_info,
                        skip_check,
                    )
                })?;

                Ok(Output::new_success())
            }
            ("add-output", Some(m)) => {
                let tx_file: PathBuf = FilePathParser::new(true).from_matches(m, "tx-file")?;
                let capacity: u64 = CapacityParser.from_matches(m, "capacity")?;
                let to_sighash_address_opt: Option<Address> = AddressParser::new_sighash()
                    .from_matches_opt(m, "to-sighash-address", false)?;
                let to_short_multisig_address_opt: Option<Address> = AddressParser::new_multisig()
                    .from_matches_opt(m, "to-short-multisig-address", false)?;
                let to_long_multisig_address_opt: Option<Address> = AddressParser::default()
                    .set_full_type(MULTISIG_TYPE_HASH)
                    .from_matches_opt(m, "to-long-multisig-address", false)?;

                let to_data = get_to_data(m)?;
                check_capacity(capacity, to_data.len())?;
                if let Some(address) = to_long_multisig_address_opt.as_ref() {
                    let payload = address.payload();
                    if payload.args().len() != 28 {
                        return Err(format!(
                            "Invalid address lock_arg length({}) for `to-long-multisig-address`",
                            payload.args().len()
                        ));
                    }
                }
                let lock_script = to_sighash_address_opt
                    .or(to_short_multisig_address_opt)
                    .or(to_long_multisig_address_opt)
                    .map(|address| Script::from(address.payload()))
                    .ok_or_else(|| "missing target address".to_string())?;
                let output = CellOutput::new_builder()
                    .capacity(Capacity::shannons(capacity).pack())
                    .lock(lock_script)
                    .build();

                modify_tx_file(&tx_file, network, |helper| {
                    helper.add_output(output, to_data);
                    Ok(())
                })?;

                Ok(Output::new_success())
            }
            ("add-signature", Some(m)) => {
                let tx_file: PathBuf = FilePathParser::new(true).from_matches(m, "tx-file")?;
                let lock_arg: Bytes = HexParser.from_matches(m, "lock-arg")?;
                let signature: Bytes = HexParser.from_matches(m, "signature")?;

                modify_tx_file(&tx_file, network, |helper| {
                    helper.add_signature(lock_arg, signature)
                })?;
                Ok(Output::new_success())
            }
            ("add-multisig-config", Some(m)) => {
                let tx_file: PathBuf = FilePathParser::new(false).from_matches(m, "tx-file")?;
                let sighash_addresses: Vec<Address> = AddressParser::default()
                    .set_network(network)
                    .set_short(CodeHashIndex::Sighash)
                    .from_matches_vec(m, "sighash-address")?;
                let require_first_n: u8 =
                    FromStrParser::<u8>::default().from_matches(m, "require-first-n")?;
                let threshold: u8 = FromStrParser::<u8>::default().from_matches(m, "threshold")?;

                let sighash_addresses = sighash_addresses
                    .into_iter()
                    .map(|address| address.payload().clone())
                    .collect::<Vec<_>>();
                let cfg = MultisigConfig::new_with(sighash_addresses, require_first_n, threshold)?;
                modify_tx_file(&tx_file, network, |helper| {
                    helper.add_multisig_config(cfg);
                    Ok(())
                })?;
                Ok(Output::new_success())
            }
            ("info", Some(m)) => {
                let tx_file: PathBuf = FilePathParser::new(false).from_matches(m, "tx-file")?;

                let mut live_cell_cache: HashMap<OutPoint, (CellOutput, Bytes)> =
                    Default::default();
                let mut get_live_cell = |out_point: OutPoint, with_data: bool| {
                    get_live_cell_with_cache(
                        &mut live_cell_cache,
                        self.rpc_client,
                        out_point,
                        with_data,
                    )
                };

                let file = fs::File::open(tx_file).map_err(|err| err.to_string())?;
                let repr: ReprTxHelper =
                    serde_json::from_reader(&file).map_err(|err| err.to_string())?;
                let helper = TxHelper::try_from(repr)?;
                let tx = helper.transaction();

                let mut input_total = 0;
                for input in tx.inputs().into_iter() {
                    let (output, data) = get_live_cell(input.previous_output(), true)?;
                    let capacity: u64 = output.capacity().unpack();
                    input_total += capacity;

                    let type_script_empty = output.type_().to_opt().is_none();
                    let prefix = if helper
                        .signatures()
                        .contains_key(&output.lock().args().raw_data())
                    {
                        "input(signed)"
                    } else {
                        "input"
                    };
                    print_cell_info(
                        prefix,
                        network,
                        output.lock(),
                        capacity,
                        data.len(),
                        type_script_empty,
                    );
                }

                let mut output_total = 0;
                for (output, data) in tx.outputs().into_iter().zip(tx.outputs_data().into_iter()) {
                    let capacity: u64 = output.capacity().unpack();
                    output_total += capacity;
                    let data_len = data.raw_data().len();
                    let type_script_empty = output.type_().is_none();
                    print_cell_info(
                        "output",
                        network,
                        output.lock(),
                        capacity,
                        data_len,
                        type_script_empty,
                    );
                }
                let tx_fee_string = if input_total >= output_total {
                    format!("{:#}", HumanCapacity(input_total - output_total))
                } else {
                    format!("-{:#}", HumanCapacity(output_total - input_total))
                };

                let resp = serde_json::json!({
                    "input_total": format!("{:#}", HumanCapacity(input_total)),
                    "output_total": format!("{:#}", HumanCapacity(output_total)),
                    "tx_fee": tx_fee_string,
                });
                Ok(Output::new_output(resp))
            }
            ("sign-inputs", Some(m)) => {
                let tx_file: PathBuf = FilePathParser::new(true).from_matches(m, "tx-file")?;
                let privkey_opt: Option<PrivkeyWrapper> =
                    PrivkeyPathParser.from_matches_opt(m, "privkey-path", false)?;
                let account_opt: Option<H160> = m
                    .value_of("from-account")
                    .map(|input| {
                        FixedHashParser::<H160>::default()
                            .parse(&input)
                            .or_else(|err| {
                                let result: Result<Address, String> = AddressParser::new_sighash()
                                    .set_network(network)
                                    .parse(&input);
                                result
                                    .map(|address| {
                                        H160::from_slice(&address.payload().args()).unwrap()
                                    })
                                    .map_err(|_| err)
                            })
                    })
                    .transpose()?;
                let skip_check: bool = m.is_present("skip-check");

                let mut signer = if let Some(privkey) = privkey_opt {
                    get_privkey_signer(privkey)
                } else {
                    let password = if self.plugin_mgr.keystore_require_password() {
                        Some(read_password(false, None)?)
                    } else {
                        None
                    };
                    let account = account_opt.unwrap();
                    let keystore = self.plugin_mgr.keystore_handler();
                    let new_client = HttpRpcClient::new(self.rpc_client.url().to_owned());
                    get_keystore_signer(keystore, new_client, Vec::new(), account, password)
                };

                let mut live_cell_cache: HashMap<OutPoint, (CellOutput, Bytes)> =
                    Default::default();
                let get_live_cell = |out_point: OutPoint, with_data: bool| {
                    get_live_cell_with_cache(
                        &mut live_cell_cache,
                        self.rpc_client,
                        out_point,
                        with_data,
                    )
                    .map(|(output, _)| output)
                };

                let signatures = modify_tx_file(&tx_file, network, |helper| {
                    let signatures = helper.sign_inputs(&mut signer, get_live_cell, skip_check)?;
                    if m.is_present("add-signatures") {
                        for (lock_arg, signature) in signatures.clone() {
                            helper.add_signature(lock_arg, signature)?;
                        }
                    }
                    Ok(signatures)
                })?;
                let resp = signatures
                    .into_iter()
                    .map(|(lock_arg, signature)| {
                        serde_json::json!({
                            "lock-arg": format!("0x{}", hex_string(&lock_arg).unwrap()),
                            "signature": format!("0x{}", hex_string(&signature).unwrap()),
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(Output::new_output(resp))
            }
            ("send", Some(m)) => {
                let tx_file: PathBuf = FilePathParser::new(false).from_matches(m, "tx-file")?;
                let max_tx_fee: u64 = CapacityParser.from_matches(m, "max-tx-fee")?;
                let skip_check: bool = m.is_present("skip-check");

                let mut live_cell_cache: HashMap<OutPoint, (CellOutput, Bytes)> =
                    Default::default();
                let mut get_live_cell = |out_point: OutPoint, with_data: bool| {
                    get_live_cell_with_cache(
                        &mut live_cell_cache,
                        self.rpc_client,
                        out_point,
                        with_data,
                    )
                    .map(|(output, _)| output)
                };

                let file = fs::File::open(tx_file).map_err(|err| err.to_string())?;
                let repr: ReprTxHelper =
                    serde_json::from_reader(&file).map_err(|err| err.to_string())?;
                let helper = TxHelper::try_from(repr)?;

                if !skip_check {
                    let (input_total, output_total) = helper.check_tx(&mut get_live_cell)?;
                    let tx_fee = input_total - output_total;
                    if tx_fee > max_tx_fee {
                        return Err(format!(
                            "Too much transaction fee: {:#}, max: {:#}",
                            HumanCapacity(tx_fee),
                            HumanCapacity(max_tx_fee),
                        ));
                    }
                }
                let tx = helper.build_tx(&mut get_live_cell, skip_check)?;
                let rpc_tx = json_types::Transaction::from(tx.data());
                if debug {
                    eprintln!(
                        "[send transaction]:\n{}",
                        serde_json::to_string_pretty(&rpc_tx).unwrap()
                    );
                }
                let resp = self
                    .rpc_client
                    .send_transaction(tx.data())
                    .map_err(|err| format!("Send transaction error: {}", err))?;
                Ok(Output::new_output(resp))
            }
            ("build-multisig-address", Some(m)) => {
                let sighash_addresses: Vec<Address> = AddressParser::default()
                    .set_network(network)
                    .set_short(CodeHashIndex::Sighash)
                    .from_matches_vec(m, "sighash-address")?;
                let require_first_n: u8 =
                    FromStrParser::<u8>::default().from_matches(m, "require-first-n")?;
                let threshold: u8 = FromStrParser::<u8>::default().from_matches(m, "threshold")?;
                let since_absolute_epoch_opt: Option<u64> = FromStrParser::<u64>::default()
                    .from_matches_opt(m, "since-absolute-epoch", false)?;

                let sighash_addresses = sighash_addresses
                    .into_iter()
                    .map(|address| address.payload().clone())
                    .collect::<Vec<_>>();
                let cfg = MultisigConfig::new_with(sighash_addresses, require_first_n, threshold)?;
                let address_payload = cfg.to_address_payload(since_absolute_epoch_opt);
                let lock_script = Script::from(&address_payload);
                let resp = serde_json::json!({
                    "mainnet": Address::new(NetworkType::Mainnet, address_payload.clone()).to_string(),
                    "testnet": Address::new(NetworkType::Testnet, address_payload.clone()).to_string(),
                    "lock-arg": format!("0x{}", hex_string(address_payload.args().as_ref()).unwrap()),
                    "lock-hash": format!("{:#x}", lock_script.calc_script_hash()),
                    "lock-script": json_types::Script::from(lock_script),
                });
                Ok(Output::new_output(resp))
            }
            _ => Err(Self::subcommand("tx").generate_usage()),
        }
    }
}

fn print_cell_info(
    prefix: &str,
    network: NetworkType,
    lock: packed::Script,
    capacity: u64,
    data_len: usize,
    type_script_empty: bool,
) {
    let address_payload = AddressPayload::from(lock);
    let lock_kind = if address_payload.code_hash() == MULTISIG_TYPE_HASH.pack() {
        if address_payload.args().len() == 20 {
            "multisig without since"
        } else {
            "multisig with since"
        }
    } else {
        "sighash(secp)"
    };
    let address = Address::new(network, address_payload);
    let type_script_status = if type_script_empty { "none" } else { "some" };
    eprintln!(
        "[{}] {} => {}, (data-length: {}, type-script: {}, lock-kind: {})",
        prefix,
        address,
        HumanCapacity(capacity),
        data_len,
        type_script_status,
        lock_kind,
    );
}

fn modify_tx_file<T, F: FnOnce(&mut TxHelper) -> Result<T, String>>(
    path: &Path,
    network: NetworkType,
    func: F,
) -> Result<T, String> {
    let file = fs::File::open(path).map_err(|err| err.to_string())?;
    let repr: ReprTxHelper = serde_json::from_reader(&file).map_err(|err| err.to_string())?;
    let mut helper = TxHelper::try_from(repr)?;

    let result = func(&mut helper)?;

    let repr = helper.into_repr(network);
    let mut file = fs::File::create(path).map_err(|err| err.to_string())?;
    let content = serde_json::to_string_pretty(&repr).map_err(|err| err.to_string())?;
    file.write_all(content.as_bytes())
        .map_err(|err| err.to_string())?;
    Ok(result)
}
