use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use ckb_jsonrpc_types as json_types;
use ckb_jsonrpc_types::JsonBytes;
use ckb_sdk::constants::MultisigScript;
use ckb_sdk::{
    constants::SECP_SIGNATURE_SIZE, unlock::MultisigConfig, Address, AddressPayload, HumanCapacity,
    NetworkType,
};
use ckb_types::{
    bytes::Bytes,
    core::Capacity,
    h256,
    packed::{self, CellOutput, OutPoint, Script},
    prelude::*,
    H160, H256,
};
use clap::{ArgAction, ArgMatches, Args, Command, CommandFactory, FromArgMatches, Parser, Subcommand};
use faster_hex::hex_string;
use serde_derive::{Deserialize, Serialize};

use super::{
    CliSubCommand, Output,
};
use crate::plugin::{KeyStoreHandler, PluginManager, SignTarget};
use crate::utils::{
    arg_parser::{
        AddressParser, ArgParser, CapacityParser, FilePathParser, FixedHashParser, FromStrParser,
        HexParser, PrivkeyPathParser, PrivkeyWrapper,
    },
    genesis_info::GenesisInfo,
    other::{
        check_capacity, get_genesis_info, get_live_cell, get_live_cell_with_cache,
        get_network_type, get_privkey_signer, read_password,
    },
    rpc::HttpRpcClient,
    tx_helper::{SignerFn, TxHelper},
};

pub struct TxSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    plugin_mgr: &'a mut PluginManager,
    genesis_info: Option<GenesisInfo>,
}

fn parse_tx_file(input: &str) -> Result<String, String> {
    FilePathParser::new(false)
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_sighash_address(input: &str) -> Result<String, String> {
    AddressParser::new_sighash()
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_multisig_address(input: &str) -> Result<String, String> {
    AddressParser::new_multisig(MultisigScript::Legacy)
        .validate(input)
        .or_else(|_| AddressParser::new_multisig(MultisigScript::V2).validate(input))
        .map(|_| input.to_string())
}

fn parse_u8(input: &str) -> Result<String, String> {
    FromStrParser::<u8>::default()
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_u32(input: &str) -> Result<String, String> {
    FromStrParser::<u32>::default()
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_u64(input: &str) -> Result<String, String> {
    FromStrParser::<u64>::default()
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_h256(input: &str) -> Result<String, String> {
    FixedHashParser::<H256>::default()
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_capacity(input: &str) -> Result<String, String> {
    CapacityParser.validate(input).map(|_| input.to_string())
}

fn parse_hex(input: &str) -> Result<String, String> {
    HexParser.validate(input).map(|_| input.to_string())
}

fn parse_lock_arg_20_28(input: &str) -> Result<String, String> {
    match HexParser.parse(input) {
        Ok(data) if data.len() == 20 || data.len() == 28 => Ok(input.to_string()),
        Ok(data) => Err(format!("invalid data length: {}", data.len())),
        Err(err) => Err(err),
    }
}

fn parse_signature(input: &str) -> Result<String, String> {
    match HexParser.parse(input) {
        Ok(data) if data.len() == SECP_SIGNATURE_SIZE => Ok(input.to_string()),
        Ok(data) => Err(format!("invalid data length: {}", data.len())),
        Err(err) => Err(err),
    }
}

fn parse_multisig_code_hash_value(input: &str) -> Result<H256, String> {
    match input {
        "legacy" => Ok(MultisigScript::Legacy.script_id().code_hash),
        "v2" => Ok(MultisigScript::V2.script_id().code_hash),
        _ => FixedHashParser::<H256>::default().parse(input),
    }
}

fn parse_privkey_path(input: &str) -> Result<String, String> {
    PrivkeyPathParser.validate(input).map(|_| input.to_string())
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

fn parse_to_data_path(input: &str) -> Result<String, String> {
    FilePathParser::new(true)
        .validate(input)
        .map(|_| input.to_string())
}

#[derive(Parser, Debug)]
#[command(about = "Handle common sighash/multisig transaction")]
pub struct TxCmd {
    #[command(subcommand)]
    pub command: TxSubcommands,
}

#[derive(Subcommand, Debug)]
#[command(rename_all = "kebab-case")]
pub enum TxSubcommands {
    /// Init a common (sighash/multisig) transaction
    Init(TxInitArgs),
    /// Add multisig config
    AddMultisigConfig(TxAddMultisigConfigArgs),
    /// Remove all field items in transaction
    ClearField(TxClearFieldArgs),
    /// Add cell input (with secp/multisig lock)
    AddInput(TxAddInputArgs),
    /// Add cell output
    AddOutput(TxAddOutputArgs),
    /// Add signature
    AddSignature(TxAddSignatureArgs),
    /// Show detail of this multisig transaction (capacity, tx-fee, etc.)
    Info(TxInfoArgs),
    /// Sign all sighash/multisig inputs in this transaction
    SignInputs(TxSignInputsArgs),
    /// Send multisig transaction
    Send(TxSendArgs),
    /// Build multisig address with multisig config and since(optional) argument
    BuildMultisigAddress(TxBuildMultisigAddressArgs),
}

#[derive(Args, Debug)]
pub struct TxInitArgs {
    #[arg(long = "tx-file", id = "tx-file", value_parser = parse_tx_file)]
    pub tx_file: String,
}

#[derive(Args, Debug)]
pub struct TxAddMultisigConfigArgs {
    #[arg(long = "sighash-address", id = "sighash-address", action = ArgAction::Append, num_args = 1.., required = true, value_parser = parse_sighash_address)]
    pub sighash_address: Vec<String>,
    #[arg(long = "multisig-code-hash", id = "multisig-code-hash", value_parser = [
        "legacy",
        "0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8",
        "v2",
        "0x36c971b8d41fbd94aabca77dc75e826729ac98447b46f91e00796155dddb0d29",
    ])]
    pub multisig_code_hash: String,
    #[arg(long = "require-first-n", id = "require-first-n", default_value = "0", value_parser = parse_u8)]
    pub require_first_n: String,
    #[arg(long = "threshold", id = "threshold", default_value = "1", value_parser = parse_u8)]
    pub threshold: String,
    #[arg(long = "tx-file", id = "tx-file", value_parser = parse_tx_file)]
    pub tx_file: String,
}

#[derive(Args, Debug)]
pub struct TxClearFieldArgs {
    #[arg(long = "field", id = "field", value_parser = ["inputs", "outputs", "signatures"])]
    pub field: String,
    #[arg(long = "tx-file", id = "tx-file", value_parser = parse_tx_file)]
    pub tx_file: String,
}

#[derive(Args, Debug)]
pub struct TxAddInputArgs {
    #[arg(long = "tx-hash", id = "tx-hash", value_parser = parse_h256)]
    pub tx_hash: String,
    #[arg(long = "index", id = "index", value_parser = parse_u32)]
    pub index: String,
    #[arg(long = "since-absolute-epoch", id = "since-absolute-epoch", value_parser = parse_u64)]
    pub since_absolute_epoch: Option<String>,
    #[arg(long = "tx-file", id = "tx-file", value_parser = parse_tx_file)]
    pub tx_file: String,
    #[arg(long = "skip-check", id = "skip-check")]
    pub skip_check: bool,
}

#[derive(Args, Debug)]
pub struct TxAddOutputArgs {
    #[arg(long = "to-sighash-address", id = "to-sighash-address", conflicts_with_all = ["to-short-multisig-address", "to-long-multisig-address"], value_parser = parse_sighash_address)]
    pub to_sighash_address: Option<String>,
    #[arg(long = "to-short-multisig-address", id = "to-short-multisig-address", conflicts_with = "to-long-multisig-address", value_parser = parse_multisig_address)]
    pub to_short_multisig_address: Option<String>,
    #[arg(long = "to-long-multisig-address", id = "to-long-multisig-address", value_parser = parse_multisig_address)]
    pub to_long_multisig_address: Option<String>,
    #[arg(long = "capacity", id = "capacity", value_parser = parse_capacity)]
    pub capacity: String,
    #[arg(long = "to-data", id = "to-data", value_parser = parse_hex)]
    pub to_data: Option<String>,
    #[arg(long = "to-data-path", id = "to-data-path", value_parser = parse_to_data_path)]
    pub to_data_path: Option<String>,
    #[arg(long = "tx-file", id = "tx-file", value_parser = parse_tx_file)]
    pub tx_file: String,
}

#[derive(Args, Debug)]
pub struct TxAddSignatureArgs {
    #[arg(long = "lock-arg", id = "lock-arg", value_parser = parse_lock_arg_20_28)]
    pub lock_arg: String,
    #[arg(long = "signature", id = "signature", value_parser = parse_signature)]
    pub signature: String,
    #[arg(long = "tx-file", id = "tx-file", value_parser = parse_tx_file)]
    pub tx_file: String,
}

#[derive(Args, Debug)]
pub struct TxInfoArgs {
    #[arg(long = "tx-file", id = "tx-file", value_parser = parse_tx_file)]
    pub tx_file: String,
}

#[derive(Args, Debug)]
pub struct TxSignInputsArgs {
    #[arg(long = "privkey-path", id = "privkey-path", required_unless_present = "from-account", value_parser = parse_privkey_path)]
    pub privkey_path: Option<String>,
    #[arg(long = "from-account", id = "from-account", required_unless_present = "privkey-path", value_parser = parse_from_account)]
    pub from_account: Option<String>,
    #[arg(long = "tx-file", id = "tx-file", value_parser = parse_tx_file)]
    pub tx_file: String,
    #[arg(long = "add-signatures", id = "add-signatures")]
    pub add_signatures: bool,
    #[arg(long = "skip-check", id = "skip-check")]
    pub skip_check: bool,
}

#[derive(Args, Debug)]
pub struct TxSendArgs {
    #[arg(long = "tx-file", id = "tx-file", value_parser = parse_tx_file)]
    pub tx_file: String,
    #[arg(long = "max-tx-fee", id = "max-tx-fee", default_value = "1.0", value_parser = parse_capacity)]
    pub max_tx_fee: String,
    #[arg(long = "skip-check", id = "skip-check")]
    pub skip_check: bool,
    #[arg(long = "zero-lock", id = "zero-lock")]
    pub zero_lock: bool,
}

#[derive(Args, Debug)]
pub struct TxBuildMultisigAddressArgs {
    #[arg(long = "sighash-address", id = "sighash-address", action = ArgAction::Append, num_args = 1.., required = true, value_parser = parse_sighash_address)]
    pub sighash_address: Vec<String>,
    #[arg(long = "require-first-n", id = "require-first-n", default_value = "0", value_parser = parse_u8)]
    pub require_first_n: String,
    #[arg(long = "multisig-code-hash", id = "multisig-code-hash", value_parser = [
        "legacy",
        "0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8",
        "v2",
        "0x36c971b8d41fbd94aabca77dc75e826729ac98447b46f91e00796155dddb0d29",
    ])]
    pub multisig_code_hash: String,
    #[arg(long = "threshold", id = "threshold", default_value = "1", value_parser = parse_u8)]
    pub threshold: String,
    #[arg(long = "since-absolute-epoch", id = "since-absolute-epoch", value_parser = parse_u64)]
    pub since_absolute_epoch: Option<String>,
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

    pub fn subcommand(name: &'static str) -> Command {
        TxCmd::command().name(name)
    }
}

impl CliSubCommand for TxSubCommand<'_> {
    fn process(&mut self, matches: &ArgMatches, debug: bool) -> Result<Output, String> {
        let network = get_network_type(self.rpc_client)?;

        let cmd = TxCmd::from_arg_matches(matches).map_err(|err| err.to_string())?;
        match cmd.command {
            TxSubcommands::Init(args) => {
                let tx_file: PathBuf = FilePathParser::new(false).parse(&args.tx_file)?;
                let helper = TxHelper::default();
                let repr = ReprTxHelper::new(helper, network);

                let mut file = fs::File::create(tx_file).map_err(|err| err.to_string())?;
                let content = serde_json::to_string_pretty(&repr).map_err(|err| err.to_string())?;
                file.write_all(content.as_bytes())
                    .map_err(|err| err.to_string())?;
                Ok(Output::new_success())
            }
            TxSubcommands::ClearField(args) => {
                let tx_file: PathBuf = FilePathParser::new(true).parse(&args.tx_file)?;
                let field = args.field.as_str();
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
            TxSubcommands::AddInput(args) => {
                let tx_file: PathBuf = FilePathParser::new(true).parse(&args.tx_file)?;
                let tx_hash: H256 = FixedHashParser::<H256>::default().parse(&args.tx_hash)?;
                let index: u32 = FromStrParser::<u32>::default().parse(&args.index)?;
                let since_absolute_epoch_opt: Option<u64> = args
                    .since_absolute_epoch
                    .as_ref()
                    .map(|value| FromStrParser::<u64>::default().parse(value))
                    .transpose()?;

                let skip_check: bool = args.skip_check;
                let genesis_info = get_genesis_info(&self.genesis_info, self.rpc_client)?;
                let out_point = OutPoint::new_builder()
                    .tx_hash(tx_hash.pack())
                    .index(index)
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
            TxSubcommands::AddOutput(args) => {
                let tx_file: PathBuf = FilePathParser::new(true).parse(&args.tx_file)?;
                let capacity: u64 = CapacityParser.parse(&args.capacity)?.into();

                let to_sighash_address_opt: Option<Address> = args
                    .to_sighash_address
                    .as_ref()
                    .map(|value| AddressParser::new_sighash().parse(value))
                    .transpose()?;
                let to_short_multisig_address_opt: Option<Address> = args
                    .to_short_multisig_address
                    .as_ref()
                    .map(|value| {
                        AddressParser::new_multisig(MultisigScript::Legacy)
                            .parse(value)
                            .or_else(|_| {
                                AddressParser::new_multisig(MultisigScript::V2).parse(value)
                            })
                    })
                    .transpose()?;
                let to_long_multisig_address_opt: Option<Address> = args
                    .to_long_multisig_address
                    .as_ref()
                    .map(|value| {
                        AddressParser::new_multisig(MultisigScript::Legacy)
                            .parse(value)
                            .or_else(|_| {
                                AddressParser::new_multisig(MultisigScript::V2).parse(value)
                            })
                    })
                    .transpose()?;

                let to_data = if let Some(hex) = args.to_data.as_ref() {
                    Bytes::from(HexParser.parse(hex)?)
                } else if let Some(path) = args.to_data_path.as_ref() {
                    Bytes::from(fs::read(path).map_err(|err| err.to_string())?)
                } else {
                    Bytes::new()
                };
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
            TxSubcommands::AddSignature(args) => {
                let tx_file: PathBuf = FilePathParser::new(true).parse(&args.tx_file)?;
                let lock_arg: Bytes = Bytes::from(HexParser.parse(&args.lock_arg)?);
                let signature: Bytes = Bytes::from(HexParser.parse(&args.signature)?);

                modify_tx_file(&tx_file, network, |helper| {
                    helper.add_signature(lock_arg, signature)
                })?;
                Ok(Output::new_success())
            }
            TxSubcommands::AddMultisigConfig(args) => {
                let multisig_lock_code_hash: H256 =
                    parse_multisig_code_hash_value(&args.multisig_code_hash)?;
                let multisig_script = MultisigScript::try_from(multisig_lock_code_hash.clone())
                    .map_err(|_err| {
                        format!(
                            "invalid multisig lock code hash: {}",
                            multisig_lock_code_hash
                        )
                    })?;

                let tx_file: PathBuf = FilePathParser::new(false).parse(&args.tx_file)?;
                let sighash_addresses: Vec<Address> = args
                    .sighash_address
                    .iter()
                    .map(|value| AddressParser::new_sighash().set_network(network).parse(value))
                    .collect::<Result<Vec<_>, String>>()?;
                let require_first_n: u8 =
                    FromStrParser::<u8>::default().parse(&args.require_first_n)?;
                let threshold: u8 = FromStrParser::<u8>::default().parse(&args.threshold)?;

                let sighash_addresses = sighash_addresses
                    .into_iter()
                    .map(|address| H160::from_slice(address.payload().args().as_ref()).unwrap())
                    .collect::<Vec<_>>();
                let cfg = MultisigConfig::new_with(
                    multisig_script,
                    sighash_addresses,
                    require_first_n,
                    threshold,
                )
                .map_err(|err| err.to_string())?;
                modify_tx_file(&tx_file, network, |helper| {
                    helper.add_multisig_config(cfg);
                    Ok(())
                })?;
                Ok(Output::new_success())
            }
            TxSubcommands::Info(args) => {
                let tx_file: PathBuf = FilePathParser::new(false).parse(&args.tx_file)?;

                let mut live_cell_cache: HashMap<(OutPoint, bool), (CellOutput, Bytes)> =
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
            TxSubcommands::SignInputs(args) => {
                let tx_file: PathBuf = FilePathParser::new(true).parse(&args.tx_file)?;
                let privkey_opt: Option<PrivkeyWrapper> = args
                    .privkey_path
                    .as_ref()
                    .map(|value| PrivkeyPathParser.parse(value))
                    .transpose()?;
                let account_opt: Option<H160> = args
                    .from_account
                    .as_ref()
                    .map(|input| {
                        FixedHashParser::<H160>::default()
                            .parse(input)
                            .or_else(|err| {
                                let result: Result<Address, String> =
                                    AddressParser::new_sighash().set_network(network).parse(input);
                                result
                                    .map(|address| {
                                        H160::from_slice(&address.payload().args()).unwrap()
                                    })
                                    .map_err(|_| err)
                            })
                    })
                    .transpose()?;
                let skip_check: bool = args.skip_check;

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
                    get_keystore_signer(keystore, new_client, account, password)
                };

                let mut live_cell_cache: HashMap<(OutPoint, bool), (CellOutput, Bytes)> =
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
                    if args.add_signatures {
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
                            "lock-arg": format!("0x{}", hex_string(&lock_arg)),
                            "signature": format!("0x{}", hex_string(&signature)),
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(Output::new_output(resp))
            }
            TxSubcommands::Send(args) => {
                let tx_file: PathBuf = FilePathParser::new(false).parse(&args.tx_file)?;
                let max_tx_fee: u64 = CapacityParser.parse(&args.max_tx_fee)?.into();
                let skip_check: bool = args.skip_check;
                let allow_zero_lock: bool = args.zero_lock;

                let mut live_cell_cache: HashMap<(OutPoint, bool), (CellOutput, Bytes)> =
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
                    let (input_total, output_total) =
                        helper.check_tx(&mut get_live_cell, allow_zero_lock)?;
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
                    .send_transaction(tx.data(), Some(json_types::OutputsValidator::Passthrough))
                    .map_err(|err| format!("Send transaction error: {}", err))?;
                Ok(Output::new_output(resp))
            }
            TxSubcommands::BuildMultisigAddress(args) => {
                let multisig_lock_code_hash: H256 =
                    parse_multisig_code_hash_value(&args.multisig_code_hash)?;
                let multisig_script = MultisigScript::try_from(multisig_lock_code_hash.clone())
                    .map_err(|_err| {
                        format!(
                            "invalid multisig lock code hash: {}",
                            multisig_lock_code_hash
                        )
                    })?;

                let sighash_addresses: Vec<Address> = args
                    .sighash_address
                    .iter()
                    .map(|value| AddressParser::new_sighash().set_network(network).parse(value))
                    .collect::<Result<Vec<_>, String>>()?;
                let require_first_n: u8 =
                    FromStrParser::<u8>::default().parse(&args.require_first_n)?;
                let threshold: u8 = FromStrParser::<u8>::default().parse(&args.threshold)?;
                let since_absolute_epoch_opt: Option<u64> = args
                    .since_absolute_epoch
                    .as_ref()
                    .map(|value| FromStrParser::<u64>::default().parse(value))
                    .transpose()?;

                let sighash_addresses = sighash_addresses
                    .into_iter()
                    .map(|address| H160::from_slice(address.payload().args().as_ref()).unwrap())
                    .collect::<Vec<_>>();
                let cfg = MultisigConfig::new_with(
                    multisig_script,
                    sighash_addresses,
                    require_first_n,
                    threshold,
                )
                .map_err(|err| err.to_string())?;
                let address_payload =
                    cfg.to_address_payload(multisig_script, since_absolute_epoch_opt);
                let lock_script = Script::from(&address_payload);
                let resp = serde_json::json!({
                    "mainnet": Address::new(NetworkType::Mainnet, address_payload.clone(), true).to_string(),
                    "testnet": Address::new(NetworkType::Testnet, address_payload.clone(), true).to_string(),
                    "lock-arg": format!("0x{}", hex_string(address_payload.args().as_ref())),
                    "lock-hash": format!("{:#x}", lock_script.calc_script_hash())
                });
                Ok(Output::new_output(resp))
            }
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
    let lock_kind = if [
        MultisigScript::Legacy.script_id().code_hash.pack(),
        MultisigScript::V2.script_id().code_hash.pack(),
    ]
    .contains(&address_payload.code_hash(Some(network)))
    {
        if address_payload.args().len() == 20 {
            "multisig without since"
        } else {
            "multisig with since"
        }
    } else {
        "sighash(secp)"
    };
    let address = Address::new(network, address_payload, true);
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

fn get_keystore_signer(
    keystore: KeyStoreHandler,
    mut client: HttpRpcClient,
    account: H160,
    password: Option<String>,
) -> SignerFn {
    Box::new(
        move |lock_args: &HashSet<H160>, message: &H256, tx: &json_types::Transaction| {
            if lock_args.contains(&account) {
                if message == &h256!("0x0") {
                    Ok(Some([0u8; 65]))
                } else {
                    let root_key_path = keystore.root_key_path(account.clone())?;
                    let sign_target = if keystore.has_account_in_default(account.clone())? {
                        SignTarget::AnyData(Default::default())
                    } else {
                        let inputs = tx
                            .inputs
                            .iter()
                            .map(|input| {
                                let tx_hash = &input.previous_output.tx_hash;
                                client
                                    .get_transaction(tx_hash.clone())?
                                    .and_then(|tx_with_status| {
                                        tx_with_status.transaction.map(|tx| tx.inner)
                                    })
                                    .map(packed::Transaction::from)
                                    .map(json_types::Transaction::from)
                                    .ok_or_else(|| format!("transaction not exists: {:x}", tx_hash))
                            })
                            .collect::<Result<Vec<_>, String>>()?;
                        SignTarget::Transaction {
                            tx: tx.clone(),
                            inputs,
                            change_path: root_key_path.to_string(),
                        }
                    };
                    let data = keystore.sign(
                        account.clone(),
                        &root_key_path,
                        message.clone(),
                        sign_target,
                        password.clone(),
                        true,
                    )?;
                    if data.len() != 65 {
                        Err(format!(
                            "Invalid signature data length: {}, data: {:?}",
                            data.len(),
                            data
                        ))
                    } else {
                        let mut data_bytes = [0u8; 65];
                        data_bytes.copy_from_slice(&data[..]);
                        Ok(Some(data_bytes))
                    }
                }
            } else {
                Ok(None)
            }
        },
    )
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

    let repr = ReprTxHelper::new(helper, network);
    let mut file = fs::File::create(path).map_err(|err| err.to_string())?;
    let content = serde_json::to_string_pretty(&repr).map_err(|err| err.to_string())?;
    file.write_all(content.as_bytes())
        .map_err(|err| err.to_string())?;
    Ok(result)
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReprTxHelper {
    pub(crate) transaction: json_types::Transaction,
    pub(crate) multisig_configs: HashMap<H160, ReprMultisigConfig>,
    pub(crate) signatures: HashMap<JsonBytes, Vec<JsonBytes>>,
}

impl ReprTxHelper {
    pub(crate) fn new(tx: TxHelper, network: NetworkType) -> Self {
        ReprTxHelper {
            transaction: tx.transaction().data().into(),
            multisig_configs: tx
                .multisig_configs()
                .iter()
                .map(|(lock_arg, cfg)| {
                    (
                        lock_arg.clone(),
                        ReprMultisigConfig::new((*cfg).clone(), network),
                    )
                })
                .collect(),
            signatures: tx
                .signatures()
                .iter()
                .map(|(lock_arg, signatures)| {
                    (
                        JsonBytes::from_bytes(lock_arg.clone()),
                        signatures
                            .iter()
                            .cloned()
                            .map(JsonBytes::from_bytes)
                            .collect(),
                    )
                })
                .collect(),
        }
    }
}

impl TryFrom<ReprTxHelper> for TxHelper {
    type Error = String;
    fn try_from(repr: ReprTxHelper) -> Result<Self, Self::Error> {
        let transaction = packed::Transaction::from(repr.transaction).into_view();
        let multisig_configs = repr
            .multisig_configs
            .into_values()
            .map(MultisigConfig::try_from)
            .collect::<Result<Vec<_>, String>>()?;
        let signatures: HashMap<Bytes, HashSet<Bytes>> = repr
            .signatures
            .into_iter()
            .map(|(lock_arg, signatures)| {
                (
                    lock_arg.into_bytes(),
                    signatures.into_iter().map(JsonBytes::into_bytes).collect(),
                )
            })
            .collect();

        let mut tx_helper = TxHelper::new(transaction);
        for cfg in multisig_configs {
            tx_helper.add_multisig_config(cfg);
        }
        for (lock_arg, sub_signatures) in signatures {
            for sub_signature in sub_signatures {
                tx_helper.add_signature(lock_arg.clone(), sub_signature)?;
            }
        }
        Ok(tx_helper)
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct ReprMultisigConfig {
    #[serde(default = "compatibility_lock_code_hash")]
    pub lock_code_hash: H256,
    pub sighash_addresses: Vec<String>,
    pub require_first_n: u8,
    pub threshold: u8,
}

// for compatibility
fn compatibility_lock_code_hash() -> H256 {
    MultisigScript::Legacy.script_id().code_hash
}

impl ReprMultisigConfig {
    pub(crate) fn new(cfg: MultisigConfig, network: NetworkType) -> Self {
        let sighash_addresses = cfg
            .sighash_addresses()
            .iter()
            .map(|hash160| {
                let payload = AddressPayload::from_pubkey_hash(hash160.clone());
                Address::new(network, payload, false).to_string()
            })
            .collect();
        ReprMultisigConfig {
            lock_code_hash: cfg.lock_code_hash(),
            sighash_addresses,
            require_first_n: cfg.require_first_n(),
            threshold: cfg.threshold(),
        }
    }
}

impl TryFrom<ReprMultisigConfig> for MultisigConfig {
    type Error = String;
    fn try_from(repr: ReprMultisigConfig) -> Result<Self, Self::Error> {
        let sighash_addresses = repr
            .sighash_addresses
            .into_iter()
            .map(|address_string| {
                Address::from_str(&address_string)
                    .map(|addr| H160::from_slice(addr.payload().args().as_ref()))?
                    .map_err(|err| format!("invalid address: {address_string} error: {err:?}"))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let multisig_script = MultisigScript::try_from(repr.lock_code_hash.clone())
            .map_err(|_err| format!("invalid lock_code_hash {}", repr.lock_code_hash))?;
        MultisigConfig::new_with(
            multisig_script,
            sighash_addresses,
            repr.require_first_n,
            repr.threshold,
        )
        .map_err(|err| err.to_string())
    }
}
