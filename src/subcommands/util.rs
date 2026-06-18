use std::fs;
use std::io::Read;

use bitcoin::bip32::{ChildNumber, DerivationPath};
use chrono::prelude::*;
use clap::{ArgMatches, Args, Command, CommandFactory, FromArgMatches, Parser, Subcommand};
use clap_complete::Shell;
use eaglesong::EagleSongBuilder;
use faster_hex::hex_string;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId, Signature};

use ckb_crypto::secp::SECP256K1;
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::{self as json_types, JsonBytes};
use ckb_sdk::{
    constants::{MultisigScript, DAO_TYPE_HASH, SIGHASH_TYPE_HASH, TYPE_ID_CODE_HASH},
    util::serialize_signature,
    Address, AddressPayload, NetworkType, OldAddress,
};
use ckb_types::{
    bytes::BytesMut,
    core::{BlockView, EpochNumberWithFraction},
    packed,
    prelude::*,
    utilities::{compact_to_difficulty, difficulty_to_compact},
    H160, H256, U256,
};

use super::{CliSubCommand, Output};
use crate::plugin::{PluginManager, SignTarget};
use crate::utils::{
    arg_parser::{
        AddressParser, ArgParser, FilePathParser, FixedHashParser, FromStrParser, HexParser,
        PrivkeyPathParser, PrivkeyWrapper, PubkeyHexParser,
    },
    genesis_info::GenesisInfo,
    other::{address_json, get_network_type, read_password},
    rpc::{ChainInfo, HttpRpcClient},
};
use crate::{build_cli, get_version};

// Magic bytes to put before every sign-data binary argument
const SIGN_MAGIC_BYTES: &[u8] = b"Nervos Message:";
const FLAG_SINCE_EPOCH_NUMBER: u64 =
    0b010_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000;
const EPOCH_LENGTH: u64 = 1800;
const BLOCK_PERIOD: u64 = 8 * 1000; // 8 seconds

fn parse_privkey_path(input: &str) -> Result<String, String> {
    PrivkeyPathParser.validate(input).map(|_| input.to_string())
}

fn parse_pubkey_hex(input: &str) -> Result<String, String> {
    PubkeyHexParser.validate(input).map(|_| input.to_string())
}

fn parse_address(input: &str) -> Result<String, String> {
    AddressParser::default()
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_sighash_address(input: &str) -> Result<String, String> {
    AddressParser::new_sighash()
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_sighash_address_mainnet(input: &str) -> Result<String, String> {
    AddressParser::new_sighash()
        .set_network(NetworkType::Mainnet)
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_hex(input: &str) -> Result<String, String> {
    HexParser.validate(input).map(|_| input.to_string())
}

fn parse_message_hash(input: &str) -> Result<String, String> {
    FixedHashParser::<H256>::default()
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_file_path_exists(input: &str) -> Result<String, String> {
    FilePathParser::new(true)
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_compact_target(input: &str) -> Result<String, String> {
    FromStrParser::<u32>::default()
        .validate(input)
        .or_else(|_| {
            let trimmed = if input.starts_with("0x") || input.starts_with("0X") {
                &input[2..]
            } else {
                input
            };
            u32::from_str_radix(trimmed, 16)
                .map(|_| ())
                .map_err(|err| err.to_string())
        })
        .map(|_| input.to_string())
}

fn parse_difficulty(input: &str) -> Result<String, String> {
    let trimmed = if input.starts_with("0x") || input.starts_with("0X") {
        &input[2..]
    } else {
        input
    };
    U256::from_hex_str(trimmed)
        .map(|_| input.to_string())
        .map_err(|err| err.to_string())
}

fn parse_u32(input: &str) -> Result<String, String> {
    FromStrParser::<u32>::default()
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_locktime_rfc3339(input: &str) -> Result<String, String> {
    DateTime::parse_from_rfc3339(input)
        .map(|_| input.to_string())
        .map_err(|err| err.to_string())
}

#[derive(Parser, Debug)]
#[command(name = "util", about = "Utilities")]
pub struct UtilCmd {
    #[command(subcommand)]
    pub command: UtilSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum UtilSubcommands {
    /// Show public information of a secp256k1 private key (from file) or public key
    KeyInfo(UtilKeyInfoArgs),
    /// Sign data with secp256k1 signature
    SignData(UtilSignDataArgs),
    /// Sign message with secp256k1 signature
    SignMessage(UtilSignMessageArgs),
    /// Verify a compact format signature
    VerifySignature(UtilVerifySignatureArgs),
    /// Hash binary use eaglesong algorithm
    Eaglesong(UtilBinaryHexArgs),
    /// Hash binary use blake2b algorithm (personalization: 'ckb-default-hash')
    Blake2b(UtilBlake2bArgs),
    /// Convert compact target value to difficulty value
    CompactToDifficulty(UtilCompactToDifficultyArgs),
    /// Convert difficulty value to compact target value
    DifficultyToCompact(UtilDifficultyToCompactArgs),
    /// Show information about an address
    AddressInfo(UtilAddressInfoArgs),
    /// Convert address in single signature format to multisig format (only for mainnet genesis cells)
    ToGenesisMultisigAddr(UtilToGenesisMultisigAddrArgs),
    /// Convert address in single signature format to multisig format
    ToMultisigAddr(UtilToMultisigAddrArgs),
    /// Query live cell's metadata
    CellMeta(UtilCellMetaArgs),
    /// Show genesis scripts code hash and cell_deps information
    GenesisScripts,
    /// Generates completion scripts for your shell
    Completions(UtilCompletionsArgs),
}

#[derive(Args, Debug)]
pub struct UtilKeyInfoArgs {
    #[arg(long = "privkey-path", id = "privkey-path", value_parser = parse_privkey_path, conflicts_with = "pubkey")]
    pub privkey_path: Option<String>,
    #[arg(long, value_parser = parse_pubkey_hex)]
    pub pubkey: Option<String>,
    #[arg(long, value_parser = parse_address)]
    pub address: Option<String>,
    #[arg(long = "lock-arg", id = "lock-arg")]
    pub lock_arg: Option<String>,
}

#[derive(Args, Debug)]
pub struct UtilSignDataArgs {
    #[arg(long = "privkey-path", id = "privkey-path", required_unless_present = "from-account", value_parser = parse_privkey_path)]
    pub privkey_path: Option<String>,
    #[arg(
        long = "from-account",
        id = "from-account",
        required_unless_present = "privkey-path",
        conflicts_with = "privkey-path"
    )]
    pub from_account: Option<String>,
    #[arg(long)]
    pub recoverable: bool,
    #[arg(long = "extended-address", id = "extended-address", conflicts_with = "privkey-path", value_parser = parse_sighash_address)]
    pub extended_address: Option<String>,
    #[arg(long = "binary-hex", id = "binary-hex", required_unless_present = "utf8-string", conflicts_with = "utf8-string", value_parser = parse_hex)]
    pub binary_hex: Option<String>,
    #[arg(long = "no-magic-bytes", id = "no-magic-bytes")]
    pub no_magic_bytes: bool,
    #[arg(
        long = "utf8-string",
        id = "utf8-string",
        required_unless_present = "binary-hex",
        conflicts_with = "binary-hex"
    )]
    pub utf8_string: Option<String>,
}

#[derive(Args, Debug)]
pub struct UtilSignMessageArgs {
    #[arg(long = "privkey-path", id = "privkey-path", required_unless_present = "from-account", value_parser = parse_privkey_path)]
    pub privkey_path: Option<String>,
    #[arg(
        long = "from-account",
        id = "from-account",
        required_unless_present = "privkey-path",
        conflicts_with = "privkey-path"
    )]
    pub from_account: Option<String>,
    #[arg(long)]
    pub recoverable: bool,
    #[arg(long = "extended-address", id = "extended-address", conflicts_with = "privkey-path", value_parser = parse_sighash_address)]
    pub extended_address: Option<String>,
    #[arg(long = "message", id = "message", value_parser = parse_message_hash)]
    pub message: String,
}

#[derive(Args, Debug)]
pub struct UtilVerifySignatureArgs {
    #[arg(long, value_parser = parse_pubkey_hex)]
    pub pubkey: Option<String>,
    #[arg(long = "privkey-path", id = "privkey-path", value_parser = parse_privkey_path, conflicts_with = "pubkey")]
    pub privkey_path: Option<String>,
    #[arg(long = "from-account", id = "from-account", conflicts_with_all = ["privkey-path", "pubkey"])]
    pub from_account: Option<String>,
    #[arg(long = "message", id = "message", value_parser = parse_message_hash)]
    pub message: String,
    #[arg(long = "extended-address", id = "extended-address", conflicts_with = "pubkey", value_parser = parse_sighash_address)]
    pub extended_address: Option<String>,
    #[arg(long, value_parser = parse_hex)]
    pub signature: String,
}

#[derive(Args, Debug)]
pub struct UtilBinaryHexArgs {
    #[arg(long = "binary-hex", id = "binary-hex", value_parser = parse_hex)]
    pub binary_hex: String,
}

#[derive(Args, Debug)]
pub struct UtilBlake2bArgs {
    #[arg(long = "binary-hex", id = "binary-hex", value_parser = parse_hex)]
    pub binary_hex: Option<String>,
    #[arg(long = "binary-path", id = "binary-path", value_parser = parse_file_path_exists)]
    pub binary_path: Option<String>,
    #[arg(long = "prefix-160", id = "prefix-160")]
    pub prefix_160: bool,
}

#[derive(Args, Debug)]
pub struct UtilCompactToDifficultyArgs {
    #[arg(long = "compact-target", id = "compact-target", value_parser = parse_compact_target)]
    pub compact_target: String,
}

#[derive(Args, Debug)]
pub struct UtilDifficultyToCompactArgs {
    #[arg(long, value_parser = parse_difficulty)]
    pub difficulty: String,
}

#[derive(Args, Debug)]
pub struct UtilAddressInfoArgs {
    #[arg(long, value_parser = parse_address)]
    pub address: String,
}

#[derive(Args, Debug)]
pub struct UtilToGenesisMultisigAddrArgs {
    #[arg(long = "sighash-address", id = "sighash-address", value_parser = parse_sighash_address_mainnet)]
    pub sighash_address: String,
    #[arg(long)]
    pub locktime: String,
}

#[derive(Args, Debug)]
pub struct UtilToMultisigAddrArgs {
    #[arg(long = "sighash-address", id = "sighash-address", value_parser = parse_sighash_address)]
    pub sighash_address: String,
    #[arg(long = "multisig-code-hash", id = "multisig-code-hash", value_parser = [
        "legacy",
        "0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8",
        "v2",
        "0x36c971b8d41fbd94aabca77dc75e826729ac98447b46f91e00796155dddb0d29",
    ])]
    pub multisig_code_hash: String,
    #[arg(long, value_parser = parse_locktime_rfc3339)]
    pub locktime: String,
}

#[derive(Args, Debug)]
pub struct UtilCellMetaArgs {
    #[arg(long = "tx-hash", id = "tx-hash", value_parser = parse_message_hash)]
    pub tx_hash: String,
    #[arg(long, value_parser = parse_u32)]
    pub index: String,
    #[arg(long = "with-data", id = "with-data")]
    pub with_data: bool,
}

#[derive(Args, Debug)]
pub struct UtilCompletionsArgs {
    #[arg(value_parser = ["bash", "zsh", "fish", "elvish", "powershell"])]
    pub shell: String,
}

pub struct UtilSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    plugin_mgr: &'a mut PluginManager,
}

impl<'a> UtilSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        plugin_mgr: &'a mut PluginManager,
    ) -> UtilSubCommand<'a> {
        UtilSubCommand {
            rpc_client,
            plugin_mgr,
        }
    }

    pub fn subcommand(name: &'static str) -> Command {
        UtilCmd::command().name(name)
    }
}

fn parse_multisig_code_hash_value(input: &str) -> Result<H256, String> {
    match input {
        "legacy" => Ok(MultisigScript::Legacy.script_id().code_hash),
        "v2" => Ok(MultisigScript::V2.script_id().code_hash),
        _ => FixedHashParser::<H256>::default().parse(input),
    }
}

impl CliSubCommand for UtilSubCommand<'_> {
    fn process(&mut self, matches: &ArgMatches, debug: bool) -> Result<Output, String> {
        let cmd = UtilCmd::from_arg_matches(matches).map_err(|err| err.to_string())?;
        match cmd.command {
            UtilSubcommands::KeyInfo(args) => {
                let privkey_opt: Option<PrivkeyWrapper> = args
                    .privkey_path
                    .as_ref()
                    .map(|value| PrivkeyPathParser.parse(value))
                    .transpose()?;
                let pubkey_opt: Option<secp256k1::PublicKey> = args
                    .pubkey
                    .as_ref()
                    .map(|value| PubkeyHexParser.parse(value))
                    .transpose()?;
                let pubkey_opt = privkey_opt
                    .map(|privkey| secp256k1::PublicKey::from_secret_key(&SECP256K1, &privkey))
                    .or(pubkey_opt);
                let pubkey_string_opt = pubkey_opt
                    .as_ref()
                    .map(|pubkey| hex_string(&pubkey.serialize()[..]));

                let address_payload = match pubkey_opt {
                    Some(pubkey) => AddressPayload::from_pubkey(&pubkey),
                    None => {
                        if let Some(address) = args.address.as_ref() {
                            AddressParser::default().parse(address)?.payload().clone()
                        } else if let Some(lock_arg) = args.lock_arg.as_ref() {
                            let lock_arg: H160 =
                                FixedHashParser::<H160>::default().parse(lock_arg)?;
                            AddressPayload::from_pubkey_hash(lock_arg)
                        } else {
                            return Err("Please give one argument".to_string());
                        }
                    }
                };
                let lock_arg = H160::from_slice(address_payload.args().as_ref()).unwrap();
                let old_address = OldAddress::new_default(lock_arg.clone());

                eprintln!(
                    r#"Put this config in < ckb.toml >:

[block_assembler]
code_hash = "{:#x}"
hash_type = "type"
args = "{:#x}"
message = "0x"
"#,
                    SIGHASH_TYPE_HASH, lock_arg,
                );

                let lock_hash: H256 = packed::Script::from(&address_payload)
                    .calc_script_hash()
                    .unpack();
                let resp = serde_json::json!({
                    "pubkey": pubkey_string_opt,
                    "address(deprecated)": address_json(address_payload.clone(), false),
                    "address": address_json(address_payload, true),
                    // NOTE: remove this later (after all testnet race reward received)
                    "old-testnet-address": old_address.display_with_prefix(NetworkType::Testnet),
                    "lock_arg": format!("{:#x}", lock_arg),
                    "lock_hash": format!("{:#x}", lock_hash),
                });
                Ok(Output::new_output(resp))
            }
            UtilSubcommands::SignData(args) => {
                let binary_opt: Option<Vec<u8>> = args
                    .binary_hex
                    .as_ref()
                    .map(|value| HexParser.parse(value))
                    .transpose()?;
                let recoverable = args.recoverable;
                let from_privkey_opt: Option<PrivkeyWrapper> = args
                    .privkey_path
                    .as_ref()
                    .map(|value| PrivkeyPathParser.parse(value))
                    .transpose()?;
                let from_account_opt: Option<H160> = args
                    .from_account
                    .as_ref()
                    .map(|input| {
                        FixedHashParser::<H160>::default()
                            .parse(input)
                            .or_else(|err| {
                                let result: Result<Address, String> =
                                    AddressParser::new_sighash().parse(input);
                                result
                                    .map(|address| {
                                        H160::from_slice(&address.payload().args()).unwrap()
                                    })
                                    .map_err(|_| err)
                            })
                    })
                    .transpose()?;
                let no_magic_bytes = args.no_magic_bytes;
                let password =
                    if self.plugin_mgr.keystore_require_password() && from_account_opt.is_some() {
                        Some(read_password(false, None)?)
                    } else {
                        None
                    };
                let extended_address_opt: Option<Address> = args
                    .extended_address
                    .as_ref()
                    .map(|value| AddressParser::new_sighash().parse(value))
                    .transpose()?;
                let root_path = if let Some(ref account) = from_account_opt {
                    self.plugin_mgr.root_key_path(account.clone())?
                } else {
                    DerivationPath::default()
                };
                let target_path = extended_address_opt
                    .and_then(|addr| from_account_opt.clone().map(|account| (addr, account)))
                    .map(|(addr, account)| {
                        search_path(self.plugin_mgr, account, addr, password.clone())
                    })
                    .transpose()?
                    .unwrap_or(root_path);

                let (mut binary, target) = if let Some(data) = binary_opt {
                    (data.clone(), SignTarget::AnyData(JsonBytes::from_vec(data)))
                } else {
                    let utf8_string = args
                        .utf8_string
                        .as_ref()
                        .ok_or_else(|| "<binary-hex> or <string> is required".to_string())?;
                    let binary = utf8_string.as_bytes().to_vec();
                    (binary, SignTarget::AnyString(utf8_string.clone()))
                };

                if !no_magic_bytes {
                    #[allow(clippy::reversed_empty_ranges)]
                    binary.splice(0..0, SIGN_MAGIC_BYTES.iter().cloned());
                }
                let message = H256::from(blake2b_256(&binary));
                let plugin_mgr_opt =
                    from_account_opt.map(|account| (&mut *self.plugin_mgr, account));
                let signature = sign_message(
                    from_privkey_opt.as_ref(),
                    plugin_mgr_opt,
                    &target_path,
                    recoverable,
                    &message,
                    target,
                    password,
                )?;
                let result = serde_json::json!({
                    "message": format!("{:#x}", message),
                    "signature": format!("0x{}", hex_string(&signature)),
                    "recoverable": recoverable,
                    "path": target_path.to_string(),
                });
                Ok(Output::new_output(result))
            }
            UtilSubcommands::SignMessage(args) => {
                let message: H256 = FixedHashParser::<H256>::default().parse(&args.message)?;
                let recoverable = args.recoverable;
                let from_privkey_opt: Option<PrivkeyWrapper> = args
                    .privkey_path
                    .as_ref()
                    .map(|value| PrivkeyPathParser.parse(value))
                    .transpose()?;
                let from_account_opt: Option<H160> = args
                    .from_account
                    .as_ref()
                    .map(|input| {
                        FixedHashParser::<H160>::default()
                            .parse(input)
                            .or_else(|err| {
                                let result: Result<Address, String> =
                                    AddressParser::new_sighash().parse(input);
                                result
                                    .map(|address| {
                                        H160::from_slice(&address.payload().args()).unwrap()
                                    })
                                    .map_err(|_| err)
                            })
                    })
                    .transpose()?;
                let password =
                    if self.plugin_mgr.keystore_require_password() && from_account_opt.is_some() {
                        Some(read_password(false, None)?)
                    } else {
                        None
                    };
                let extended_address_opt: Option<Address> = args
                    .extended_address
                    .as_ref()
                    .map(|value| AddressParser::new_sighash().parse(value))
                    .transpose()?;

                let root_path = if let Some(ref account) = from_account_opt {
                    self.plugin_mgr.root_key_path(account.clone())?
                } else {
                    DerivationPath::default()
                };
                let target_path = extended_address_opt
                    .and_then(|addr| from_account_opt.clone().map(|account| (addr, account)))
                    .map(|(addr, account)| {
                        search_path(self.plugin_mgr, account, addr, password.clone())
                    })
                    .transpose()?
                    .unwrap_or(root_path);

                let plugin_mgr_opt =
                    from_account_opt.map(|account| (&mut *self.plugin_mgr, account));
                let signature = sign_message(
                    from_privkey_opt.as_ref(),
                    plugin_mgr_opt,
                    &target_path,
                    recoverable,
                    &message,
                    SignTarget::AnyMessage(message.clone()),
                    password,
                )?;
                let result = serde_json::json!({
                    "signature": format!("0x{}", hex_string(&signature)),
                    "recoverable": recoverable,
                    "path": target_path.to_string(),
                });
                Ok(Output::new_output(result))
            }
            UtilSubcommands::VerifySignature(args) => {
                let message: H256 = FixedHashParser::<H256>::default().parse(&args.message)?;
                let signature: Vec<u8> = HexParser.parse(&args.signature)?;
                let pubkey_opt: Option<secp256k1::PublicKey> = args
                    .pubkey
                    .as_ref()
                    .map(|value| PubkeyHexParser.parse(value))
                    .transpose()?;
                let from_privkey_opt: Option<PrivkeyWrapper> = args
                    .privkey_path
                    .as_ref()
                    .map(|value| PrivkeyPathParser.parse(value))
                    .transpose()?;
                let from_account_opt: Option<H160> = args
                    .from_account
                    .as_ref()
                    .map(|input| {
                        FixedHashParser::<H160>::default()
                            .parse(input)
                            .or_else(|err| {
                                let result: Result<Address, String> =
                                    AddressParser::new_sighash().parse(input);
                                result
                                    .map(|address| {
                                        H160::from_slice(&address.payload().args()).unwrap()
                                    })
                                    .map_err(|_| err)
                            })
                    })
                    .transpose()?;
                let extended_address_opt: Option<Address> = args
                    .extended_address
                    .as_ref()
                    .map(|value| AddressParser::new_sighash().parse(value))
                    .transpose()?;
                let password =
                    if self.plugin_mgr.keystore_require_password() && from_account_opt.is_some() {
                        Some(read_password(false, None)?)
                    } else {
                        None
                    };
                let root_path = if let Some(ref account) = from_account_opt {
                    self.plugin_mgr.root_key_path(account.clone())?
                } else {
                    DerivationPath::default()
                };
                let target_path = extended_address_opt
                    .and_then(|addr| from_account_opt.clone().map(|account| (addr, account)))
                    .map(|(addr, account)| {
                        search_path(self.plugin_mgr, account, addr, password.clone())
                    })
                    .transpose()?
                    .unwrap_or(root_path);

                let pubkey = if let Some(pubkey) = pubkey_opt {
                    pubkey
                } else if let Some(privkey) = from_privkey_opt {
                    secp256k1::PublicKey::from_secret_key(&SECP256K1, &privkey)
                } else if let Some(account) = from_account_opt {
                    self.plugin_mgr.keystore_handler().extended_pubkey(
                        account,
                        &target_path,
                        password,
                    )?
                } else {
                    return Err(String::from(
                        "Missing <pubkey> or <privkey-path> or <from-account> argument",
                    ));
                };

                let recoverable = signature.len() == 65;
                let signature = if signature.len() == 65 {
                    let recov_id = RecoveryId::try_from(i32::from(signature[64]))
                        .map_err(|err| err.to_string())?;
                    RecoverableSignature::from_compact(&signature[0..64], recov_id)
                        .map_err(|err| err.to_string())?
                        .to_standard()
                } else if signature.len() == 64 {
                    Signature::from_compact(&signature).map_err(|err| err.to_string())?
                } else {
                    return Err(format!("Invalid signature length: {}", signature.len()));
                };
                let message = secp256k1::Message::from_digest_slice(message.as_bytes())
                    .expect("Convert to message failed");
                let verify_ok = SECP256K1
                    .verify_ecdsa(&message, &signature, &pubkey)
                    .is_ok();
                let result = serde_json::json!({
                    "pubkey": format!("0x{}", hex_string(&pubkey.serialize()[..])),
                    "recoverable": recoverable,
                    "verify-ok": verify_ok,
                });
                Ok(Output::new_output(result))
            }
            UtilSubcommands::Eaglesong(args) => {
                let binary: Vec<u8> = HexParser.parse(&args.binary_hex)?;
                let mut builder = EagleSongBuilder::new();
                builder.update(&binary);
                let output_string = format!("{:#x}", H256::from(builder.finalize()));
                Ok(Output::new_output(serde_json::Value::String(output_string)))
            }
            UtilSubcommands::Blake2b(args) => {
                let binary: Vec<u8> = if let Some(hex) = args.binary_hex.as_ref() {
                    HexParser.parse(hex)?
                } else if let Some(path) = args.binary_path.as_ref() {
                    let path = FilePathParser::new(true).parse(path).map_err(|err| {
                        format!("<binary-hex> or <binary-path> is required: {}", err)
                    })?;
                    let mut data = Vec::new();
                    let mut file = fs::File::open(path).map_err(|err| err.to_string())?;
                    file.read_to_end(&mut data).map_err(|err| err.to_string())?;
                    data
                } else {
                    return Err("<binary-hex> or <binary-path> is required".to_string());
                };
                let hash_data = blake2b_256(binary);
                let slice = if args.prefix_160 {
                    &hash_data[0..20]
                } else {
                    &hash_data[..]
                };
                let output_string = format!("0x{}", hex_string(slice));
                Ok(Output::new_output(serde_json::Value::String(output_string)))
            }
            UtilSubcommands::CompactToDifficulty(args) => {
                let compact_target: u32 = FromStrParser::<u32>::default()
                    .parse(&args.compact_target)
                    .or_else(|_| {
                        let input = if args.compact_target.starts_with("0x")
                            || args.compact_target.starts_with("0X")
                        {
                            &args.compact_target[2..]
                        } else {
                            args.compact_target.as_str()
                        };
                        u32::from_str_radix(input, 16).map_err(|err| err.to_string())
                    })?;
                let resp = serde_json::json!({
                    "difficulty": format!("{:#x}", compact_to_difficulty(compact_target))
                });
                Ok(Output::new_output(resp))
            }
            UtilSubcommands::DifficultyToCompact(args) => {
                let input =
                    if args.difficulty.starts_with("0x") || args.difficulty.starts_with("0X") {
                        &args.difficulty[2..]
                    } else {
                        args.difficulty.as_str()
                    };
                let difficulty = U256::from_hex_str(input).map_err(|err| err.to_string())?;
                let resp = serde_json::json!({
                    "compact-target": format!("{:#x}", difficulty_to_compact(difficulty)),
                });
                Ok(Output::new_output(resp))
            }
            UtilSubcommands::AddressInfo(args) => {
                let address: Address = AddressParser::default().parse(&args.address)?;
                if matches!(address.network(), NetworkType::Staging | NetworkType::Dev)
                    && address.payload().is_short_acp()
                {
                    return Err("only mainnet(line) and testnet(aggron) support short format anone-can-pay address".to_string());
                }
                let mut resp = serde_json::json!({
                    "extra": {
                        "data-encoding": if address.is_new() { "bech32m" } else { "bech32"},
                        "address-type": address.payload().ty(address.is_new()),
                    },
                    "network": address.network().to_str(),
                    "lock_script": {
                        "code_hash": format!("{:#x}", address.payload().code_hash(Some(address.network()))),
                        "hash_type": json_types::ScriptHashType::from(address.payload().hash_type()),
                        "args": format!("0x{}", hex_string(address.payload().args().as_ref())),
                    },
                });
                let other_format = if address.is_new() {
                    "old-format(deprecated)"
                } else {
                    "new-format"
                };
                resp["extra"][other_format] = serde_json::json!(Address::new(
                    address.network(),
                    AddressPayload::from(packed::Script::from(&address)),
                    !address.is_new(),
                )
                .to_string());
                Ok(Output::new_output(resp))
            }
            UtilSubcommands::ToGenesisMultisigAddr(args) => {
                let chain_info: ChainInfo = self
                    .rpc_client
                    .get_blockchain_info()
                    .map_err(|err| format!("RPC get_blockchain_info error: {:?}", err))?;
                if &chain_info.chain != "ckb" {
                    return Err("Node is not in mainnet spec".to_owned());
                }

                let locktime = args.locktime.as_str();
                let address = {
                    AddressParser::new_sighash()
                        .set_network(NetworkType::Mainnet)
                        .parse(&args.sighash_address)?
                };

                let genesis_timestamp =
                    NaiveDateTime::parse_from_str("2019-11-16 06:00:00", "%Y-%m-%d  %H:%M:%S")
                        .map(|dt| dt.and_utc().timestamp_millis() as u64)
                        .unwrap();
                let target_timestamp = to_timestamp(locktime)?;
                let elapsed = target_timestamp.saturating_sub(genesis_timestamp);
                let (epoch_fraction, addr_payload) =
                    gen_multisig_addr(MultisigScript::Legacy, address.payload(), None, elapsed);
                let multisig_addr = Address::new(NetworkType::Mainnet, addr_payload, true);
                let resp = format!("{},{},{}", address, locktime, multisig_addr);
                if debug {
                    eprintln!(
                        "[DEBUG] genesis_time: {}, target_time: {}, elapsed_in_secs: {}, target_epoch: {}, lock_arg: {}, code_hash: {:#x}",
                        DateTime::from_timestamp(genesis_timestamp as i64 / 1000, 0)
                            .expect("genesis time"),
                        DateTime::from_timestamp(target_timestamp as i64 / 1000, 0)
                            .ok_or_else(|| "target timestamp out of range".to_string())?,
                        elapsed / 1000,
                        epoch_fraction,
                        hex_string(multisig_addr.payload().args().as_ref()),
                        MultisigScript::Legacy.script_id().code_hash,
                    );
                }
                Ok(Output::new_output(serde_json::json!(resp)))
            }
            UtilSubcommands::ToMultisigAddr(args) => {
                let address: Address = AddressParser::new_sighash().parse(&args.sighash_address)?;
                let locktime_timestamp = DateTime::parse_from_rfc3339(&args.locktime)
                    .map(|dt| dt.timestamp_millis() as u64)
                    .map_err(|err| err.to_string())?;

                let multisig_lock_code_hash: H256 =
                    parse_multisig_code_hash_value(&args.multisig_code_hash)?;

                let multisig_script = MultisigScript::try_from(multisig_lock_code_hash.clone())
                    .map_err(|_err| {
                        format!(
                            "invalid multisig lock code hash: {}",
                            multisig_lock_code_hash
                        )
                    })?;
                let (tip_epoch, tip_timestamp) =
                    self.rpc_client.get_tip_header().map(|header_view| {
                        let header = header_view.inner;
                        let epoch = EpochNumberWithFraction::from_full_value(header.epoch.0);
                        let timestamp = header.timestamp;
                        (epoch, timestamp)
                    })?;
                let elapsed = locktime_timestamp.saturating_sub(tip_timestamp.0);
                let (epoch, multisig_addr) =
                    gen_multisig_addr(multisig_script, address.payload(), Some(tip_epoch), elapsed);
                let resp = serde_json::json!({
                    "address": {
                        "mainnet": Address::new(NetworkType::Mainnet, multisig_addr.clone(), true).to_string(),
                        "testnet": Address::new(NetworkType::Testnet, multisig_addr, true).to_string(),
                    },
                    "target_epoch": epoch.to_string(),
                });
                Ok(Output::new_output(resp))
            }
            UtilSubcommands::CellMeta(args) => {
                let tx_hash: H256 = FixedHashParser::<H256>::default().parse(&args.tx_hash)?;
                let index: u32 = FromStrParser::<u32>::default().parse(&args.index)?;
                let with_data = args.with_data;
                let out_point = packed::OutPoint::new_builder()
                    .tx_hash(tx_hash.pack())
                    .index(index)
                    .build();
                let cell_with_status = self.rpc_client.get_live_cell(out_point, true, None)?;
                if cell_with_status.status != "live" {
                    Ok(Output::new_output(cell_with_status))
                } else {
                    let network = get_network_type(self.rpc_client)?;
                    let info = cell_with_status.cell.expect("cell.info");
                    let output = info.output;
                    let data = info.data.expect("info.data");
                    let packed_output = packed::CellOutput::from(output.clone());
                    let lock_hash: H256 = packed_output.lock().calc_script_hash().unpack();
                    let address_payload = AddressPayload::from(packed_output.lock());
                    let address = Address::new(network, address_payload, true);
                    let type_hash: Option<H256> = packed_output
                        .type_()
                        .to_opt()
                        .map(|script| script.calc_script_hash().unpack());
                    let mut resp = serde_json::json!({
                        "output": output,
                        "data_hash": data.hash,
                        "lock_hash": lock_hash,
                        "type_hash": type_hash,
                        "address": address.to_string(),
                    });
                    if with_data {
                        resp["data"] = serde_json::json!(data.content);
                    }
                    Ok(Output::new_output(resp))
                }
            }
            UtilSubcommands::GenesisScripts => {
                let genesis_block: BlockView = self
                    .rpc_client
                    .get_block_by_number(0)?
                    .expect("Can not get genesis block?")
                    .into();
                let genesis_info = GenesisInfo::from_block(&genesis_block)?;
                let genesis_cellbase_tx_hash: H256 =
                    genesis_block.transaction(0).unwrap().hash().unpack();
                let resp = serde_json::json!({
                    "secp256k1_blake160_sighash_all": {
                        "script_id": {
                            "code_hash": SIGHASH_TYPE_HASH,
                            "hash_type": json_types::ScriptHashType::Type,
                        },
                        "cell_dep": json_types::CellDep::from(genesis_info.sighash_dep()),
                    },
                    "secp256k1_blake160_multisig_all": {
                        "script_id": {
                            "code_hash": MultisigScript::Legacy.script_id().code_hash,
                            "hash_type": json_types::ScriptHashType::from(MultisigScript::Legacy.script_id().hash_type),
                        },
                        "cell_dep": json_types::CellDep::from(genesis_info.multisig_dep(MultisigScript::Legacy)),
                    },
                    "dao": {
                        "script_id": {
                            "code_hash": DAO_TYPE_HASH,
                            "hash_type": json_types::ScriptHashType::Type,
                        },
                        "cell_dep": json_types::CellDep::from(genesis_info.dao_dep()),
                    },
                    "secp256k1_data": {
                        "out_point": {
                            "tx_hash": genesis_cellbase_tx_hash,
                            "index": json_types::Uint32::from(3),
                        }
                    },
                    "type_id": {
                        "script_id": {
                            "code_hash": TYPE_ID_CODE_HASH,
                            "hash_type": json_types::ScriptHashType::Type,
                        }
                    },
                });
                Ok(Output::new_output(resp))
            }
            UtilSubcommands::Completions(args) => {
                let shell = args.shell.as_str();
                let version = get_version();
                let version_short = version.short();
                let version_long = version.long();
                let mut app = build_cli(&version_short, &version_long);
                let bin_name = "ckb-cli";
                let output = &mut std::io::stdout();
                let shell = match shell {
                    "bash" => Shell::Bash,
                    "zsh" => Shell::Zsh,
                    "fish" => Shell::Fish,
                    "elvish" => Shell::Elvish,
                    "powershell" => Shell::PowerShell,
                    _ => panic!("Invalid shell: {}", shell),
                };
                clap_complete::generate(shell, &mut app, bin_name, output);
                Ok(Output::new_success())
            }
        }
    }
}

fn search_path(
    plugin_mgr: &mut PluginManager,
    hash160: H160,
    extended_address: Address,
    password: Option<String>,
) -> Result<DerivationPath, String> {
    let target = H160::from_slice(extended_address.payload().args().as_ref())
        .map_err(|err| format!("parse extended address lock args error: {}", err))?;
    let key_set = plugin_mgr
        .keystore_handler()
        .derived_key_set_by_index(hash160, 0, 2000, 0, 2000, password)?;
    for (path, hash) in key_set.external.into_iter().chain(key_set.change) {
        if hash == target {
            return Ok(path);
        }
    }
    Err(format!(
        "can not found path for address: {}",
        extended_address
    ))
}

fn sign_message<P: ?Sized + AsRef<[ChildNumber]>>(
    from_privkey_opt: Option<&PrivkeyWrapper>,
    from_account_opt: Option<(&mut PluginManager, H160)>,
    path: &P,
    recoverable: bool,
    message: &H256,
    target: SignTarget,
    password: Option<String>,
) -> Result<Vec<u8>, String> {
    match (from_privkey_opt, from_account_opt, recoverable) {
        (Some(privkey), _, false) => {
            let message = secp256k1::Message::from_digest_slice(message.as_bytes()).unwrap();
            Ok(SECP256K1
                .sign_ecdsa(&message, privkey)
                .serialize_compact()
                .to_vec())
        }
        (Some(privkey), _, true) => {
            let message = secp256k1::Message::from_digest_slice(message.as_bytes()).unwrap();
            Ok(serialize_signature(&SECP256K1.sign_ecdsa_recoverable(&message, privkey)).to_vec())
        }
        (None, Some((plugin_mgr, account)), false) => plugin_mgr
            .keystore_handler()
            .sign(account, path, message.clone(), target, password, false)
            .map(|bytes| (bytes[..]).to_vec()),
        (None, Some((plugin_mgr, account)), true) => plugin_mgr
            .keystore_handler()
            .sign(account, path, message.clone(), target, password, true)
            .map(|bytes| (bytes[..]).to_vec()),
        _ => Err(String::from("Both privkey and key store is missing")),
    }
}

fn gen_multisig_addr(
    multisig_script: MultisigScript,
    sighash_address_payload: &AddressPayload,
    tip_epoch_opt: Option<EpochNumberWithFraction>,
    elapsed: u64,
) -> (EpochNumberWithFraction, AddressPayload) {
    let epoch_fraction = {
        let tip_epoch =
            tip_epoch_opt.unwrap_or_else(|| EpochNumberWithFraction::new(0, 0, EPOCH_LENGTH));
        let blocks = tip_epoch.number() * EPOCH_LENGTH
            + tip_epoch.index() * EPOCH_LENGTH / tip_epoch.length()
            + elapsed / BLOCK_PERIOD;
        let epoch_number = blocks / EPOCH_LENGTH;
        let epoch_index = blocks % EPOCH_LENGTH;
        EpochNumberWithFraction::new(epoch_number, epoch_index, EPOCH_LENGTH)
    };
    let since = FLAG_SINCE_EPOCH_NUMBER | epoch_fraction.full_value();

    let args = {
        let mut multi_script = vec![0u8, 0, 1, 1]; // [S, R, M, N]
        multi_script.extend_from_slice(sighash_address_payload.args().as_ref());
        let mut data = BytesMut::from(&blake2b_256(multi_script)[..20]);
        data.extend_from_slice(&since.to_le_bytes()[..]);
        data.freeze()
    };
    let payload = AddressPayload::new_full(
        multisig_script.script_id().hash_type,
        multisig_script.script_id().code_hash.pack(),
        args,
    );
    (epoch_fraction, payload)
}

fn to_timestamp(input: &str) -> Result<u64, String> {
    let date = NaiveDate::parse_from_str(input, "%Y-%m-%d").map_err(|err| format!("{:?}", err))?;
    let date = NaiveDateTime::parse_from_str(&format!("{} 00:00:00", date), "%Y-%m-%d  %H:%M:%S")
        .map_err(|err| format!("{:?}", err))?;
    Ok(date.and_utc().timestamp_millis() as u64)
}

#[cfg(test)]
mod test {
    use super::*;
    use ckb_sdk::CodeHashIndex;
    #[test]
    fn test_gen_multisig_addr() {
        let payload = AddressPayload::new_short(CodeHashIndex::Sighash, H160::default());

        let (epoch, _) =
            gen_multisig_addr(MultisigScript::Legacy, &payload, None, BLOCK_PERIOD * 2000);
        assert_eq!(epoch, EpochNumberWithFraction::new(1, 200, EPOCH_LENGTH));

        // (1+2/3) + (1+1/2) = 3+1/6
        let (epoch, _) = gen_multisig_addr(
            MultisigScript::Legacy,
            &payload,
            Some(EpochNumberWithFraction::new(1, 400, 600)),
            BLOCK_PERIOD * 2700,
        );
        assert_eq!(epoch, EpochNumberWithFraction::new(3, 300, EPOCH_LENGTH))
    }
}
