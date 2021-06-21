use chrono::prelude::*;
use ckb_crypto::secp::SECP256K1;
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::JsonBytes;
use ckb_sdk::{
    constants::{MULTISIG_TYPE_HASH, SIGHASH_TYPE_HASH},
    rpc::ChainInfo,
    wallet::{ChildNumber, DerivationPath},
    AcpConfig, Address, AddressPayload, CodeHashIndex, HttpRpcClient, NetworkType, OldAddress,
};
use ckb_types::{
    bytes::BytesMut,
    core::{EpochNumberWithFraction, ScriptHashType},
    packed,
    prelude::*,
    utilities::{compact_to_difficulty, difficulty_to_compact},
    H160, H256, U256,
};
use clap::{App, Arg, ArgMatches};
use clap_generate::generators::{Bash, Elvish, Fish, PowerShell, Zsh};
use eaglesong::EagleSongBuilder;
use faster_hex::hex_string;
use secp256k1::recovery::{RecoverableSignature, RecoveryId};
use std::fs;
use std::io::Read;
use std::path::PathBuf;

use super::{CliSubCommand, Output};
use crate::plugin::{PluginManager, SignTarget};
use crate::utils::{
    arg,
    arg_parser::{
        AcpConfigParser, AddressParser, AddressPayloadOption, ArgParser, FilePathParser,
        FixedHashParser, FromStrParser, HexParser, PrivkeyPathParser, PrivkeyWrapper,
        PubkeyHexParser,
    },
    other::{get_address, get_network_type, read_password, serialize_signature},
};
use crate::{build_cli, get_version};

// Magic bytes to put before every sign-data binary argument
const SIGN_MAGIC_BYTES: &[u8] = b"Nervos Message:";
const FLAG_SINCE_EPOCH_NUMBER: u64 =
    0b010_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000;
const EPOCH_LENGTH: u64 = 1800;
const BLOCK_PERIOD: u64 = 8 * 1000; // 8 seconds

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

    pub fn subcommand(name: &'static str) -> App<'static> {
        let arg_privkey = Arg::with_name("privkey-path")
            .long("privkey-path")
            .takes_value(true)
            .validator(|input| PrivkeyPathParser.validate(input))
            .about("Private key file path (only read first line)");
        let arg_pubkey = Arg::with_name("pubkey")
            .long("pubkey")
            .takes_value(true)
            .validator(|input| PubkeyHexParser.validate(input))
            .about("Public key (hex string, compressed format)");
        let arg_address = Arg::with_name("address")
            .long("address")
            .takes_value(true)
            .validator(|input| AddressParser::default().validate(input))
            .required(true)
            .about("Target address (see: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0021-ckb-address-format/0021-ckb-address-format.md)");

        let binary_hex_arg = Arg::with_name("binary-hex")
            .long("binary-hex")
            .takes_value(true)
            .required(true)
            .validator(|input| HexParser.validate(input));
        let arg_sighash_address = Arg::with_name("sighash-address")
            .long("sighash-address")
            .required(true)
            .takes_value(true)
            .validator(|input| AddressParser::new_short_sighash().validate(input))
            .about("The address in single signature format");

        let arg_recoverable = Arg::with_name("recoverable")
            .long("recoverable")
            .about("Sign use recoverable signature");

        let arg_message = Arg::with_name("message")
            .long("message")
            .takes_value(true)
            .required(true)
            .validator(|input| FixedHashParser::<H256>::default().validate(input));

        let arg_extended_address = Arg::with_name("extended-address")
            .long("extended-address")
            .takes_value(true)
            .validator(|input| AddressParser::new_short_sighash().validate(input))
            .conflicts_with(arg::privkey_path().get_name())
            .about("The address extended from `m/44'/309'/0'` (Search 2000 receiving addresses and 2000 change addresses max)");

        App::new(name)
            .about("Utilities")
            .subcommands(vec![
                App::new("key-info")
                    .about(
                        "Show public information of a secp256k1 private key (from file) or public key",
                    )
                    .arg(arg::acp_config())
                    .arg(arg_privkey.clone().conflicts_with("pubkey"))
                    .arg(arg_pubkey.clone().required(false))
                    .arg(arg_address.clone().required(false))
                    .arg(arg::lock_arg().clone()),
                App::new("sign-data")
                    .about("Sign data with secp256k1 signature ")
                    .arg(arg::privkey_path().required_unless(arg::from_account().get_name()))
                    .arg(
                        arg::from_account()
                            .required_unless(arg::privkey_path().get_name())
                            .conflicts_with(arg::privkey_path().get_name()),
                    )
                    .arg(arg_recoverable.clone())
                    .arg(arg_extended_address.clone())
                    .arg(
                        binary_hex_arg
                            .clone()
                            .required(false)
                            .required_unless("utf8-string")
                            .conflicts_with("utf8-string")
                            .about("The data to be signed. The input data will be hashed using blake2b with 'ckb-default-hash' personalization first.")
                    )
                    .arg(
                        Arg::with_name("no-magic-bytes")
                            .long("no-magic-bytes")
                            .about("Don't add magic bytes before binary data (magic bytes: \"Nervos Message:\")")
                    )
                    .arg(
                        Arg::with_name("utf8-string")
                            .long("utf8-string")
                            .takes_value(true)
                            .required_unless(binary_hex_arg.get_name())
                            .conflicts_with(binary_hex_arg.get_name())
                            .about("The utf-8 string to be signed. The input string will be hashed using blake2b with 'ckb-default-hash' personalization first.")
                    ),
                App::new("sign-message")
                    .about("Sign message with secp256k1 signature")
                    .arg(arg::privkey_path().required_unless(arg::from_account().get_name()))
                    .arg(
                        arg::from_account()
                            .required_unless(arg::privkey_path().get_name())
                            .conflicts_with(arg::privkey_path().get_name()),
                    )
                    .arg(arg_recoverable.clone())
                    .arg(arg_extended_address.clone())
                    .arg(arg_message.clone().about("The message to be signed (32 bytes)")),
                App::new("verify-signature")
                    .about("Verify a compact format signature")
                    .arg(arg::pubkey())
                    .arg(arg::privkey_path().conflicts_with(arg::pubkey().get_name()))
                    .arg(
                        arg::from_account()
                            .conflicts_with_all(&[arg::privkey_path().get_name(), arg::pubkey().get_name()]),
                    )
                    .arg(arg_message.clone().about("The message to be verify (32 bytes)"))
                    .arg(
                        arg_extended_address
                            .clone()
                            .conflicts_with(arg::pubkey().get_name())
                    )
                    .arg(
                        Arg::with_name("signature")
                            .long("signature")
                            .takes_value(true)
                            .required(true)
                            .validator(|input| HexParser.validate(input))
                            .about("The compact format signature (support recoverable signature)")
                    ),
                App::new("eaglesong")
                    .about("Hash binary use eaglesong algorithm")
                    .arg(binary_hex_arg.clone().about("The binary in hex format to hash")),
                App::new("blake2b")
                    .about("Hash binary use blake2b algorithm (personalization: 'ckb-default-hash')")
                    .arg(binary_hex_arg.clone().required(false).about("The binary in hex format to hash"))
                    .arg(
                        Arg::with_name("binary-path")
                            .long("binary-path")
                            .takes_value(true)
                            .validator(|input| FilePathParser::new(true).validate(input))
                            .about("The binary file path")
                    )
                    .arg(
                        Arg::with_name("prefix-160")
                            .long("prefix-160")
                            .about("Only show prefix 160 bits (Example: calculate lock_arg from pubkey)")
                    ),
                App::new("compact-to-difficulty")
                    .about("Convert compact target value to difficulty value")
                    .arg(Arg::with_name("compact-target")
                         .long("compact-target")
                         .takes_value(true)
                         .validator(|input| {
                             FromStrParser::<u32>::default()
                                 .validate(input)
                                 .or_else(|_| {
                                     let input = if input.starts_with("0x") || input.starts_with("0X") {
                                         &input[2..]
                                     } else {
                                         &input[..]
                                     };
                                     u32::from_str_radix(input, 16).map(|_| ()).map_err(|err| err.to_string())
                                 })
                         })
                         .required(true)
                         .about("The compact target value")
                    ),
                App::new("difficulty-to-compact")
                    .about("Convert difficulty value to compact target value")
                    .arg(Arg::with_name("difficulty")
                         .long("difficulty")
                         .takes_value(true)
                         .validator(|input| {
                             let input = if input.starts_with("0x") || input.starts_with("0X") {
                                 &input[2..]
                             } else {
                                 &input[..]
                             };
                             U256::from_hex_str(input).map(|_| ()).map_err(|err| err.to_string())
                         })
                         .required(true)
                         .about("The difficulty value")
                    ),
                App::new("to-genesis-multisig-addr")
                    .about("Convert address in single signature format to multisig format (only for mainnet genesis cells)")
                    .arg(arg::acp_config())
                    .arg(
                        arg_sighash_address
                            .clone()
                            .validator(|input| {
                                AddressParser::default()
                                    .set_network(NetworkType::Mainnet)
                                    .set_short(CodeHashIndex::Sighash)
                                    .validate(input)
                            }))
                    .arg(
                        Arg::with_name("locktime")
                            .long("locktime")
                            .required(true)
                            .takes_value(true)
                            .about("The locktime in UTC format date. Example: 2022-05-01")
                    ),
                App::new("to-multisig-addr")
                    .about("Convert address in single signature format to multisig format")
                    .arg(arg::acp_config())
                    .arg(arg_sighash_address.clone())
                    .arg(
                        Arg::with_name("locktime")
                            .long("locktime")
                            .required(true)
                            .takes_value(true)
                            .validator(|input| DateTime::parse_from_rfc3339(&input).map(|_| ()).map_err(|err| err.to_string()))
                            .about("The locktime in RFC3339 format. Example: 2014-11-28T21:00:00+00:00")
                    ),
                App::new("cell-meta")
                    .about("Query live cell's metadata")
                    .arg(arg::acp_config())
                    .arg(
                        Arg::with_name("tx-hash")
                            .long("tx-hash")
                            .takes_value(true)
                            .validator(|input| FixedHashParser::<H256>::default().validate(input))
                            .required(true)
                            .about("Tx hash"),
                    )
                    .arg(
                        Arg::with_name("index")
                            .long("index")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<u32>::default().validate(input))
                            .required(true)
                            .about("Output index"),
                    )
                    .arg(
                        Arg::with_name("with-data")
                            .long("with-data")
                            .about("Get live cell with data")
                    ),
                App::new("completions")
                    .about("Generates completion scripts for your shell")
                    .arg(
                        Arg::with_name("shell")
                            .required(true)
                            .possible_values(&["bash", "zsh", "fish", "elvish", "powershell"])
                            .about("The shell to generate the script for")
                    ),
        ])
    }
}

impl<'a> CliSubCommand for UtilSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches, debug: bool) -> Result<Output, String> {
        match matches.subcommand() {
            ("key-info", Some(m)) => {
                let acp_config: Option<AcpConfig> =
                    AcpConfigParser::default().from_matches_opt(m, "acp-config", false)?;
                let privkey_opt: Option<PrivkeyWrapper> =
                    PrivkeyPathParser.from_matches_opt(m, "privkey-path", false)?;
                let pubkey_opt: Option<secp256k1::PublicKey> =
                    PubkeyHexParser.from_matches_opt(m, "pubkey", false)?;
                let pubkey_opt = privkey_opt
                    .map(|privkey| secp256k1::PublicKey::from_secret_key(&SECP256K1, &privkey))
                    .or_else(|| pubkey_opt);
                let pubkey_string_opt = pubkey_opt.as_ref().map(|pubkey| {
                    hex_string(&pubkey.serialize()[..]).expect("encode pubkey failed")
                });
                let address_payload = match pubkey_opt {
                    Some(pubkey) => AddressPayload::from_pubkey(&pubkey),
                    None => get_address(None, m)?,
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

                let lock_hash: H256 = address_payload
                    .try_to_script(acp_config.as_ref())?
                    .calc_script_hash()
                    .unpack();
                let resp = serde_json::json!({
                    "pubkey": pubkey_string_opt,
                    "address": {
                        "mainnet": Address::new(NetworkType::Mainnet, address_payload.clone()).to_string(),
                        "testnet": Address::new(NetworkType::Testnet, address_payload).to_string(),
                    },
                    // NOTE: remove this later (after all testnet race reward received)
                    "old-testnet-address": old_address.display_with_prefix(NetworkType::Testnet),
                    "lock_arg": format!("{:#x}", lock_arg),
                    "lock_hash": format!("{:#x}", lock_hash),
                });
                Ok(Output::new_output(resp))
            }
            ("sign-data", Some(m)) => {
                let binary_opt: Option<Vec<u8>> =
                    HexParser.from_matches_opt(m, "binary-hex", false)?;
                let recoverable = m.is_present("recoverable");
                let from_privkey_opt: Option<PrivkeyWrapper> =
                    PrivkeyPathParser.from_matches_opt(m, "privkey-path", false)?;
                let from_account_opt: Option<H160> = FixedHashParser::<H160>::default()
                    .from_matches_opt(m, "from-account", false)
                    .or_else(|err| {
                        let result: Result<Option<Address>, String> =
                            AddressParser::new_short_sighash().from_matches_opt(
                                m,
                                "from-account",
                                false,
                            );
                        result
                            .map(|address_opt| {
                                address_opt.map(|address| {
                                    H160::from_slice(&address.payload().args()).unwrap()
                                })
                            })
                            .map_err(|_| err)
                    })?;
                let no_magic_bytes = m.is_present("no-magic-bytes");
                let password =
                    if self.plugin_mgr.keystore_require_password() && from_account_opt.is_some() {
                        Some(read_password(false, None)?)
                    } else {
                        None
                    };
                let extended_address_opt: Option<Address> = AddressParser::new_short_sighash()
                    .from_matches_opt(m, "extended-address", false)?;
                let root_path = if let Some(ref account) = from_account_opt {
                    self.plugin_mgr.root_key_path(account.clone())?
                } else {
                    DerivationPath::empty()
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
                    let utf8_string = m
                        .value_of("utf8-string")
                        .ok_or_else(|| "<binary-hex> or <string> is required".to_string())?;
                    let binary = utf8_string.as_bytes().to_vec();
                    (binary, SignTarget::AnyString(utf8_string.to_string()))
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
                    "signature": format!("0x{}", hex_string(&signature).unwrap()),
                    "recoverable": recoverable,
                    "path": target_path.to_string(),
                });
                Ok(Output::new_output(result))
            }
            ("sign-message", Some(m)) => {
                let message: H256 =
                    FixedHashParser::<H256>::default().from_matches(m, "message")?;
                let recoverable = m.is_present("recoverable");
                let from_privkey_opt: Option<PrivkeyWrapper> =
                    PrivkeyPathParser.from_matches_opt(m, "privkey-path", false)?;
                let from_account_opt: Option<H160> = FixedHashParser::<H160>::default()
                    .from_matches_opt(m, "from-account", false)
                    .or_else(|err| {
                        let result: Result<Option<Address>, String> =
                            AddressParser::new_short_sighash().from_matches_opt(
                                m,
                                "from-account",
                                false,
                            );
                        result
                            .map(|address_opt| {
                                address_opt.map(|address| {
                                    H160::from_slice(&address.payload().args()).unwrap()
                                })
                            })
                            .map_err(|_| err)
                    })?;
                let password =
                    if self.plugin_mgr.keystore_require_password() && from_account_opt.is_some() {
                        Some(read_password(false, None)?)
                    } else {
                        None
                    };
                let extended_address_opt: Option<Address> = AddressParser::new_short_sighash()
                    .from_matches_opt(m, "extended-address", false)?;

                let root_path = if let Some(ref account) = from_account_opt {
                    self.plugin_mgr.root_key_path(account.clone())?
                } else {
                    DerivationPath::empty()
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
                    "signature": format!("0x{}", hex_string(&signature).unwrap()),
                    "recoverable": recoverable,
                    "path": target_path.to_string(),
                });
                Ok(Output::new_output(result))
            }
            ("verify-signature", Some(m)) => {
                let message: H256 =
                    FixedHashParser::<H256>::default().from_matches(m, "message")?;
                let signature: Vec<u8> = HexParser.from_matches(m, "signature")?;
                let pubkey_opt: Option<secp256k1::PublicKey> =
                    PubkeyHexParser.from_matches_opt(m, "pubkey", false)?;
                let from_privkey_opt: Option<PrivkeyWrapper> =
                    PrivkeyPathParser.from_matches_opt(m, "privkey-path", false)?;
                let from_account_opt: Option<H160> = FixedHashParser::<H160>::default()
                    .from_matches_opt(m, "from-account", false)
                    .or_else(|err| {
                        let result: Result<Option<Address>, String> =
                            AddressParser::new_short_sighash().from_matches_opt(
                                m,
                                "from-account",
                                false,
                            );
                        result
                            .map(|address_opt| {
                                address_opt.map(|address| {
                                    H160::from_slice(&address.payload().args()).unwrap()
                                })
                            })
                            .map_err(|_| err)
                    })?;
                let extended_address_opt: Option<Address> = AddressParser::new_short_sighash()
                    .from_matches_opt(m, "extended-address", false)?;
                let password =
                    if self.plugin_mgr.keystore_require_password() && from_account_opt.is_some() {
                        Some(read_password(false, None)?)
                    } else {
                        None
                    };
                let root_path = if let Some(ref account) = from_account_opt {
                    self.plugin_mgr.root_key_path(account.clone())?
                } else {
                    DerivationPath::empty()
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
                    let recov_id = RecoveryId::from_i32(i32::from(signature[64]))
                        .map_err(|err| err.to_string())?;
                    RecoverableSignature::from_compact(&signature[0..64], recov_id)
                        .map_err(|err| err.to_string())?
                        .to_standard()
                } else if signature.len() == 64 {
                    secp256k1::Signature::from_compact(&signature).map_err(|err| err.to_string())?
                } else {
                    return Err(format!("Invalid signature length: {}", signature.len()));
                };
                let message = secp256k1::Message::from_slice(message.as_bytes())
                    .expect("Convert to message failed");
                let verify_ok = SECP256K1.verify(&message, &signature, &pubkey).is_ok();
                let result = serde_json::json!({
                    "pubkey": format!("0x{}", hex_string(&pubkey.serialize()[..]).unwrap()),
                    "recoverable": recoverable,
                    "verify-ok": verify_ok,
                });
                Ok(Output::new_output(result))
            }
            ("eaglesong", Some(m)) => {
                let binary: Vec<u8> = HexParser.from_matches(m, "binary-hex")?;
                let mut builder = EagleSongBuilder::new();
                builder.update(&binary);
                let output_string = format!("{:#x}", H256::from(builder.finalize()));
                Ok(Output::new_output(serde_json::Value::String(output_string)))
            }
            ("blake2b", Some(m)) => {
                let binary: Vec<u8> = HexParser
                    .from_matches_opt(m, "binary-hex", false)?
                    .ok_or_else(String::new)
                    .or_else(|_| -> Result<_, String> {
                        let path: PathBuf = FilePathParser::new(true)
                            .from_matches(m, "binary-path")
                            .map_err(|err| {
                                format!("<binary-hex> or <binary-path> is required: {}", err)
                            })?;
                        let mut data = Vec::new();
                        let mut file = fs::File::open(path).map_err(|err| err.to_string())?;
                        file.read_to_end(&mut data).map_err(|err| err.to_string())?;
                        Ok(data)
                    })?;
                let hash_data = blake2b_256(&binary);
                let slice = if m.is_present("prefix-160") {
                    &hash_data[0..20]
                } else {
                    &hash_data[..]
                };
                let output_string = format!("0x{}", hex_string(slice).unwrap());
                Ok(Output::new_output(serde_json::Value::String(output_string)))
            }
            ("compact-to-difficulty", Some(m)) => {
                let compact_target: u32 = FromStrParser::<u32>::default()
                    .from_matches(m, "compact-target")
                    .or_else(|_| {
                        let input = m.value_of("compact-target").unwrap();
                        let input = if input.starts_with("0x") || input.starts_with("0X") {
                            &input[2..]
                        } else {
                            &input[..]
                        };
                        u32::from_str_radix(input, 16).map_err(|err| err.to_string())
                    })?;
                let resp = serde_json::json!({
                    "difficulty": format!("{:#x}", compact_to_difficulty(compact_target))
                });
                Ok(Output::new_output(resp))
            }
            ("difficulty-to-compact", Some(m)) => {
                let input = m.value_of("difficulty").unwrap();
                let input = if input.starts_with("0x") || input.starts_with("0X") {
                    &input[2..]
                } else {
                    &input[..]
                };
                let difficulty = U256::from_hex_str(input).map_err(|err| err.to_string())?;
                let resp = serde_json::json!({
                    "compact-target": format!("{:#x}", difficulty_to_compact(difficulty)),
                });
                Ok(Output::new_output(resp))
            }
            ("to-genesis-multisig-addr", Some(m)) => {
                let chain_info: ChainInfo = self
                    .rpc_client
                    .get_blockchain_info()
                    .map_err(|err| format!("RPC get_blockchain_info error: {:?}", err))?;
                if &chain_info.chain != "ckb" {
                    return Err("Node is not in mainnet spec".to_owned());
                }

                let locktime = m.value_of("locktime").unwrap();
                let address = {
                    let input = m.value_of("sighash-address").unwrap();
                    AddressParser::new(
                        Some(NetworkType::Mainnet),
                        Some(AddressPayloadOption::Short(Some(CodeHashIndex::Sighash))),
                    )
                    .parse(input)?
                };

                let genesis_timestamp =
                    NaiveDateTime::parse_from_str("2019-11-16 06:00:00", "%Y-%m-%d  %H:%M:%S")
                        .map(|dt| dt.timestamp_millis() as u64)
                        .unwrap();
                let target_timestamp = to_timestamp(locktime)?;
                let elapsed = target_timestamp.saturating_sub(genesis_timestamp);
                let (epoch_fraction, addr_payload) =
                    gen_multisig_addr(address.payload(), None, elapsed);
                let multisig_addr = Address::new(NetworkType::Mainnet, addr_payload);
                let resp = format!("{},{},{}", address, locktime, multisig_addr);
                if debug {
                    eprintln!(
                        "[DEBUG] genesis_time: {}, target_time: {}, elapsed_in_secs: {}, target_epoch: {}, lock_arg: {}, code_hash: {:#x}",
                        NaiveDateTime::from_timestamp(genesis_timestamp as i64 / 1000, 0),
                        NaiveDateTime::from_timestamp(target_timestamp as i64 / 1000, 0),
                        elapsed / 1000,
                        epoch_fraction,
                        hex_string(multisig_addr.payload().args().as_ref()).unwrap(),
                        MULTISIG_TYPE_HASH,
                    );
                }
                Ok(Output::new_output(serde_json::json!(resp)))
            }
            ("to-multisig-addr", Some(m)) => {
                let address: Address = AddressParser::default()
                    .set_short(CodeHashIndex::Sighash)
                    .from_matches(m, "sighash-address")?;
                let locktime_timestamp =
                    DateTime::parse_from_rfc3339(m.value_of("locktime").unwrap())
                        .map(|dt| dt.timestamp_millis() as u64)
                        .map_err(|err| err.to_string())?;
                let (tip_epoch, tip_timestamp) =
                    self.rpc_client.get_tip_header().map(|header_view| {
                        let header = header_view.inner;
                        let epoch = EpochNumberWithFraction::from_full_value(header.epoch.0);
                        let timestamp = header.timestamp;
                        (epoch, timestamp)
                    })?;
                let elapsed = locktime_timestamp.saturating_sub(tip_timestamp.0);
                let (epoch, multisig_addr) =
                    gen_multisig_addr(address.payload(), Some(tip_epoch), elapsed);
                let resp = serde_json::json!({
                    "address": {
                        "mainnet": Address::new(NetworkType::Mainnet, multisig_addr.clone()).to_string(),
                        "testnet": Address::new(NetworkType::Testnet, multisig_addr).to_string(),
                    },
                    "target_epoch": epoch.to_string(),
                });
                Ok(Output::new_output(resp))
            }
            ("cell-meta", Some(m)) => {
                let acp_config: Option<AcpConfig> =
                    AcpConfigParser::default().from_matches_opt(m, "acp-config", false)?;
                let tx_hash: H256 =
                    FixedHashParser::<H256>::default().from_matches(m, "tx-hash")?;
                let index: u32 = FromStrParser::<u32>::default().from_matches(m, "index")?;
                let with_data = m.is_present("with-data");
                let out_point = packed::OutPoint::new_builder()
                    .tx_hash(tx_hash.pack())
                    .index(index.pack())
                    .build();
                let cell_with_status = self.rpc_client.get_live_cell(out_point, true)?;
                if cell_with_status.status != "live" {
                    Ok(Output::new_output(cell_with_status))
                } else {
                    let network = get_network_type(self.rpc_client)?;
                    let info = cell_with_status.cell.expect("cell.info");
                    let output = info.output;
                    let data = info.data.expect("info.data");
                    let packed_output = packed::CellOutput::from(output.clone());
                    let lock_hash: H256 = packed_output.lock().calc_script_hash().unpack();
                    let address_payload = AddressPayload::try_from_script(
                        &packed_output.lock(),
                        acp_config.as_ref(),
                    )?;
                    let address = Address::new(network, address_payload);
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
            ("completions", Some(m)) => {
                let shell = m.value_of("shell").unwrap();
                let version = get_version();
                let version_short = version.short();
                let version_long = version.long();
                let mut app = build_cli(&version_short, &version_long);
                let bin_name = "ckb-cli";
                let output = &mut std::io::stdout();
                match shell {
                    "bash" => clap_generate::generate::<Bash, _>(&mut app, bin_name, output),
                    "zsh" => clap_generate::generate::<Zsh, _>(&mut app, bin_name, output),
                    "fish" => clap_generate::generate::<Fish, _>(&mut app, bin_name, output),
                    "elvish" => clap_generate::generate::<Elvish, _>(&mut app, bin_name, output),
                    "powershell" => {
                        clap_generate::generate::<PowerShell, _>(&mut app, bin_name, output)
                    }
                    _ => panic!("Invalid shell: {}", shell),
                }
                Ok(Output::new_success())
            }
            _ => Err(Self::subcommand("util").generate_usage()),
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
    for (path, hash) in key_set
        .external
        .into_iter()
        .chain(key_set.change.into_iter())
    {
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
            let message = secp256k1::Message::from_slice(message.as_bytes()).unwrap();
            Ok(SECP256K1
                .sign(&message, privkey)
                .serialize_compact()
                .to_vec())
        }
        (Some(privkey), _, true) => {
            let message = secp256k1::Message::from_slice(message.as_bytes()).unwrap();
            Ok(serialize_signature(&SECP256K1.sign_recoverable(&message, privkey)).to_vec())
        }
        (None, Some((plugin_mgr, account)), false) => plugin_mgr
            .keystore_handler()
            .sign(account, path, message.clone(), target, password, false)
            .map(|bytes| (&bytes[..]).to_vec()),
        (None, Some((plugin_mgr, account)), true) => plugin_mgr
            .keystore_handler()
            .sign(account, path, message.clone(), target, password, true)
            .map(|bytes| (&bytes[..]).to_vec()),
        _ => Err(String::from("Both privkey and key store is missing")),
    }
}

fn gen_multisig_addr(
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
    let payload = AddressPayload::new_full(ScriptHashType::Type, MULTISIG_TYPE_HASH.pack(), args);
    (epoch_fraction, payload)
}

fn to_timestamp(input: &str) -> Result<u64, String> {
    let date = NaiveDate::parse_from_str(input, "%Y-%m-%d").map_err(|err| format!("{:?}", err))?;
    let date = NaiveDateTime::parse_from_str(
        &format!("{} 00:00:00", date.to_string()),
        "%Y-%m-%d  %H:%M:%S",
    )
    .map_err(|err| format!("{:?}", err))?;
    Ok(date.timestamp_millis() as u64)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_gen_multisig_addr() {
        let payload = AddressPayload::new_short_sighash(H160::default());

        let (epoch, _) = gen_multisig_addr(&payload, None, BLOCK_PERIOD * 2000);
        assert_eq!(epoch, EpochNumberWithFraction::new(1, 200, EPOCH_LENGTH));

        // (1+2/3) + (1+1/2) = 3+1/6
        let (epoch, _) = gen_multisig_addr(
            &payload,
            Some(EpochNumberWithFraction::new(1, 400, 600)),
            BLOCK_PERIOD * 2700,
        );
        assert_eq!(epoch, EpochNumberWithFraction::new(3, 300, EPOCH_LENGTH))
    }
}
