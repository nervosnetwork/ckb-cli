use chrono::{NaiveDate, NaiveDateTime};
use ckb_crypto::secp::SECP256K1;
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::{ChainInfo, Script as RpcScript, Transaction as RpcTransaction};
use ckb_sdk::{
    constants::{MULTISIG_TYPE_HASH, SIGHASH_TYPE_HASH},
    Address, AddressPayload, CodeHashIndex, GenesisInfo, HttpRpcClient, NetworkType, OldAddress,
};
use ckb_types::{
    bytes::Bytes,
    core::{EpochNumberWithFraction, ScriptHashType},
    packed,
    prelude::*,
    utilities::{compact_to_difficulty, difficulty_to_compact},
    H160, H256, U256,
};
use clap::{App, Arg, ArgMatches, SubCommand};
use faster_hex::hex_string;
use std::fs;
use std::path::PathBuf;

use super::CliSubCommand;
use crate::utils::{
    arg_parser::{
        AddressParser, AddressPayloadOption, ArgParser, FilePathParser, FixedHashParser,
        FromStrParser, HexParser, PrivkeyPathParser, PrivkeyWrapper, PubkeyHexParser,
    },
    other::{get_address, get_genesis_info},
    printer::{OutputFormat, Printable},
};

pub struct UtilSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    genesis_info: Option<GenesisInfo>,
}

impl<'a> UtilSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        genesis_info: Option<GenesisInfo>,
    ) -> UtilSubCommand<'a> {
        UtilSubCommand {
            rpc_client,
            genesis_info,
        }
    }

    pub fn subcommand(name: &'static str) -> App<'static, 'static> {
        let arg_privkey = Arg::with_name("privkey-path")
            .long("privkey-path")
            .takes_value(true)
            .validator(|input| PrivkeyPathParser.validate(input))
            .help("Private key file path (only read first line)");
        let arg_pubkey = Arg::with_name("pubkey")
            .long("pubkey")
            .takes_value(true)
            .validator(|input| PubkeyHexParser.validate(input))
            .help("Public key (hex string, compressed format)");
        let arg_address = Arg::with_name("address")
            .long("address")
            .takes_value(true)
            .validator(|input| AddressParser::default().validate(input))
            .required(true)
            .help("Target address (see: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0021-ckb-address-format/0021-ckb-address-format.md)");
        let arg_lock_arg = Arg::with_name("lock-arg")
            .long("lock-arg")
            .takes_value(true)
            .validator(|input| FixedHashParser::<H160>::default().validate(input))
            .help("Lock argument (account identifier, blake2b(pubkey)[0..20])");

        let json_path_arg = Arg::with_name("json-path")
            .long("json-path")
            .takes_value(true)
            .required(true)
            .validator(|input| FilePathParser::new(true).validate(input));
        let binary_hex_arg = Arg::with_name("binary-hex")
            .long("binary-hex")
            .takes_value(true)
            .required(true)
            .validator(|input| HexParser.validate(input));
        let serialize_output_type_arg = Arg::with_name("output-type")
            .long("output-type")
            .takes_value(true)
            .default_value("binary")
            .possible_values(&["binary", "hash"])
            .help("Serialize output type");
        SubCommand::with_name(name)
            .about("Utilities")
            .subcommands(vec![
                SubCommand::with_name("key-info")
                    .about(
                        "Show public information of a secp256k1 private key (from file) or public key",
                    )
                    .arg(arg_privkey.clone().conflicts_with("pubkey"))
                    .arg(arg_pubkey.clone().required(false))
                    .arg(arg_address.clone().required(false))
                    .arg(arg_lock_arg.clone()),
                SubCommand::with_name("serialize-tx")
                    .about("Serialize a transaction from json file to hex binary or hash")
                    .arg(json_path_arg.clone()
                         .help("Transaction content (json format, without witnesses/hash, see rpc get_transaction)"))
                    .arg(serialize_output_type_arg.clone()),
                SubCommand::with_name("deserialize-tx")
                    .about("Deserialize a transaction from binary hex to json")
                    .arg(binary_hex_arg.clone().help("Transaction binary hex")),
                SubCommand::with_name("serialize-script")
                    .about("Serialize a script from json file to hex binary or hash")
                    .arg(json_path_arg.clone()
                         .help("Script content (json format, see rpc get_transaction)"))
                    .arg(serialize_output_type_arg.clone()),
                SubCommand::with_name("deserialize-script")
                    .about("Deserialize a script from hex binary to json")
                    .arg(binary_hex_arg.clone().help("Script binary hex")),
                SubCommand::with_name("compact-to-difficulty")
                    .about("Convert compact target value to difficulty value")
                    .arg(Arg::with_name("compact-target")
                         .long("compact-target")
                         .takes_value(true)
                         .validator(|input| {
                             FromStrParser::<u32>::default()
                                 .validate(input.clone())
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
                         .help("The compact target value")
                    ),
                SubCommand::with_name("difficulty-to-compact")
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
                         .help("The difficulty value")
                    ),
                SubCommand::with_name("to-multisig-addr")
                    .about("Convert address in single signature format to multisig format")
                    .arg(
                        Arg::with_name("address")
                            .long("address")
                            .required(true)
                            .takes_value(true)
                            .hidden(true)
                            .validator(|input| {
                                AddressParser::default()
                                    .set_network(NetworkType::Mainnet)
                                    .set_short(CodeHashIndex::Sighash)
                                    .validate(input)
                            })
                            .help("The address in single signature format")
                    )
                    .arg(
                        Arg::with_name("locktime")
                            .long("locktime")
                            .required(true)
                            .takes_value(true)
                            .hidden(true)
                            .help("The locktime in UTC format")
                    )
            ])
    }
}

impl<'a> CliSubCommand for UtilSubCommand<'a> {
    fn process(
        &mut self,
        matches: &ArgMatches,
        format: OutputFormat,
        color: bool,
        debug: bool,
    ) -> Result<String, String> {
        match matches.subcommand() {
            ("key-info", Some(m)) => {
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

                println!(
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
                    "address": {
                        "mainnet": Address::new(NetworkType::Mainnet, address_payload.clone()).to_string(),
                        "testnet": Address::new(NetworkType::Testnet, address_payload.clone()).to_string(),
                    },
                    // NOTE: remove this later (after all testnet race reward received)
                    "old-testnet-address": old_address.display_with_prefix(NetworkType::Testnet),
                    "lock_arg": format!("{:#x}", lock_arg),
                    "lock_hash": format!("{:#x}", lock_hash),
                });
                Ok(resp.render(format, color))
            }
            ("serialize-tx", Some(m)) => {
                let json_path: PathBuf = FilePathParser::new(true).from_matches(m, "json-path")?;
                let content = fs::read_to_string(json_path).map_err(|err| err.to_string())?;
                let rpc_tx: RpcTransaction =
                    serde_json::from_str(&content).map_err(|err| err.to_string())?;
                let tx: packed::Transaction = rpc_tx.into();
                let output = match m.value_of("output-type") {
                    Some("binary") => hex_string(tx.raw().as_slice()).unwrap(),
                    Some("hash") => format!("{:#x}", tx.calc_tx_hash()),
                    _ => panic!("Invalid output type"),
                };
                Ok(output)
            }
            ("deserialize-tx", Some(m)) => {
                let binary: Vec<u8> = HexParser.from_matches(m, "binary-hex")?;
                let raw_tx =
                    packed::RawTransaction::from_slice(&binary).map_err(|err| err.to_string())?;
                let rpc_tx: RpcTransaction = packed::Transaction::new_builder()
                    .raw(raw_tx)
                    .build()
                    .into();
                Ok(rpc_tx.render(format, color))
            }
            ("serialize-script", Some(m)) => {
                let json_path: PathBuf = FilePathParser::new(true).from_matches(m, "json-path")?;
                let content = fs::read_to_string(json_path).map_err(|err| err.to_string())?;
                let rpc_script: RpcScript =
                    serde_json::from_str(&content).map_err(|err| err.to_string())?;
                let script: packed::Script = rpc_script.into();
                let output = match m.value_of("output-type") {
                    Some("binary") => hex_string(script.as_slice()).unwrap(),
                    Some("hash") => format!("{:#x}", script.calc_script_hash()),
                    _ => panic!("Invalid output type"),
                };
                Ok(output)
            }
            ("deserialize-script", Some(m)) => {
                let binary: Vec<u8> = HexParser.from_matches(m, "binary-hex")?;
                let rpc_script: RpcScript = packed::Script::from_slice(&binary)
                    .map_err(|err| err.to_string())?
                    .into();
                Ok(rpc_script.render(format, color))
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
                Ok(resp.render(format, color))
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
                Ok(resp.render(format, color))
            }
            ("to-multisig-addr", Some(m)) => {
                const FLAG_SINCE_EPOCH_NUMBER: u64 =
                    0b010_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000;
                const EPOCH_LENGTH: u64 = 1800;
                const EPOCH_PERIOD: u64 = EPOCH_LENGTH * 8 * 1000; // 4h in millis

                let chain_info: ChainInfo = self
                    .rpc_client
                    .get_blockchain_info()
                    .call()
                    .map_err(|err| format!("RPC get_blockchain_info error: {:?}", err))?;
                if &chain_info.chain != "ckb" {
                    return Err("Node is not in mainnet spec".to_owned());
                }

                let locktime = m.value_of("locktime").unwrap();
                let address = {
                    let input = m.value_of("address").unwrap();
                    AddressParser::new(
                        Some(NetworkType::Mainnet),
                        Some(AddressPayloadOption::Short(Some(CodeHashIndex::Sighash))),
                    )
                    .parse(input)?
                };

                let genesis_timestamp = get_genesis_info(&self.genesis_info, self.rpc_client)?
                    .header()
                    .timestamp();
                let target_timestamp = to_timestamp(locktime)?;
                let elapsed = target_timestamp.saturating_sub(genesis_timestamp);
                let epoch_fraction = {
                    let epoch_number = elapsed / EPOCH_PERIOD;
                    let epoch_index =
                        (elapsed - epoch_number * EPOCH_PERIOD) * EPOCH_LENGTH / EPOCH_PERIOD;
                    EpochNumberWithFraction::new(epoch_number, epoch_index, EPOCH_LENGTH)
                };
                let since = FLAG_SINCE_EPOCH_NUMBER | epoch_fraction.full_value();

                let args = {
                    let mut multi_script = vec![0u8, 0, 1, 1]; // [S, R, M, N]
                    multi_script.extend_from_slice(address.payload().args().as_ref());
                    let mut data = Bytes::from(&blake2b_256(multi_script)[..20]);
                    data.extend(since.to_le_bytes().iter());
                    data
                };
                let addr_payload =
                    AddressPayload::new_full(ScriptHashType::Type, MULTISIG_TYPE_HASH.pack(), args);
                let multisig_addr = Address::new(NetworkType::Mainnet, addr_payload);
                let resp = format!("{},{},{}", address, locktime, multisig_addr);
                if debug {
                    println!(
                        "[DEBUG] genesis_time: {}, target_time: {}, elapsed_in_secs: {}, target_epoch: {}, lock_arg: {}, code_hash: {:#x}",
                        NaiveDateTime::from_timestamp(genesis_timestamp as i64 / 1000, 0),
                        NaiveDateTime::from_timestamp(target_timestamp as i64 / 1000, 0),
                        elapsed / 1000,
                        epoch_fraction,
                        hex_string(multisig_addr.payload().args().as_ref()).unwrap(),
                        MULTISIG_TYPE_HASH,
                    );
                }
                Ok(serde_json::json!(resp).render(format, color))
            }
            _ => Err(matches.usage().to_owned()),
        }
    }
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
