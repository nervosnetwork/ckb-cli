use chrono::prelude::*;
use ckb_crypto::secp::SECP256K1;
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::ChainInfo;
use ckb_sdk::{
    constants::{MULTISIG_TYPE_HASH, SIGHASH_TYPE_HASH},
    Address, AddressPayload, CodeHashIndex, HttpRpcClient, NetworkType, OldAddress,
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

use super::CliSubCommand;
use crate::utils::{
    arg_parser::{
        AddressParser, AddressPayloadOption, ArgParser, FixedHashParser, FromStrParser,
        PrivkeyPathParser, PrivkeyWrapper, PubkeyHexParser,
    },
    other::get_address,
    printer::{OutputFormat, Printable},
};

const FLAG_SINCE_EPOCH_NUMBER: u64 =
    0b010_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000;
const EPOCH_LENGTH: u64 = 1800;
const BLOCK_PERIOD: u64 = 8 * 1000; // 8 seconds

pub struct UtilSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
}

impl<'a> UtilSubCommand<'a> {
    pub fn new(rpc_client: &'a mut HttpRpcClient) -> UtilSubCommand<'a> {
        UtilSubCommand { rpc_client }
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

        let arg_sighash_address = Arg::with_name("sighash-address")
            .long("sighash-address")
            .required(true)
            .takes_value(true)
            .validator(|input| {
                AddressParser::default()
                    .set_short(CodeHashIndex::Sighash)
                    .validate(input)
            })
            .help("The address in single signature format");

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
            SubCommand::with_name("compact-to-difficulty")
                .about("Convert compact target value to difficulty value")
                .arg(
                    Arg::with_name("compact-target")
                        .long("compact-target")
                        .takes_value(true)
                        .validator(|input| {
                            FromStrParser::<u32>::default()
                                .validate(input.clone())
                                .or_else(|_| {
                                    let input =
                                        if input.starts_with("0x") || input.starts_with("0X") {
                                            &input[2..]
                                        } else {
                                            &input[..]
                                        };
                                    u32::from_str_radix(input, 16)
                                        .map(|_| ())
                                        .map_err(|err| err.to_string())
                                })
                        })
                        .required(true)
                        .help("The compact target value"),
                ),
            SubCommand::with_name("difficulty-to-compact")
                .about("Convert difficulty value to compact target value")
                .arg(
                    Arg::with_name("difficulty")
                        .long("difficulty")
                        .takes_value(true)
                        .validator(|input| {
                            let input = if input.starts_with("0x") || input.starts_with("0X") {
                                &input[2..]
                            } else {
                                &input[..]
                            };
                            U256::from_hex_str(input)
                                .map(|_| ())
                                .map_err(|err| err.to_string())
                        })
                        .required(true)
                        .help("The difficulty value"),
                ),
                SubCommand::with_name("to-genesis-multisig-addr")
                    .about("Convert address in single signature format to multisig format (only for mainnet genesis cells)")
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
                            .help("The locktime in UTC format date. Example: 2022-05-01")
                    ),
                SubCommand::with_name("to-multisig-addr")
                    .about("Convert address in single signature format to multisig format")
                    .arg(arg_sighash_address.clone())
                    .arg(
                        Arg::with_name("locktime")
                            .long("locktime")
                            .required(true)
                            .takes_value(true)
                            .validator(|input| DateTime::parse_from_rfc3339(&input).map(|_| ()).map_err(|err| err.to_string()))
                            .help("The locktime in RFC3339 format. Example: 2014-11-28T21:00:00+00:00")
                    ),
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
            ("to-genesis-multisig-addr", Some(m)) => {
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
            ("to-multisig-addr", Some(m)) => {
                let address: Address = AddressParser::default()
                    .set_short(CodeHashIndex::Sighash)
                    .from_matches(m, "sighash-address")?;
                let locktime_timestamp =
                    DateTime::parse_from_rfc3339(m.value_of("locktime").unwrap())
                        .map(|dt| dt.timestamp_millis() as u64)
                        .map_err(|err| err.to_string())?;
                let (tip_epoch, tip_timestamp) = self
                    .rpc_client
                    .get_tip_header()
                    .call()
                    .map(|header_view| {
                        let header = header_view.inner;
                        let epoch = EpochNumberWithFraction::from_full_value(header.epoch.value());
                        let timestamp = header.timestamp.value();
                        (epoch, timestamp)
                    })
                    .map_err(|err| err.to_string())?;
                let elapsed = locktime_timestamp.saturating_sub(tip_timestamp);
                let (epoch, multisig_addr) =
                    gen_multisig_addr(address.payload(), Some(tip_epoch), elapsed);
                let resp = serde_json::json!({
                    "address": {
                        "mainnet": Address::new(NetworkType::Mainnet, multisig_addr.clone()).to_string(),
                        "testnet": Address::new(NetworkType::Testnet, multisig_addr.clone()).to_string(),
                    },
                    "target_epoch": epoch.to_string(),
                });
                Ok(resp.render(format, color))
            }
            _ => Err(matches.usage().to_owned()),
        }
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
        let mut data = Bytes::from(&blake2b_256(multi_script)[..20]);
        data.extend(since.to_le_bytes().iter());
        data
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
        let payload = AddressPayload::new_short(CodeHashIndex::Sighash, H160::default());

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
