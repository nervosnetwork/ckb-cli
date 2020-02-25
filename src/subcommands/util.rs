use chrono::prelude::*;
use ckb_crypto::secp::SECP256K1;
use ckb_hash::blake2b_256;
use ckb_sdk::{
    constants::{MULTISIG_TYPE_HASH, SIGHASH_TYPE_HASH},
    rpc::ChainInfo,
    wallet::KeyStore,
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
use eaglesong::EagleSongBuilder;
use faster_hex::hex_string;
use secp256k1::recovery::{RecoverableSignature, RecoveryId};

use super::CliSubCommand;
use crate::utils::{
    arg,
    arg_parser::{
        AddressParser, AddressPayloadOption, ArgParser, FixedHashParser, FromStrParser, HexParser,
        PrivkeyPathParser, PrivkeyWrapper, PubkeyHexParser,
    },
    other::{get_address, read_password, serialize_signature},
    printer::{OutputFormat, Printable},
};

const FLAG_SINCE_EPOCH_NUMBER: u64 =
    0b010_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000;
const EPOCH_LENGTH: u64 = 1800;
const BLOCK_PERIOD: u64 = 8 * 1000; // 8 seconds

pub struct UtilSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    key_store: &'a mut KeyStore,
}

impl<'a> UtilSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        key_store: &'a mut KeyStore,
    ) -> UtilSubCommand<'a> {
        UtilSubCommand {
            rpc_client,
            key_store,
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

        let binary_hex_arg = Arg::with_name("binary-hex")
            .long("binary-hex")
            .takes_value(true)
            .required(true)
            .validator(|input| HexParser.validate(input));
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

        let arg_recoverable = Arg::with_name("recoverable")
            .long("recoverable")
            .help("Sign use recoverable signature");

        let arg_message = Arg::with_name("message")
            .long("message")
            .takes_value(true)
            .required(true)
            .validator(|input| FixedHashParser::<H256>::default().validate(input));

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
                    .arg(arg::lock_arg().clone()),
                SubCommand::with_name("sign-data")
                    .about("Sign data with secp256k1 signature ")
                    .arg(arg::privkey_path().required_unless(arg::from_account().b.name))
                    .arg(
                        arg::from_account()
                            .required_unless(arg::privkey_path().b.name)
                            .conflicts_with(arg::privkey_path().b.name),
                    )
                    .arg(arg_recoverable.clone())
                    .arg(
                        binary_hex_arg
                            .clone()
                            .help("The data to be signed (blake2b hashed with 'ckb-default-hash' personalization)")
                    ),
                SubCommand::with_name("sign-message")
                    .about("Sign message with secp256k1 signature")
                    .arg(arg::privkey_path().required_unless(arg::from_account().b.name))
                    .arg(
                        arg::from_account()
                            .required_unless(arg::privkey_path().b.name)
                            .conflicts_with(arg::privkey_path().b.name),
                    )
                    .arg(arg_recoverable.clone())
                    .arg(arg_message.clone().help("The message to be signed (32 bytes)")),
                SubCommand::with_name("verify-signature")
                    .about("Verify a compact format signature")
                    .arg(arg::pubkey())
                    .arg(arg::privkey_path().conflicts_with(arg::pubkey().b.name))
                    .arg(
                        arg::from_account()
                            .conflicts_with_all(&[arg::privkey_path().b.name, arg::pubkey().b.name]),
                    )
                    .arg(arg_message.clone().help("The message to be verify (32 bytes)"))
                    .arg(
                        Arg::with_name("signature")
                            .long("signature")
                            .takes_value(true)
                            .required(true)
                            .validator(|input| HexParser.validate(input))
                            .help("The compact format signature (support recoverable signature)")
                    ),
                SubCommand::with_name("eaglesong")
                    .about("Hash binary use eaglesong algorithm")
                    .arg(binary_hex_arg.clone()),
                SubCommand::with_name("blake2b")
                    .about("Hash binary use blake2b algorithm (personalization: 'ckb-default-hash')")
                    .arg(binary_hex_arg.clone())
                    .arg(
                        Arg::with_name("prefix-160")
                            .long("prefix-160")
                            .help("Only show prefix 160 bits (Example: calculate lock_arg from pubkey)")
                    ),
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
            ("sign-data", Some(m)) => {
                let binary: Vec<u8> = HexParser.from_matches(m, "binary-hex")?;
                let recoverable = m.is_present("recoverable");
                let from_privkey_opt: Option<PrivkeyWrapper> =
                    PrivkeyPathParser.from_matches_opt(m, "privkey-path", false)?;
                let from_account_opt: Option<H160> = FixedHashParser::<H160>::default()
                    .from_matches_opt(m, "from-account", false)
                    .or_else(|err| {
                        let result: Result<Option<Address>, String> =
                            AddressParser::new_sighash().from_matches_opt(m, "from-account", false);
                        result
                            .map(|address_opt| {
                                address_opt.map(|address| {
                                    H160::from_slice(&address.payload().args()).unwrap()
                                })
                            })
                            .map_err(|_| err)
                    })?;

                let message = H256::from(blake2b_256(&binary));
                let key_store_opt = from_account_opt
                    .as_ref()
                    .map(|account| (&*self.key_store, account));
                let signature = sign_message(
                    from_privkey_opt.as_ref(),
                    key_store_opt,
                    recoverable,
                    &message,
                )?;
                let result = serde_json::json!({
                    "message": format!("{:#x}", message),
                    "signature": format!("0x{}", hex_string(&signature).unwrap()),
                    "recoverable": recoverable,
                });
                Ok(result.render(format, color))
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
                            AddressParser::new_sighash().from_matches_opt(m, "from-account", false);
                        result
                            .map(|address_opt| {
                                address_opt.map(|address| {
                                    H160::from_slice(&address.payload().args()).unwrap()
                                })
                            })
                            .map_err(|_| err)
                    })?;

                let key_store_opt = from_account_opt
                    .as_ref()
                    .map(|account| (&*self.key_store, account));
                let signature = sign_message(
                    from_privkey_opt.as_ref(),
                    key_store_opt,
                    recoverable,
                    &message,
                )?;
                let result = serde_json::json!({
                    "signature": format!("0x{}", hex_string(&signature).unwrap()),
                    "recoverable": recoverable,
                });
                Ok(result.render(format, color))
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
                            AddressParser::new_sighash().from_matches_opt(m, "from-account", false);
                        result
                            .map(|address_opt| {
                                address_opt.map(|address| {
                                    H160::from_slice(&address.payload().args()).unwrap()
                                })
                            })
                            .map_err(|_| err)
                    })?;

                let pubkey = if let Some(pubkey) = pubkey_opt {
                    pubkey
                } else if let Some(privkey) = from_privkey_opt {
                    secp256k1::PublicKey::from_secret_key(&SECP256K1, &privkey)
                } else if let Some(account) = from_account_opt {
                    let password = read_password(false, None)?;
                    self.key_store
                        .extended_pubkey_with_password(&account, &[], password.as_bytes())
                        .map_err(|err| err.to_string())?
                        .public_key
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
                Ok(result.render(format, color))
            }
            ("eaglesong", Some(m)) => {
                let binary: Vec<u8> = HexParser.from_matches(m, "binary-hex")?;
                let mut builder = EagleSongBuilder::new();
                builder.update(&binary);
                Ok(format!("{:#x}", H256::from(builder.finalize())))
            }
            ("blake2b", Some(m)) => {
                let binary: Vec<u8> = HexParser.from_matches(m, "binary-hex")?;
                let hash_data = blake2b_256(&binary);
                let slice = if m.is_present("prefix-160") {
                    &hash_data[0..20]
                } else {
                    &hash_data[..]
                };
                Ok(format!("0x{}", hex_string(slice).unwrap()))
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
                    .map(|header_view| {
                        let header = header_view.inner;
                        let epoch = EpochNumberWithFraction::from_full_value(header.epoch.0);
                        let timestamp = header.timestamp;
                        (epoch, timestamp)
                    })
                    .map_err(|err| err.to_string())?;
                let elapsed = locktime_timestamp.saturating_sub(tip_timestamp.0);
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

fn sign_message(
    from_privkey_opt: Option<&PrivkeyWrapper>,
    from_account_opt: Option<(&KeyStore, &H160)>,
    recoverable: bool,
    message: &H256,
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
        (None, Some((key_store, account)), false) => {
            let password = read_password(false, None)?;
            key_store
                .sign_with_password(account, &[], message, password.as_bytes())
                .map(|sig| sig.serialize_compact().to_vec())
                .map_err(|err| err.to_string())
        }
        (None, Some((key_store, account)), true) => {
            let password = read_password(false, None)?;
            key_store
                .sign_recoverable_with_password(account, &[], message, password.as_bytes())
                .map(|sig| serialize_signature(&sig).to_vec())
                .map_err(|err| err.to_string())
        }
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
