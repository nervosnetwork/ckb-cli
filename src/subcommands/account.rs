use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use ckb_sdk::{
    wallet::{DerivationPath, Key, KeyStore, MasterPrivKey},
    Address, AddressPayload, NetworkType,
};
use ckb_types::{packed::Script, prelude::*, H160, H256};
use clap::{App, Arg, ArgMatches};
use faster_hex::hex_string;

use super::{CliSubCommand, Output};
use crate::plugin::PluginManager;
use crate::utils::{
    arg::lock_arg,
    arg_parser::{
        ArgParser, ExtendedPrivkeyPathParser, FilePathParser, FixedHashParser, FromStrParser,
        HexParser, PrivkeyPathParser, PrivkeyWrapper,
    },
    other::read_password,
};

pub struct AccountSubCommand<'a> {
    plugin_mgr: &'a mut PluginManager,
    key_store: &'a mut KeyStore,
}

impl<'a> AccountSubCommand<'a> {
    pub fn new(
        plugin_mgr: &'a mut PluginManager,
        key_store: &'a mut KeyStore,
    ) -> AccountSubCommand<'a> {
        AccountSubCommand {
            plugin_mgr,
            key_store,
        }
    }

    pub fn subcommand(name: &'static str) -> App<'static> {
        let arg_privkey_path = Arg::with_name("privkey-path")
            .long("privkey-path")
            .takes_value(true);
        let arg_extended_privkey_path = Arg::with_name("extended-privkey-path")
            .long("extended-privkey-path")
            .takes_value(true)
            .about("Extended private key path (include master private key and chain code)");
        App::new(name)
            .about("Manage accounts")
            .subcommands(vec![
                App::new("list")
                    .arg(
                        Arg::with_name("only-mainnet-address")
                            .long("only-mainnet-address")
                            .about("Only show CKB mainnet address")
                    )
                    .arg(
                        Arg::with_name("only-testnet-address")
                            .long("only-testnet-address")
                            .about("Only show CKB testnet address")
                    )
                    .about("List all accounts"),
                App::new("new").about("Create a new account and print related information."),
                App::new("import")
                    .about("Import an unencrypted private key from <privkey-path> and create a new account.")
                    .arg(
                        arg_privkey_path
                            .clone()
                            .required_unless("extended-privkey-path")
                            .validator(|input| PrivkeyPathParser.validate(input))
                            .about("The privkey is assumed to contain an unencrypted private key in hexadecimal format. (only read first line)")
                    )
                    .arg(arg_extended_privkey_path
                         .clone()
                         .required_unless("privkey-path")
                         .validator(|input| ExtendedPrivkeyPathParser.validate(input))
                    ),
                App::new("import-from-plugin")
                    .about("Import an account from keystore plugin")
                    .arg(
                        Arg::with_name("account-id")
                            .long("account-id")
                            .takes_value(true)
                            .required(true)
                            .validator(|input| {
                                let hex = HexParser.parse(input)?;
                                if hex.is_empty() {
                                    Err("empty account id is not allowed".to_string())
                                } else {
                                    Ok(())
                                }
                            })
                            .about("The account id (hex format, can be found in account list)")
                    ),
                App::new("import-keystore")
                    .about("Import key from encrypted keystore json file and create a new account.")
                    .arg(
                        Arg::with_name("path")
                            .long("path")
                            .takes_value(true)
                            .required(true)
                            .validator(|input| FilePathParser::new(true).validate(input))
                            .about("The keystore file path (json format)")
                    ),
                App::new("update")
                    .about("Update password of an account")
                    .arg(lock_arg().required(true)),
                App::new("upgrade")
                    .about("Upgrade an account to latest json format")
                    .arg(lock_arg().required(true)),
                App::new("export")
                    .about("Export master private key and chain code as hex plain text (USE WITH YOUR OWN RISK)")
                    .arg(lock_arg().required(true))
                    .arg(
                        arg_extended_privkey_path
                            .clone()
                            .required(true)
                            .about("Output extended private key path (PrivKey + ChainCode)")
                    ),
                App::new("bip44-addresses")
                    .about("Extended receiving/change Addresses (see: BIP-44)")
                    .arg(
                        Arg::with_name("from-receiving-index")
                            .long("from-receiving-index")
                            .takes_value(true)
                            .default_value("0")
                            .validator(|input| FromStrParser::<u32>::default().validate(input))
                            .about("Start from receiving path index")
                    )
                    .arg(
                        Arg::with_name("receiving-length")
                            .long("receiving-length")
                            .takes_value(true)
                            .default_value("20")
                            .validator(|input| FromStrParser::<u32>::default().validate(input))
                            .about("Receiving addresses length")
                    )
                    .arg(
                        Arg::with_name("from-change-index")
                            .long("from-change-index")
                            .takes_value(true)
                            .default_value("0")
                            .validator(|input| FromStrParser::<u32>::default().validate(input))
                            .about("Start from change path index")
                    )
                    .arg(
                        Arg::with_name("change-length")
                            .long("change-length")
                            .takes_value(true)
                            .default_value("10")
                            .validator(|input| FromStrParser::<u32>::default().validate(input))
                            .about("Change addresses length")
                    )
                    .arg(
                        Arg::with_name("network")
                            .long("network")
                            .takes_value(true)
                            .default_value("mainnet")
                            .possible_values(&["mainnet", "testnet"])
                            .about("The network type")
                    )
                    .arg(lock_arg().required(true)),
                App::new("extended-address")
                    .about("Extended address (see: BIP-44)")
                    .arg(lock_arg().required(true))
                    .arg(
                        Arg::with_name("path")
                            .long("path")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<DerivationPath>::new().validate(input))
                            .about("The address path")
                    ),
            ])
    }
}

impl<'a> CliSubCommand for AccountSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches, _debug: bool) -> Result<Output, String> {
        match matches.subcommand() {
            ("list", Some(m)) => {
                let mut accounts = self.plugin_mgr.keystore_handler().list_account()?;
                // Sort by file path name
                accounts.sort_by(|a, b| a.1.cmp(&b.1));
                let only_mainnet_address = m.is_present("only-mainnet-address");
                let only_testnet_address = m.is_present("only-testnet-address");
                let partial_fields = only_mainnet_address || only_testnet_address;
                let resp = accounts
                    .into_iter()
                    .enumerate()
                    .map(|(idx, (data, source))| {
                        if data.len() == 20 {
                            let lock_arg = H160::from_slice(data.as_ref()).expect("H160");
                            let address_payload = AddressPayload::from_pubkey_hash(lock_arg.clone());
                            let lock_hash: H256 = Script::from(&address_payload)
                                .calc_script_hash()
                                .unpack();
                            if partial_fields {
                                let key = format!("{:#x}", lock_arg);
                                if only_mainnet_address {
                                    serde_json::json!({
                                        key: Address::new(NetworkType::Mainnet, address_payload).to_string()
                                    })
                                } else if only_testnet_address {
                                    serde_json::json!({
                                        key: Address::new(NetworkType::Testnet, address_payload).to_string()
                                    })
                                } else {
                                    unreachable!();
                                }
                            } else {
                                let has_ckb_root = self.key_store.get_ckb_root(&lock_arg, false).is_some();
                                serde_json::json!({
                                    "#": idx,
                                    "source": source,
                                    "lock_arg": format!("{:#x}", lock_arg),
                                    "lock_hash": format!("{:#x}", lock_hash),
                                    "has_ckb_root": has_ckb_root,
                                    "address": {
                                        "mainnet": Address::new(NetworkType::Mainnet, address_payload.clone()).to_string(),
                                        "testnet": Address::new(NetworkType::Testnet, address_payload).to_string(),
                                    },
                                })
                            }
                        } else {
                            serde_json::json!({
                                "#": idx,
                                "source": source,
                                "account-id": format!("0x{}", hex_string(data.as_ref()).expect("hex")),
                            })
                        }
                    })
                    .collect::<Vec<_>>();
                Ok(Output::new_output(resp))
            }
            ("new", _) => {
                eprintln!("Your new account is locked with a password. Please give a password. Do not forget this password.");
                let password = read_password(true, None)?;
                let lock_arg = self
                    .plugin_mgr
                    .keystore_handler()
                    .create_account(password)?;
                let address_payload = AddressPayload::from_pubkey_hash(lock_arg.clone());
                let lock_hash: H256 = Script::from(&address_payload).calc_script_hash().unpack();
                let resp = serde_json::json!({
                    "lock_arg": format!("{:#x}", lock_arg),
                    "lock_hash": format!("{:#x}", lock_hash),
                    "address": {
                        "mainnet": Address::new(NetworkType::Mainnet, address_payload.clone()).to_string(),
                        "testnet": Address::new(NetworkType::Testnet, address_payload).to_string(),
                    },
                });
                Ok(Output::new_output(resp))
            }
            ("import", Some(m)) => {
                let secp_key: Option<PrivkeyWrapper> =
                    PrivkeyPathParser.from_matches_opt(m, "privkey-path", false)?;
                let password = Some(read_password(false, None)?);
                let master_privkey = if let Some(secp_key) = secp_key {
                    // Default chain code is [255u8; 32]
                    let mut data = [255u8; 64];
                    data[0..32].copy_from_slice(&secp_key[..]);
                    MasterPrivKey::from_bytes(data).map_err(|err| err.to_string())?
                } else {
                    let master_privkey: MasterPrivKey =
                        ExtendedPrivkeyPathParser.from_matches(m, "extended-privkey-path")?;
                    master_privkey
                };

                let lock_arg = self
                    .plugin_mgr
                    .keystore_handler()
                    .import_key(master_privkey, password)?;
                let address_payload = AddressPayload::from_pubkey_hash(lock_arg.clone());
                let resp = serde_json::json!({
                    "lock_arg": format!("{:#x}", lock_arg),
                    "address": {
                        "mainnet": Address::new(NetworkType::Mainnet, address_payload.clone()).to_string(),
                        "testnet": Address::new(NetworkType::Testnet, address_payload).to_string(),
                    },
                });
                Ok(Output::new_output(resp))
            }
            ("import-from-plugin", Some(m)) => {
                let account_id: Vec<u8> = HexParser.from_matches(m, "account-id")?;
                let password = if self.plugin_mgr.keystore_require_password() {
                    Some(read_password(false, None)?)
                } else {
                    None
                };
                let lock_arg = self
                    .plugin_mgr
                    .keystore_handler()
                    .import_account(account_id.into(), password)?;
                let address_payload = AddressPayload::from_pubkey_hash(lock_arg.clone());
                let resp = serde_json::json!({
                    "lock_arg": format!("{:#x}", lock_arg),
                    "address": {
                        "mainnet": Address::new(NetworkType::Mainnet, address_payload.clone()).to_string(),
                        "testnet": Address::new(NetworkType::Testnet, address_payload).to_string(),
                    },
                });
                Ok(Output::new_output(resp))
            }
            ("import-keystore", Some(m)) => {
                let path: PathBuf = FilePathParser::new(true).from_matches(m, "path")?;

                let old_password = read_password(false, Some("Decrypt password"))?;
                let new_password = Some(read_password(false, None)?);
                let content = fs::read_to_string(path).map_err(|err| err.to_string())?;
                let data: serde_json::Value =
                    serde_json::from_str(&content).map_err(|err| err.to_string())?;
                let master_privkey = Key::from_json(&data, old_password.as_bytes())
                    .map(|key| key.master_privkey().clone())
                    .map_err(|err| err.to_string())?;

                let lock_arg = self
                    .plugin_mgr
                    .keystore_handler()
                    .import_key(master_privkey, new_password)?;
                let address_payload = AddressPayload::from_pubkey_hash(lock_arg.clone());
                let resp = serde_json::json!({
                    "lock_arg": format!("{:x}", lock_arg),
                    "address": {
                        "mainnet": Address::new(NetworkType::Mainnet, address_payload.clone()).to_string(),
                        "testnet": Address::new(NetworkType::Testnet, address_payload).to_string(),
                    },
                });
                Ok(Output::new_output(resp))
            }
            ("update", Some(m)) => {
                let lock_arg: H160 =
                    FixedHashParser::<H160>::default().from_matches(m, "lock-arg")?;
                let old_password = read_password(false, Some("Old password"))?;
                let new_passsword = read_password(true, Some("New password"))?;
                self.plugin_mgr.keystore_handler().update_password(
                    lock_arg,
                    old_password,
                    new_passsword,
                )?;
                Ok(Output::new_success())
            }
            ("upgrade", Some(m)) => {
                let lock_arg: H160 =
                    FixedHashParser::<H160>::default().from_matches(m, "lock-arg")?;
                let password = read_password(false, None)?;
                self.key_store
                    .upgrade(&lock_arg, password.as_bytes())
                    .map_err(|err| err.to_string())?;
                Ok(Output::new_success())
            }
            ("export", Some(m)) => {
                let lock_arg: H160 =
                    FixedHashParser::<H160>::default().from_matches(m, "lock-arg")?;
                let key_path = m.value_of("extended-privkey-path").unwrap();
                let password = Some(read_password(false, None)?);

                if Path::new(key_path).exists() {
                    return Err(format!("File exists: {}", key_path));
                }
                let master_privkey = self
                    .plugin_mgr
                    .keystore_handler()
                    .export_key(lock_arg, password)?;
                let bytes = master_privkey.to_bytes();
                let privkey = H256::from_slice(&bytes[0..32]).unwrap();
                let chain_code = H256::from_slice(&bytes[32..64]).unwrap();
                let mut file = fs::File::create(key_path).map_err(|err| err.to_string())?;
                file.write(format!("{:x}\n", privkey).as_bytes())
                    .map_err(|err| err.to_string())?;
                file.write(format!("{:x}", chain_code).as_bytes())
                    .map_err(|err| err.to_string())?;
                let resp = serde_json::json!({
                    "message": format!(
                        "Success exported account as extended privkey to: \"{}\", please use this file carefully",
                        key_path
                    )
                });
                Ok(Output::new_error(resp))
            }
            ("bip44-addresses", Some(m)) => {
                let lock_arg: H160 =
                    FixedHashParser::<H160>::default().from_matches(m, "lock-arg")?;
                let from_receiving_index: u32 =
                    FromStrParser::<u32>::default().from_matches(m, "from-receiving-index")?;
                let receiving_length: u32 =
                    FromStrParser::<u32>::default().from_matches(m, "receiving-length")?;
                let from_change_index: u32 =
                    FromStrParser::<u32>::default().from_matches(m, "from-change-index")?;
                let change_length: u32 =
                    FromStrParser::<u32>::default().from_matches(m, "change-length")?;
                let network = match m.value_of("network").expect("network argument") {
                    "mainnet" => NetworkType::Mainnet,
                    "testnet" => NetworkType::Testnet,
                    _ => unreachable!(),
                };

                let key_set = self
                    .plugin_mgr
                    .keystore_handler()
                    .derived_key_set_by_index(
                        lock_arg,
                        from_receiving_index,
                        receiving_length,
                        from_change_index,
                        change_length,
                        None,
                    )?;
                let get_addresses = |set: &[(DerivationPath, H160)]| {
                    set.iter()
                        .map(|(path, hash160)| {
                            let payload = AddressPayload::from_pubkey_hash(hash160.clone());
                            serde_json::json!({
                                "path": path.to_string(),
                                "address": Address::new(network, payload).to_string(),
                            })
                        })
                        .collect::<Vec<_>>()
                };
                let resp = serde_json::json!({
                    "receiving": get_addresses(&key_set.external),
                    "change": get_addresses(&key_set.change),
                });
                Ok(Output::new_output(resp))
            }
            ("extended-address", Some(m)) => {
                let lock_arg: H160 =
                    FixedHashParser::<H160>::default().from_matches(m, "lock-arg")?;
                let root_key_path = self.plugin_mgr.root_key_path(lock_arg.clone())?;
                let path: DerivationPath = FromStrParser::<DerivationPath>::new()
                    .from_matches_opt(m, "path", false)?
                    .unwrap_or(root_key_path);

                let password = if self.plugin_mgr.keystore_require_password() {
                    Some(read_password(false, None)?)
                } else {
                    None
                };
                let extended_pubkey = self
                    .plugin_mgr
                    .keystore_handler()
                    .extended_pubkey(lock_arg, &path, password)?;
                let address_payload = AddressPayload::from_pubkey(&extended_pubkey);
                let resp = serde_json::json!({
                    "lock_arg": format!("{:#x}", H160::from_slice(address_payload.args().as_ref()).unwrap()),
                    "address": {
                        "mainnet": Address::new(NetworkType::Mainnet, address_payload.clone()).to_string(),
                        "testnet": Address::new(NetworkType::Testnet, address_payload).to_string(),
                    },
                });
                Ok(Output::new_output(resp))
            }
            _ => Err(Self::subcommand("account").generate_usage()),
        }
    }
}
