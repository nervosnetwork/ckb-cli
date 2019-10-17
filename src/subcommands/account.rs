use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ckb_jsonrpc_types::BlockNumber;
use ckb_sdk::{
    wallet::{DerivationPath, Key, KeyStore, MasterPrivKey},
    Address, GenesisInfo, HttpRpcClient, NetworkType,
};
use ckb_types::{core::BlockView, prelude::*, H160, H256};
use clap::{App, Arg, ArgMatches, SubCommand};

use super::CliSubCommand;
use crate::utils::{
    arg_parser::{
        ArgParser, DurationParser, ExtendedPrivkeyPathParser, FixedHashParser, FromStrParser,
        PrivkeyPathParser, PrivkeyWrapper,
    },
    other::read_password,
    printer::{OutputFormat, Printable},
};

pub struct AccountSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    key_store: &'a mut KeyStore,
    genesis_info: Option<GenesisInfo>,
}

impl<'a> AccountSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        key_store: &'a mut KeyStore,
        genesis_info: Option<GenesisInfo>,
    ) -> AccountSubCommand<'a> {
        AccountSubCommand {
            rpc_client,
            key_store,
            genesis_info,
        }
    }

    fn genesis_info(&mut self) -> Result<GenesisInfo, String> {
        if self.genesis_info.is_none() {
            let genesis_block: BlockView = self
                .rpc_client
                .get_block_by_number(BlockNumber::from(0))
                .call()
                .map_err(|err| err.to_string())?
                .0
                .expect("Can not get genesis block?")
                .into();
            self.genesis_info = Some(GenesisInfo::from_block(&genesis_block)?);
        }
        Ok(self.genesis_info.clone().unwrap())
    }

    pub fn subcommand(name: &'static str) -> App<'static, 'static> {
        let arg_lock_arg = Arg::with_name("lock-arg")
            .long("lock-arg")
            .takes_value(true)
            .validator(|input| FixedHashParser::<H160>::default().validate(input))
            .required(true)
            .help("The lock_arg (identifier) of the account");
        let arg_privkey_path = Arg::with_name("privkey-path")
            .long("privkey-path")
            .takes_value(true);
        let arg_extended_privkey_path = Arg::with_name("extended-privkey-path")
            .long("extended-privkey-path")
            .takes_value(true)
            .help("Extended private key path (include master private key and chain code)");
        SubCommand::with_name(name)
            .about("Manage accounts")
            .subcommands(vec![
                SubCommand::with_name("list").about("List all accounts"),
                SubCommand::with_name("new").about("Create a new account and print related information."),
                SubCommand::with_name("import")
                    .about("Import an unencrypted private key from <privkey-path> and create a new account.")
                    .arg(
                        arg_privkey_path
                            .clone()
                            .required_unless("extended-privkey-path")
                            .validator(|input| PrivkeyPathParser.validate(input))
                            .help("The privkey is assumed to contain an unencrypted private key in hexadecimal format. (only read first line)")
                    )
                    .arg(arg_extended_privkey_path
                         .clone()
                         .required_unless("privkey-path")
                         .validator(|input| ExtendedPrivkeyPathParser.validate(input))
                    ),
                SubCommand::with_name("unlock")
                    .about("Unlock an account")
                    .arg(arg_lock_arg.clone())
                    .arg(
                        Arg::with_name("keep")
                            .long("keep")
                            .takes_value(true)
                            .validator(|input| DurationParser.validate(input))
                            .required(true)
                            .help("How long before the key expired, format: 30s, 15m, 1h (repeat unlock will increase the time)")
                    ),
                SubCommand::with_name("update")
                    .about("Update password of an account")
                    .arg(arg_lock_arg.clone()),
                SubCommand::with_name("export")
                    .about("Export master private key and chain code as hex plain text (USE WITH YOUR OWN RISK)")
                    .arg(arg_lock_arg.clone())
                    .arg(
                        arg_extended_privkey_path
                            .clone()
                            .required(true)
                            .help("Output extended private key path (PrivKey + ChainCode)")
                    ),
                SubCommand::with_name("extended-address")
                    .about("Extended address (see: BIP-44)")
                    .arg(arg_lock_arg.clone())
                    .arg(
                        Arg::with_name("path")
                            .long("path")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<DerivationPath>::new().validate(input))
                            .help("The address path")
                    ),
            ])
    }
}

impl<'a> CliSubCommand for AccountSubCommand<'a> {
    fn process(
        &mut self,
        matches: &ArgMatches,
        format: OutputFormat,
        color: bool,
        _debug: bool,
    ) -> Result<String, String> {
        match matches.subcommand() {
            ("list", _) => {
                let mut accounts = self
                    .key_store
                    .get_accounts()
                    .iter()
                    .map(|(address, filepath)| (address.clone(), filepath.clone()))
                    .collect::<Vec<(H160, PathBuf)>>();
                accounts.sort_by(|a, b| a.1.cmp(&b.1));
                let genesis_info_opt = self.genesis_info().ok();
                let resp = accounts
                    .into_iter()
                    .enumerate()
                    .map(|(idx, (lock_arg, filepath))| {
                        let address = Address::from_lock_arg(lock_arg.as_bytes()).unwrap();
                        let timeout = self.key_store.get_lock_timeout(&lock_arg);
                        let status = timeout
                            .map(|timeout| timeout.to_string())
                            .unwrap_or_else(|| "locked".to_owned());
                        let lock_hash_opt: Option<H256> = genesis_info_opt.as_ref().map(|info| {
                            address
                                .lock_script(info.secp_type_hash().clone())
                                .calc_script_hash()
                                .unpack()
                        });
                        serde_json::json!({
                            "#": idx,
                            "lock_arg": format!("{:x}", lock_arg),
                            "lock_hash": lock_hash_opt,
                            "address": {
                                "mainnet": address.to_string(NetworkType::MainNet),
                                "testnet": address.to_string(NetworkType::TestNet),
                            },
                            "path": filepath.to_string_lossy(),
                            "status": status,
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(serde_json::json!(resp).render(format, color))
            }
            ("new", _) => {
                println!("Your new account is locked with a password. Please give a password. Do not forget this password.");

                let pass = read_password(true, None)?;
                let lock_arg = self
                    .key_store
                    .new_account(pass.as_bytes())
                    .map_err(|err| err.to_string())?;
                let genesis_info_opt = self.genesis_info().ok();
                let address = Address::from_lock_arg(lock_arg.as_bytes()).unwrap();
                let lock_hash_opt: Option<H256> = genesis_info_opt.as_ref().map(|info| {
                    address
                        .lock_script(info.secp_type_hash().clone())
                        .calc_script_hash()
                        .unpack()
                });
                let resp = serde_json::json!({
                    "lock_arg": format!("{:x}", lock_arg),
                    "lock_hash": lock_hash_opt,
                    "address": {
                        "mainnet": address.to_string(NetworkType::MainNet),
                        "testnet": address.to_string(NetworkType::TestNet),
                    },
                });
                Ok(resp.render(format, color))
            }
            ("import", Some(m)) => {
                let secp_key: Option<PrivkeyWrapper> =
                    PrivkeyPathParser.from_matches_opt(m, "privkey-path", false)?;
                let password = read_password(true, None)?;
                let lock_arg = if let Some(secp_key) = secp_key {
                    self.key_store
                        .import_secp_key(&secp_key, password.as_bytes())
                        .map_err(|err| err.to_string())?
                } else {
                    let master_privkey: MasterPrivKey =
                        ExtendedPrivkeyPathParser.from_matches(m, "extended-privkey-path")?;
                    let key = Key::new(master_privkey);
                    self.key_store
                        .import_key(&key, password.as_bytes())
                        .map_err(|err| err.to_string())?
                };
                let address = Address::from_lock_arg(lock_arg.as_bytes()).unwrap();
                let resp = serde_json::json!({
                    "lock_arg": format!("{:x}", lock_arg),
                    "address": {
                        "mainnet": address.to_string(NetworkType::MainNet),
                        "testnet": address.to_string(NetworkType::TestNet),
                    },
                });
                Ok(resp.render(format, color))
            }
            ("unlock", Some(m)) => {
                let lock_arg: H160 =
                    FixedHashParser::<H160>::default().from_matches(m, "lock-arg")?;
                let keep: Duration = DurationParser.from_matches(m, "keep")?;
                let password = read_password(false, None)?;
                let lock_after = self
                    .key_store
                    .timed_unlock(&lock_arg, password.as_bytes(), keep)
                    .map(|timeout| timeout.to_string())
                    .map_err(|err| err.to_string())?;
                let resp = serde_json::json!({
                    "status": lock_after,
                });
                Ok(resp.render(format, color))
            }
            ("update", Some(m)) => {
                let lock_arg: H160 =
                    FixedHashParser::<H160>::default().from_matches(m, "lock-arg")?;
                let old_password = read_password(false, Some("Old password"))?;
                let new_passsword = read_password(true, Some("New password"))?;
                self.key_store
                    .update(&lock_arg, old_password.as_bytes(), new_passsword.as_bytes())
                    .map_err(|err| err.to_string())?;
                Ok("success".to_owned())
            }
            ("export", Some(m)) => {
                let lock_arg: H160 =
                    FixedHashParser::<H160>::default().from_matches(m, "lock-arg")?;
                let key_path = m.value_of("extended-privkey-path").unwrap();
                let password = read_password(false, None)?;

                if Path::new(key_path).exists() {
                    return Err(format!("File exists: {}", key_path));
                }
                let master_privkey = self
                    .key_store
                    .export_key(&lock_arg, password.as_bytes())
                    .map_err(|err| err.to_string())?;
                let bytes = master_privkey.to_bytes();
                let privkey = H256::from_slice(&bytes[0..32]).unwrap();
                let chain_code = H256::from_slice(&bytes[32..64]).unwrap();
                let mut file = fs::File::create(key_path).map_err(|err| err.to_string())?;
                file.write(format!("{:x}\n", privkey).as_bytes())
                    .map_err(|err| err.to_string())?;
                file.write(format!("{:x}", chain_code).as_bytes())
                    .map_err(|err| err.to_string())?;
                Ok(format!(
                    "Success exported account as extended privkey to: \"{}\", please use this file carefully",
                    key_path
                ))
            }
            ("extended-address", Some(m)) => {
                let lock_arg: H160 =
                    FixedHashParser::<H160>::default().from_matches(m, "lock-arg")?;
                let path: Option<DerivationPath> =
                    FromStrParser::<DerivationPath>::new().from_matches_opt(m, "path", false)?;

                let extended_pubkey = self
                    .key_store
                    .extended_pubkey(&lock_arg, path.as_ref())
                    .map_err(|err| err.to_string())?;
                let address = Address::from_pubkey(&extended_pubkey.public_key)?;
                let resp = serde_json::json!({
                    "lock_arg": format!("{:x}", address.hash()),
                    "address": {
                        "mainnet": address.to_string(NetworkType::MainNet),
                        "testnet": address.to_string(NetworkType::TestNet),
                    },
                });
                Ok(resp.render(format, color))
            }
            _ => Err(matches.usage().to_owned()),
        }
    }
}
