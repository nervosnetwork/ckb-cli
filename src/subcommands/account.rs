use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use bitcoin::bip32::DerivationPath;

use ckb_sdk::{Address, AddressPayload, NetworkType};
use ckb_signer::{Key, KeyStore, MasterPrivKey};
use ckb_types::{packed::Script, prelude::*, H160, H256};
use clap::{ArgMatches, Args, Command, CommandFactory, FromArgMatches, Parser, Subcommand};
use faster_hex::hex_string;

use super::{CliSubCommand, Output};
use crate::plugin::PluginManager;
use crate::utils::{
    arg_parser::{
        ArgParser, ExtendedPrivkeyPathParser, FilePathParser, FixedHashParser, FromStrParser,
        HexParser, PrivkeyPathParser, PrivkeyWrapper,
    },
    other::{address_json, read_password},
};

pub struct AccountSubCommand<'a> {
    plugin_mgr: &'a mut PluginManager,
    key_store: &'a mut KeyStore,
}

const ACCOUNT_LIST_LONG_ABOUT: &str = "List all accounts. There are two kinds of account item indicated by `source` field:\n\n  When `source` is \"Local File System\" means the account is stored in json keystore file, the output fields are:\n    * lock_arg: The blake2b160 hash of the public key.\n    * lock_hash: The lock script hash of secp256k1_blake160_sighash_all lock (See [1]).\n    * has_ckb_pubkey_derivation_root_path: The CKB public key derivation root path (m/44'/309'/0') is stored so that password is not required to do public key derivation.\n    * address: The Mainnet/Testnet addresses of secp256k1_blake160_sighash_all lock (See [1]).\n\n  When `source` is \"[plugin]: xxx_keysotre_plugin\" means the account is stored in keystore plugin (Ledger plugin like [2]). If the account metadata is imported by `ckb-cli account import-from-plugin` the output fields are just like \"Local File System\". If the account is not imported, the output fields are:\n    * account-id: The account id used to import the account metadata from plugin.\n\n[1]: https://github.com/nervosnetwork/ckb-system-scripts/blob/master/c/secp256k1_blake160_sighash_all.c\n[2]: https://github.com/obsidiansystems/ckb-plugin-ledger";

fn parse_privkey_path(input: &str) -> Result<String, String> {
    PrivkeyPathParser.validate(input).map(|_| input.to_string())
}

fn parse_extended_privkey_path(input: &str) -> Result<String, String> {
    ExtendedPrivkeyPathParser
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_derivation_path(input: &str) -> Result<String, String> {
    FromStrParser::<DerivationPath>::new()
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_account_id(input: &str) -> Result<String, String> {
    let hex = HexParser.parse(input)?;
    if hex.is_empty() {
        Err("empty account id is not allowed".to_string())
    } else {
        Ok(input.to_string())
    }
}

fn parse_file_path_exists(input: &str) -> Result<String, String> {
    FilePathParser::new(true)
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_lock_arg(input: &str) -> Result<String, String> {
    FixedHashParser::<H160>::default()
        .validate(input)
        .map(|_| input.to_string())
}

#[derive(Parser, Debug)]
#[command(name = "account", about = "Manage accounts")]
pub struct AccountCmd {
    #[command(subcommand)]
    pub command: AccountSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum AccountSubcommands {
    /// List all accounts
    #[command(long_about = ACCOUNT_LIST_LONG_ABOUT)]
    List(AccountListArgs),
    /// Create a new account and print related information.
    New,
    /// Import an unencrypted private key from <privkey-path> and create a new account.
    Import(AccountImportArgs),
    /// Import an account from keystore plugin
    ImportFromPlugin(AccountImportFromPluginArgs),
    /// Import key from encrypted keystore json file and create a new account.
    ImportKeystore(AccountImportKeystoreArgs),
    /// Update password of an account
    Update(AccountLockArgArgs),
    /// Upgrade an account to latest json format
    Upgrade(AccountLockArgArgs),
    /// Export master private key and chain code as hex plain text (USE WITH YOUR OWN RISK)
    Export(AccountExportArgs),
    /// Show BIP-32 Extended Public Key in Base58Check format (with xpub prefix)
    BitcoinXpub(AccountDeriveArgs),
    /// Extended receiving/change Addresses (see: BIP-44)
    Bip44Addresses(AccountBip44Args),
    /// Extended address (see: BIP-44)
    ExtendedAddress(AccountDeriveArgs),
    /// Print information about how to remove an account
    Remove(AccountLockArgArgs),
}

#[derive(Args, Debug)]
pub struct AccountListArgs {
    /// Only show CKB mainnet address
    #[arg(long = "only-mainnet-address", id = "only-mainnet-address")]
    pub only_mainnet_address: bool,
    /// Only show CKB testnet address
    #[arg(long = "only-testnet-address", id = "only-testnet-address")]
    pub only_testnet_address: bool,
}

#[derive(Args, Debug)]
pub struct AccountImportArgs {
    /// The privkey is assumed to contain an unencrypted private key in hexadecimal format. (only read first line)
    #[arg(long = "privkey-path", id = "privkey-path", required_unless_present = "extended-privkey-path", value_parser = parse_privkey_path)]
    pub privkey_path: Option<String>,
    /// Extended private key path (include master private key and chain code)
    #[arg(long = "extended-privkey-path", id = "extended-privkey-path", required_unless_present = "privkey-path", value_parser = parse_extended_privkey_path)]
    pub extended_privkey_path: Option<String>,
}

#[derive(Args, Debug)]
pub struct AccountImportFromPluginArgs {
    /// The account id (hex format, can be found in account list)
    #[arg(long = "account-id", id = "account-id", value_parser = parse_account_id)]
    pub account_id: String,
}

#[derive(Args, Debug)]
pub struct AccountImportKeystoreArgs {
    /// The keystore file path (json format)
    #[arg(long, value_parser = parse_file_path_exists)]
    pub path: String,
}

#[derive(Args, Debug)]
pub struct AccountLockArgArgs {
    #[arg(long = "lock-arg", id = "lock-arg", value_parser = parse_lock_arg)]
    pub lock_arg: String,
}

#[derive(Args, Debug)]
pub struct AccountExportArgs {
    #[arg(long = "lock-arg", id = "lock-arg", value_parser = parse_lock_arg)]
    pub lock_arg: String,
    /// Output extended private key path (PrivKey + ChainCode)
    #[arg(long = "extended-privkey-path", id = "extended-privkey-path", value_parser = parse_extended_privkey_path)]
    pub extended_privkey_path: String,
}

#[derive(Args, Debug)]
pub struct AccountDeriveArgs {
    #[arg(long = "lock-arg", id = "lock-arg", value_parser = parse_lock_arg)]
    pub lock_arg: String,
    /// The derivation key path
    #[arg(long = "path", id = "path", value_parser = parse_derivation_path)]
    pub path: String,
}

#[derive(Args, Debug)]
pub struct AccountBip44Args {
    #[arg(long = "from-receiving-index", id = "from-receiving-index", default_value = "0")]
    pub from_receiving_index: u32,
    #[arg(long = "receiving-length", id = "receiving-length", default_value = "20")]
    pub receiving_length: u32,
    #[arg(long = "from-change-index", id = "from-change-index", default_value = "0")]
    pub from_change_index: u32,
    #[arg(long = "change-length", id = "change-length", default_value = "10")]
    pub change_length: u32,
    #[arg(long, default_value = "mainnet", value_parser = ["mainnet", "testnet"])]
    pub network: String,
    #[arg(long = "lock-arg", id = "lock-arg", value_parser = parse_lock_arg)]
    pub lock_arg: String,
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

    pub fn subcommand(name: &'static str) -> Command {
        AccountCmd::command().name(name)
    }
}

impl CliSubCommand for AccountSubCommand<'_> {
    fn process(&mut self, matches: &ArgMatches, _debug: bool) -> Result<Output, String> {
        let cmd = AccountCmd::from_arg_matches(matches).map_err(|err| err.to_string())?;
        match cmd.command {
            AccountSubcommands::List(args) => {
                let mut accounts = self.plugin_mgr.keystore_handler().list_account()?;
                // Sort by file path name
                accounts.sort_by(|a, b| a.1.cmp(&b.1));
                let only_mainnet_address = args.only_mainnet_address;
                let only_testnet_address = args.only_testnet_address;
                let partial_fields = only_mainnet_address || only_testnet_address;
                self.key_store
                    .refresh_dir()
                    .map_err(|err| err.to_string())?;
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
                                        key: Address::new(NetworkType::Mainnet, address_payload, false).to_string()
                                    })
                                } else if only_testnet_address {
                                    serde_json::json!({
                                        key: Address::new(NetworkType::Testnet, address_payload, false).to_string()
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
                                    "has_ckb_pubkey_derivation_root_path": has_ckb_root,
                                    "address": address_json(address_payload.clone(), true),
                                    "address(deprecated)": address_json(address_payload, false),
                                })
                            }
                        } else {
                            serde_json::json!({
                                "#": idx,
                                "source": source,
                                "account-id": format!("0x{}", hex_string(data.as_ref())),
                            })
                        }
                    })
                    .collect::<Vec<_>>();
                Ok(Output::new_output(resp))
            }
            AccountSubcommands::New => {
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
                    "address": address_json(address_payload.clone(), true),
                    "address(deprecated)": address_json(address_payload, false),
                });
                Ok(Output::new_output(resp))
            }
            AccountSubcommands::Import(args) => {
                let secp_key: Option<PrivkeyWrapper> = match args.privkey_path.as_ref() {
                    Some(path) => Some(PrivkeyPathParser.parse(path)?),
                    None => None,
                };
                let password = Some(read_password(false, None)?);
                let master_privkey = if let Some(secp_key) = secp_key {
                    // Default chain code is [255u8; 32]
                    let mut data = [255u8; 64];
                    data[0..32].copy_from_slice(&secp_key[..]);
                    MasterPrivKey::from_bytes(data).map_err(|err| err.to_string())?
                } else {
                    let extended_privkey_path = args
                        .extended_privkey_path
                        .as_ref()
                        .ok_or_else(|| "<extended-privkey-path> is required".to_string())?;
                    ExtendedPrivkeyPathParser.parse(extended_privkey_path)?
                };

                let lock_arg = self
                    .plugin_mgr
                    .keystore_handler()
                    .import_key(master_privkey, password)?;
                let address_payload = AddressPayload::from_pubkey_hash(lock_arg.clone());
                let resp = serde_json::json!({
                    "lock_arg": format!("{:#x}", lock_arg),
                    "address": address_json(address_payload.clone(), true),
                    "address(deprecated)": address_json(address_payload, false),
                });
                Ok(Output::new_output(resp))
            }
            AccountSubcommands::ImportFromPlugin(args) => {
                let account_id: Vec<u8> = HexParser.parse(&args.account_id)?;
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
                    "address": address_json(address_payload.clone(), true),
                    "address(deprecated)": address_json(address_payload, false),
                });
                Ok(Output::new_output(resp))
            }
            AccountSubcommands::ImportKeystore(args) => {
                let path: PathBuf = FilePathParser::new(true).parse(&args.path)?;

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
                    "address": address_json(address_payload.clone(), true),
                    "address(deprecated)": address_json(address_payload, false),
                });
                Ok(Output::new_output(resp))
            }
            AccountSubcommands::Update(args) => {
                let lock_arg: H160 = FixedHashParser::<H160>::default().parse(&args.lock_arg)?;
                let old_password = read_password(false, Some("Old password"))?;
                let new_passsword = read_password(true, Some("New password"))?;
                self.plugin_mgr.keystore_handler().update_password(
                    lock_arg,
                    old_password,
                    new_passsword,
                )?;
                Ok(Output::new_success())
            }
            AccountSubcommands::Upgrade(args) => {
                let lock_arg: H160 = FixedHashParser::<H160>::default().parse(&args.lock_arg)?;
                let password = read_password(false, None)?;
                self.key_store
                    .upgrade(&lock_arg, password.as_bytes())
                    .map_err(|err| err.to_string())?;
                Ok(Output::new_success())
            }
            AccountSubcommands::Export(args) => {
                let lock_arg: H160 = FixedHashParser::<H160>::default().parse(&args.lock_arg)?;
                let key_path = args.extended_privkey_path.as_str();
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

                #[cfg(unix)]
                let mut file = {
                    fs::OpenOptions::new()
                        .create_new(true)
                        .read(true)
                        .write(true)
                        .append(false)
                        .mode(0o400)
                        .open(key_path)
                        .map_err(|err| err.to_string())
                }?;

                #[cfg(not(unix))]
                let mut file = fs::File::create(&key_path).map_err(|err| err.to_string())?;

                file.write(format!("{:x}\n", privkey).as_bytes())
                    .map_err(|err| err.to_string())?;
                file.write(format!("{:x}", chain_code).as_bytes())
                    .map_err(|err| err.to_string())?;
                file.flush().map_err(|err| err.to_string())?;
                let resp = serde_json::json!({
                    "message": format!(
                        "Success exported account as extended privkey to: \"{}\", please use this file carefully",
                        key_path
                    )
                });
                Ok(Output::new_error(resp))
            }
            AccountSubcommands::BitcoinXpub(args) => {
                let lock_arg: H160 = FixedHashParser::<H160>::default().parse(&args.lock_arg)?;
                let password = read_password(false, None)?;
                let path: DerivationPath =
                    FromStrParser::<DerivationPath>::new().parse(&args.path)?;
                let extended_pubkey = self
                    .key_store
                    .extended_pubkey_with_password(&lock_arg, &path, password.as_bytes())
                    .map_err(|err| err.to_string())?;
                let resp = serde_json::json!({
                    "bitcoin-xpub": extended_pubkey.to_string(),
                });
                Ok(Output::new_output(resp))
            }
            AccountSubcommands::Bip44Addresses(args) => {
                let lock_arg: H160 = FixedHashParser::<H160>::default().parse(&args.lock_arg)?;
                let from_receiving_index = args.from_receiving_index;
                let receiving_length = args.receiving_length;
                let from_change_index = args.from_change_index;
                let change_length = args.change_length;
                let network = match args.network.as_str() {
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
                            let path = {
                                if !path.to_string().starts_with("m/"){
                                    String::new()+ "m/" + &path.to_string()
                                }else{
                                    path.to_string()
                                }
                            };
                            serde_json::json!({
                                "path": path,
                                "address(deprecated)": Address::new(network, payload.clone(), false).to_string(),
                                "address": Address::new(network, payload, true).to_string(),
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
            AccountSubcommands::ExtendedAddress(args) => {
                let lock_arg: H160 = FixedHashParser::<H160>::default().parse(&args.lock_arg)?;
                let path: DerivationPath =
                    FromStrParser::<DerivationPath>::new().parse(&args.path)?;

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
                    "address(deprecated)": address_json(address_payload.clone(), false),
                    "address": address_json(address_payload, true),
                });
                Ok(Output::new_output(resp))
            }
            AccountSubcommands::Remove(args) => {
                let lock_arg: H160 = FixedHashParser::<H160>::default().parse(&args.lock_arg)?;
                let filepath = self
                    .key_store
                    .get_filepath(&lock_arg)
                    .map_err(|err| err.to_string())?;
                eprintln!("WARNING: please remove it CAREFULLY! Once you remove it you may lost all assets owned by this key and it's sub-keys");
                let resp = serde_json::json!({
                    "filepath": filepath.to_string_lossy()
                });
                Ok(Output::new_output(resp))
            }
        }
    }
}
