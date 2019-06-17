use std::path::PathBuf;

use ckb_sdk::{with_rocksdb, HttpRpcClient, KeyManager, NetworkType, SecpKey};
use clap::{App, Arg, ArgMatches, SubCommand};

use super::super::CliSubCommand;
use crate::utils::printer::Printable;

pub struct LocalKeySubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    db_path: PathBuf,
}

impl<'a> LocalKeySubCommand<'a> {
    pub fn new(rpc_client: &'a mut HttpRpcClient, db_path: PathBuf) -> LocalKeySubCommand<'a> {
        LocalKeySubCommand {
            rpc_client,
            db_path,
        }
    }

    pub fn subcommand() -> App<'static, 'static> {
        SubCommand::with_name("key").subcommands(vec![
            SubCommand::with_name("add").arg(
                Arg::with_name("privkey-path")
                    .long("privkey-path")
                    .takes_value(true)
                    .required(true)
                    .help("Private key file path"),
            ),
            SubCommand::with_name("remove").arg(
                Arg::with_name("pubkey")
                    .long("pubkey")
                    .takes_value(true)
                    .required(true)
                    .help("Public key hex"),
            ),
            SubCommand::with_name("list"),
        ])
    }
}

impl<'a> CliSubCommand for LocalKeySubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches) -> Result<Box<dyn Printable>, String> {
        match matches.subcommand() {
            ("add", Some(m)) => {
                let privkey_path = m.value_of("privkey-path").unwrap();
                let key = SecpKey::from_privkey_path(privkey_path)?;
                let result = serde_json::json!({
                    "privkey-path": key.privkey_path.as_ref().unwrap().to_string_lossy(),
                    "pubkey": key.pubkey_string(),
                    "address": key.address().unwrap().to_string(NetworkType::TestNet),
                });
                with_rocksdb(&self.db_path, None, |db| {
                    KeyManager::new(db).add(key).map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;
                Ok(Box::new(serde_json::to_string(&result).unwrap()))
            }
            ("remove", Some(m)) => {
                let pubkey = m.value_of("pubkey").unwrap();
                let key = SecpKey::from_pubkey_str(pubkey)?;
                let removed_key = with_rocksdb(&self.db_path, None, |db| {
                    KeyManager::new(db).remove(&key).map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;
                let result = serde_json::json!({
                    "privkey-path": removed_key.privkey_path.as_ref().unwrap().to_string_lossy(),
                    "pubkey": removed_key.pubkey_string(),
                    "address": removed_key.address().unwrap().to_string(NetworkType::TestNet),
                });
                Ok(Box::new(serde_json::to_string(&result).unwrap()))
            }
            ("list", _) => {
                let keys = with_rocksdb(&self.db_path, None, |db| {
                    KeyManager::new(db).list().map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;
                let results = keys
                    .into_iter()
                    .map(|key| {
                        serde_json::json!({
                            "privkey-path": key.privkey_path.as_ref().unwrap().to_string_lossy(),
                            "pubkey": key.pubkey_string(),
                            "address": key.address().unwrap().to_string(NetworkType::TestNet),
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(Box::new(serde_json::to_string(&results).unwrap()))
            }
            _ => Err(matches.usage().to_owned()),
        }
    }
}
