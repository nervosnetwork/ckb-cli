use std::path::PathBuf;

use ckb_core::block::Block;
use ckb_sdk::{with_rocksdb, GenesisInfo, HttpRpcClient, KeyManager, NetworkType, SecpKey};
use clap::{App, Arg, ArgMatches, SubCommand};
use jsonrpc_types::BlockNumber;

use super::super::CliSubCommand;
use crate::utils::arg_parser::{ArgParser, PrivkeyPathParser, PubkeyHexParser};
use crate::utils::printer::{OutputFormat, Printable};

pub struct LocalKeySubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    genesis_info: Option<GenesisInfo>,
    db_path: PathBuf,
}

impl<'a> LocalKeySubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        genesis_info: Option<GenesisInfo>,
        db_path: PathBuf,
    ) -> LocalKeySubCommand<'a> {
        LocalKeySubCommand {
            rpc_client,
            genesis_info,
            db_path,
        }
    }

    fn genesis_info(&mut self) -> Result<GenesisInfo, String> {
        if self.genesis_info.is_none() {
            let genesis_block: Block = self
                .rpc_client
                .get_block_by_number(BlockNumber(0))
                .call()
                .map_err(|err| err.to_string())?
                .0
                .expect("Can not get genesis block?")
                .into();
            self.genesis_info = Some(GenesisInfo::from_block(&genesis_block)?);
        }
        Ok(self.genesis_info.clone().unwrap())
    }

    pub fn subcommand() -> App<'static, 'static> {
        SubCommand::with_name("key").subcommands(vec![
            SubCommand::with_name("add").arg(
                Arg::with_name("privkey-path")
                    .long("privkey-path")
                    .takes_value(true)
                    .validator(|input| PrivkeyPathParser.validate(input))
                    .required(true)
                    .help("Private key file path"),
            ),
            SubCommand::with_name("remove").arg(
                Arg::with_name("pubkey")
                    .long("pubkey")
                    .takes_value(true)
                    .validator(|input| PubkeyHexParser.validate(input))
                    .required(true)
                    .help("Public key hex"),
            ),
            SubCommand::with_name("list"),
        ])
    }
}

impl<'a> CliSubCommand for LocalKeySubCommand<'a> {
    fn process(
        &mut self,
        matches: &ArgMatches,
        format: OutputFormat,
        color: bool,
    ) -> Result<String, String> {
        let secp_code_hash = self.genesis_info()?.secp_code_hash().clone();
        let key_info = |key: &SecpKey| {
            let address = key.address().unwrap();
            serde_json::json!({
                "privkey-path": key.privkey_path.as_ref().unwrap().to_string_lossy(),
                "pubkey": key.pubkey_string(),
                "address_string": address.to_string(NetworkType::TestNet),
                "address": address,
                "lock-hash": address.lock_script(secp_code_hash.clone()).hash(),
            })
        };
        match matches.subcommand() {
            ("add", Some(m)) => {
                let key: SecpKey = PrivkeyPathParser.from_matches(m, "privkey-path")?;
                let result = key_info(&key);
                with_rocksdb(&self.db_path, None, |db| {
                    KeyManager::new(db).add(key).map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;
                Ok(result.render(format, color))
            }
            ("remove", Some(m)) => {
                let key: SecpKey = PubkeyHexParser.from_matches(m, "pubkey")?;
                let removed_key = with_rocksdb(&self.db_path, None, |db| {
                    KeyManager::new(db).remove(&key).map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;
                let result = key_info(&removed_key);
                Ok(result.render(format, color))
            }
            ("list", _) => {
                let keys = with_rocksdb(&self.db_path, None, |db| {
                    KeyManager::new(db).list().map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;
                let results = keys
                    .into_iter()
                    .map(|key| key_info(&key))
                    .collect::<Vec<_>>();
                Ok(results.render(format, color))
            }
            _ => Err(matches.usage().to_owned()),
        }
    }
}
