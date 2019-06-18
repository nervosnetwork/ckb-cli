use std::fs;
use std::io::Read;
use std::path::PathBuf;

use bytes::Bytes;
use ckb_core::{transaction::CellOutput, Capacity};
use ckb_sdk::{with_rocksdb, CellManager, HttpRpcClient, ScriptManager};
use clap::{App, Arg, ArgMatches, SubCommand};
use jsonrpc_types::CellOutput as RpcCellOutput;
use numext_fixed_hash::H256;

use super::super::CliSubCommand;
use crate::utils::arg_parser::{
    ArgParser, CapacityParser, FilePathParser, FixedHashParser, HexParser,
};
use crate::utils::printer::Printable;

pub struct LocalCellSubCommand<'a> {
    _rpc_client: &'a mut HttpRpcClient,
    db_path: PathBuf,
}

impl<'a> LocalCellSubCommand<'a> {
    pub fn new(rpc_client: &'a mut HttpRpcClient, db_path: PathBuf) -> LocalCellSubCommand<'a> {
        LocalCellSubCommand {
            _rpc_client: rpc_client,
            db_path,
        }
    }

    pub fn subcommand() -> App<'static, 'static> {
        let arg_name = Arg::with_name("name")
            .long("name")
            .takes_value(true)
            .required(true)
            .help("Cell name");
        let arg_json_path = Arg::with_name("path")
            .long("path")
            .takes_value(true)
            .validator(|input| FilePathParser::new(false).validate(input))
            .required(true)
            .help("JSON file path");
        SubCommand::with_name("cell")
            .about("Local cell management")
            .subcommands(vec![
                SubCommand::with_name("add")
                    .arg(arg_name.clone())
                    .arg(
                        Arg::with_name("data-path")
                            .long("data-path")
                            .takes_value(true)
                            .validator(|input| FilePathParser::new(true).validate(input))
                            .help("Data file path"),
                    )
                    .arg(
                        Arg::with_name("data")
                            .long("data")
                            .takes_value(true)
                            .validator(|input| HexParser.validate(input))
                            .help("Hex data"),
                    )
                    .arg(
                        Arg::with_name("lock-hash")
                            .long("lock-hash")
                            .takes_value(true)
                            .validator(|input| FixedHashParser::<H256>::default().validate(input))
                            .required(true)
                            .help("Lock script hash"),
                    )
                    .arg(
                        Arg::with_name("type-hash")
                            .long("type-hash")
                            .takes_value(true)
                            .validator(|input| FixedHashParser::<H256>::default().validate(input))
                            .help("Type script hash"),
                    )
                    .arg(
                        Arg::with_name("capacity")
                            .long("capacity")
                            .takes_value(true)
                            .validator(|input| CapacityParser.validate(input))
                            .help("Capacity (unit: CKB, format: 123.456)"),
                    ),
                SubCommand::with_name("remove").arg(arg_name.clone()),
                SubCommand::with_name("show").arg(arg_name.clone()),
                SubCommand::with_name("list"),
                SubCommand::with_name("dump")
                    .arg(arg_name.clone())
                    .arg(arg_json_path.clone()),
                SubCommand::with_name("dump")
                    .arg(arg_name.clone())
                    .arg(arg_json_path.clone()),
            ])
    }
}

impl<'a> CliSubCommand for LocalCellSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches) -> Result<Box<dyn Printable>, String> {
        match matches.subcommand() {
            ("add", Some(m)) => {
                let name: String = m.value_of("name").unwrap().to_owned();
                let data_path: Option<String> = m.value_of("data-path").map(ToOwned::to_owned);
                let data_bin: Option<Vec<u8>> = HexParser.from_matches_opt(m, "data", false)?;
                let lock_hash: H256 =
                    FixedHashParser::<H256>::default().from_matches(m, "lock-hash")?;
                let type_hash: Option<H256> =
                    FixedHashParser::<H256>::default().from_matches_opt(m, "lock-hash", false)?;
                let capacity: u64 = CapacityParser.from_matches(m, "capacity")?;

                let mut data = Vec::new();
                if let Some(path) = data_path {
                    let mut file = fs::File::open(path).map_err(|err| err.to_string())?;
                    file.read_to_end(&mut data).map_err(|err| err.to_string())?;
                }
                if let Some(data_bin) = data_bin {
                    data = data_bin;
                }
                let data = Bytes::from(data);

                let lock = with_rocksdb(&self.db_path, None, |db| {
                    ScriptManager::new(db).get(&lock_hash).map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;
                let type_ = match type_hash {
                    Some(hash) => Some(
                        with_rocksdb(&self.db_path, None, |db| {
                            ScriptManager::new(db).get(&hash).map_err(Into::into)
                        })
                        .map_err(|err| format!("{:?}", err))?,
                    ),
                    None => None,
                };

                let cell_output = CellOutput {
                    capacity: Capacity::shannons(capacity),
                    data,
                    lock,
                    type_,
                };
                with_rocksdb(&self.db_path, None, |db| {
                    CellManager::new(db)
                        .add(&name, cell_output.clone())
                        .map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;

                Ok(Box::new(serde_json::to_string(&cell_output).unwrap()))
            }
            ("remove", Some(m)) => {
                let name: String = m.value_of("name").map(ToOwned::to_owned).unwrap();
                let cell_output = with_rocksdb(&self.db_path, None, |db| {
                    CellManager::new(db).remove(&name).map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;
                Ok(Box::new(serde_json::to_string(&cell_output).unwrap()))
            }
            ("show", Some(m)) => {
                let name: String = m.value_of("name").map(ToOwned::to_owned).unwrap();
                let cell_output = with_rocksdb(&self.db_path, None, |db| {
                    CellManager::new(db).get(&name).map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;
                Ok(Box::new(serde_json::to_string(&cell_output).unwrap()))
            }
            ("list", _) => {
                let cells = with_rocksdb(&self.db_path, None, |db| {
                    CellManager::new(db).list().map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;
                let rpc_cells: Vec<(String, RpcCellOutput)> = cells
                    .into_iter()
                    .map(|(name, cell)| (name, cell.into()))
                    .collect();
                Ok(Box::new(serde_json::to_string(&rpc_cells).unwrap()))
            }
            ("dump", Some(_m)) => Ok(Box::new("null".to_string())),
            ("load", Some(_m)) => Ok(Box::new("null".to_string())),
            _ => Err(matches.usage().to_owned()),
        }
    }
}
