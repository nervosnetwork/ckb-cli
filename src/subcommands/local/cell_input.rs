use std::path::PathBuf;

use super::super::{from_matches, CliSubCommand};
use crate::utils::printer::Printable;
use ckb_core::transaction::{CellInput, CellOutPoint, OutPoint};
use ckb_sdk::{to_local_cell_out_point, with_rocksdb, CellInputManager, HttpRpcClient};
use clap::{App, Arg, ArgMatches, SubCommand};
use jsonrpc_types::{BlockNumber as RpcBlockNumber, CellInput as RpcCellInput};
use numext_fixed_hash::H256;

pub struct LocalCellInputSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    db_path: PathBuf,
}

impl<'a> LocalCellInputSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        db_path: PathBuf,
    ) -> LocalCellInputSubCommand<'a> {
        LocalCellInputSubCommand {
            rpc_client,
            db_path,
        }
    }

    pub fn subcommand() -> App<'static, 'static> {
        let arg_name = Arg::with_name("name")
            .long("name")
            .takes_value(true)
            .required(true)
            .help("Cell input name");
        SubCommand::with_name("cell-input").subcommands(vec![
            SubCommand::with_name("add")
                .arg(arg_name.clone())
                .arg(
                    Arg::with_name("output-block")
                        .long("output-block")
                        .takes_value(true)
                        .help("Output block number or hash"),
                )
                .arg(
                    Arg::with_name("cell-name")
                        .long("cell-name")
                        .takes_value(true)
                        .help("Cell Output name"),
                )
                .arg(
                    Arg::with_name("cell-tx-hash")
                        .long("cell-tx-hash")
                        .takes_value(true)
                        .help("Cell transaction hash"),
                )
                .arg(
                    Arg::with_name("cell-index")
                        .long("cell-index")
                        .takes_value(true)
                        .help("Cell output index in the transaction"),
                )
                .arg(
                    Arg::with_name("since")
                        .long("since")
                        .takes_value(true)
                        .default_value("0")
                        .help("Since which block"),
                ),
            SubCommand::with_name("remove").arg(arg_name.clone()),
            SubCommand::with_name("show").arg(arg_name.clone()),
            SubCommand::with_name("list"),
        ])
    }
}

impl<'a> CliSubCommand for LocalCellInputSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches) -> Result<Box<dyn Printable>, String> {
        match matches.subcommand() {
            ("add", Some(m)) => {
                let name: String = m.value_of("name").map(|s| s.to_owned()).unwrap();
                let output_block: Option<&str> = m.value_of("output-block");
                let cell_name: Option<&str> = m.value_of("cell-name");
                let cell_tx_hash: Option<&str> = m.value_of("cell-tx-hash");
                let cell_index: Option<u32> = m.value_of("cell-index").map(|s| s.parse().unwrap());
                let since: u64 = m.value_of("since").map(|s| s.parse().unwrap()).unwrap();
                let cell_out_point = match cell_name {
                    Some(cell_name) => to_local_cell_out_point(cell_name),
                    None => {
                        let tx_hash = cell_tx_hash
                            .ok_or_else(|| "cell tx-hash not given".to_owned())
                            .and_then(|hash_str| {
                                H256::from_hex_str(hash_str).map_err(|err| err.to_string())
                            })?;
                        let index = cell_index.ok_or_else(|| "cell index not given".to_owned())?;
                        CellOutPoint { tx_hash, index }
                    }
                };
                let output_block_hash = match output_block {
                    Some(s) => {
                        if let Ok(number) = s.parse::<u64>() {
                            Some(
                                self.rpc_client
                                    .get_block_hash(RpcBlockNumber(number))
                                    .call()
                                    .unwrap()
                                    .0
                                    .unwrap(),
                            )
                        } else {
                            Some(H256::from_hex_str(s).map_err(|err| err.to_string())?)
                        }
                    }
                    None => None,
                };
                let cell_input = CellInput {
                    previous_output: OutPoint {
                        cell: Some(cell_out_point),
                        block_hash: output_block_hash,
                    },
                    since,
                };
                with_rocksdb(&self.db_path, None, |db| {
                    CellInputManager::new(db)
                        .add(&name, cell_input.clone())
                        .map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;
                Ok(Box::new(serde_json::to_string(&cell_input).unwrap()))
            }
            ("remove", Some(m)) => {
                let name: String = from_matches(m, "name");
                let cell_input = with_rocksdb(&self.db_path, None, |db| {
                    CellInputManager::new(db).remove(&name).map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;
                Ok(Box::new(serde_json::to_string(&cell_input).unwrap()))
            }
            ("show", Some(m)) => {
                let name: String = from_matches(m, "name");
                let cell_input = with_rocksdb(&self.db_path, None, |db| {
                    CellInputManager::new(db).get(&name).map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;
                Ok(Box::new(serde_json::to_string(&cell_input).unwrap()))
            }
            ("list", _) => {
                let cell_inputs = with_rocksdb(&self.db_path, None, |db| {
                    CellInputManager::new(db).list().map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;
                let rpc_cell_inputs: Vec<(String, RpcCellInput)> = cell_inputs
                    .into_iter()
                    .map(|(name, cell_input)| (name, cell_input.into()))
                    .collect();
                Ok(Box::new(serde_json::to_string(&rpc_cell_inputs).unwrap()))
            }
            _ => Err(matches.usage().to_owned()),
        }
    }
}
