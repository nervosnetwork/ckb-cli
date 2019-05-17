mod types;

use clap::{App, Arg, ArgMatches, SubCommand};
use jsonrpc_types::{CellOutPoint, OutPoint};

use super::{from_matches, from_matches_opt, CliSubCommand};
use crate::utils::printer::Printable;
use crate::utils::rpc_client::HttpRpcClient;

pub struct RpcSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
}

impl<'a> RpcSubCommand<'a> {
    pub fn new(rpc_client: &'a mut HttpRpcClient) -> RpcSubCommand<'a> {
        RpcSubCommand { rpc_client }
    }

    pub fn subcommand() -> App<'static, 'static> {
        let arg_hash = Arg::with_name("hash")
            .long("hash")
            .takes_value(true)
            .required(true);
        let arg_number = Arg::with_name("number")
            .long("number")
            .takes_value(true)
            .required(true)
            .help("Block number");

        SubCommand::with_name("rpc").subcommands(vec![
            SubCommand::with_name("get_tip_header"),
            SubCommand::with_name("get_block").arg(arg_hash.clone().help("Block hash")),
            SubCommand::with_name("get_block_hash").arg(arg_number.clone()),
            SubCommand::with_name("get_block_by_number").arg(arg_number.clone()),
            SubCommand::with_name("get_transaction").arg(arg_hash.clone().help("Tx hash")),
            SubCommand::with_name("get_cells_by_lock_hash")
                .arg(arg_hash.clone().help("Lock hash"))
                .arg(
                    Arg::with_name("from")
                        .long("from")
                        .takes_value(true)
                        .required(true)
                        .help("From block number"),
                )
                .arg(
                    Arg::with_name("to")
                        .long("to")
                        .takes_value(true)
                        .required(true)
                        .help("To block number"),
                ),
            SubCommand::with_name("get_live_cell")
                .arg(arg_hash.clone().required(false).help("Block hash"))
                .arg(
                    Arg::with_name("tx-hash")
                        .long("tx-hash")
                        .takes_value(true)
                        .required(true)
                        .help("Tx hash"),
                )
                .arg(
                    Arg::with_name("index")
                        .long("index")
                        .takes_value(true)
                        .required(true)
                        .help("Output index"),
                ),
            SubCommand::with_name("get_current_epoch"),
            SubCommand::with_name("get_epoch_by_number")
                .arg(arg_number.clone().help("Epoch number")),
            SubCommand::with_name("local_node_info"),
            SubCommand::with_name("tx_pool_info"),
            SubCommand::with_name("get_peers"),
        ])
    }
}

impl<'a> CliSubCommand for RpcSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches) -> Result<Box<dyn Printable>, String> {
        match matches.subcommand() {
            ("get_tip_header", _) => {
                let resp = self
                    .rpc_client
                    .get_tip_header()
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(Box::new(resp))
            }
            ("get_block", Some(m)) => {
                let hash = from_matches(m, "hash");

                let resp = self
                    .rpc_client
                    .get_block(hash)
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(Box::new(resp))
            }
            ("get_block_hash", Some(m)) => {
                let number = from_matches(m, "number");

                let resp = self
                    .rpc_client
                    .get_block_hash(number)
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(Box::new(resp))
            }
            ("get_block_by_number", Some(m)) => {
                let number = from_matches(m, "number");

                let resp = self
                    .rpc_client
                    .get_block_by_number(number)
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(Box::new(resp))
            }
            ("get_transaction", Some(m)) => {
                let hash = from_matches(m, "hash");

                let resp = self
                    .rpc_client
                    .get_transaction(hash)
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(Box::new(resp))
            }
            ("get_cells_by_lock_hash", Some(m)) => {
                let lock_hash = from_matches(m, "hash");
                let from_number = from_matches(m, "from");
                let to_number = from_matches(m, "to");

                let resp = self
                    .rpc_client
                    .get_cells_by_lock_hash(lock_hash, from_number, to_number)
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(Box::new(resp))
            }
            ("get_live_cell", Some(m)) => {
                let block_hash = from_matches_opt(m, "hash");
                let tx_hash = from_matches(m, "tx-hash");
                let index = from_matches(m, "index");
                let out_point = OutPoint {
                    cell: Some(CellOutPoint { tx_hash, index }),
                    block_hash,
                };

                let resp = self
                    .rpc_client
                    .get_live_cell(out_point)
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(Box::new(resp))
            }
            ("get_current_epoch", _) => {
                let resp = self
                    .rpc_client
                    .get_current_epoch()
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(Box::new(resp))
            }
            ("local_node_info", _) => {
                let resp = self
                    .rpc_client
                    .local_node_info()
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(Box::new(resp))
            }
            ("tx_pool_info", _) => {
                let resp = self
                    .rpc_client
                    .tx_pool_info()
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(Box::new(resp))
            }
            ("get_peers", _) => {
                let resp = self
                    .rpc_client
                    .get_peers()
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(Box::new(resp))
            }
            _ => Err(matches.usage().to_owned()),
        }
    }
}
