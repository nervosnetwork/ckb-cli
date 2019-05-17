mod types;

use clap::{SubCommand, App, Arg, ArgMatches};
use jsonrpc_types::{
    CellOutPoint,
    OutPoint,
};

use crate::utils::rpc_client::HttpRpcClient;
use crate::utils::printer::Printable;
use super::{CliSubCommand, from_matches, from_matches_opt};

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

        SubCommand::with_name("rpc")
            .subcommands(vec![
                SubCommand::with_name("get_tip_header"),
                SubCommand::with_name("get_block")
                    .arg(arg_hash.clone().help("Block hash")),
                SubCommand::with_name("get_block_hash")
                    .arg(arg_number.clone()),
                SubCommand::with_name("get_block_by_number")
                    .arg(arg_number.clone()),
                SubCommand::with_name("get_transaction")
                    .arg(arg_hash.clone().help("Tx hash")),
                SubCommand::with_name("get_cells_by_lock_hash")
                    .arg(arg_hash.clone().help("Lock hash"))
                    .arg(Arg::with_name("from")
                         .long("from")
                         .takes_value(true)
                         .required(true)
                         .help("From block number"))
                    .arg(Arg::with_name("to")
                         .long("to")
                         .takes_value(true)
                         .required(true)
                         .help("To block number")),
                SubCommand::with_name("get_live_cell")
                    .arg(arg_hash.clone().required(false).help("Block hash"))
                    .arg(Arg::with_name("tx-hash")
                         .long("tx-hash")
                         .takes_value(true)
                         .required(true)
                         .help("Tx hash"))
                    .arg(Arg::with_name("index")
                         .long("index")
                         .takes_value(true)
                         .required(true)
                         .help("Output index")),
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
                Ok(Box::new(self.rpc_client.get_tip_header().call().unwrap()))
            }
            ("get_block", Some(m)) => {
                let hash = from_matches(m, "hash");
                Ok(Box::new(self.rpc_client.get_block(hash).call().unwrap()))
            }
            ("get_block_hash", Some(m)) => {
                let number = from_matches(m, "number");
                Ok(Box::new(self.rpc_client.get_block_hash(number).call().unwrap()))
            }
            ("get_block_by_number", Some(m)) => {
                let number = from_matches(m, "number");
                Ok(Box::new(self.rpc_client.get_block_by_number(number).call().unwrap()))
            }
            ("get_transaction", Some(m)) => {
                let hash = from_matches(m, "hash");
                Ok(Box::new(self.rpc_client.get_transaction(hash).call().unwrap()))
            }
            ("get_cells_by_lock_hash", Some(m)) => {
                let lock_hash = from_matches(m, "hash");
                let from_number = from_matches(m, "from");
                let to_number = from_matches(m, "to");
                Ok(Box::new(self.rpc_client.get_cells_by_lock_hash(lock_hash, from_number, to_number).call().unwrap()))
            }
            ("get_live_cell", Some(m)) => {
                let block_hash = from_matches_opt(m, "hash");
                let tx_hash = from_matches(m, "tx-hash");
                let index = from_matches(m, "index");
                let out_point = OutPoint {
                    cell: Some(CellOutPoint {tx_hash, index}),
                    block_hash,
                };
                Ok(Box::new(self.rpc_client.get_live_cell(out_point).call().unwrap()))
            }
            ("get_current_epoch", _) => {
                Ok(Box::new(self.rpc_client.get_current_epoch().call().unwrap()))
            }
            ("local_node_info", _) => {
                Ok(Box::new(self.rpc_client.local_node_info().call().unwrap()))
            }
            ("tx_pool_info", _) => {
                Ok(Box::new(self.rpc_client.tx_pool_info().call().unwrap()))
            }
            ("get_peers", _) => {
                Ok(Box::new(self.rpc_client.get_peers().call().unwrap()))
            }
            _ => {
                Err(matches.usage().to_owned())
            }
        }
    }
}
