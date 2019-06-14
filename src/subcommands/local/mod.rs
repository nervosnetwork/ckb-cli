mod cell;
mod cell_input;
mod key;
mod script;
mod tx;

pub use cell::LocalCellSubCommand;
pub use cell_input::LocalCellInputSubCommand;
pub use key::LocalKeySubCommand;
pub use script::LocalScriptSubCommand;
pub use tx::LocalTxSubCommand;

use std::path::PathBuf;

use ckb_sdk::HttpRpcClient;
use clap::{App, ArgMatches, SubCommand};

use super::CliSubCommand;
use crate::utils::printer::Printable;

pub struct LocalSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    db_path: PathBuf,
}

impl<'a> LocalSubCommand<'a> {
    pub fn new(rpc_client: &'a mut HttpRpcClient, db_path: PathBuf) -> LocalSubCommand<'a> {
        LocalSubCommand {
            rpc_client,
            db_path,
        }
    }

    pub fn subcommand() -> App<'static, 'static> {
        SubCommand::with_name("local").subcommands(vec![
            LocalKeySubCommand::subcommand(),
            LocalCellSubCommand::subcommand(),
            LocalCellInputSubCommand::subcommand(),
            LocalScriptSubCommand::subcommand(),
            LocalTxSubCommand::subcommand(),
        ])
    }
}

impl<'a> CliSubCommand for LocalSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches) -> Result<Box<dyn Printable>, String> {
        match matches.subcommand() {
            ("key", Some(m)) => {
                LocalKeySubCommand::new(self.rpc_client, self.db_path.clone()).process(m)
            }
            ("script", Some(m)) => {
                LocalScriptSubCommand::new(self.rpc_client, self.db_path.clone()).process(m)
            }
            ("cell", Some(m)) => {
                LocalCellSubCommand::new(self.rpc_client, self.db_path.clone()).process(m)
            }
            ("cell-input", Some(m)) => {
                LocalCellInputSubCommand::new(self.rpc_client, self.db_path.clone()).process(m)
            }
            ("tx", Some(m)) => {
                LocalTxSubCommand::new(self.rpc_client, self.db_path.clone()).process(m)
            }
            _ => Err(matches.usage().to_owned()),
        }
    }
}
