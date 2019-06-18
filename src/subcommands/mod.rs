pub mod rpc;
#[cfg(unix)]
pub mod tui;
pub mod wallet;

pub mod local;

#[cfg(unix)]
pub use self::tui::TuiSubCommand;

pub use local::{
    LocalCellInputSubCommand, LocalCellSubCommand, LocalKeySubCommand, LocalScriptSubCommand,
    LocalSubCommand, LocalTxSubCommand,
};

pub use rpc::RpcSubCommand;
pub use wallet::{
    start_index_thread, IndexController, IndexRequest, IndexResponse, IndexThreadState,
    WalletSubCommand,
};

use clap::ArgMatches;

use crate::utils::printer::Printable;

pub trait CliSubCommand {
    fn process(&mut self, matches: &ArgMatches) -> Result<Box<dyn Printable>, String>;
}
