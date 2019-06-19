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
use std::rc::Rc;

use crate::utils::printer::OutputFormat;

pub trait CliSubCommand {
    fn process(
        &mut self,
        matches: &ArgMatches,
        format: OutputFormat,
        color: bool,
    ) -> Result<Rc<String>, String>;
}
