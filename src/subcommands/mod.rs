pub mod account;
pub mod mock_tx;
pub mod rpc;
#[cfg(unix)]
pub mod tui;
pub mod util;
pub mod wallet;

#[cfg(unix)]
pub use self::tui::TuiSubCommand;

pub use account::AccountSubCommand;
pub use mock_tx::MockTxSubCommand;
pub use rpc::RpcSubCommand;
pub use util::UtilSubCommand;
pub use wallet::{
    start_index_thread, IndexController, IndexRequest, IndexResponse, IndexThreadState,
    WalletSubCommand,
};

use clap::ArgMatches;

use crate::utils::printer::OutputFormat;

pub trait CliSubCommand {
    fn process(
        &mut self,
        matches: &ArgMatches,
        format: OutputFormat,
        color: bool,
    ) -> Result<String, String>;
}
