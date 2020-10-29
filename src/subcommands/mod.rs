pub mod account;
pub mod api_server;
pub mod dao;
pub mod index;
pub mod mock_tx;
pub mod molecule;
pub mod plugin;
pub mod rpc;
#[cfg(unix)]
pub mod tui;
pub mod tx;
pub mod util;
pub mod wallet;

#[cfg(unix)]
pub use self::tui::TuiSubCommand;

pub use account::AccountSubCommand;
pub use api_server::ApiServerSubCommand;
pub use dao::DAOSubCommand;
pub use index::IndexSubCommand;
pub use mock_tx::MockTxSubCommand;
pub use molecule::MoleculeSubCommand;
pub use plugin::PluginSubCommand;
pub use rpc::RpcSubCommand;
pub use tx::TxSubCommand;
pub use util::UtilSubCommand;
pub use wallet::{start_index_thread, LiveCells, TransferArgs, WalletSubCommand};

use clap::ArgMatches;
use serde::Serialize;

use crate::utils::printer::{OutputFormat, Printable};

pub struct Output {
    stdout: Option<serde_json::Value>,
    stderr: Option<serde_json::Value>,
    success: bool,
}

impl Output {
    pub fn new_success() -> Output {
        Output {
            stdout: None,
            stderr: None,
            success: true,
        }
    }

    pub fn new_output<T: Serialize>(value: T) -> Output {
        Output {
            stdout: Some(serde_json::to_value(value).expect("serialize stdout error")),
            stderr: None,
            success: false,
        }
    }

    pub fn new_error<T: Serialize>(value: T) -> Output {
        Output {
            stdout: None,
            stderr: Some(serde_json::to_value(value).expect("serialize stderr error")),
            success: false,
        }
    }

    pub fn print(&self, format: OutputFormat, color: bool) {
        if let Some(ref stdout) = self.stdout {
            println!("{}", stdout.render(format, color));
        }
        if let Some(ref stderr) = self.stderr {
            eprintln!("{}", stderr.render(format, color));
        }
        if self.success {
            let resp = serde_json::json!({
                "status": "success",
            });
            eprintln!("{}", resp.render(OutputFormat::Yaml, color));
        }
    }
}

pub trait CliSubCommand {
    fn process(&mut self, matches: &ArgMatches, debug: bool) -> Result<Output, String>;
}
