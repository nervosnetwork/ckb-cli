use ckb_tui::start_ckb_tui;
use clap::{App, Arg};

use crate::subcommands::CliSubCommand;

pub struct TuiSubCommand;

impl TuiSubCommand {
    pub fn new() -> Self {
        Self
    }
    pub fn subcommand(name: &str) -> App<'static> {
        let arg_rpc_url = Arg::with_name("rpc-url")
            .long("rpc-url")
            .short('r')
            .default_value("http://127.0.0.1:8114")
            .about("RPC endpoint of CKB node")
            .takes_value(true)
            .required(false);
        let arg_tcp_url= Arg::with_name("tcp-url").long("tcp-url").short('t').takes_value(true).required(false).about("TCP endpoint of CKB node, used for receiving pushed transactions data\nIf not provided, latest transactions and rejected transactions won't be displayed");
        let arg_refresh_interval = Arg::with_name("refresh-interval")
            .long("refresh_interval")
            .short('i')
            .default_value("300")
            .takes_value(true)
            .required(false)
            .about("Refresh interval of displayed data, defaults to 300ms");
        let arg_theme_file = Arg::with_name("theme-file").long("theme-file").takes_value(true).required(false).about("Theme file to use for cursive. See https://github.com/gyscos/cursive/blob/main/cursive/examples/assets/style.toml for an example.");
        App::new(name).about("Start ckb-tui").args(vec![
            arg_rpc_url,
            arg_tcp_url,
            arg_refresh_interval,
            arg_theme_file,
        ])
    }
}

impl CliSubCommand for TuiSubCommand {
    fn process(
        &mut self,
        matches: &clap::ArgMatches,
        debug: bool,
    ) -> Result<super::Output, String> {
        match start_ckb_tui(
            matches.value_of("rpc-url").unwrap(),
            matches.value_of("tcp-url").map(|x| x.to_string()),
            matches.value_of_t("refresh-interval").unwrap(),
            matches.value_of("theme-file").map(|x| x.to_string()),
            debug,
        ) {
            Ok(_) => Ok(super::Output {
                stderr: None,
                stdout: None,
                success: true,
            }),
            Err(e) => Err(e.to_string()),
        }
    }
}
