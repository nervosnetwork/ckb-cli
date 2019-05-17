use clap::{App, AppSettings, Arg, SubCommand};
use std::collections::HashMap;
use std::env;
use std::iter::FromIterator;
use std::process;

use clap::crate_version;
use subcommands::{CliSubCommand, RpcSubCommand, WalletSubCommand};
use url::Url;
use utils::printer::Printer;
use utils::rpc_client::RpcClient;

mod interactive;
mod subcommands;
mod utils;

include!(concat!(env!("OUT_DIR"), "/build_info.rs"));

const DEFAULT_JSONRPC_URL: &str = "http://127.0.0.1:8114";

fn main() {
    let version = format!("{}+{}", crate_version!(), get_commit_id());
    let matches = build_cli(version.as_str()).get_matches();

    let mut env_map: HashMap<String, String> = HashMap::from_iter(env::vars());
    let api_uri = matches
        .value_of("url")
        .map(|value| value.to_owned())
        .or_else(|| env_map.remove("API_URL"))
        .unwrap_or_else(|| DEFAULT_JSONRPC_URL.to_owned());

    let mut rpc_client = RpcClient::from_uri(&api_uri);
    let printer = Printer::default();
    let result = match matches.subcommand() {
        ("rpc", Some(sub_matches)) => RpcSubCommand::new(&mut rpc_client).process(&sub_matches),
        ("wallet", Some(sub_matches)) => {
            WalletSubCommand::new(&mut rpc_client).process(&sub_matches)
        }
        _ => {
            if let Err(err) = interactive::start(&api_uri) {
                eprintln!("Something error: kind {:?}, message {}", err.kind(), err);
                process::exit(1);
            }
            process::exit(0)
        }
    };

    let color = !matches.is_present("no-color");
    match result {
        Ok(message) => {
            printer.println(&message, color);
        }
        Err(err) => {
            printer.eprintln(&format!("API_URL: {}", api_uri), false);
            printer.eprintln(&err, color);
            process::exit(1);
        }
    }
}

pub fn build_cli(version: &str) -> App {
    App::new("ckb-cli")
        .version(version)
        .global_setting(AppSettings::ColoredHelp)
        .global_setting(AppSettings::DeriveDisplayOrder)
        .subcommand(RpcSubCommand::subcommand())
        .subcommand(WalletSubCommand::subcommand())
        .arg(
            Arg::with_name("url")
                .long("url")
                .takes_value(true)
                .help("RPC API server url"),
        )
        .arg(
            Arg::with_name("no-color")
                .long("no-color")
                .global(true)
                .help("Do not highlight(color) output json"),
        )
        .arg(
            Arg::with_name("debug")
                .long("debug")
                .global(true)
                .help("Display request parameters"),
        )
}

pub fn build_interactive() -> App<'static, 'static> {
    App::new("interactive")
        .version(crate_version!())
        .setting(AppSettings::NoBinaryName)
        .global_setting(AppSettings::ColoredHelp)
        .global_setting(AppSettings::DeriveDisplayOrder)
        .global_setting(AppSettings::DisableVersion)
        .subcommand(
            SubCommand::with_name("config")
                .about("Config environment")
                .arg(
                    Arg::with_name("url")
                        .long("url")
                        .validator(|url| {
                            Url::parse(url.as_ref())
                                .map(|_| ())
                                .map_err(|err| err.to_string())
                        })
                        .takes_value(true)
                        .help("Config RPC API url"),
                )
                .arg(
                    Arg::with_name("color")
                        .long("color")
                        .help("Switch color for rpc interface"),
                )
                .arg(
                    Arg::with_name("debug")
                        .long("debug")
                        .help("Switch debug mode"),
                )
                .arg(
                    Arg::with_name("json")
                        .long("json")
                        .help("Switch json format"),
                )
                .arg(
                    Arg::with_name("completion_style")
                        .long("completion_style")
                        .help("Switch completion style"),
                )
                .arg(
                    Arg::with_name("edit_style")
                        .long("edit_style")
                        .help("Switch edit style"),
                ),
        )
        .subcommand(SubCommand::with_name("info").about("Display global variables"))
        .subcommand(
            SubCommand::with_name("exit")
                .visible_alias("quit")
                .about("Exit the interactive interface"),
        )
        .subcommand(RpcSubCommand::subcommand())
        .subcommand(WalletSubCommand::subcommand())
}
