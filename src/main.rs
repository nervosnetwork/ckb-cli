use std::collections::HashMap;
use std::env;
use std::iter::FromIterator;
use std::process;

use build_info::Version;
use clap::crate_version;
use clap::{App, AppSettings, Arg, SubCommand};
use subcommands::{start_index_thread, CliSubCommand, RpcSubCommand, WalletSubCommand};
use url::Url;
use utils::printer::Printer;
use utils::rpc_client::RpcClient;

mod interactive;
mod subcommands;
mod utils;

const DEFAULT_JSONRPC_URL: &str = "http://127.0.0.1:8114";

fn main() {
    env_logger::init();

    let version = get_version();
    let version_short = version.short();
    let version_long = version.long();
    let matches = build_cli(&version_short, &version_long).get_matches();

    let mut env_map: HashMap<String, String> = HashMap::from_iter(env::vars());
    let api_uri = matches
        .value_of("url")
        .map(|value| value.to_owned())
        .or_else(|| env_map.remove("API_URL"))
        .unwrap_or_else(|| DEFAULT_JSONRPC_URL.to_owned());

    let mut rpc_client = RpcClient::from_uri(&api_uri);
    let printer = Printer::default();

    let mut ckb_cli_dir = dirs::home_dir().unwrap();
    ckb_cli_dir.push(".ckb-cli");
    let mut index_file = ckb_cli_dir.clone();
    index_file.push("utxo-index.db");
    let index_controller = start_index_thread(&api_uri, index_file);

    let result = match matches.subcommand() {
        ("rpc", Some(sub_matches)) => RpcSubCommand::new(&mut rpc_client).process(&sub_matches),
        ("wallet", Some(sub_matches)) => {
            WalletSubCommand::new(&mut rpc_client, index_controller.sender().clone())
                .process(&sub_matches)
        }
        _ => {
            if let Err(err) = interactive::start(&api_uri, ckb_cli_dir, index_controller.clone()) {
                eprintln!("Something error: kind {:?}, message {}", err.kind(), err);
                index_controller.shutdown();
                process::exit(1);
            }
            index_controller.shutdown();
            process::exit(0)
        }
    };

    let color = !matches.is_present("no-color");
    match result {
        Ok(message) => {
            printer.println(&message, color);
            index_controller.shutdown();
        }
        Err(err) => {
            printer.eprintln(&format!("API_URL: {}", api_uri), false);
            printer.eprintln(&err, color);
            index_controller.shutdown();
            process::exit(1);
        }
    }
}

fn get_version() -> Version {
    let major = env!("CARGO_PKG_VERSION_MAJOR")
        .parse::<u8>()
        .expect("CARGO_PKG_VERSION_MAJOR parse success");
    let minor = env!("CARGO_PKG_VERSION_MINOR")
        .parse::<u8>()
        .expect("CARGO_PKG_VERSION_MINOR parse success");
    let patch = env!("CARGO_PKG_VERSION_PATCH")
        .parse::<u16>()
        .expect("CARGO_PKG_VERSION_PATCH parse success");
    let dash_pre = {
        let pre = env!("CARGO_PKG_VERSION_PRE");
        if pre == "" {
            pre.to_string()
        } else {
            "-".to_string() + pre
        }
    };

    let commit_describe = option_env!("COMMIT_DESCRIBE").map(ToString::to_string);
    #[cfg(docker)]
    let commit_describe = commit_describe.map(|s| s.replace("-dirty", ""));
    let commit_date = option_env!("COMMIT_DATE").map(ToString::to_string);
    Version {
        major,
        minor,
        patch,
        dash_pre,
        commit_describe,
        commit_date,
    }
}

pub fn build_cli<'a>(version_short: &'a str, version_long: &'a str) -> App<'a, 'a> {
    App::new("ckb-cli")
        .version(version_short)
        .long_version(version_long)
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
        .global_setting(AppSettings::NoBinaryName)
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
