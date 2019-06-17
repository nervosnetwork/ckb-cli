use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::iter::FromIterator;
use std::process;
use std::sync::Arc;

use build_info::Version;
use ckb_sdk::rpc::RpcClient;
use ckb_util::RwLock;
use clap::crate_version;
use clap::{App, AppSettings, Arg, SubCommand};
#[cfg(unix)]
use subcommands::TuiSubCommand;

#[cfg(feature = "local")]
use subcommands::LocalSubCommand;

use interactive::InteractiveEnv;
use subcommands::{
    start_index_thread, CliSubCommand, IndexThreadState, RpcSubCommand, WalletSubCommand,
};
use utils::arg_parser::{ArgParser, UrlParser};
use utils::config::GlobalConfig;
use utils::printer::Printer;

mod interactive;
mod subcommands;
mod utils;

fn main() -> Result<(), io::Error> {
    env_logger::init();

    let version = get_version();
    let version_short = version.short();
    let version_long = version.long();
    let matches = build_cli(&version_short, &version_long).get_matches();

    let mut env_map: HashMap<String, String> = HashMap::from_iter(env::vars());
    let api_uri_opt = matches
        .value_of("url")
        .map(|value| value.to_owned())
        .or_else(|| env_map.remove("API_URL"));

    let printer = Printer::default();

    let mut ckb_cli_dir = dirs::home_dir().unwrap();
    ckb_cli_dir.push(".ckb-cli");
    let mut resource_dir = ckb_cli_dir.clone();
    resource_dir.push("resource");
    let mut index_dir = ckb_cli_dir.clone();
    index_dir.push("index");
    let index_state = Arc::new(RwLock::new(IndexThreadState::default()));

    let mut config = GlobalConfig::new(api_uri_opt.clone(), Arc::clone(&index_state));
    let mut config_file = ckb_cli_dir.clone();
    config_file.push("config");

    if config_file.as_path().exists() {
        let mut file = fs::File::open(&config_file)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        let configs: serde_json::Value = serde_json::from_str(content.as_str()).unwrap();
        if api_uri_opt.is_none() {
            if let Some(value) = configs["url"].as_str() {
                config.set_url(value.to_string());
            }
        }
        config.set_debug(configs["debug"].as_bool().unwrap_or(false));
        config.set_color(configs["color"].as_bool().unwrap_or(true));
        config.set_json_format(configs["json_format"].as_bool().unwrap_or(true));
        config.set_completion_style(configs["completion_style"].as_bool().unwrap_or(true));
        config.set_edit_style(configs["edit_style"].as_bool().unwrap_or(true));
    }

    let api_uri = config.get_url().to_string();
    let index_controller = start_index_thread(api_uri.as_str(), index_dir.clone(), index_state);
    let mut rpc_client = RpcClient::from_uri(api_uri.as_str());

    let result = match matches.subcommand() {
        #[cfg(unix)]
        ("tui", _) => TuiSubCommand::new(
            api_uri.to_string(),
            index_dir.clone(),
            index_controller.clone(),
        )
        .start(),
        ("rpc", Some(sub_matches)) => RpcSubCommand::new(&mut rpc_client).process(&sub_matches),

        #[cfg(feature = "local")]
        ("local", Some(sub_matches)) => {
            LocalSubCommand::new(&mut rpc_client, resource_dir.clone()).process(&sub_matches)
        }

        ("wallet", Some(sub_matches)) => WalletSubCommand::new(
            &mut rpc_client,
            None,
            index_dir.clone(),
            index_controller.clone(),
            false,
        )
        .process(&sub_matches),
        _ => {
            if let Err(err) =
                InteractiveEnv::from_config(ckb_cli_dir, config, index_controller.clone())
                    .and_then(|mut env| env.start())
            {
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
            printer.eprintln(&err, color);
            index_controller.shutdown();
            process::exit(1);
        }
    }
    Ok(())
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
        code_name: None,
        major,
        minor,
        patch,
        dash_pre,
        commit_describe,
        commit_date,
    }
}

pub fn build_cli<'a>(version_short: &'a str, version_long: &'a str) -> App<'a, 'a> {
    let app = App::new("ckb-cli")
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
                .validator(|input| UrlParser.validate(input))
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
        );

    #[cfg(feature = "local")]
    let app = app.subcommand(LocalSubCommand::subcommand());

    #[cfg(unix)]
    let app = app.subcommand(SubCommand::with_name("tui").about("Enter TUI mode"));

    app
}

pub fn build_interactive() -> App<'static, 'static> {
    let app = App::new("interactive")
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
                        .validator(|input| UrlParser.validate(input))
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
        .subcommand(WalletSubCommand::subcommand());

    #[cfg(feature = "local")]
    let app = app.subcommand(LocalSubCommand::subcommand());

    app
}
