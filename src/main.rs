use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::iter::FromIterator;
use std::process;
use std::sync::Arc;

use ckb_build_info::Version;
use ckb_sdk::HttpRpcClient;
use ckb_util::RwLock;
use clap::crate_version;
use clap::{App, AppSettings, Arg, SubCommand};
#[cfg(unix)]
use subcommands::TuiSubCommand;

use interactive::InteractiveEnv;
use subcommands::{
    start_index_thread, AccountSubCommand, CliSubCommand, IndexThreadState, LocalSubCommand,
    RpcSubCommand, WalletSubCommand,
};
use utils::{
    arg_parser::{ArgParser, UrlParser},
    config::GlobalConfig,
    other::get_key_store,
    printer::{ColorWhen, OutputFormat},
};

mod interactive;
mod subcommands;
mod utils;

fn main() -> Result<(), io::Error> {
    env_logger::init();

    #[cfg(not(unix))]
    let _enabled = ansi_term::enable_ansi_support();

    let version = get_version();
    let version_short = version.short();
    let version_long = version.long();
    let matches = build_cli(&version_short, &version_long).get_matches();

    let mut env_map: HashMap<String, String> = HashMap::from_iter(env::vars());
    let api_uri_opt = matches
        .value_of("url")
        .map(ToOwned::to_owned)
        .or_else(|| env_map.remove("API_URL"));

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

    let mut output_format = OutputFormat::Yaml;
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
        output_format =
            OutputFormat::from_str(&configs["output_format"].as_str().unwrap_or("yaml"))
                .unwrap_or(OutputFormat::Yaml);
        config.set_output_format(output_format);
        config.set_completion_style(configs["completion_style"].as_bool().unwrap_or(true));
        config.set_edit_style(configs["edit_style"].as_bool().unwrap_or(true));
    }

    let api_uri = config.get_url().to_string();
    let index_controller = start_index_thread(api_uri.as_str(), index_dir.clone(), index_state);
    let mut rpc_client = HttpRpcClient::from_uri(api_uri.as_str());

    let color = ColorWhen::new(!matches.is_present("no-color")).color();
    if let Some(format) = matches.value_of("output-format") {
        output_format = OutputFormat::from_str(format).unwrap();
    }
    let result = match matches.subcommand() {
        #[cfg(unix)]
        ("tui", _) => TuiSubCommand::new(
            api_uri.to_string(),
            index_dir.clone(),
            index_controller.clone(),
        )
        .start(),
        ("rpc", Some(sub_matches)) => {
            RpcSubCommand::new(&mut rpc_client).process(&sub_matches, output_format, color)
        }
        ("local", Some(sub_matches)) => get_key_store(&ckb_cli_dir).and_then(|mut key_store| {
            LocalSubCommand::new(&mut rpc_client, &mut key_store, None, resource_dir.clone())
                .process(&sub_matches, output_format, color)
        }),
        ("account", Some(sub_matches)) => get_key_store(&ckb_cli_dir).and_then(|mut key_store| {
            AccountSubCommand::new(&mut rpc_client, &mut key_store, None).process(
                &sub_matches,
                output_format,
                color,
            )
        }),
        ("wallet", Some(sub_matches)) => get_key_store(&ckb_cli_dir).and_then(|mut key_store| {
            WalletSubCommand::new(
                &mut rpc_client,
                &mut key_store,
                None,
                index_dir.clone(),
                index_controller.clone(),
                false,
            )
            .process(&sub_matches, output_format, color)
        }),
        _ => {
            if let Err(err) =
                InteractiveEnv::from_config(ckb_cli_dir, config, index_controller.clone())
                    .and_then(|mut env| env.start())
            {
                eprintln!("Process error: {}", err);
                index_controller.shutdown();
                process::exit(1);
            }
            index_controller.shutdown();
            process::exit(0)
        }
    };

    match result {
        Ok(message) => {
            println!("{}", message);
            index_controller.shutdown();
        }
        Err(err) => {
            eprintln!("{}", err);
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
        .subcommand(AccountSubCommand::subcommand("account"))
        .subcommand(WalletSubCommand::subcommand())
        .arg(
            Arg::with_name("url")
                .long("url")
                .takes_value(true)
                .validator(|input| UrlParser.validate(input))
                .help("RPC API server url"),
        )
        .arg(
            Arg::with_name("output-format")
                .long("output-format")
                .takes_value(true)
                .possible_values(&["yaml", "json"])
                .default_value("yaml")
                .global(true)
                .help("Select output format"),
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

    let app = app.subcommand(LocalSubCommand::subcommand());

    #[cfg(unix)]
    let app = app.subcommand(SubCommand::with_name("tui").about("Enter TUI mode"));

    app
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
                    Arg::with_name("output-format")
                        .long("output-format")
                        .takes_value(true)
                        .possible_values(&["yaml", "json"])
                        .default_value("yaml")
                        .help("Select output format"),
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
        .subcommand(AccountSubCommand::subcommand("account"))
        .subcommand(WalletSubCommand::subcommand())
        .subcommand(LocalSubCommand::subcommand())
}
