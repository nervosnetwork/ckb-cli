use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process;

use ckb_build_info::Version;
use clap::crate_version;
use clap::{Arg, ColorChoice, Command};

use interactive::InteractiveEnv;
use plugin::PluginManager;
use subcommands::{
    AccountSubCommand, ApiServerSubCommand, CliSubCommand, DAOSubCommand, DeploySubCommand,
    MockTxSubCommand, MoleculeSubCommand, PluginSubCommand, PubSubCommand, RpcSubCommand,
    SudtSubCommand, TxSubCommand, UtilSubCommand, WalletSubCommand,
};
use utils::other::get_genesis_info;
use utils::arg::ArgValidatorExt;
use utils::{
    arg_parser::{ArgMatchesExt, ArgParser, UrlParser},
    config::GlobalConfig,
    other::{check_alerts, get_key_store, get_network_type},
    printer::{ColorWhen, OutputFormat},
    rpc::{HttpRpcClient, RawHttpRpcClient},
};

mod interactive;
mod plugin;
#[allow(clippy::mutable_key_type)]
mod subcommands;
#[allow(clippy::mutable_key_type)]
mod utils;

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    env_logger::init();

    #[cfg(unix)]
    let ansi_support = true;
    #[cfg(not(unix))]
    let ansi_support = ansi_term::enable_ansi_support().is_ok();

    let version = get_version();
    // TODO:
    //   It will not print newline with --version or -V, it's a bug of clap. https://github.com/clap-rs/clap/issues/1960
    //   revisit here when clap updated.
    let version_short = format!("{}\n", version.short());
    let version_long = format!("{}\n", version.long());
    let matches = build_cli(version_short.as_str(), version_long.as_str()).get_matches();

    let mut env_map: HashMap<String, String> = env::vars().collect();
    let ckb_url_opt = matches
        .value_of("url")
        .map(ToOwned::to_owned)
        .or_else(|| env_map.remove("API_URL"));
    let local_only = matches.is_present("local-only");

    let ckb_cli_dir = if let Some(dir_string) = env_map.remove("CKB_CLI_HOME") {
        let dir = PathBuf::from(dir_string.as_str());
        if dir.exists() && !dir.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a directory", dir_string),
            ));
        }
        dir
    } else {
        let mut dir = dirs::home_dir().unwrap();
        dir.push(".ckb-cli");
        dir
    };
    if !ckb_cli_dir.exists() {
        fs::create_dir_all(&ckb_cli_dir)?;
    }

    let mut config = GlobalConfig::new(ckb_url_opt.clone());
    let mut config_file = ckb_cli_dir.clone();
    config_file.push("config");

    let mut output_format = OutputFormat::Yaml;
    if config_file.as_path().exists() {
        let content = fs::read_to_string(&config_file)?;
        let configs: serde_json::Value = serde_json::from_str(content.as_str()).unwrap();
        if ckb_url_opt.is_none() {
            if let Some(value) = configs["url"].as_str() {
                config.set_url(value.to_string());
            }
        }
        config.set_debug(configs["debug"].as_bool().unwrap_or(false));
        config.set_no_sync(configs["no-sync"].as_bool().unwrap_or(false));
        config.set_color(ansi_support && configs["color"].as_bool().unwrap_or(true));
        output_format = OutputFormat::from_str(configs["output_format"].as_str().unwrap_or("yaml"))
            .unwrap_or(OutputFormat::Yaml);
        config.set_output_format(output_format);
        config.set_completion_style(configs["completion_style"].as_bool().unwrap_or(true));
        config.set_edit_style(configs["edit_style"].as_bool().unwrap_or(true));
    }

    let ckb_url = config.get_url().to_string();
    let mut rpc_client = HttpRpcClient::new(ckb_url.clone());
    let mut raw_rpc_client = RawHttpRpcClient::new(ckb_url.as_str());

    if !local_only {
        check_alerts(&mut rpc_client);
        config.set_network(get_network_type(&mut rpc_client).ok());
    }

    let color = ColorWhen::new(!matches.is_present("no-color")).color();
    let debug = matches.is_present("debug");

    if let Some(format) = matches.value_of("output-format") {
        output_format = OutputFormat::from_str(format).unwrap();
    }
    let mut key_store = get_key_store(ckb_cli_dir.clone())
        .map_err(|err| io::Error::other(format!("Open file based key store error: {}", err)))?;
    let mut plugin_mgr = PluginManager::init(&ckb_cli_dir, ckb_url).unwrap();
    let result = match matches.subcommand() {
        Some(("rpc", sub_matches)) => match sub_matches.subcommand() {
            Some(("subscribe", sub_sub_matches)) => {
                PubSubCommand::new(output_format, color).process(sub_sub_matches, debug)
            }
            _ => {
                RpcSubCommand::new(&mut rpc_client, &mut raw_rpc_client).process(sub_matches, debug)
            }
        },
        Some(("account", sub_matches)) => {
            AccountSubCommand::new(&mut plugin_mgr, &mut key_store).process(sub_matches, debug)
        }
        Some(("mock-tx", sub_matches)) => {
            MockTxSubCommand::new(&mut rpc_client, &mut plugin_mgr, None)
                .process(sub_matches, debug)
        }
        Some(("tx", sub_matches)) => {
            TxSubCommand::new(&mut rpc_client, &mut plugin_mgr, None).process(sub_matches, debug)
        }
        Some(("util", sub_matches)) => {
            UtilSubCommand::new(&mut rpc_client, &mut plugin_mgr).process(sub_matches, debug)
        }
        Some(("server", sub_matches)) => {
            ApiServerSubCommand::new(&mut rpc_client, plugin_mgr, None).process(sub_matches, debug)
        }
        Some(("plugin", sub_matches)) => {
            PluginSubCommand::new(&mut plugin_mgr).process(sub_matches, debug)
        }
        Some(("molecule", sub_matches)) => MoleculeSubCommand::new().process(sub_matches, debug),
        Some(("wallet", sub_matches)) => {
            WalletSubCommand::new(&mut rpc_client, &mut plugin_mgr, None)
                .process(sub_matches, debug)
        }
        Some(("dao", sub_matches)) => {
            get_genesis_info(&None, &mut rpc_client).and_then(|genesis_info| {
                DAOSubCommand::new(&mut rpc_client, &mut plugin_mgr, genesis_info)
                    .process(sub_matches, debug)
            })
        }
        Some(("sudt", sub_matches)) => {
            get_genesis_info(&None, &mut rpc_client).and_then(|genesis_info| {
                SudtSubCommand::new(&mut rpc_client, &mut plugin_mgr, genesis_info)
                    .process(sub_matches, debug)
            })
        }
        Some(("deploy", sub_matches)) => {
            get_genesis_info(&None, &mut rpc_client).and_then(|genesis_info| {
                DeploySubCommand::new(&mut rpc_client, &mut plugin_mgr, genesis_info)
                    .process(sub_matches, debug)
            })
        }
        _ => {
            if let Err(err) =
                InteractiveEnv::from_config(ckb_cli_dir, config, plugin_mgr, key_store)
                    .and_then(|mut env| env.start())
            {
                eprintln!("Process error: {}", err);
                process::exit(1);
            }
            process::exit(0)
        }
    };

    match result {
        Ok(output) => {
            output.print(output_format, color);
        }
        Err(err) => {
            eprintln!("{}", err);
            process::exit(1);
        }
    }
    Ok(())
}

pub fn get_version() -> Version {
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
        if pre.is_empty() {
            pre.to_string()
        } else {
            "-".to_string() + pre
        }
    };

    let commit_describe = option_env!("COMMIT_DESCRIBE").map(ToString::to_string);
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

pub fn build_cli(version_short: &str, version_long: &str) -> Command {
    let version_short: &'static str = Box::leak(version_short.to_owned().into_boxed_str());
    let version_long: &'static str = Box::leak(version_long.to_owned().into_boxed_str());
    Command::new("ckb-cli")
        .version(version_short)
        .long_version(version_long)
        .color(ColorChoice::Auto)
        .subcommand(RpcSubCommand::subcommand().subcommand(PubSubCommand::subcommand()))
        .subcommand(AccountSubCommand::subcommand("account"))
        .subcommand(MockTxSubCommand::subcommand("mock-tx"))
        .subcommand(TxSubCommand::subcommand("tx"))
        .subcommand(ApiServerSubCommand::subcommand("server"))
        .subcommand(UtilSubCommand::subcommand("util"))
        .subcommand(PluginSubCommand::subcommand("plugin"))
        .subcommand(MoleculeSubCommand::subcommand("molecule"))
        .subcommand(WalletSubCommand::subcommand())
        .subcommand(DAOSubCommand::subcommand())
        .subcommand(SudtSubCommand::subcommand("sudt"))
        .subcommand(DeploySubCommand::subcommand("deploy"))
        .arg(

            Arg::new("url")
                .long("url")
                .num_args(1)
                .validator(|input| UrlParser.validate(input))
                .help(
                    r#"CKB RPC server url.
The default value is http://127.0.0.1:8114
You may also use some public available nodes, check the list of public nodes: https://github.com/nervosnetwork/ckb/wiki/Public-JSON-RPC-nodes"#,
                ),
        )
        .arg(
            Arg::new("output-format")
                .long("output-format")
                .num_args(1)
                .value_parser(["yaml", "json"])
                .default_value("yaml")
                .global(true)
                .help("Select output format"),
        )
        .arg(
            Arg::new("no-color")
                .long("no-color")
                .global(true)
                .help("Do not highlight(color) output json"),
        )
        .arg(
            Arg::new("debug")
                .long("debug")
                .global(true)
                .help("Display request parameters"),
        )
        .arg(
            Arg::new("local-only")
                .long("local-only")
                .global(true)
                .help("This is a local only subcommand, do not check alerts and get network type"),
        )
}

pub fn build_interactive() -> Command {
    Command::new("interactive")
        .version(crate_version!())
        .no_binary_name(true)
        .color(ColorChoice::Auto)
        .disable_version_flag(true)
        .subcommand(
            Command::new("config")
                .about("Config environment")
                .arg(
                    Arg::new("url")
                        .long("url")
                        .validator(|input| UrlParser.validate(input))
                        .num_args(1)
                        .help(
                            r#"CKB RPC server url.
The default value is http://127.0.0.1:8114
You may also use some public available nodes, check the list of public nodes: https://github.com/nervosnetwork/ckb/wiki/Public-JSON-RPC-nodes"#,
                        ),
                )
                .arg(
                    Arg::new("color")
                        .long("color")
                        .help("Switch color for rpc interface"),
                )
                .arg(
                    Arg::new("debug")
                        .long("debug")
                        .help("Switch debug mode"),
                )
                .arg(
                    Arg::new("output-format")
                        .long("output-format")
                        .num_args(1)
                        .value_parser(["yaml", "json"])
                        .default_value("yaml")
                        .help("Select output format"),
                )
                .arg(
                    Arg::new("completion_style")
                        .long("completion_style")
                        .help("Switch completion style"),
                )
                .arg(
                    Arg::new("edit_style")
                        .long("edit_style")
                        .help("Switch edit style"),
                ),
        )
        .subcommand(Command::new("info").about("Display global variables"))
        .subcommand(
            Command::new("exit")
                .visible_alias("quit")
                .about("Exit the interactive interface"),
        )
        .subcommand(RpcSubCommand::subcommand())
        .subcommand(AccountSubCommand::subcommand("account"))
        .subcommand(MockTxSubCommand::subcommand("mock-tx"))
        .subcommand(TxSubCommand::subcommand("tx"))
        .subcommand(UtilSubCommand::subcommand("util"))
        .subcommand(PluginSubCommand::subcommand("plugin"))
        .subcommand(MoleculeSubCommand::subcommand("molecule"))
        .subcommand(WalletSubCommand::subcommand())
        .subcommand(DAOSubCommand::subcommand())
        .subcommand(SudtSubCommand::subcommand("sudt"))
        .subcommand(DeploySubCommand::subcommand("deploy"))
}
