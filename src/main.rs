use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process;

use ckb_build_info::Version;
use clap::crate_version;
use clap::{App, AppSettings, Arg};
use dialoguer::{theme::ColorfulTheme, Select};

use interactive::InteractiveEnv;
use plugin::PluginManager;
use subcommands::{
    AccountSubCommand, ApiServerSubCommand, CliSubCommand, DAOSubCommand, MockTxSubCommand,
    MoleculeSubCommand, PluginSubCommand, PubSubCommand, RpcSubCommand, SudtSubCommand,
    TxSubCommand, UtilSubCommand, WalletSubCommand,
};
use utils::other::get_genesis_info;
use utils::{
    arg_parser::{ArgParser, UrlParser},
    config::{GlobalConfig, DEFAULT_CKB_INDEXER_URL, DEFAULT_CKB_URL},
    other::{check_alerts, get_key_store, get_network_type},
    printer::{is_a_tty, is_term_dumb, ColorWhen, OutputFormat},
    rpc::{HttpRpcClient, RawHttpRpcClient},
};

mod interactive;
mod plugin;
#[allow(clippy::mutable_key_type)]
mod subcommands;
#[allow(clippy::mutable_key_type)]
mod utils;

fn main() -> Result<(), io::Error> {
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
    let ckb_indexer_url_opt = matches
        .value_of("ckb-indexer-url")
        .map(ToOwned::to_owned)
        .or_else(|| env_map.remove("CKB_INDEXER_URL"));
    let local_only = matches.is_present("local-only");

    let ckb_cli_dir = if let Some(dir_string) = env_map.remove("CKB_CLI_HOME") {
        let dir = PathBuf::from(dir_string.as_str());
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }
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

    let mut config = GlobalConfig::new(ckb_url_opt.clone(), ckb_indexer_url_opt.clone());
    let mut config_file = ckb_cli_dir.clone();
    config_file.push("config");

    let mut output_format = OutputFormat::Yaml;
    let configs_opt = if config_file.as_path().exists() {
        let content = fs::read_to_string(&config_file)?;
        let configs: serde_json::Value = serde_json::from_str(content.as_str()).unwrap();
        if ckb_url_opt.is_none() {
            if let Some(value) = configs["url"].as_str() {
                config.set_url(value.to_string());
            }
        }
        if ckb_indexer_url_opt.is_none() {
            if let Some(value) = configs["ckb-indexer-url"].as_str() {
                config.set_ckb_indexer_url(value.to_string());
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
        Some(configs)
    } else {
        None
    };
    // Prompt select a ckb/ckb-indexer url from public servers (testnet/mainnet)
    if !local_only {
        prompt_select_urls(
            &mut config,
            &config_file,
            configs_opt.as_ref(),
            ckb_url_opt.as_ref(),
            ckb_indexer_url_opt.as_ref(),
        )?;
    }

    let ckb_url = config.get_url().to_string();
    let ckb_indexer_url = config.get_ckb_indexer_url().to_string();
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
    let mut key_store = get_key_store(ckb_cli_dir.clone()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Open file based key store error: {}", err),
        )
    })?;
    let mut plugin_mgr = PluginManager::init(&ckb_cli_dir, ckb_url).unwrap();
    let result = match matches.subcommand() {
        ("rpc", Some(sub_matches)) => match sub_matches.subcommand() {
            ("subscribe", Some(sub_sub_matches)) => {
                PubSubCommand::new(output_format, color).process(sub_sub_matches, debug)
            }
            _ => {
                RpcSubCommand::new(&mut rpc_client, &mut raw_rpc_client).process(sub_matches, debug)
            }
        },
        ("account", Some(sub_matches)) => {
            AccountSubCommand::new(&mut plugin_mgr, &mut key_store).process(sub_matches, debug)
        }
        ("mock-tx", Some(sub_matches)) => {
            MockTxSubCommand::new(&mut rpc_client, &mut plugin_mgr, None)
                .process(sub_matches, debug)
        }
        ("tx", Some(sub_matches)) => {
            TxSubCommand::new(&mut rpc_client, &mut plugin_mgr, None).process(sub_matches, debug)
        }
        ("util", Some(sub_matches)) => {
            UtilSubCommand::new(&mut rpc_client, &mut plugin_mgr).process(sub_matches, debug)
        }
        ("server", Some(sub_matches)) => {
            ApiServerSubCommand::new(&mut rpc_client, plugin_mgr, None, ckb_indexer_url.as_str())
                .process(sub_matches, debug)
        }
        ("plugin", Some(sub_matches)) => {
            PluginSubCommand::new(&mut plugin_mgr).process(sub_matches, debug)
        }
        ("molecule", Some(sub_matches)) => MoleculeSubCommand::new().process(sub_matches, debug),
        ("wallet", Some(sub_matches)) => WalletSubCommand::new(
            &mut rpc_client,
            &mut plugin_mgr,
            None,
            ckb_indexer_url.as_str(),
        )
        .process(sub_matches, debug),
        ("dao", Some(sub_matches)) => {
            get_genesis_info(&None, &mut rpc_client).and_then(|genesis_info| {
                DAOSubCommand::new(
                    &mut rpc_client,
                    &mut plugin_mgr,
                    genesis_info,
                    ckb_indexer_url.as_str(),
                )
                .process(sub_matches, debug)
            })
        }
        ("sudt", Some(sub_matches)) => {
            get_genesis_info(&None, &mut rpc_client).and_then(|genesis_info| {
                SudtSubCommand::new(
                    &mut rpc_client,
                    &mut plugin_mgr,
                    genesis_info,
                    ckb_indexer_url.as_str(),
                )
                .process(sub_matches, debug)
            })
        }
        _ => {
            if let Err(err) = InteractiveEnv::from_config(
                ckb_cli_dir,
                config,
                plugin_mgr,
                key_store,
                ckb_indexer_url,
            )
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

fn prompt_select_urls(
    config: &mut GlobalConfig,
    config_file: &Path,
    configs_opt: Option<&serde_json::Value>,
    ckb_url_opt: Option<&String>,
    ckb_indexer_url_opt: Option<&String>,
) -> Result<(), io::Error> {
    if is_a_tty(false)
        && !is_term_dumb()
    // Check if this is the first time set ckb-indexer-url config
        && configs_opt
        .map(|configs| configs.get("ckb-indexer-url").is_none())
        .unwrap_or(true)
    // And not given ckb-indexer-url value by command line args
        && ckb_indexer_url_opt.is_none()
    {
        // For fix hidden cursor problem, see follow issue for more details:
        //   https://github.com/mitsuhiko/dialoguer/issues/77
        ctrlc::set_handler(move || {
            let term = console::Term::stdout();
            let _ = term.show_cursor();
        })
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Set ctrlc handler error: {}", err),
            )
        })?;

        // select ckb url
        {
            let ckb_url_default = ckb_url_opt
                .map(|s| s.as_str())
                .or_else(|| {
                    configs_opt
                        .and_then(|configs| configs.get("url").and_then(|value| value.as_str()))
                })
                .unwrap_or(DEFAULT_CKB_URL);
            let mut selections = vec![
                "https://testnet.ckbapp.dev/rpc",
                "https://mainnet.ckbapp.dev/rpc",
            ];
            for url in [ckb_url_default, DEFAULT_CKB_URL] {
                if !selections.contains(&url) {
                    selections.push(url);
                }
            }
            let selection = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Please select the ckb rpc url")
                .default(0)
                .items(&selections[..])
                .interact()?;
            config.set_url(selections[selection].to_string());
        }

        // select ckb-indexer url
        {
            let ckb_indexer_url_default = configs_opt
                .and_then(|configs| {
                    configs
                        .get("ckb-indexer-url")
                        .and_then(|value| value.as_str())
                })
                .unwrap_or(DEFAULT_CKB_INDEXER_URL);
            let mut selections = vec![
                "https://testnet.ckbapp.dev/indexer",
                "https://mainnet.ckbapp.dev/indexer",
            ];
            for url in [ckb_indexer_url_default, DEFAULT_CKB_INDEXER_URL] {
                if !selections.contains(&url) {
                    selections.push(url);
                }
            }
            let selection = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Please select the ckb-indexer rpc server url")
                .default(0)
                .items(&selections[..])
                .interact()?;
            config.set_ckb_indexer_url(selections[selection].to_string());
        }
        config.save(config_file)?;
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

pub fn build_cli<'a>(version_short: &'a str, version_long: &'a str) -> App<'a> {
    App::new("ckb-cli")
        .version(version_short)
        .long_version(version_long)
        .global_setting(AppSettings::ColoredHelp)
        .global_setting(AppSettings::DeriveDisplayOrder)
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
        .arg(
            Arg::with_name("url")
                .long("url")
                .takes_value(true)
                .validator(|input| UrlParser.validate(input))
                .about("CKB RPC server url.\nThe default value is http://127.0.0.1:8114 \nmainnet public: https://mainnet.ckbapp.dev/rpc \ntestnet public: https://testnet.ckbapp.dev/rpc"),
        )
        .arg(
            Arg::with_name("ckb-indexer-url")
                .long("ckb-indexer-url")
                .takes_value(true)
                .validator(|input| UrlParser.validate(input))
                .about("CKB indexer server RPC url.\nThe default value is http://127.0.0.1:8116 \nmainnet public: https://mainnet.ckbapp.dev/indexer \ntestnet public: https://testnet.ckbapp.dev/indexer"),
        )
        .arg(
            Arg::with_name("output-format")
                .long("output-format")
                .takes_value(true)
                .possible_values(&["yaml", "json"])
                .default_value("yaml")
                .global(true)
                .about("Select output format"),
        )
        .arg(
            Arg::with_name("no-color")
                .long("no-color")
                .global(true)
                .about("Do not highlight(color) output json"),
        )
        .arg(
            Arg::with_name("debug")
                .long("debug")
                .global(true)
                .about("Display request parameters"),
        )
        .arg(
            Arg::with_name("local-only")
                .long("local-only")
                .global(true)
                .about("This is a local only subcommand, do not check alerts and get network type")
        )
}

pub fn build_interactive() -> App<'static> {
    App::new("interactive")
        .version(crate_version!())
        .global_setting(AppSettings::NoBinaryName)
        .global_setting(AppSettings::ColoredHelp)
        .global_setting(AppSettings::DeriveDisplayOrder)
        .global_setting(AppSettings::DisableVersion)
        .subcommand(
            App::new("config")
                .about("Config environment")
                .arg(
                    Arg::with_name("url")
                        .long("url")
                        .validator(|input| UrlParser.validate(input))
                        .takes_value(true)
                        .about("CKB RPC server url.\nThe default value is http://127.0.0.1:8114 \nmainnet public: https://mainnet.ckbapp.dev/rpc \ntestnet public: https://testnet.ckbapp.dev/rpc"),
                )
                .arg(
                    Arg::with_name("ckb-indexer-url")
                        .long("ckb-indexer-url")
                        .takes_value(true)
                        .validator(|input| UrlParser.validate(input))
                        .about("CKB indexer server RPC url.\nThe default value is http://127.0.0.1:8116 \nmainnet public: https://mainnet.ckbapp.dev/indexer \ntestnet public: https://testnet.ckbapp.dev/indexer"),
                )
                .arg(
                    Arg::with_name("color")
                        .long("color")
                        .about("Switch color for rpc interface"),
                )
                .arg(
                    Arg::with_name("debug")
                        .long("debug")
                        .about("Switch debug mode"),
                )
                .arg(
                    Arg::with_name("output-format")
                        .long("output-format")
                        .takes_value(true)
                        .possible_values(&["yaml", "json"])
                        .default_value("yaml")
                        .about("Select output format"),
                )
                .arg(
                    Arg::with_name("completion_style")
                        .long("completion_style")
                        .about("Switch completion style"),
                )
                .arg(
                    Arg::with_name("edit_style")
                        .long("edit_style")
                        .about("Switch edit style"),
                ),
        )
        .subcommand(App::new("info").about("Display global variables"))
        .subcommand(
            App::new("exit")
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
}
