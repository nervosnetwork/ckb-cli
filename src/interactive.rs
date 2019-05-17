use std::path::PathBuf;
use std::io;
use std::io::{Write, Read};
use std::fs;

use serde_json::{json};

use ansi_term::Colour::{Green, Blue};

use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::{Cmd, CompletionType, Config, EditMode, Editor, KeyPress};

use regex::{Regex};

use crate::subcommands::{RpcSubCommand, WalletSubCommand, CliSubCommand};
use crate::utils::config::GlobalConfig;
use crate::utils::printer::Printer;
use crate::utils::rpc_client::HttpRpcClient;
use crate::utils::completer::CkbCompleter;

const ASCII_WORD: &str = r#"
  _   _   ______   _____   __      __   ____     _____
 | \ | | |  ____| |  __ \  \ \    / /  / __ \   / ____|
 |  \| | | |__    | |__) |  \ \  / /  | |  | | | (___
 | . ` | |  __|   |  _  /    \ \/ /   | |  | |  \___ \
 | |\  | | |____  | | \ \     \  /    | |__| |  ____) |
 |_| \_| |______| |_|  \_\     \/      \____/  |_____/
"#;
const ENV_PATTERN: &str = r"\$\{\s*(?P<key>\S+)\s*\}";


/// Interactive command line
pub fn start(url: &str) -> io::Result<()> {
    let mut config = GlobalConfig::new(url.to_string());

    let mut ckb_cli_dir = dirs::home_dir().unwrap();
    ckb_cli_dir.push(".ckb-cli");
    if !ckb_cli_dir.as_path().exists() {
        fs::create_dir(&ckb_cli_dir)?;
    }
    let mut history_file = ckb_cli_dir.clone();
    history_file.push("history");
    let history_file = history_file.to_str().unwrap();
    let mut config_file = ckb_cli_dir.clone();
    config_file.push("config");
    if config_file.as_path().exists() {
        let mut file = fs::File::open(&config_file)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        let configs: serde_json::Value = serde_json::from_str(content.as_str()).unwrap();
        if let Some(value) = configs["url"].as_str() {
            config.set_url(value.to_string());
        }
        config.set_debug(configs["debug"].as_bool().unwrap_or(false));
        config.set_color(configs["color"].as_bool().unwrap_or(true));
        config.set_json_format(configs["json_format"].as_bool().unwrap_or(true));
        config.set_completion_style(configs["completion_style"].as_bool().unwrap_or(true));
        config.set_edit_style(configs["edit_style"].as_bool().unwrap_or(true));
    }

    let mut env_file = ckb_cli_dir.clone();
    env_file.push("env_vars");
    if env_file.as_path().exists() {
        let file = fs::File::open(&env_file)?;
        let env_vars_json = serde_json::from_reader(file).unwrap_or(json!(null));
        match env_vars_json {
            serde_json::Value::Object(env_vars) => config.add_env_vars(env_vars),
            _ => eprintln!("Parse environment variable file failed."),
        }
    }

    let mut printer = Printer::default();
    if !config.json_format() {
        printer.switch_format();
    }
    println!("{}", Blue.bold().paint(ASCII_WORD));
    config.print();
    start_rustyline(&mut config, &mut printer, &config_file, history_file)
}

pub fn start_rustyline(
    config: &mut GlobalConfig,
    printer: &mut Printer,
    config_file: &PathBuf,
    history_file: &str,
) -> io::Result<()> {
    let env_regex = Regex::new(ENV_PATTERN).unwrap();
    let parser = crate::build_interactive();
    let colored_prompt = Green.bold().paint("ckb> ").to_string();
    let mut rpc_client = HttpRpcClient::from_uri(config.get_url());

    let rl_mode = |rl: &mut Editor<CkbCompleter>, config: &GlobalConfig| {
        if config.completion_style() {
            rl.set_completion_type(CompletionType::List)
        } else {
            rl.set_completion_type(CompletionType::Circular)
        }

        if config.edit_style() {
            rl.set_edit_mode(EditMode::Emacs)
        } else {
            rl.set_edit_mode(EditMode::Vi)
        }
    };

    let rl_config = Config::builder()
        .history_ignore_space(true)
        .completion_type(CompletionType::List)
        .edit_mode(EditMode::Emacs)
        .build();
    let helper = CkbCompleter::new(parser.clone());
    let mut rl = Editor::with_config(rl_config);
    rl.set_helper(Some(helper));
    rl.bind_sequence(KeyPress::Meta('N'), Cmd::HistorySearchForward);
    rl.bind_sequence(KeyPress::Meta('P'), Cmd::HistorySearchBackward);
    if rl.load_history(history_file).is_err() {
        eprintln!("No previous history.");
    }

    loop {
        rl_mode(&mut rl, &config);
        match rl.readline(&colored_prompt) {
            Ok(line) => {
                match handle_command(
                    line.as_str(),
                    config,
                    printer,
                    &parser,
                    &env_regex,
                    config_file,
                    &mut rpc_client,
                ) {
                    Ok(true) => {
                        break;
                    }
                    Ok(false) => {}
                    Err(err) => {
                        printer.eprintln(&err.to_string(), true);
                    }
                }
                rl.add_history_entry(line.as_ref());
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                break;
            }
        }
    }
    if let Err(err) = rl.save_history(history_file) {
        eprintln!("Save command history failed: {}", err);
    }
    Ok(())
}


fn handle_command(
    line: &str,
    config: &mut GlobalConfig,
    printer: &mut Printer,
    parser: &clap::App<'static, 'static>,
    env_regex: &Regex,
    config_file: &PathBuf,
    rpc_client: &mut HttpRpcClient,
) -> Result<bool, String> {
    let args = match shell_words::split(config.replace_cmd(&env_regex, line).as_str()) {
        Ok(args) => args,
        Err(e) => return Err(e.to_string()),
    };

    match parser.clone().get_matches_from_safe(args) {
        Ok(matches) => match matches.subcommand() {
            ("switch", Some(m)) => {
                m.value_of("url").and_then(|url| {
                    config.set_url(url.to_string());
                    *rpc_client = HttpRpcClient::from_uri(config.get_url());
                    Some(())
                });
                if m.is_present("color") {
                    config.switch_color();
                }

                if m.is_present("json") {
                    printer.switch_format();
                    config.switch_format();
                }

                if m.is_present("debug") {
                    config.switch_debug();
                }

                if m.is_present("edit_style") {
                    config.switch_edit_style();
                }

                if m.is_present("completion_style") {
                    config.switch_completion_style();
                }

                config.print();
                let mut file = fs::File::create(config_file.as_path())
                    .map_err(|err| format!("open config error: {:?}", err))?;
                let content = serde_json::to_string_pretty(&json!({
                    "url": config.get_url().clone(),
                    "color": config.color(),
                    "debug": config.debug(),
                    "json_format": config.json_format(),
                    "completion_style": config.completion_style(),
                    "edit_style": config.edit_style(),
                }))
                .unwrap();
                file.write_all(content.as_bytes())
                    .map_err(|err| format!("save config error: {:?}", err))?;
                Ok(())
            }
            ("set", Some(m)) => {
                let key = m.value_of("key").unwrap().to_owned();
                let value = m.value_of("value").unwrap().to_owned();
                config.set(key, serde_json::Value::String(value));
                Ok(())
            }
            ("get", Some(m)) => {
                let key = m.value_of("key");
                printer.println(&config.get(key).clone(), config.color());
                Ok(())
            }
            ("info", _) => {
                config.print();
                Ok(())
            }
            ("rpc", Some(sub_matches)) => {
                let value = RpcSubCommand::new(rpc_client).process(&sub_matches)?;
                printer.println(&value, config.color());
                Ok(())
            }
            ("wallet", Some(sub_matches)) => {
                let value = WalletSubCommand::new(rpc_client).process(&sub_matches)?;
                printer.println(&value, config.color());
                Ok(())
            }
            ("exit", _) => {
                return Ok(true);
            }
            _ => Ok(()),
        },
        Err(err) => Err(err.to_string()),
    }
    .map(|_| false)
}
