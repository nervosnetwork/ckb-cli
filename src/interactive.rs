use std::fs;
use std::io;
use std::io::Write;
use std::path::PathBuf;

use ansi_term::Colour::{Blue, Green};
use ckb_core::service::Request;
use crossbeam_channel::Sender;
use regex::Regex;
use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::{Cmd, CompletionType, Config, EditMode, Editor, KeyPress};
use serde_json::json;

use crate::subcommands::{
    CliSubCommand, IndexController, IndexRequest, IndexResponse, LocalScriptSubCommand,
    RpcSubCommand, WalletSubCommand,
};
use crate::utils::completer::CkbCompleter;
use crate::utils::config::GlobalConfig;
use crate::utils::printer::Printer;
use ckb_sdk::rpc::HttpRpcClient;

const ENV_PATTERN: &str = r"\$\{\s*(?P<key>\S+)\s*\}";

/// Interactive command line
pub fn start(
    ckb_cli_dir: PathBuf,
    mut config: GlobalConfig,
    index_controller: IndexController,
) -> io::Result<()> {
    if !ckb_cli_dir.as_path().exists() {
        fs::create_dir(&ckb_cli_dir)?;
    }
    let mut history_file = ckb_cli_dir.clone();
    history_file.push("history");
    let history_file = history_file.to_str().unwrap();
    let mut config_file = ckb_cli_dir.clone();
    config_file.push("config");

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

    Request::call(
        index_controller.sender(),
        IndexRequest::UpdateUrl(config.get_url().to_string()),
    );

    let mut printer = Printer::default();
    if !config.json_format() {
        printer.switch_format();
    }
    println!(
        "{}",
        format!(
            r#"
  _   _   ______   _____   __      __ {}   _____
 | \ | | |  ____| |  __ \  \ \    / / {}  / ____|
 |  \| | | |__    | |__) |  \ \  / /  {} | (___
 | . ` | |  __|   |  _  /    \ \/ /   {}  \___ \
 | |\  | | |____  | | \ \     \  /    {}  ____) |
 |_| \_| |______| |_|  \_\     \/     {} |_____/
"#,
            Green.bold().paint(r#"  ____  "#),
            Green.bold().paint(r#" / __ \ "#),
            Green.bold().paint(r#"| |  | |"#),
            Green.bold().paint(r#"| |  | |"#),
            Green.bold().paint(r#"| |__| |"#),
            Green.bold().paint(r#" \____/ "#),
        )
    );
    config.print();
    start_rustyline(
        &mut config,
        &mut printer,
        &config_file,
        history_file,
        index_controller.sender().clone(),
    )
}

pub fn start_rustyline(
    config: &mut GlobalConfig,
    printer: &mut Printer,
    config_file: &PathBuf,
    history_file: &str,
    index_sender: Sender<Request<IndexRequest, IndexResponse>>,
) -> io::Result<()> {
    let env_regex = Regex::new(ENV_PATTERN).unwrap();
    let parser = crate::build_interactive();
    let colored_prompt = Blue.bold().paint("CKB> ").to_string();
    let prompt = {
        #[cfg(unix)]
        {
            &colored_prompt
        }
        #[cfg(not(unix))]
        {
            "CKB> "
        }
    };
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
        match rl.readline(prompt) {
            Ok(line) => {
                match handle_command(
                    line.as_str(),
                    config,
                    printer,
                    &parser,
                    &env_regex,
                    config_file,
                    &mut rpc_client,
                    &index_sender,
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
    index_sender: &Sender<Request<IndexRequest, IndexResponse>>,
) -> Result<bool, String> {
    let args = match shell_words::split(config.replace_cmd(&env_regex, line).as_str()) {
        Ok(args) => args,
        Err(e) => return Err(e.to_string()),
    };

    match parser.clone().get_matches_from_safe(args) {
        Ok(matches) => match matches.subcommand() {
            ("config", Some(m)) => {
                m.value_of("url").and_then(|url| {
                    Request::call(&index_sender, IndexRequest::UpdateUrl(url.to_string()));
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
                let value = WalletSubCommand::new(rpc_client, index_sender.clone())
                    .process(&sub_matches)?;
                printer.println(&value, config.color());
                Ok(())
            }
            // TODO: move to local later
            ("script", Some(sub_matches)) => {
                let value = LocalScriptSubCommand::new(rpc_client, "resource".into())
                    .process(&sub_matches)?;
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
