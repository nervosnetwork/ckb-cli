use std::fs;
use std::io;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ansi_term::Colour::{Blue, Green};
use ckb_core::{block::Block, service::Request};
use jsonrpc_types::BlockNumber;
use regex::Regex;
use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::{Cmd, CompletionType, Config, EditMode, Editor, KeyPress};
use serde_json::json;

use crate::subcommands::{
    CliSubCommand, IndexController, IndexRequest, LocalSubCommand, RpcSubCommand, WalletSubCommand,
};
use crate::utils::completer::CkbCompleter;
use crate::utils::config::GlobalConfig;
use crate::utils::printer::Printer;
use ckb_sdk::{GenesisInfo, HttpRpcClient};

const ENV_PATTERN: &str = r"\$\{\s*(?P<key>\S+)\s*\}";

/// Interactive command line
pub struct InteractiveEnv {
    config: GlobalConfig,
    printer: Printer,
    config_file: PathBuf,
    resource_dir: PathBuf,
    history_file: PathBuf,
    index_dir: PathBuf,
    parser: clap::App<'static, 'static>,
    rpc_client: HttpRpcClient,
    index_controller: IndexController,
    genesis_info: Option<GenesisInfo>,
}

impl InteractiveEnv {
    pub fn from_config(
        ckb_cli_dir: PathBuf,
        mut config: GlobalConfig,
        index_controller: IndexController,
    ) -> io::Result<InteractiveEnv> {
        if !ckb_cli_dir.as_path().exists() {
            fs::create_dir(&ckb_cli_dir)?;
        }
        let mut history_file = ckb_cli_dir.clone();
        history_file.push("history");
        let mut config_file = ckb_cli_dir.clone();
        config_file.push("config");
        let mut resource_dir = ckb_cli_dir.clone();
        resource_dir.push("resource");
        let mut index_dir = ckb_cli_dir.clone();
        index_dir.push("index");

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

        let parser = crate::build_interactive();
        let rpc_client = HttpRpcClient::from_uri(config.get_url());
        Ok(InteractiveEnv {
            config,
            printer,
            config_file,
            resource_dir,
            index_dir,
            history_file,
            parser,
            rpc_client,
            index_controller,
            genesis_info: None,
        })
    }

    pub fn start(&mut self) -> io::Result<()> {
        self.print_logo();
        self.config.print();

        let env_regex = Regex::new(ENV_PATTERN).unwrap();
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

        let rl_mode = |rl: &mut Editor<CkbCompleter>, is_list: bool, is_emacs: bool| {
            if is_list {
                rl.set_completion_type(CompletionType::List)
            } else {
                rl.set_completion_type(CompletionType::Circular)
            }

            if is_emacs {
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
        let helper = CkbCompleter::new(self.parser.clone());
        let mut rl = Editor::with_config(rl_config);
        rl.set_helper(Some(helper));
        rl.bind_sequence(KeyPress::Meta('N'), Cmd::HistorySearchForward);
        rl.bind_sequence(KeyPress::Meta('P'), Cmd::HistorySearchBackward);
        if rl.load_history(&self.history_file).is_err() {
            eprintln!("No previous history.");
        }

        Request::call(
            self.index_controller.sender(),
            IndexRequest::UpdateUrl(self.config.get_url().to_string()),
        );
        let mut last_save_history = Instant::now();
        loop {
            rl_mode(
                &mut rl,
                self.config.completion_style(),
                self.config.edit_style(),
            );
            match rl.readline(prompt) {
                Ok(line) => {
                    match self.handle_command(line.as_str(), &env_regex) {
                        Ok(true) => {
                            break;
                        }
                        Ok(false) => {}
                        Err(err) => {
                            self.printer.eprintln(&err.to_string(), true);
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

            if last_save_history.elapsed() >= Duration::from_secs(120) {
                if let Err(err) = rl.save_history(&self.history_file) {
                    eprintln!("Save command history failed: {}", err);
                    break;
                }
                last_save_history = Instant::now();
            }
        }
        if let Err(err) = rl.save_history(&self.history_file) {
            eprintln!("Save command history failed: {}", err);
        }
        Ok(())
    }

    fn print_logo(&mut self) {
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
    }

    fn genesis_info(&mut self) -> Result<GenesisInfo, String> {
        if self.genesis_info.is_none() {
            let genesis_block: Block = self
                .rpc_client
                .get_block_by_number(BlockNumber(0))
                .call()
                .map_err(|err| err.to_string())?
                .0
                .expect("Can not get genesis block?")
                .into();
            self.genesis_info = Some(GenesisInfo::from_block(&genesis_block)?);
        }
        Ok(self.genesis_info.clone().unwrap())
    }

    fn handle_command(&mut self, line: &str, env_regex: &Regex) -> Result<bool, String> {
        let args = match shell_words::split(self.config.replace_cmd(&env_regex, line).as_str()) {
            Ok(args) => args,
            Err(e) => return Err(e.to_string()),
        };

        match self.parser.clone().get_matches_from_safe(args) {
            Ok(matches) => match matches.subcommand() {
                ("config", Some(m)) => {
                    m.value_of("url").and_then(|url| {
                        let index_sender = self.index_controller.sender();
                        Request::call(index_sender, IndexRequest::UpdateUrl(url.to_string()));
                        self.config.set_url(url.to_string());
                        self.rpc_client = HttpRpcClient::from_uri(self.config.get_url());
                        self.genesis_info = None;
                        Some(())
                    });
                    if m.is_present("color") {
                        self.config.switch_color();
                    }

                    if m.is_present("json") {
                        self.printer.switch_format();
                        self.config.switch_format();
                    }

                    if m.is_present("debug") {
                        self.config.switch_debug();
                    }

                    if m.is_present("edit_style") {
                        self.config.switch_edit_style();
                    }

                    if m.is_present("completion_style") {
                        self.config.switch_completion_style();
                    }

                    self.config.print();
                    let mut file = fs::File::create(self.config_file.as_path())
                        .map_err(|err| format!("open config error: {:?}", err))?;
                    let content = serde_json::to_string_pretty(&json!({
                        "url": self.config.get_url().to_string(),
                        "color": self.config.color(),
                        "debug": self.config.debug(),
                        "json_format": self.config.json_format(),
                        "completion_style": self.config.completion_style(),
                        "edit_style": self.config.edit_style(),
                    }))
                    .unwrap();
                    file.write_all(content.as_bytes())
                        .map_err(|err| format!("save config error: {:?}", err))?;
                    Ok(())
                }
                ("set", Some(m)) => {
                    let key = m.value_of("key").unwrap().to_owned();
                    let value = m.value_of("value").unwrap().to_owned();
                    self.config.set(key, serde_json::Value::String(value));
                    Ok(())
                }
                ("get", Some(m)) => {
                    let key = m.value_of("key");
                    self.printer
                        .println(&self.config.get(key).clone(), self.config.color());
                    Ok(())
                }
                ("info", _) => {
                    self.config.print();
                    Ok(())
                }
                ("rpc", Some(sub_matches)) => {
                    let value = RpcSubCommand::new(&mut self.rpc_client).process(&sub_matches)?;
                    self.printer.println(&value, self.config.color());
                    Ok(())
                }
                ("wallet", Some(sub_matches)) => {
                    let genesis_info = self.genesis_info()?;
                    let value = WalletSubCommand::new(
                        &mut self.rpc_client,
                        Some(genesis_info),
                        self.index_dir.clone(),
                        self.index_controller.clone(),
                        true,
                    )
                    .process(&sub_matches)?;
                    self.printer.println(&value, self.config.color());
                    Ok(())
                }
                ("local", Some(sub_matches)) => {
                    let genesis_info = self.genesis_info()?;
                    let value = LocalSubCommand::new(
                        &mut self.rpc_client,
                        Some(genesis_info),
                        self.resource_dir.clone(),
                    )
                    .process(&sub_matches)?;
                    self.printer.println(&value, self.config.color());
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
}
