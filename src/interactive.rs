use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ansi_term::Colour::Green;
use ckb_types::{core::service::Request, core::BlockView};
use ckb_util::RwLock;
use regex::Regex;
use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::{Cmd, CompletionType, Config, EditMode, Editor, KeyPress};
use serde_json::json;

use crate::plugin::PluginManager;
use crate::subcommands::{
    AccountSubCommand, CliSubCommand, DAOSubCommand, IndexSubCommand, MockTxSubCommand,
    MoleculeSubCommand, PluginSubCommand, RpcSubCommand, TxSubCommand, UtilSubCommand,
    WalletSubCommand,
};
use crate::utils::{
    completer::CkbCompleter,
    config::GlobalConfig,
    index::{IndexController, IndexRequest, IndexThreadState},
    other::{check_alerts, get_network_type, index_dirname},
    printer::{ColorWhen, OutputFormat, Printable},
};
use ckb_sdk::{rpc::RawHttpRpcClient, wallet::KeyStore, GenesisInfo, HttpRpcClient};

const ENV_PATTERN: &str = r"\$\{\s*(?P<key>\S+)\s*\}";

/// Interactive command line
pub struct InteractiveEnv {
    config: GlobalConfig,
    config_file: PathBuf,
    history_file: PathBuf,
    index_dir: PathBuf,
    parser: clap::App<'static>,
    plugin_mgr: PluginManager,
    key_store: KeyStore,
    rpc_client: HttpRpcClient,
    raw_rpc_client: RawHttpRpcClient,
    index_controller: IndexController,
    index_state: Arc<RwLock<IndexThreadState>>,
    genesis_info: Option<GenesisInfo>,
}

impl InteractiveEnv {
    pub fn from_config(
        ckb_cli_dir: PathBuf,
        mut config: GlobalConfig,
        plugin_mgr: PluginManager,
        key_store: KeyStore,
        index_controller: IndexController,
        index_state: Arc<RwLock<IndexThreadState>>,
    ) -> Result<InteractiveEnv, String> {
        if !ckb_cli_dir.as_path().exists() {
            fs::create_dir(&ckb_cli_dir).map_err(|err| err.to_string())?;
        }
        let mut history_file = ckb_cli_dir.clone();
        history_file.push("history");
        let mut config_file = ckb_cli_dir.clone();
        config_file.push("config");
        let mut index_dir = ckb_cli_dir.clone();
        index_dir.push(index_dirname());

        let mut env_file = ckb_cli_dir;
        env_file.push("env_vars");
        if env_file.as_path().exists() {
            let file = fs::File::open(&env_file).map_err(|err| err.to_string())?;
            let env_vars_json = serde_json::from_reader(file).unwrap_or(json!(null));
            match env_vars_json {
                serde_json::Value::Object(env_vars) => config.add_env_vars(env_vars),
                _ => eprintln!("Parse environment variable file failed."),
            }
        }

        let parser = crate::build_interactive();
        let rpc_client = HttpRpcClient::new(config.get_url().to_string());
        let raw_rpc_client = RawHttpRpcClient::new(config.get_url());
        Ok(InteractiveEnv {
            config,
            config_file,
            index_dir,
            history_file,
            parser,
            plugin_mgr,
            key_store,
            rpc_client,
            raw_rpc_client,
            index_controller,
            index_state,
            genesis_info: None,
        })
    }

    pub fn start(&mut self) -> Result<(), String> {
        self.print_logo();
        self.config.print();

        let env_regex = Regex::new(ENV_PATTERN).unwrap();
        let prompt = {
            #[cfg(unix)]
            {
                use ansi_term::Colour::Blue;
                Blue.bold().paint("CKB> ").to_string()
            }
            #[cfg(not(unix))]
            {
                "CKB> ".to_string()
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

        let mut plugin_sub_cmds = Vec::new();
        let mut parser = self.parser.clone();
        for (cmd_name, plugin_name) in self.plugin_mgr.sub_commands() {
            if let Some((_, config)) = self.plugin_mgr.plugins().get(plugin_name.as_str()) {
                plugin_sub_cmds
                    .push((cmd_name.clone(), format!("[plugin] {}", config.description)));
            }
        }
        for (cmd_name, description) in &plugin_sub_cmds {
            parser = parser.subcommand(
                // FIXME: when clap updated add `clap::AppSettings::DisableHelpFlags` back
                clap::App::new(cmd_name.as_str()).about(description.as_str()),
            );
        }

        let rl_config = Config::builder()
            .history_ignore_space(true)
            .completion_type(CompletionType::List)
            .edit_mode(EditMode::Emacs)
            .build();
        let mut rl = Editor::with_config(rl_config);
        let helper = CkbCompleter::new(parser.clone());
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
            match rl.readline(&prompt) {
                Ok(line) => {
                    match self.handle_command(&parser, line.as_str(), &env_regex) {
                        Ok(true) => {
                            break;
                        }
                        Ok(false) => {}
                        Err(err) => {
                            eprintln!("{}", err);
                        }
                    }
                    rl.add_history_entry(line.as_str());
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
            let genesis_block: BlockView = self
                .rpc_client
                .get_block_by_number(0)?
                .expect("Can not get genesis block?")
                .into();
            self.genesis_info = Some(GenesisInfo::from_block(&genesis_block)?);
        }
        Ok(self.genesis_info.clone().unwrap())
    }

    fn handle_command(
        &mut self,
        parser: &clap::App,
        line: &str,
        env_regex: &Regex,
    ) -> Result<bool, String> {
        let args = match shell_words::split(self.config.replace_cmd(&env_regex, line).as_str()) {
            Ok(args) => args,
            Err(e) => return Err(e.to_string()),
        };
        if args.is_empty() {
            return Ok(false);
        }

        let format = self.config.output_format();
        let color = ColorWhen::new(self.config.color()).color();
        let debug = self.config.debug();
        let wait_for_sync = !self.config.no_sync();

        let current_cmd_name = &args[0];
        if self
            .plugin_mgr
            .sub_commands()
            .contains_key(current_cmd_name.as_str())
        {
            let rest_args = line[current_cmd_name.len()..].to_string();
            log::debug!("[call sub command]: {} {}", current_cmd_name, rest_args);
            let resp = self
                .plugin_mgr
                .sub_command(current_cmd_name.as_str(), rest_args)?;
            println!("{}", resp.render(format, color));
            return Ok(false);
        }

        match parser.clone().try_get_matches_from(args) {
            Ok(matches) => match matches.subcommand() {
                ("config", Some(m)) => {
                    if let Some(url) = m.value_of("url") {
                        let index_sender = self.index_controller.sender();
                        Request::call(index_sender, IndexRequest::UpdateUrl(url.to_string()));
                        self.config.set_url(url.to_string());
                        self.rpc_client = HttpRpcClient::new(self.config.get_url().to_string());
                        self.raw_rpc_client = RawHttpRpcClient::new(self.config.get_url());
                        self.config
                            .set_network(get_network_type(&mut self.rpc_client).ok());
                        self.genesis_info = None;
                    };
                    if m.is_present("color") {
                        self.config.switch_color();
                    }

                    if let Some(format) = m.value_of("output-format") {
                        let output_format =
                            OutputFormat::from_str(format).unwrap_or(OutputFormat::Yaml);
                        self.config.set_output_format(output_format);
                    }

                    if m.is_present("debug") {
                        self.config.switch_debug();
                    }
                    if m.is_present("no-sync") {
                        self.config.switch_no_sync();
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
                        "no-sync": self.config.no_sync(),
                        "output_format": self.config.output_format().to_string(),
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
                    println!("{}", self.config.get(key).render(format, color));
                    Ok(())
                }
                ("info", _) => {
                    self.config.print();
                    Ok(())
                }
                ("rpc", Some(sub_matches)) => {
                    check_alerts(&mut self.rpc_client);
                    let output = RpcSubCommand::new(&mut self.rpc_client, &mut self.raw_rpc_client)
                        .process(&sub_matches, debug)?;
                    output.print(format, color);
                    Ok(())
                }
                ("account", Some(sub_matches)) => {
                    let output = AccountSubCommand::new(&mut self.plugin_mgr, &mut self.key_store)
                        .process(&sub_matches, debug)?;
                    output.print(format, color);
                    Ok(())
                }
                ("mock-tx", Some(sub_matches)) => {
                    let genesis_info = self.genesis_info().ok();
                    let output = MockTxSubCommand::new(
                        &mut self.rpc_client,
                        &mut self.plugin_mgr,
                        genesis_info,
                    )
                    .process(&sub_matches, debug)?;
                    output.print(format, color);
                    Ok(())
                }
                ("tx", Some(sub_matches)) => {
                    let genesis_info = self.genesis_info().ok();
                    let output =
                        TxSubCommand::new(&mut self.rpc_client, &mut self.plugin_mgr, genesis_info)
                            .process(&sub_matches, debug)?;
                    output.print(format, color);
                    Ok(())
                }
                ("util", Some(sub_matches)) => {
                    let output = UtilSubCommand::new(&mut self.rpc_client, &mut self.plugin_mgr)
                        .process(&sub_matches, debug)?;
                    output.print(format, color);
                    Ok(())
                }
                ("plugin", Some(sub_matches)) => {
                    let output =
                        PluginSubCommand::new(&mut self.plugin_mgr).process(&sub_matches, debug)?;
                    output.print(format, color);
                    Ok(())
                }
                ("molecule", Some(sub_matches)) => {
                    let output = MoleculeSubCommand::new().process(&sub_matches, debug)?;
                    output.print(format, color);
                    Ok(())
                }
                ("index", Some(sub_matches)) => {
                    let genesis_info = self.genesis_info()?;
                    let output = IndexSubCommand::new(
                        &mut self.rpc_client,
                        Some(genesis_info),
                        self.index_dir.clone(),
                        self.index_controller.clone(),
                        Arc::clone(&self.index_state),
                        wait_for_sync,
                    )
                    .process(&sub_matches, debug)?;
                    output.print(format, color);
                    Ok(())
                }
                ("wallet", Some(sub_matches)) => {
                    let genesis_info = self.genesis_info()?;
                    let output = WalletSubCommand::new(
                        &mut self.rpc_client,
                        &mut self.plugin_mgr,
                        Some(genesis_info),
                        self.index_dir.clone(),
                        self.index_controller.clone(),
                        wait_for_sync,
                    )
                    .process(&sub_matches, debug)?;
                    output.print(format, color);
                    Ok(())
                }
                ("dao", Some(sub_matches)) => {
                    let genesis_info = self.genesis_info()?;
                    let output = DAOSubCommand::new(
                        &mut self.rpc_client,
                        &mut self.plugin_mgr,
                        genesis_info,
                        self.index_dir.clone(),
                        self.index_controller.clone(),
                        wait_for_sync,
                    )
                    .process(&sub_matches, debug)?;
                    output.print(format, color);
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
