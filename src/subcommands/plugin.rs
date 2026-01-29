use clap::{ArgMatches, Args, Command, CommandFactory, Parser, Subcommand};
use crate::utils::arg_parser::ArgMatchesExt;
use std::path::PathBuf;

use super::{CliSubCommand, Output};
use crate::plugin::PluginManager;
use crate::utils::arg_parser::{ArgParser, FilePathParser};

fn parse_plugin_binary_path(input: &str) -> Result<PathBuf, String> {
    FilePathParser::new(true).parse(input)
}

#[derive(Parser, Debug)]
#[command(name = "plugin", about = "ckb-cli plugin management")]
pub struct PluginCmd {
    #[command(subcommand)]
    pub command: PluginSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum PluginSubcommands {
    /// Active a plugin (at most one keystore/indexer role plugin can be actived)
    Active(PluginNameArg),
    /// Deactive a plugin
    Deactive(PluginNameArg),
    /// List all plugins
    List,
    /// Show the detail information of a plugin
    Info(PluginNameArg),
    /// Install a plugin, will active it immediately by default
    Install(PluginInstallArgs),
    /// Uninstall a plugin, deactive it then remove the binary file
    Uninstall(PluginNameArg),
}

#[derive(Args, Debug)]
pub struct PluginNameArg {
    /// Plugin name
    #[arg(long)]
    pub name: String,
}

#[derive(Args, Debug)]
pub struct PluginInstallArgs {
    /// The binary file path of the plugin
    #[arg(long, value_parser = parse_plugin_binary_path)]
    pub binary_path: PathBuf,
    /// Install the plugin but not active it
    #[arg(long)]
    pub inactive: bool,
}

pub struct PluginSubCommand<'a> {
    plugin_mgr: &'a mut PluginManager,
}

impl<'a> PluginSubCommand<'a> {
    pub fn new(plugin_mgr: &'a mut PluginManager) -> PluginSubCommand<'a> {
        PluginSubCommand { plugin_mgr }
    }

    pub fn subcommand(name: &'static str) -> Command {
        PluginCmd::command().name(name)
    }
}

impl CliSubCommand for PluginSubCommand<'_> {
    fn process(&mut self, matches: &ArgMatches, _debug: bool) -> Result<Output, String> {
        match matches.subcommand() {
            Some(("active", m)) => {
                let name = m.value_of("name").unwrap();
                self.plugin_mgr.active(name)?;
                Ok(Output::new_output(serde_json::json!(format!(
                    "Plugin {} is actived!",
                    name
                ))))
            }
            Some(("deactive", m)) => {
                let name = m.value_of("name").unwrap();
                self.plugin_mgr.deactive(name)?;
                Ok(Output::new_output(serde_json::json!(format!(
                    "Plugin {} is deactived!",
                    name
                ))))
            }
            Some(("list", _)) => {
                let resp = self
                    .plugin_mgr
                    .plugins()
                    .values()
                    .map(|(plugin, config)| {
                        serde_json::json!({
                            "name": config.name,
                            "description": config.description,
                            "is_active": plugin.is_active(),
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(Output::new_output(resp))
            }
            Some(("info", m)) => {
                let name = m.value_of("name").unwrap();
                if let Some((plugin, config)) = self.plugin_mgr.plugins().get(name) {
                    let resp = serde_json::json!({
                        "name": config.name,
                        "description": config.description,
                        "daemon": config.daemon,
                        "is_active": plugin.is_active(),
                        "roles": serde_json::json!(config.roles),
                    });
                    Ok(Output::new_output(resp))
                } else {
                    Err(format!("Plugin {} not found", name))
                }
            }
            Some(("install", m)) => {
                let path: PathBuf = FilePathParser::new(true).from_matches(m, "binary-path")?;
                let active = !m.is_present("inactive");
                let config = self.plugin_mgr.install(path, active)?;
                let resp = serde_json::json!({
                    "name": config.name,
                    "description": config.description,
                    "daemon": config.daemon,
                });
                Ok(Output::new_output(resp))
            }
            Some(("uninstall", m)) => {
                let name = m.value_of("name").unwrap();
                self.plugin_mgr.uninstall(name)?;
                Ok(Output::new_output(serde_json::json!(format!(
                    "Plugin {} uninstalled!",
                    name
                ))))
            }
            _ => Err(Self::subcommand("plugin").render_usage().to_string()),
        }
    }
}
