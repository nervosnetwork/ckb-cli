use clap::{Arg, ArgMatches, Command};
use crate::utils::arg::ArgValidatorExt;
use crate::utils::arg_parser::ArgMatchesExt;
use std::path::PathBuf;

use super::{CliSubCommand, Output};
use crate::plugin::PluginManager;
use crate::utils::arg_parser::{ArgParser, FilePathParser};

pub struct PluginSubCommand<'a> {
    plugin_mgr: &'a mut PluginManager,
}

impl<'a> PluginSubCommand<'a> {
    pub fn new(plugin_mgr: &'a mut PluginManager) -> PluginSubCommand<'a> {
        PluginSubCommand { plugin_mgr }
    }

    pub fn subcommand(name: &'static str) -> Command {
        let arg_plugin_name = Arg::new("name")
            .long("name")
            .required(true)
            .num_args(1)
            .help("Plugin name");
        Command::new(name)
            .about("ckb-cli plugin management")
            .subcommands(vec![
                Command::new("active")
                    .about(
                        "Active a plugin (at most one keystore/indexer role plugin can be actived)",
                    )
                    .arg(arg_plugin_name.clone()),
                Command::new("deactive")
                    .about("Deactive a plugin")
                    .arg(arg_plugin_name.clone()),
                Command::new("list").about("List all plugins"),
                Command::new("info")
                    .about("Show the detail information of a plugin")
                    .arg(arg_plugin_name.clone()),
                Command::new("install")
                    .about("Install a plugin, will active it immediately by default")
                    .arg(
                        Arg::new("binary-path")
                            .long("binary-path")
                            .required(true)
                            .num_args(1)
                            .validator(|input| FilePathParser::new(true).validate(input))
                            .help("The binary file path of the plugin"),
                    )
                    .arg(
                        Arg::new("inactive")
                            .long("inactive")
                            .help("Install the plugin but not active it"),
                    ),
                Command::new("uninstall")
                    .about("Uninstall a plugin, deactive it then remove the binary file")
                    .arg(arg_plugin_name.clone()),
            ])
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
