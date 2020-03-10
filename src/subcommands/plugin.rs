use clap::{App, Arg, ArgMatches};
use std::path::PathBuf;

use super::{CliSubCommand, Output};
use crate::plugin::PluginManager;
use crate::utils::arg_parser::{ArgParser, FilePathParser};

pub struct PluginSubCommand<'a> {
    plugin_mgr: &'a mut PluginManager,
}

impl<'a> PluginSubCommand<'a> {
    pub fn new(plugin_mgr: &'a mut PluginManager) -> PluginSubCommand {
        PluginSubCommand { plugin_mgr }
    }

    pub fn subcommand(name: &'static str) -> App<'static> {
        let arg_plugin_name = Arg::with_name("name")
            .long("name")
            .required(true)
            .takes_value(true)
            .about("Plugin name");
        App::new(name)
            .about("ckb-cli plugin management")
            .subcommands(vec![
                App::new("active")
                    .about(
                        "Active a plugin (at most one keystore/indexer role plugin can be actived)",
                    )
                    .arg(arg_plugin_name.clone()),
                App::new("deactive")
                    .about("Deactive a plugin")
                    .arg(arg_plugin_name.clone()),
                App::new("list").about("List all plugins"),
                App::new("info")
                    .about("Show the detail information of a plugin")
                    .arg(arg_plugin_name.clone()),
                App::new("install")
                    .about("Install a plugin, will active it immediately by default")
                    .arg(
                        Arg::with_name("binary-path")
                            .long("binary-path")
                            .required(true)
                            .takes_value(true)
                            .validator(|input| FilePathParser::new(true).validate(input))
                            .about("The binary file path of the plugin"),
                    )
                    .arg(
                        Arg::with_name("inactive")
                            .long("inactive")
                            .about("Install the plugin but not active it"),
                    ),
                App::new("uninstall")
                    .about("Uninstall a plugin, deactive it then remove the binary file")
                    .arg(arg_plugin_name.clone()),
            ])
    }
}

impl<'a> CliSubCommand for PluginSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches, _debug: bool) -> Result<Output, String> {
        match matches.subcommand() {
            ("active", Some(m)) => {
                let name = m.value_of("name").unwrap();
                self.plugin_mgr.active(name)?;
                Ok(Output::new_output(serde_json::json!(format!(
                    "Plugin {} is actived!",
                    name
                ))))
            }
            ("deactive", Some(m)) => {
                let name = m.value_of("name").unwrap();
                self.plugin_mgr.deactive(name)?;
                Ok(Output::new_output(serde_json::json!(format!(
                    "Plugin {} is deactived!",
                    name
                ))))
            }
            ("list", Some(_)) => {
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
            ("info", Some(m)) => {
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
            ("install", Some(m)) => {
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
            ("uninstall", Some(m)) => {
                let name = m.value_of("name").unwrap();
                self.plugin_mgr.uninstall(name)?;
                Ok(Output::new_output(serde_json::json!(format!(
                    "Plugin {} uninstalled!",
                    name
                ))))
            }
            _ => Err(Self::subcommand("plugin").generate_usage()),
        }
    }
}
