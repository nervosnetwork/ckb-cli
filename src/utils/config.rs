use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::ops::Deref;
use std::path::{Path, PathBuf};

use ansi_term::Colour::Yellow;
use ckb_sdk::{CkbRpcClient, NetworkType};
use regex::{Captures, Regex};
use serde_json::json;

use crate::utils::printer::{OutputFormat, Printable};

pub const DEFAULT_CKB_URL: &str = "http://127.0.0.1:8114";

pub struct GlobalConfig {
    url: Option<String>,
    network: Option<NetworkType>,
    color: bool,
    debug: bool,
    no_sync: bool,
    output_format: OutputFormat,
    path: PathBuf,
    completion_style: bool,
    edit_style: bool,
    env_variable: HashMap<String, serde_json::Value>,
}

impl GlobalConfig {
    pub fn new(url: Option<String>) -> Self {
        GlobalConfig {
            url,
            network: None,
            color: true,
            debug: false,
            no_sync: false,
            output_format: OutputFormat::Yaml,
            path: env::current_dir().unwrap(),
            completion_style: true,
            edit_style: true,
            env_variable: HashMap::new(),
        }
    }

    pub fn set(&mut self, key: String, value: serde_json::Value) -> &mut Self {
        self.env_variable.insert(key, value);
        self
    }

    pub fn get(&self, key: Option<&str>) -> KV {
        match key {
            Some(key) => {
                let mut parts_iter = key.split('.');
                let value = match parts_iter.next() {
                    Some(name) => parts_iter
                        .try_fold(
                            self.env_variable.get(name),
                            |value_opt: Option<&serde_json::Value>, part| match value_opt {
                                Some(value) => match part.parse::<usize>() {
                                    Ok(index) => match value.get(index) {
                                        None => Ok(value.get(part)),
                                        result => Ok(result),
                                    },
                                    _ => Ok(value.get(part)),
                                },
                                None => Err(()),
                            },
                        )
                        .unwrap_or_default(),
                    None => None,
                };
                KV::Value(value)
            }
            None => KV::Keys(
                self.env_variable
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<&str>>(),
            ),
        }
    }

    pub fn add_env_vars<T>(&mut self, vars: T)
    where
        T: IntoIterator<Item = (String, serde_json::Value)>,
    {
        self.env_variable.extend(vars);
    }

    pub fn replace_cmd(&self, regex: &Regex, line: &str) -> String {
        regex
            .replace_all(line, |caps: &Captures| match caps.name("key") {
                Some(key) => self
                    .get(Some(key.as_str()))
                    .map(|value| match value {
                        serde_json::Value::String(s) => s.to_owned(),
                        serde_json::Value::Number(n) => n.to_string(),
                        _ => String::new(),
                    })
                    .next()
                    .unwrap_or_default(),
                None => String::new(),
            })
            .into_owned()
    }

    pub fn set_url(&mut self, value: String) {
        if value.starts_with("http://") || value.starts_with("https://") {
            self.url = Some(value);
        } else {
            self.url = Some(format!("http://{}", value));
        }
    }
    pub fn get_url(&self) -> &str {
        self.url.as_deref().unwrap_or(DEFAULT_CKB_URL)
    }

    pub fn set_network(&mut self, network: Option<NetworkType>) {
        self.network = network;
    }
    pub fn network(&self) -> Option<NetworkType> {
        self.network
    }

    pub fn switch_color(&mut self) {
        self.color = !self.color;
    }

    pub fn switch_debug(&mut self) {
        self.debug = !self.debug;
    }

    pub fn switch_completion_style(&mut self) {
        self.completion_style = !self.completion_style;
    }

    pub fn switch_edit_style(&mut self) {
        self.edit_style = !self.edit_style;
    }

    pub fn set_color(&mut self, value: bool) {
        self.color = value;
    }

    pub fn set_debug(&mut self, value: bool) {
        self.debug = value;
    }

    pub fn set_no_sync(&mut self, value: bool) {
        self.no_sync = value;
    }

    pub fn set_output_format(&mut self, value: OutputFormat) {
        self.output_format = value;
    }

    pub fn set_completion_style(&mut self, value: bool) {
        self.completion_style = value;
    }

    pub fn set_edit_style(&mut self, value: bool) {
        self.edit_style = value;
    }

    pub fn color(&self) -> bool {
        self.color
    }

    pub fn debug(&self) -> bool {
        self.debug
    }

    pub fn no_sync(&self) -> bool {
        self.no_sync
    }

    pub fn output_format(&self) -> OutputFormat {
        self.output_format
    }

    pub fn completion_style(&self) -> bool {
        self.completion_style
    }

    pub fn edit_style(&self) -> bool {
        self.edit_style
    }

    pub fn print(&self, fast_mode: bool) {
        let path = self.path.to_string_lossy();
        let color = self.color.to_string();
        let debug = self.debug.to_string();
        let no_sync = self.no_sync.to_string();
        let output_format = self.output_format.to_string();
        let completion_style = if self.completion_style {
            "List"
        } else {
            "Circular"
        };
        let edit_style = if self.edit_style { "Emacs" } else { "Vi" };
        let version = crate::get_version();
        let version_long = version.long();
        let network_string = self
            .network()
            .map(|value| format!("{:?}", value))
            .unwrap_or_else(|| "unknown".to_string());
        let ckb_tip = if fast_mode {
            "loading...".to_string()
        } else {
            match CkbRpcClient::new(self.get_url()).get_tip_block_number() {
                Ok(number) => format!("#{}", number.value()),
                Err(err) => err.to_string(),
            }
        };
        let url_string = format!(
            "{} (network: {}, {})",
            self.get_url(),
            network_string,
            ckb_tip
        );

        let values = [
            ("ckb-cli version", version_long.as_str()),
            ("url", url_string.as_str()),
            ("pwd", path.deref()),
            ("color", color.as_str()),
            ("debug", debug.as_str()),
            ("no-sync", no_sync.as_str()),
            ("output format", output_format.as_str()),
            ("completion style", completion_style),
            ("edit style", edit_style),
        ];

        let max_width = values
            .iter()
            .map(|(name, _)| name.len())
            .max()
            .unwrap_or(20);
        let output = values
            .iter()
            .map(|(name, value)| {
                let value = if self.color {
                    Yellow.paint(*value).to_string()
                } else {
                    (*value).to_string()
                };
                format!("[ {:>width$} ]: {}", name, value, width = max_width)
            })
            .collect::<Vec<String>>()
            .join("\n");
        println!("{}", output);
    }

    pub fn save(&self, path: &Path) -> Result<(), io::Error> {
        let mut file = fs::File::create(path)?;
        let content = serde_json::to_string_pretty(&json!({
            "url": self.get_url().to_string(),
            "color": self.color(),
            "debug": self.debug(),
            "no-sync": self.no_sync(),
            "output_format": self.output_format().to_string(),
            "completion_style": self.completion_style(),
            "edit_style": self.edit_style(),
        }))
        .unwrap();
        file.write_all(content.as_bytes())?;
        Ok(())
    }
}

#[derive(Clone)]
pub enum KV<'a> {
    Value(Option<&'a serde_json::Value>),
    Keys(Vec<&'a str>),
}

impl<'a> Printable for KV<'a> {
    fn render(&self, format: OutputFormat, color: bool) -> String {
        match self {
            KV::Value(Some(value)) => value.render(format, color),
            KV::Keys(value) => value
                .iter()
                .enumerate()
                .map(|(index, key)| format!("{}) {}", index, key))
                .collect::<Vec<String>>()
                .join("\n"),
            KV::Value(None) => "None".to_owned(),
        }
    }
}

impl<'a> ::std::iter::Iterator for KV<'a> {
    type Item = &'a serde_json::Value;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            KV::Value(value) => *value.deref(),
            _ => None,
        }
    }
}
