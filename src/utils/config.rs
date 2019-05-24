use std::collections::HashMap;
use std::env;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;

use ansi_term::Colour::Yellow;
use ckb_util::RwLock;
use regex::{Captures, Regex};

use crate::subcommands::wallet::IndexThreadState;
use crate::utils::printer::{OutputFormat, Printable};

const DEFAULT_JSONRPC_URL: &str = "http://127.0.0.1:8114";

pub struct GlobalConfig {
    url: Option<String>,
    color: bool,
    debug: bool,
    json_format: bool,
    path: PathBuf,
    completion_style: bool,
    edit_style: bool,
    env_variable: HashMap<String, serde_json::Value>,
    index_state: Arc<RwLock<IndexThreadState>>,
}

impl GlobalConfig {
    pub fn new(url: Option<String>, index_state: Arc<RwLock<IndexThreadState>>) -> Self {
        GlobalConfig {
            url,
            color: true,
            debug: false,
            json_format: true,
            path: env::current_dir().unwrap(),
            completion_style: true,
            edit_style: true,
            env_variable: HashMap::new(),
            index_state,
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
            self.url = Some("http://".to_owned() + &value);
        }
    }

    pub fn get_url(&self) -> &str {
        &self
            .url
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or(DEFAULT_JSONRPC_URL)
    }

    pub fn switch_color(&mut self) {
        self.color = !self.color;
    }

    pub fn switch_debug(&mut self) {
        self.debug = !self.debug;
    }

    pub fn switch_format(&mut self) {
        self.json_format = !self.json_format;
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

    pub fn set_json_format(&mut self, value: bool) {
        self.json_format = value;
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

    pub fn json_format(&self) -> bool {
        self.json_format
    }

    pub fn completion_style(&self) -> bool {
        self.completion_style
    }

    pub fn edit_style(&self) -> bool {
        self.edit_style
    }

    pub fn print(&self) {
        let path = self.path.to_string_lossy();
        let color = self.color.to_string();
        let debug = self.debug.to_string();
        let json = self.json_format.to_string();
        let completion_style = if self.completion_style {
            "List"
        } else {
            "Circular"
        };
        let edit_style = if self.edit_style { "Emacs" } else { "Vi" };
        let index_state = self.index_state.read().to_string();
        let values = [
            ("url", self.get_url()),
            ("pwd", path.deref()),
            ("color", color.as_str()),
            ("debug", debug.as_str()),
            ("json", json.as_str()),
            ("completion style", completion_style),
            ("edit style", edit_style),
            ("index db state", index_state.as_str()),
        ];

        let max_width = values
            .iter()
            .map(|(name, _)| name.len())
            .max()
            .unwrap_or(20)
            + 2;
        let output = values
            .iter()
            .map(|(name, value)| {
                format!(
                    "[{:^width$}]: {}",
                    name,
                    Yellow.paint(*value),
                    width = max_width
                )
            })
            .collect::<Vec<String>>()
            .join("\n");
        println!("{}", output);
    }
}

#[derive(Clone)]
pub enum KV<'a> {
    Value(Option<&'a serde_json::Value>),
    Keys(Vec<&'a str>),
}

impl<'a> Printable for KV<'a> {
    fn rc_string(&self, format: OutputFormat, color: bool) -> ::std::rc::Rc<String> {
        match self {
            KV::Value(Some(value)) => value.rc_string(format, color),
            KV::Keys(value) => ::std::rc::Rc::new(
                value
                    .iter()
                    .enumerate()
                    .map(|(index, key)| format!("{}) {}", index, key))
                    .collect::<Vec<String>>()
                    .join("\n"),
            ),
            KV::Value(None) => ::std::rc::Rc::new("None".to_string()),
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
