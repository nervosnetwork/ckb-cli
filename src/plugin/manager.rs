use std::collections::HashMap;
use std::convert::TryInto;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::str::FromStr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use ckb_index::LiveCellInfo;
use ckb_jsonrpc_types::{BlockNumber, HeaderView, JsonBytes, Script};
use ckb_sdk::{
    wallet::{ChildNumber, DerivationPath, DerivedKeySet, MasterPrivKey, CKB_ROOT_PATH},
    HttpRpcClient,
};
use ckb_types::{bytes::Bytes, core::service::Request, H160, H256};
use crossbeam_channel::{bounded, select, Sender};

use super::builtin::{DefaultIndexer, DefaultKeyStore, ERROR_KEYSTORE_REQUIRE_PASSWORD};
use crate::utils::other::read_password;
use plugin_protocol::{
    CallbackName, CallbackRequest, CallbackResponse, IndexerRequest, JsonrpcError, JsonrpcRequest,
    JsonrpcResponse, KeyStoreRequest, LiveCellIndexType, PluginConfig, PluginRequest,
    PluginResponse, PluginRole, RpcRequest, SignTarget,
};

pub const PLUGINS_DIRNAME: &str = "plugins";
pub const INACTIVE_DIRNAME: &str = "inactive";
#[cfg(unix)]
pub const PLUGIN_FILENAME_EXT: &str = "bin";
#[cfg(not(unix))]
pub const PLUGIN_FILENAME_EXT: &str = "exe";
pub const ACCOUNT_SOURCE_FS: &str = "Local File System";

pub struct PluginManager {
    plugin_dir: PathBuf,
    plugins: HashMap<String, (Plugin, PluginConfig)>,
    daemon_processes: HashMap<String, PluginProcess>,

    // == Plugin role configs
    // The keystore plugins currently actived
    keystores: Vec<String>,
    // The indexer plugins currently actived
    indexers: Vec<String>,
    // The actived sub command plugins. The key is sub-command name
    sub_commands: HashMap<String, String>,
    // The actived callback plugins. The key is callback name
    callbacks: HashMap<CallbackName, Vec<String>>,

    default_keystore_handler: PluginHandler,
    service_provider: ServiceProvider,
    _jsonrpc_id: Arc<AtomicU64>,
}

pub type PluginHandler = Sender<Request<(u64, PluginRequest), (u64, PluginResponse)>>;
pub type ServiceHandler = Sender<Request<ServiceRequest, ServiceResponse>>;

impl PluginManager {
    pub fn load(
        ckb_cli_dir: &PathBuf,
    ) -> Result<HashMap<String, (Plugin, PluginConfig)>, io::Error> {
        let plugin_dir = ckb_cli_dir.join(PLUGINS_DIRNAME);
        let inactive_plugin_dir = plugin_dir.join(INACTIVE_DIRNAME);

        if !inactive_plugin_dir.exists() {
            fs::create_dir_all(&inactive_plugin_dir)?;
        }

        let mut plugins = HashMap::default();
        for (dir, is_active) in &[(&plugin_dir, true), (&inactive_plugin_dir, false)] {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file()
                    && path
                        .extension()
                        .map(|ext| ext == PLUGIN_FILENAME_EXT)
                        .unwrap_or(false)
                {
                    let plugin = Plugin::new(path.clone(), Vec::new(), *is_active);
                    match plugin.get_config() {
                        Ok(config) => {
                            if let Err(err) = config.validate() {
                                log::warn!("Invalid plugin config: {:?}, error: {}", config, err);
                            } else {
                                log::info!("Loaded plugin: {}", config.name);
                                plugins.insert(config.name.clone(), (plugin, config));
                            }
                        }
                        Err(err) => {
                            log::warn!("get_config error: {}, path: {:?}", err, path);
                        }
                    }
                }
            }
        }
        Ok(plugins)
    }

    pub fn init(ckb_cli_dir: &PathBuf, rpc_url: String) -> Result<PluginManager, String> {
        let plugin_dir = ckb_cli_dir.join(PLUGINS_DIRNAME);
        let plugins = Self::load(ckb_cli_dir).map_err(|err| err.to_string())?;
        let default_keystore = DefaultKeyStore::start(ckb_cli_dir)?;
        // TODO: impl indexer thread
        let default_indexer = DefaultIndexer::start()?;

        // Make sure ServiceProvider start before all daemon processes
        let mut daemon_plugins = Vec::new();
        let mut daemon_processes = HashMap::new();
        let mut keystores = Vec::new();
        let mut indexers = Vec::new();
        let mut sub_commands = HashMap::new();
        let mut callbacks: HashMap<CallbackName, Vec<String>> = HashMap::new();
        let mut keystore_plugin = None;
        let mut indexer_plugin = None;
        // TODO plugins order matters
        for (plugin_name, (plugin, config)) in &plugins {
            for role in &config.roles {
                match role {
                    PluginRole::KeyStore { .. } => {
                        if plugin.is_active() && keystore_plugin.is_none() {
                            keystore_plugin = Some((plugin.clone(), config.clone()));
                        }
                        keystores.push(plugin_name.clone());
                    }
                    PluginRole::Indexer => {
                        if plugin.is_active() && indexer_plugin.is_none() {
                            indexer_plugin = Some((plugin.clone(), config.clone()));
                        }
                        indexers.push(plugin_name.clone());
                    }
                    PluginRole::SubCommand { name } => {
                        sub_commands.insert(name.clone(), plugin_name.clone());
                    }
                    PluginRole::Callback { name } => {
                        callbacks
                            .entry(name.clone())
                            .or_default()
                            .push(plugin_name.clone());
                    }
                }
            }
            if config.is_normal_daemon() {
                log::info!("Start daemon plugin: {}", config.name);
                daemon_plugins.push((plugin.clone(), config.clone()));
            }
        }
        let default_keystore_handler = default_keystore.handler().clone();
        let service_provider = ServiceProvider::start(
            default_keystore,
            default_indexer,
            keystore_plugin,
            indexer_plugin,
            rpc_url,
        )?;
        for (plugin, config) in daemon_plugins {
            let plugin_name = config.name.clone();
            let process = PluginProcess::start(plugin, config, service_provider.handler().clone())?;
            daemon_processes.insert(plugin_name, process);
        }

        let jsonrpc_id = Arc::new(AtomicU64::new(0));

        Ok(PluginManager {
            plugin_dir,
            plugins,
            daemon_processes,
            indexers,
            keystores,
            sub_commands,
            callbacks,
            service_provider,
            default_keystore_handler,
            _jsonrpc_id: jsonrpc_id,
        })
    }

    pub fn plugins(&self) -> &HashMap<String, (Plugin, PluginConfig)> {
        &self.plugins
    }
    pub fn sub_commands(&self) -> &HashMap<String, String> {
        &self.sub_commands
    }
    #[allow(unused)]
    pub fn callbacks(&self) -> &HashMap<CallbackName, Vec<String>> {
        &self.callbacks
    }
    pub fn actived_keystore(&self) -> Option<(&Plugin, &PluginConfig, bool)> {
        self.keystores
            .iter()
            .filter_map(|name| {
                self.plugins
                    .get(name)
                    .filter(|(plugin, _)| plugin.is_active())
                    .map(|(plugin, config)| {
                        for role in &config.roles {
                            if let PluginRole::KeyStore { require_password } = role {
                                return (plugin, config, *require_password);
                            }
                        }
                        panic!("Plugin {} is not a keystore plugin", config.name);
                    })
            })
            .next()
    }
    pub fn actived_indexer(&self) -> Option<(&Plugin, &PluginConfig)> {
        self.indexers
            .iter()
            .filter_map(|name| {
                self.plugins
                    .get(name)
                    .filter(|(plugin, _)| plugin.is_active())
                    .map(|(plugin, config)| {
                        for role in &config.roles {
                            if let PluginRole::Indexer = role {
                                return (plugin, config);
                            }
                        }
                        panic!("Plugin {} is not a indexer plugin", config.name);
                    })
            })
            .next()
    }

    pub fn keystore_require_password(&self) -> bool {
        self.actived_keystore()
            .map(|(_, _, require_password)| require_password)
            .unwrap_or(true)
    }
    pub fn keystore_handler(&self) -> KeyStoreHandler {
        KeyStoreHandler::new(
            self.default_keystore_handler.clone(),
            self.service_provider.handler().clone(),
            self.actived_keystore().map(|(_, cfg, _)| cfg.clone()),
        )
    }
    #[allow(unused)]
    pub fn indexer_handler(&self) -> IndexerHandler {
        IndexerHandler::new(self.service_provider.handler().clone())
    }
    pub fn root_key_path(&self, h160: H160) -> Result<DerivationPath, String> {
        self.keystore_handler().root_key_path(h160)
    }

    pub fn active(&mut self, name: &str) -> Result<(), String> {
        if !self.plugins.contains_key(name) {
            return Err(format!("Plugin not found: {}", name));
        }

        let last_actived_keystore = self
            .actived_keystore()
            .map(|(_, config, _)| config.name.clone());
        let last_actived_indexer = self
            .actived_indexer()
            .map(|(_, config)| config.name.clone());
        if let Some((plugin, config)) = self.plugins.get_mut(name).and_then(|(plugin, config)| {
            if !plugin.is_active() {
                plugin.active();
                Some((plugin.clone(), config.clone()))
            } else {
                None
            }
        }) {
            for role in &config.roles {
                match role {
                    PluginRole::KeyStore { .. } => {
                        self.keystores.push(config.name.clone());
                    }
                    PluginRole::Indexer => {
                        self.indexers.push(config.name.clone());
                    }
                    PluginRole::SubCommand { name } => {
                        self.sub_commands.insert(name.clone(), config.name.clone());
                    }
                    PluginRole::Callback { name } => {
                        self.callbacks
                            .entry(name.clone())
                            .or_default()
                            .push(config.name.clone());
                    }
                }
            }
            if config.is_normal_daemon() {
                log::info!("Starting daemon process: {}", config.name);
                let process = PluginProcess::start(
                    plugin.clone(),
                    config.clone(),
                    self.service_provider.handler().clone(),
                )?;
                log::info!("Daemon process started: {}", config.name);
                self.daemon_processes.insert(name.to_string(), process);
            }
            let new_path = self
                .plugin_dir
                .join(format!("{}.{}", config.name, PLUGIN_FILENAME_EXT));
            log::info!("Rename plugin file: {:?} => {:?}", plugin.path(), new_path);
            fs::rename(plugin.path(), &new_path).map_err(|err| err.to_string())?;
            if let Some((plugin, _)) = self.plugins.get_mut(name) {
                plugin.set_path(new_path);
            }
            self.service_plugin_changed(last_actived_keystore, last_actived_indexer)?;
        }
        Ok(())
    }
    pub fn deactive(&mut self, name: &str) -> Result<(), String> {
        if !self.plugins.contains_key(name) {
            return Err(format!("Plugin not found: {}", name));
        }

        let last_actived_keystore = self
            .actived_keystore()
            .map(|(_, config, _)| config.name.clone());
        let last_actived_indexer = self
            .actived_indexer()
            .map(|(_, config)| config.name.clone());
        if let Some((plugin, config)) = self.plugins.get_mut(name).and_then(|(plugin, config)| {
            if plugin.is_active() {
                plugin.deactive();
                Some((plugin.clone(), config.clone()))
            } else {
                None
            }
        }) {
            for role in &config.roles {
                match role {
                    PluginRole::KeyStore { .. } => {
                        self.keystores = self
                            .keystores
                            .split_off(0)
                            .into_iter()
                            .filter(|plugin_name| plugin_name != name)
                            .collect::<Vec<_>>();
                    }
                    PluginRole::Indexer => {
                        self.indexers = self
                            .indexers
                            .split_off(0)
                            .into_iter()
                            .filter(|plugin_name| plugin_name != name)
                            .collect::<Vec<_>>();
                    }
                    PluginRole::SubCommand { name } => {
                        self.sub_commands.remove(name);
                    }
                    PluginRole::Callback {
                        name: callback_name,
                    } => {
                        if let Some(names) = self.callbacks.get_mut(callback_name) {
                            *names = names
                                .split_off(0)
                                .into_iter()
                                .filter(|plugin_name| plugin_name != name)
                                .collect::<Vec<_>>();
                        }
                    }
                }
            }
            if config.is_normal_daemon() {
                log::info!("Stopping daemon process: {}", config.name);
                self.daemon_processes.remove(name);
            }
            let new_path = self
                .plugin_dir
                .join(INACTIVE_DIRNAME)
                .join(format!("{}.{}", config.name, PLUGIN_FILENAME_EXT));
            log::debug!("Rename plugin file: {:?} => {:?}", plugin.path(), new_path);
            fs::rename(plugin.path(), &new_path).map_err(|err| err.to_string())?;
            if let Some((plugin, _)) = self.plugins.get_mut(name) {
                plugin.set_path(new_path);
            }
            self.service_plugin_changed(last_actived_keystore, last_actived_indexer)?;
        }
        Ok(())
    }
    pub fn install(&mut self, tmp_path: PathBuf, active: bool) -> Result<PluginConfig, String> {
        let tmp_plugin = Plugin::new(tmp_path, Vec::new(), active);
        let config = tmp_plugin.get_config()?;
        config.validate()?;
        if self.plugins.contains_key(&config.name) {
            return Err(format!(
                "Plugin {} already installed! If you want update, please uninstall it first",
                config.name
            ));
        }
        let base_dir = if active {
            self.plugin_dir.clone()
        } else {
            self.plugin_dir.join(INACTIVE_DIRNAME)
        };
        let path = base_dir.join(format!("{}.{}", config.name, PLUGIN_FILENAME_EXT));
        fs::copy(tmp_plugin.path(), &path).map_err(|err| err.to_string())?;
        // TODO: change this address to executable
        let plugin = Plugin::new(path, Vec::new(), false);
        self.plugins
            .insert(config.name.clone(), (plugin, config.clone()));
        if active {
            self.active(&config.name)?;
        }
        Ok(config)
    }
    pub fn uninstall(&mut self, name: &str) -> Result<(), String> {
        self.deactive(name)?;
        if let Some((plugin, _config)) = self.plugins.remove(name) {
            fs::remove_file(plugin.path()).map_err(|err| err.to_string())?;
        }
        Ok(())
    }

    /// Handle sub-command and callback call
    #[allow(unused)]
    pub fn handle<T, F: FnOnce(&PluginHandler) -> Result<T, String>>(
        &self,
        name: &str,
        func: F,
    ) -> Result<T, String> {
        if let Some(process) = self.daemon_processes.get(name) {
            func(process.handler())
        } else if let Some((plugin, config)) = self.plugins.get(name) {
            if plugin.is_active() {
                let service_handler = self.service_provider.handler().clone();
                let process =
                    PluginProcess::start(plugin.clone(), config.clone(), service_handler)?;
                func(process.handler())
            } else {
                Err(format!("Plugin {} is inactive", name))
            }
        } else {
            Err(format!("Plugin name not found: {}", name))
        }
    }

    fn service_plugin_changed(
        &self,
        last_actived_keystore: Option<String>,
        last_actived_indexer: Option<String>,
    ) -> Result<(), String> {
        let actived_keystore = self.actived_keystore();
        if last_actived_keystore != actived_keystore.map(|(_, config, _)| config.name.clone()) {
            let keystore_plugin =
                actived_keystore.map(|(plugin, config, _)| (plugin.clone(), config.clone()));
            self.call_service(ServiceRequest::KeyStoreChanged(keystore_plugin))?;
        }

        let actived_indexer = self.actived_indexer();
        if last_actived_indexer != actived_indexer.map(|(_, config)| config.name.clone()) {
            let indexer_plugin =
                actived_indexer.map(|(plugin, config)| (plugin.clone(), config.clone()));
            self.call_service(ServiceRequest::IndexerChanged(indexer_plugin))?;
        }
        Ok(())
    }
    fn call_service(&self, request: ServiceRequest) -> Result<(), String> {
        match Request::call(self.service_provider.handler(), request)
            .ok_or_else(|| String::from("Send request to ServiceProvider failed"))?
        {
            ServiceResponse::Ok => Ok(()),
            _ => Err(String::from("Invalid plugin response")),
        }
    }

    #[allow(unused)]
    pub fn rpc_url_changed(&self, new_url: String) -> Result<(), String> {
        self.call_service(ServiceRequest::RpcUrlChanged(new_url))
    }

    pub fn sub_command(
        &self,
        command_name: &str,
        rest_args: String,
    ) -> Result<serde_json::Value, String> {
        if let Some(plugin_name) = self.sub_commands.get(command_name) {
            self.handle(plugin_name.as_str(), |handler| {
                let request = PluginRequest::SubCommand(rest_args);
                let id: u64 = 0;
                match Request::call(handler, (id, request))
                    .ok_or_else(|| format!("Send request to plugin {} failed", plugin_name))?
                {
                    (_id, PluginResponse::JsonValue(output)) => Ok(output),
                    (_id, PluginResponse::Error(rpc_err)) => {
                        Err(format!("ERROR: {}", rpc_err.message))
                    }
                    _ => Err("Invalid plugin response".to_string()),
                }
            })
        } else {
            Err(format!(
                "plugin for sub-command {} not found or inactive",
                command_name
            ))
        }
    }
    #[allow(unused)]
    pub fn callback(
        &self,
        callback_name: CallbackName,
        arguments: CallbackRequest,
    ) -> Result<Vec<CallbackResponse>, String> {
        if let Some(plugin_names) = self.callbacks.get(&callback_name) {
            let mut responses = Vec::new();
            for plugin_name in plugin_names {
                let response = self.handle(plugin_name.as_str(), |handler| {
                    let request = PluginRequest::Callback(arguments.clone());
                    let id: u64 = 0;
                    if let (_id, PluginResponse::Callback(response)) =
                        Request::call(handler, (id, request)).ok_or_else(|| {
                            format!("Send request to plugin {} failed", plugin_name)
                        })?
                    {
                        Ok(response)
                    } else {
                        Err(format!("Invalid response from plugin: {}", plugin_name))
                    }
                })?;
                responses.push(response);
            }
            Ok(responses)
        } else {
            Err(format!(
                "callback plugin for {} hook not found or inactive",
                callback_name
            ))
        }
    }
}

fn deserilize_key_set(set: Vec<(String, H160)>) -> Result<Vec<(DerivationPath, H160)>, String> {
    set.into_iter()
        .map(|(path, hash160)| DerivationPath::from_str(&path).map(|path| (path, hash160)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())
}

struct ServiceProvider {
    handler: ServiceHandler,
    _thread: JoinHandle<()>,
}

#[derive(Debug)]
pub enum ServiceRequest {
    Request {
        // The request is from plugin or ckb-cli
        is_from_plugin: bool,
        plugin_name: String,
        request: PluginRequest,
    },
    KeyStoreChanged(Option<(Plugin, PluginConfig)>),
    IndexerChanged(Option<(Plugin, PluginConfig)>),

    #[allow(unused)]
    RpcUrlChanged(String),
}

pub enum ServiceResponse {
    Response(PluginResponse),
    Ok,
    Error(String),
}

impl ServiceProvider {
    fn start(
        default_keystore: DefaultKeyStore,
        default_indexer: DefaultIndexer,
        mut keystore_plugin: Option<(Plugin, PluginConfig)>,
        mut indexer_plugin: Option<(Plugin, PluginConfig)>,
        rpc_url: String,
    ) -> Result<ServiceProvider, String> {
        fn start_daemon(
            plugin: &Option<(Plugin, PluginConfig)>,
            service_handler: &ServiceHandler,
        ) -> Result<Option<PluginProcess>, String> {
            plugin
                .as_ref()
                .filter(|(plugin, config)| plugin.is_active() && config.daemon)
                .map(|(plugin, config)| {
                    log::info!("Start daemon plugin: {}", config.name);
                    PluginProcess::start(plugin.clone(), config.clone(), service_handler.clone())
                })
                .transpose()
        }

        let (sender, receiver) = bounded(5);
        let mut rpc_client = HttpRpcClient::new(rpc_url);
        let service_handler = sender.clone();
        let mut keystore_daemon = start_daemon(&keystore_plugin, &service_handler)?;
        let mut indexer_daemon = start_daemon(&indexer_plugin, &service_handler)?;

        let inner_sender = sender.clone();
        let handle = thread::spawn(move || loop {
            match receiver.recv() {
                Ok(Request {
                    responder,
                    arguments,
                }) => {
                    log::debug!("ServiceProvider received a request: {:?}", arguments);
                    let response = match arguments {
                        ServiceRequest::KeyStoreChanged(Some((plugin, config))) => {
                            if Some(&config.name)
                                != keystore_plugin.as_ref().map(|(_, config)| &config.name)
                            {
                                keystore_plugin = Some((plugin, config));
                                match start_daemon(&keystore_plugin, &service_handler) {
                                    Ok(process) => {
                                        keystore_daemon = process;
                                        ServiceResponse::Ok
                                    }
                                    Err(err) => ServiceResponse::Error(err),
                                }
                            } else {
                                ServiceResponse::Ok
                            }
                        }
                        ServiceRequest::KeyStoreChanged(None) => {
                            if let Some((_, config)) = keystore_plugin {
                                if keystore_daemon.is_some() {
                                    log::info!("Stop kesytore daemon plugin: {}", config.name);
                                }
                            }
                            keystore_plugin = None;
                            keystore_daemon = None;
                            ServiceResponse::Ok
                        }
                        ServiceRequest::IndexerChanged(Some((plugin, config))) => {
                            if Some(&config.name)
                                != indexer_plugin.as_ref().map(|(_, config)| &config.name)
                            {
                                indexer_plugin = Some((plugin, config));
                                match start_daemon(&indexer_plugin, &service_handler) {
                                    Ok(process) => {
                                        indexer_daemon = process;
                                        ServiceResponse::Ok
                                    }
                                    Err(err) => ServiceResponse::Error(err),
                                }
                            } else {
                                ServiceResponse::Ok
                            }
                        }
                        ServiceRequest::IndexerChanged(None) => {
                            if let Some((_, config)) = indexer_plugin {
                                if indexer_daemon.is_some() {
                                    log::info!("Stop indexer daemon plugin: {}", config.name);
                                }
                            }
                            indexer_plugin = None;
                            indexer_daemon = None;
                            ServiceResponse::Ok
                        }
                        ServiceRequest::RpcUrlChanged(new_url) => {
                            if new_url != rpc_client.url() {
                                rpc_client = HttpRpcClient::new(new_url);
                            }
                            ServiceResponse::Ok
                        }
                        ServiceRequest::Request { request, .. } => {
                            let response = match request {
                                PluginRequest::KeyStore(_) => {
                                    match keystore_plugin
                                        .as_ref()
                                        .filter(|(plugin, config)| {
                                            plugin.is_active() && !config.daemon
                                        })
                                        .map(|(plugin, config)| {
                                            PluginProcess::start(
                                                plugin.clone(),
                                                config.clone(),
                                                inner_sender.clone(),
                                            )
                                        })
                                        .transpose()
                                    {
                                        Ok(keystore_process) => {
                                            let handler = keystore_daemon
                                                .as_ref()
                                                .or_else(|| keystore_process.as_ref())
                                                .map(|process| process.handler())
                                                .unwrap_or_else(|| default_keystore.handler())
                                                .clone();
                                            thread::spawn(move || {
                                                let response =
                                                    Request::call(&handler, (0, request.clone()))
                                                        .map(|(_id, response)| response)
                                                        .unwrap_or_else(|| {
                                                            PluginResponse::Error(JsonrpcError {
                                                        code: 0,
                                                        message: String::from(
                                                            "Send request to keystore failed",
                                                        ),
                                                        data: None,
                                                    })
                                                        });
                                                if let Err(err) = responder
                                                    .send(ServiceResponse::Response(response))
                                                {
                                                    log::warn!(
                                                        "Send ServiceResponse failed: {:?}",
                                                        err
                                                    );
                                                }
                                            });
                                            // Otherwise, if plugin send request to ServiceProvider, will case a dead loop
                                            continue;
                                        }
                                        Err(err) => PluginResponse::Error(JsonrpcError {
                                            code: 0,
                                            message: err,
                                            data: None,
                                        }),
                                    }
                                }
                                PluginRequest::Indexer { .. } => {
                                    match indexer_plugin
                                        .as_ref()
                                        .filter(|(plugin, config)| {
                                            plugin.is_active() && !config.daemon
                                        })
                                        .map(|(plugin, config)| {
                                            PluginProcess::start(
                                                plugin.clone(),
                                                config.clone(),
                                                inner_sender.clone(),
                                            )
                                        })
                                        .transpose()
                                    {
                                        Ok(indexer_process) => {
                                            let handler = indexer_daemon
                                                .as_ref()
                                                .or_else(|| indexer_process.as_ref())
                                                .map(|process| process.handler())
                                                .unwrap_or_else(|| default_indexer.handler())
                                                .clone();
                                            thread::spawn(move || {
                                                let response =
                                                    Request::call(&handler, (0, request.clone()))
                                                        .map(|(_id, response)| response)
                                                        .unwrap_or_else(|| {
                                                            PluginResponse::Error(JsonrpcError {
                                                        code: 0,
                                                        message: String::from(
                                                            "Send request to indexer failed",
                                                        ),
                                                        data: None,
                                                    })
                                                        });
                                                if let Err(err) = responder
                                                    .send(ServiceResponse::Response(response))
                                                {
                                                    log::warn!(
                                                        "Send ServiceResponse failed: {:?}",
                                                        err
                                                    );
                                                }
                                            });
                                            // Otherwise, if plugin send request to ServiceProvider, will case a dead loop
                                            continue;
                                        }
                                        Err(err) => PluginResponse::Error(JsonrpcError {
                                            code: 0,
                                            message: err,
                                            data: None,
                                        }),
                                    }
                                }
                                PluginRequest::Rpc(rpc_request) => {
                                    let response_result = match rpc_request {
                                        RpcRequest::GetBlock { hash } => {
                                            // TODO: handle error
                                            rpc_client
                                                .client()
                                                .get_block(hash)
                                                .map(|data| {
                                                    PluginResponse::BlockViewOpt(Box::new(data))
                                                })
                                                .map_err(|err| err.to_string())
                                        }
                                        RpcRequest::GetBlockByNumber { number } => rpc_client
                                            .client()
                                            .get_block_by_number(BlockNumber::from(number))
                                            .map(|data| {
                                                PluginResponse::BlockViewOpt(Box::new(data))
                                            })
                                            .map_err(|err| err.to_string()),
                                        RpcRequest::GetBlockHash { number } => rpc_client
                                            .client()
                                            .get_block_hash(BlockNumber::from(number))
                                            .map(PluginResponse::H256Opt)
                                            .map_err(|err| err.to_string()),
                                        RpcRequest::GetCellbaseOutputCapacityDetails { hash } => {
                                            rpc_client
                                                .client()
                                                .get_cellbase_output_capacity_details(hash)
                                                .map(PluginResponse::BlockRewardOpt)
                                                .map_err(|err| err.to_string())
                                        } // TODO: more rpc methods
                                    };
                                    response_result.unwrap_or_else(|err| {
                                        PluginResponse::Error(JsonrpcError {
                                            code: 0,
                                            message: err,
                                            data: None,
                                        })
                                    })
                                }
                                PluginRequest::ReadPassword(prompt) => {
                                    read_password(false, Some(prompt.as_str()))
                                        .map(PluginResponse::String)
                                        .unwrap_or_else(|err| {
                                            PluginResponse::Error(JsonrpcError {
                                                code: 0,
                                                message: err,
                                                data: None,
                                            })
                                        })
                                }
                                PluginRequest::PrintStdout(content) => {
                                    print!("{}", content);
                                    io::stdout()
                                        .flush()
                                        .map(|_| PluginResponse::Ok)
                                        .unwrap_or_else(|err| {
                                            PluginResponse::Error(JsonrpcError {
                                                code: 0,
                                                message: err.to_string(),
                                                data: None,
                                            })
                                        })
                                }
                                PluginRequest::PrintStderr(content) => {
                                    eprint!("{}", content);
                                    io::stderr()
                                        .flush()
                                        .map(|_| PluginResponse::Ok)
                                        .unwrap_or_else(|err| {
                                            PluginResponse::Error(JsonrpcError {
                                                code: 0,
                                                message: err.to_string(),
                                                data: None,
                                            })
                                        })
                                }
                                _ => PluginResponse::Error(JsonrpcError {
                                    // TODO: define code
                                    code: 0,
                                    message: String::from("Invalid request to ServiceProvider"),
                                    data: None,
                                }),
                            };
                            ServiceResponse::Response(response)
                        }
                    };
                    if let Err(err) = responder.send(response) {
                        log::warn!("Send ServiceResponse failed: {:?}", err);
                    }
                }
                Err(err) => {
                    log::warn!("ServiceProvider receive request error: {:?}", err);
                    break;
                }
            }
        });
        Ok(ServiceProvider {
            _thread: handle,
            handler: sender,
        })
    }

    fn handler(&self) -> &ServiceHandler {
        &self.handler
    }
}

pub struct PluginProcess {
    // For kill the process
    _child: Child,
    _stdin_thread: JoinHandle<()>,
    _stdout_thread: JoinHandle<()>,
    // Send message to stdin thread, and expect a response from stdout thread
    handler: PluginHandler,
}

impl Drop for PluginProcess {
    fn drop(&mut self) {
        // TODO: send term signal to the process
    }
}

impl PluginProcess {
    #[allow(clippy::zero_ptr, clippy::drop_copy)]
    pub fn start(
        plugin: Plugin,
        config: PluginConfig,
        service_handler: ServiceHandler,
    ) -> Result<PluginProcess, String> {
        let mut child = Command::new(plugin.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|err| err.to_string())?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| String::from("Get stdin failed"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| String::from("Get stdout failed"))?;
        let daemon = config.daemon;

        let (request_sender, request_receiver) = bounded(1);
        let (stdout_sender, stdout_receiver) = bounded(1);
        let (service_sender, service_receiver) = bounded(1);
        let (stop_sender, stop_receiver) = bounded(1);

        let stdin_plugin_name = config.name.clone();
        let stdin_thread = thread::spawn(move || {
            let handle_service_msgs =
                |stdin: &mut ChildStdin, (id, response)| -> Result<bool, String> {
                    let jsonrpc_response = JsonrpcResponse::from((id, response));
                    let response_string =
                        serde_json::to_string(&jsonrpc_response).expect("Serialize response error");
                    log::debug!("Send response to plugin: {}", response_string);
                    stdin
                        .write_all(format!("{}\n", response_string).as_bytes())
                        .map_err(|err| err.to_string())?;
                    stdin.flush().map_err(|err| err.to_string())?;
                    Ok(false)
                };
            let mut do_select = || -> Result<bool, String> {
                select! {
                    // Send response requested by ckb-cli to plugin
                    recv(request_receiver) -> msg_result => {
                        match msg_result {
                            Ok(Request { responder, arguments }) => {
                                // TODO: use auto increment request id
                                let jsonrpc_request = JsonrpcRequest::from(arguments);
                                let request_string = serde_json::to_string(&jsonrpc_request).expect("Serialize request error");
                                log::debug!("Send request to plugin: {}", request_string);
                                stdin.write_all(format!("{}\n", request_string).as_bytes()).map_err(|err| err.to_string())?;
                                stdin.flush().map_err(|err| err.to_string())?;
                                loop {
                                    select!{
                                        recv(service_receiver) -> msg_result => {
                                            match msg_result {
                                                Ok(msg) => {
                                                    handle_service_msgs(&mut stdin, msg)?;
                                                },
                                                Err(err) => {
                                                    return Err(err.to_string());
                                                }
                                            }
                                        },
                                        recv(stdout_receiver) -> msg_result => {
                                            match msg_result {
                                                Ok(response) => {
                                                    responder.send(response).map_err(|err| err.to_string())?;
                                                    if !daemon {
                                                        stop_sender.send(()).map_err(|err| err.to_string())?;
                                                        return Ok(true);
                                                    } else {
                                                        return Ok(false);
                                                    }
                                                }
                                                Err(err) => {
                                                    return Err(err.to_string());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Err(err) => Err(err.to_string())
                        }
                    }
                    // Send repsonse requested by plugin to ckb-cli (ServiceProvider)
                    recv(service_receiver) -> msg_result => {
                        match msg_result {
                            Ok(msg) => handle_service_msgs(&mut stdin, msg),
                            Err(err) => Err(err.to_string())
                        }
                    }
                }
            };
            loop {
                match do_select() {
                    Ok(true) => {
                        break;
                    }
                    Ok(false) => (),
                    Err(err) => {
                        log::info!("plugin {} stdin error: {}", stdin_plugin_name, err);
                        break;
                    }
                }
            }
        });

        let mut buf_reader = BufReader::new(stdout);
        let stdout_thread = thread::spawn(move || {
            let mut do_recv = || -> Result<bool, String> {
                if stop_receiver.try_recv().is_ok() {
                    return Ok(true);
                }
                let mut content = String::new();
                if buf_reader
                    .read_line(&mut content)
                    .map_err(|err| err.to_string())?
                    == 0
                {
                    // EOF
                    return Ok(true);
                }
                let result: Result<JsonrpcResponse, _> = serde_json::from_str(&content);
                if let Ok(jsonrpc_response) = result {
                    // Receive response from plugin
                    log::debug!("Receive response from plugin: {}", content.trim());
                    let (id, response) = jsonrpc_response.try_into()?;
                    stdout_sender
                        .send((id, response))
                        .map_err(|err| err.to_string())?;
                } else {
                    // Handle request from plugin
                    log::debug!("Receive request from plugin: {}", content.trim());
                    let jsonrpc_request: JsonrpcRequest =
                        serde_json::from_str(&content).map_err(|err| err.to_string())?;
                    let (id, request) = jsonrpc_request.try_into()?;
                    let service_request = ServiceRequest::Request {
                        is_from_plugin: true,
                        plugin_name: config.name.clone(),
                        request,
                    };
                    log::debug!("Sending request to ServiceProvider");
                    if let ServiceResponse::Response(response) =
                        Request::call(&service_handler, service_request)
                            .ok_or_else(|| String::from("Send request to ServiceProvider failed"))?
                    {
                        log::debug!("Received response from ServiceProvider");
                        service_sender
                            .send((id, response))
                            .map_err(|err| err.to_string())?;
                    }
                }
                Ok(false)
            };
            loop {
                match do_recv() {
                    Ok(true) => {
                        log::info!("plugin {} quit", config.name);
                        break;
                    }
                    Ok(false) => {}
                    Err(err) => {
                        log::warn!("plugin {} stdout error: {}", config.name, err);
                        break;
                    }
                }
            }
        });

        Ok(PluginProcess {
            _child: child,
            _stdin_thread: stdin_thread,
            _stdout_thread: stdout_thread,
            handler: request_sender,
        })
    }

    pub fn handler(&self) -> &PluginHandler {
        &self.handler
    }
}

#[derive(Clone, Debug)]
pub struct Plugin {
    // Executable binary path
    path: PathBuf,
    args: Vec<String>,
    is_active: bool,
}

impl Plugin {
    pub fn new(path: PathBuf, args: Vec<String>, is_active: bool) -> Plugin {
        Plugin {
            path,
            args,
            is_active,
        }
    }

    // TODO: Try read from {plugin-name}.json file first
    pub fn get_config(&self) -> Result<PluginConfig, String> {
        let mut child = Command::new(&self.path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|err| err.to_string())?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| String::from("Get stdin failed"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| String::from("Get stdout failed"))?;
        let jsonrpc_request = JsonrpcRequest::from((0, PluginRequest::GetConfig));
        let request_string =
            serde_json::to_string(&jsonrpc_request).expect("Serialize request error");
        log::debug!("Send request to plugin: {}", request_string);
        stdin
            .write_all(format!("{}\n", request_string).as_bytes())
            .map_err(|err| err.to_string())?;
        stdin.flush().map_err(|err| err.to_string())?;
        let mut buf_reader = BufReader::new(stdout);
        let mut response_string = String::new();
        buf_reader
            .read_line(&mut response_string)
            .map_err(|err| err.to_string())?;
        log::debug!("Receive response from plugin: {}", response_string.trim());
        // TODO: make sure process exit
        let jsonrpc_response: JsonrpcResponse =
            serde_json::from_str(&response_string).map_err(|err| err.to_string())?;
        let (_id, response) = jsonrpc_response.try_into()?;
        if let PluginResponse::PluginConfig(config) = response {
            Ok(config)
        } else {
            Err(format!(
                "Invalid response for get_config call to plugin {:?}, response: {}",
                self.path, response_string
            ))
        }
    }

    pub fn set_path(&mut self, path: PathBuf) {
        self.path = path;
    }
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn is_active(&self) -> bool {
        self.is_active
    }

    pub fn active(&mut self) {
        self.is_active = true;
    }

    pub fn deactive(&mut self) {
        self.is_active = false;
    }
}

#[derive(Clone)]
pub struct KeyStoreHandler {
    // Local File System keystore
    default_handler: PluginHandler,
    // For call keystore plugin
    service_handler: ServiceHandler,
    // The actived keystore plugin
    actived_plugin: Option<PluginConfig>,
}

impl KeyStoreHandler {
    fn new(
        default_handler: PluginHandler,
        service_handler: ServiceHandler,
        actived_plugin: Option<PluginConfig>,
    ) -> KeyStoreHandler {
        KeyStoreHandler {
            default_handler,
            service_handler,
            actived_plugin,
        }
    }

    pub fn actived_plugin(&self) -> Option<&PluginConfig> {
        self.actived_plugin.as_ref()
    }

    fn call(&self, request: KeyStoreRequest) -> Result<PluginResponse, String> {
        let mut default_only = false;
        let mut hash160_opt = None;
        match request {
            KeyStoreRequest::ListAccount => {
                // Both (and) handle default part out side
            }
            KeyStoreRequest::HasAccount(_) => {
                // Both (or) handle default part out side
            }
            KeyStoreRequest::CreateAccount(_) => {
                // Both (neet target), currently default only
                default_only = true;
            }
            KeyStoreRequest::Import { .. } => {
                // Default only
                default_only = true;
            }
            KeyStoreRequest::ImportAccount { .. } => {
                // Plugin only
            }
            KeyStoreRequest::Export { ref hash160, .. } => {
                // Both
                hash160_opt = Some(hash160.clone());
            }
            KeyStoreRequest::UpdatePassword { ref hash160, .. } => {
                // Both
                hash160_opt = Some(hash160.clone());
            }
            KeyStoreRequest::Sign { ref hash160, .. } => {
                // Both
                hash160_opt = Some(hash160.clone());
            }
            KeyStoreRequest::ExtendedPubkey { ref hash160, .. } => {
                // Both
                hash160_opt = Some(hash160.clone());
            }
            KeyStoreRequest::DerivedKeySet { ref hash160, .. } => {
                // Both
                hash160_opt = Some(hash160.clone());
            }
            KeyStoreRequest::DerivedKeySetByIndex { ref hash160, .. } => {
                // Both
                hash160_opt = Some(hash160.clone());
            }
            KeyStoreRequest::Any(_) => {
                // Plugin only
            }
        }
        if default_only
            || hash160_opt
                .map(|hash160| self.has_account_in_default(hash160))
                .transpose()?
                == Some(true)
        {
            let result =
                match Request::call(&self.default_handler, (0, PluginRequest::KeyStore(request)))
                    .map(|(_id, resp)| resp)
                    .ok_or_else(|| String::from("Call to default keystore failed"))?
                {
                    PluginResponse::Error(error) => Err(error.message),
                    response => Ok(response),
                };
            return result;
        }

        let request = ServiceRequest::Request {
            is_from_plugin: false,
            plugin_name: String::from("default_keystore"),
            request: PluginRequest::KeyStore(request),
        };
        match Request::call(&self.service_handler, request) {
            Some(ServiceResponse::Response(PluginResponse::Error(error))) => Err(error.message),
            Some(ServiceResponse::Response(response)) => Ok(response),
            Some(_) => Err(String::from("Mismatch plugin response")),
            None => Err(String::from("Send request error")),
        }
    }

    pub fn root_key_path(&self, h160: H160) -> Result<DerivationPath, String> {
        if self.has_account_in_default(h160)? {
            Ok(DerivationPath::empty())
        } else {
            Ok(DerivationPath::from_str(CKB_ROOT_PATH).expect("parse ckb root path"))
        }
    }

    pub fn has_account_in_default(&self, hash160: H160) -> Result<bool, String> {
        let request = PluginRequest::KeyStore(KeyStoreRequest::HasAccount(hash160));
        if let Some((_, PluginResponse::Boolean(has))) =
            Request::call(&self.default_handler, (0, request))
        {
            Ok(has)
        } else {
            Err("Mismatch keystore response".to_string())
        }
    }

    pub fn list_account(&self) -> Result<Vec<(Bytes, String)>, String> {
        let request = KeyStoreRequest::ListAccount;
        let plugin_request = PluginRequest::KeyStore(request.clone());

        let mut all_accounts = Vec::new();
        if let Some((_, PluginResponse::H160Vec(accounts))) =
            Request::call(&self.default_handler, (0, plugin_request))
        {
            all_accounts.extend(
                accounts
                    .into_iter()
                    .map(|hash160| Bytes::from(hash160.as_bytes().to_vec()))
                    .map(|data| (data, ACCOUNT_SOURCE_FS.to_owned())),
            );
        } else {
            return Err("Mismatch default keystore response".to_string());
        }
        if let Some(cfg) = self.actived_plugin() {
            match self.call(request) {
                Ok(PluginResponse::BytesVec(accounts)) => {
                    all_accounts.extend(
                        accounts
                            .into_iter()
                            .map(|data| (data.into_bytes(), format!("[plugin]: {}", cfg.name))),
                    );
                }
                Ok(_) => {
                    return Err("Mismatch plugin keystore response".to_string());
                }
                Err(err) => {
                    log::info!("Send request to plugin({}) failed: {}", cfg.name, err);
                }
            }
        }
        Ok(all_accounts)
    }

    pub fn create_account(&self, password: String) -> Result<H160, String> {
        let request = KeyStoreRequest::CreateAccount(Some(password));
        if let PluginResponse::H160(hash160) = self.call(request)? {
            Ok(hash160)
        } else {
            Err("Mismatch keystore response".to_string())
        }
    }
    pub fn update_password(
        &self,
        hash160: H160,
        password: String,
        new_password: String,
    ) -> Result<(), String> {
        let request = KeyStoreRequest::UpdatePassword {
            hash160,
            password,
            new_password,
        };
        if let PluginResponse::Ok = self.call(request)? {
            Ok(())
        } else {
            Err("Mismatch keystore response".to_string())
        }
    }
    pub fn import_key(
        &self,
        master_privkey: MasterPrivKey,
        password: Option<String>,
    ) -> Result<H160, String> {
        let data = master_privkey.to_bytes();
        let mut privkey = [0u8; 32];
        let mut chain_code = [0u8; 32];
        privkey.copy_from_slice(&data[0..32]);
        chain_code.copy_from_slice(&data[32..64]);
        let request = KeyStoreRequest::Import {
            privkey,
            chain_code,
            password,
        };
        if let PluginResponse::H160(lock_arg) = self.call(request)? {
            Ok(lock_arg)
        } else {
            Err("Mismatch keystore response".to_string())
        }
    }
    pub fn import_account(
        &self,
        account_id: Bytes,
        password: Option<String>,
    ) -> Result<H160, String> {
        let request = KeyStoreRequest::ImportAccount {
            account_id: JsonBytes::from_bytes(account_id),
            password,
        };
        if let PluginResponse::H160(lock_arg) = self.call(request)? {
            Ok(lock_arg)
        } else {
            Err("Mismatch keystore response".to_string())
        }
    }
    pub fn export_key(
        &self,
        hash160: H160,
        password: Option<String>,
    ) -> Result<MasterPrivKey, String> {
        let request = KeyStoreRequest::Export { hash160, password };
        if let PluginResponse::MasterPrivateKey {
            privkey,
            chain_code,
        } = self.call(request)?
        {
            if privkey.len() != 32 {
                return Err(format!(
                    "Invalid privkey length return from keystore, length={}, expected: 32",
                    privkey.len()
                ));
            }
            if chain_code.len() != 32 {
                return Err(format!(
                    "Invalid chain_code length return from keystore, length={}, expected: 32",
                    privkey.len()
                ));
            }
            let mut data = [0u8; 64];
            data[0..32].copy_from_slice(privkey.as_bytes());
            data[32..64].copy_from_slice(chain_code.as_bytes());
            let master_privkey = MasterPrivKey::from_bytes(data).map_err(|err| err.to_string())?;
            Ok(master_privkey)
        } else {
            Err("Mismatch keystore response".to_string())
        }
    }
    pub fn derived_key_set(
        &self,
        hash160: H160,
        external_max_len: u32,
        change_last: H160,
        change_max_len: u32,
        password: Option<String>,
    ) -> Result<DerivedKeySet, String> {
        let request = KeyStoreRequest::DerivedKeySet {
            hash160: hash160.clone(),
            external_max_len,
            change_last: change_last.clone(),
            change_max_len,
            password,
        };
        let resp = match self.call(request) {
            Ok(resp) => resp,
            // A hack for compatibility
            Err(message) if message == ERROR_KEYSTORE_REQUIRE_PASSWORD => {
                let password = read_password(false, None)?;
                let request = KeyStoreRequest::DerivedKeySet {
                    hash160,
                    external_max_len,
                    change_last,
                    change_max_len,
                    password: Some(password),
                };
                self.call(request)?
            }
            Err(other) => {
                return Err(other);
            }
        };
        if let PluginResponse::DerivedKeySet { external, change } = resp {
            let external = deserilize_key_set(external)?;
            let change = deserilize_key_set(change)?;
            Ok(DerivedKeySet { external, change })
        } else {
            Err("Mismatch keystore response".to_string())
        }
    }
    pub fn derived_key_set_by_index(
        &self,
        hash160: H160,
        external_start: u32,
        external_length: u32,
        change_start: u32,
        change_length: u32,
        password: Option<String>,
    ) -> Result<DerivedKeySet, String> {
        let request = KeyStoreRequest::DerivedKeySetByIndex {
            hash160: hash160.clone(),
            external_start,
            external_length,
            change_start,
            change_length,
            password,
        };
        let resp = match self.call(request) {
            Ok(resp) => resp,
            // A hack for compatibility
            Err(message) if message == ERROR_KEYSTORE_REQUIRE_PASSWORD => {
                let password = read_password(false, None)?;
                let request = KeyStoreRequest::DerivedKeySetByIndex {
                    hash160,
                    external_start,
                    external_length,
                    change_start,
                    change_length,
                    password: Some(password),
                };
                self.call(request)?
            }
            Err(other) => {
                return Err(other);
            }
        };
        if let PluginResponse::DerivedKeySet { external, change } = resp {
            let external = deserilize_key_set(external)?;
            let change = deserilize_key_set(change)?;
            Ok(DerivedKeySet { external, change })
        } else {
            Err("Mismatch keystore response".to_string())
        }
    }
    pub fn sign<P: ?Sized + AsRef<[ChildNumber]>>(
        &self,
        hash160: H160,
        path: &P,
        message: H256,
        target: SignTarget,
        password: Option<String>,
        recoverable: bool,
    ) -> Result<Bytes, String> {
        let path = DerivationPath::from(path.as_ref().to_vec()).to_string();
        let request = KeyStoreRequest::Sign {
            hash160: hash160.clone(),
            path: path.clone(),
            message: message.clone(),
            target: Box::new(target.clone()),
            password,
            recoverable,
        };
        let resp = match self.call(request) {
            Ok(resp) => resp,
            // A hack for compatibility
            Err(err) if err == ERROR_KEYSTORE_REQUIRE_PASSWORD => {
                let password = read_password(false, None)?;
                let request = KeyStoreRequest::Sign {
                    hash160,
                    path,
                    message,
                    target: Box::new(target),
                    password: Some(password),
                    recoverable,
                };
                self.call(request)?
            }
            Err(other) => {
                return Err(other);
            }
        };
        if let PluginResponse::Bytes(data) = resp {
            Ok(data.into_bytes())
        } else {
            Err("Mismatch keystore response".to_string())
        }
    }
    pub fn extended_pubkey<P: ?Sized + AsRef<[ChildNumber]>>(
        &self,
        hash160: H160,
        path: &P,
        password: Option<String>,
    ) -> Result<secp256k1::PublicKey, String> {
        let path = DerivationPath::from(path.as_ref().to_vec()).to_string();
        let request = KeyStoreRequest::ExtendedPubkey {
            hash160: hash160.clone(),
            path: path.clone(),
            password,
        };
        let resp = match self.call(request) {
            Ok(resp) => resp,
            // A hack for compatibility
            Err(message) if message == ERROR_KEYSTORE_REQUIRE_PASSWORD => {
                let password = read_password(false, None)?;
                let request = KeyStoreRequest::ExtendedPubkey {
                    hash160,
                    path,
                    password: Some(password),
                };
                self.call(request)?
            }
            Err(other) => {
                return Err(other);
            }
        };
        if let PluginResponse::Bytes(data) = resp {
            secp256k1::PublicKey::from_slice(data.as_bytes()).map_err(|err| err.to_string())
        } else {
            Err("Mismatch keystore response".to_string())
        }
    }
}

#[derive(Clone)]
pub struct IndexerHandler {
    handler: ServiceHandler,
}

#[allow(unused)]
impl IndexerHandler {
    fn new(handler: ServiceHandler) -> IndexerHandler {
        IndexerHandler { handler }
    }

    fn call(&self, request: PluginRequest) -> Result<PluginResponse, String> {
        let request = ServiceRequest::Request {
            is_from_plugin: false,
            plugin_name: String::from("default_indexer"),
            request,
        };
        match Request::call(&self.handler, request) {
            Some(ServiceResponse::Response(PluginResponse::Error(error))) => Err(error.message),
            Some(ServiceResponse::Response(response)) => Ok(response),
            Some(_) => Err(String::from("Mismatch plugin response")),
            None => Err(String::from("Send request error")),
        }
    }

    pub fn tip_header(&self, genesis_hash: H256) -> Result<Box<HeaderView>, String> {
        let request = PluginRequest::Indexer {
            genesis_hash,
            request: IndexerRequest::TipHeader,
        };
        if let PluginResponse::HeaderView(header_view) = self.call(request)? {
            Ok(header_view)
        } else {
            Err("Invalid plugin response".to_string())
        }
    }
    pub fn last_header(&self, genesis_hash: H256) -> Result<Box<Option<HeaderView>>, String> {
        let request = PluginRequest::Indexer {
            genesis_hash,
            request: IndexerRequest::LastHeader,
        };
        if let PluginResponse::HeaderViewOpt(header_view_opt) = self.call(request)? {
            Ok(header_view_opt)
        } else {
            Err("Invalid plugin response".to_string())
        }
    }
    pub fn get_capacity(&self, genesis_hash: H256, lock_hash: H256) -> Result<u64, String> {
        let request = PluginRequest::Indexer {
            genesis_hash,
            request: IndexerRequest::GetCapacity(lock_hash),
        };
        if let PluginResponse::Integer64(capacity) = self.call(request)? {
            Ok(capacity)
        } else {
            Err("Invalid plugin response".to_string())
        }
    }
    pub fn get_live_cells(
        &self,
        genesis_hash: H256,
        index: LiveCellIndexType,
        hash: H256,
        from_number: Option<u64>,
        to_number: Option<u64>,
        limit: u64,
    ) -> Result<Vec<LiveCellInfo>, String> {
        let request = PluginRequest::Indexer {
            genesis_hash,
            request: IndexerRequest::LiveCells {
                index,
                hash,
                from_number,
                to_number,
                limit,
            },
        };
        if let PluginResponse::LiveCells(infos) = self.call(request)? {
            Ok(infos)
        } else {
            Err("Invalid plugin response".to_string())
        }
    }
    pub fn get_top_n(
        &self,
        genesis_hash: H256,
        n: u64,
    ) -> Result<Vec<(H256, Option<Script>, u64)>, String> {
        let request = PluginRequest::Indexer {
            genesis_hash,
            request: IndexerRequest::TopN(n),
        };
        if let PluginResponse::TopN(infos) = self.call(request)? {
            Ok(infos)
        } else {
            Err("Invalid plugin response".to_string())
        }
    }
    // JSON format indexer status info
    pub fn get_indexer_info(&self, genesis_hash: H256) -> Result<serde_json::Value, String> {
        let request = PluginRequest::Indexer {
            genesis_hash,
            request: IndexerRequest::IndexerInfo,
        };
        if let PluginResponse::JsonValue(info) = self.call(request)? {
            Ok(info)
        } else {
            Err("Invalid plugin response".to_string())
        }
    }
}
