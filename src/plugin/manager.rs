use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use ckb_index::LiveCellInfo;
use ckb_sdk::{
    rpc::{HeaderView, Script},
    wallet::{ChildNumber, DerivationPath, DerivedKeySet, MasterPrivKey},
    HttpRpcClient,
};
use ckb_types::{core::service::Request, H160, H256};
use crossbeam_channel::{bounded, select, Sender};

use super::builtin::{DefaultIndexer, DefaultKeyStore};
use crate::utils::other::read_password;
use plugin_protocol::{
    CallbackName, CallbackRequest, CallbackResponse, IndexerRequest, IndexerResponse,
    KeyStoreRequest, KeyStoreResponse, LiveCellIndexType, PluginConfig, PluginRequest,
    PluginResponse, PluginRole, RpcRequest, RpcResponse,
};

pub const PLUGINS_DIRNAME: &str = "plugins";
pub const INACTIVE_DIRNAME: &str = "inactive";
#[cfg(unix)]
pub const PLUGIN_FILENAME_EXT: &str = "bin";
#[cfg(not(unix))]
pub const PLUGIN_FILENAME_EXT: &str = "exe";

pub struct PluginManager {
    plugin_dir: PathBuf,
    plugins: HashMap<String, (Plugin, PluginConfig)>,
    daemon_processes: HashMap<String, PluginProcess>,

    // == Plugin role configs
    // The keystore plugins currently actived
    keystores: Vec<String>,
    // The indexer plugins currently actived
    indexers: Vec<String>,
    // The key is sub-command name
    sub_commands: HashMap<String, String>,
    // The key is callback name
    callbacks: HashMap<CallbackName, String>,

    service_provider: ServiceProvider,
    jsonrpc_id: Arc<AtomicU64>,
}

pub type PluginHandler = Sender<Request<PluginRequest, PluginResponse>>;
pub type ServiceHandler = Sender<Request<ServiceRequest, ServiceResponse>>;

impl PluginManager {
    pub fn init(ckb_cli_dir: &PathBuf, rpc_url: String) -> Result<PluginManager, String> {
        let plugin_dir = ckb_cli_dir.join(PLUGINS_DIRNAME);
        let inactive_plugin_dir = plugin_dir.join(INACTIVE_DIRNAME);

        let mut plugins = HashMap::default();

        if !inactive_plugin_dir.exists() {
            fs::create_dir_all(&inactive_plugin_dir).map_err(|err| err.to_string())?;
        }
        for (dir, is_active) in &[(&plugin_dir, true), (&inactive_plugin_dir, false)] {
            for entry in fs::read_dir(dir).map_err(|err| err.to_string())? {
                let entry = entry.map_err(|err| err.to_string())?;
                let path = entry.path();
                if path.is_file()
                    && path
                        .extension()
                        .map(|ext| ext == PLUGIN_FILENAME_EXT)
                        .unwrap_or(false)
                {
                    let plugin = Plugin::new(path.clone(), Vec::new(), *is_active);
                    match plugin.register() {
                        Ok(config) => {
                            plugins.insert(config.name.clone(), (plugin, config));
                        }
                        Err(err) => {
                            println!("register error: {}, path: {:?}", err, path);
                        }
                    }
                }
            }
        }

        let default_keystore = DefaultKeyStore::start(ckb_cli_dir)?;
        // TODO: impl indexer thread
        let default_indexer = DefaultIndexer::start()?;

        // Make sure ServiceProvider start before all daemon processes
        let mut daemon_plugins = Vec::new();
        let mut daemon_processes = HashMap::new();
        let mut keystores = Vec::new();
        let mut indexers = Vec::new();
        let mut sub_commands = HashMap::new();
        let mut callbacks = HashMap::new();
        let mut keystore_plugin = None;
        let mut indexer_plugin = None;
        for (plugin_name, (plugin, config)) in &plugins {
            if config.daemon {
                daemon_plugins.push((plugin.clone(), config.clone()));
            }
            for role in &config.roles {
                match role {
                    PluginRole::KeyStore(_) => {
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
                    PluginRole::SubCommand(command_name) => {
                        sub_commands.insert(command_name.clone(), plugin_name.clone());
                    }
                    PluginRole::Callback(name) => {
                        let callback_name = CallbackName::from_str(name.as_str()).unwrap();
                        callbacks.insert(callback_name, plugin_name.clone());
                    }
                }
            }
        }
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
            jsonrpc_id,
        })
    }

    pub fn keystore_require_password(&self) -> bool {
        self.keystores
            .iter()
            .filter_map(|name| {
                self.plugins
                    .get(name)
                    .filter(|(plugin, _)| plugin.is_active())
                    .map(|(_, config)| {
                        for role in &config.roles {
                            if let PluginRole::KeyStore(require_password) = role {
                                return *require_password;
                            }
                        }
                        true
                    })
            })
            .next()
            .unwrap_or(true)
    }
    pub fn keystore_handler(&self) -> KeyStoreHandler {
        KeyStoreHandler::new(self.service_provider.handler().clone())
    }
    pub fn indexer_handler(&self) -> IndexerHandler {
        IndexerHandler::new(self.service_provider.handler().clone())
    }

    pub fn active(&mut self, name: &str) -> Result<(), String> {
        // TODO: notify ServiceProvider
        if let Some((plugin, config)) = self.plugins.get_mut(name) {
            if !plugin.is_active() {
                plugin.active();
                if config.daemon {
                    let process = PluginProcess::start(
                        plugin.clone(),
                        config.clone(),
                        self.service_provider.handler().clone(),
                    )?;
                    self.daemon_processes.insert(name.to_string(), process);
                }
            }
            Ok(())
        } else {
            Err(format!("Plugin not found: {}", name))
        }
    }
    pub fn deactive(&mut self, name: &str) -> Result<(), String> {
        // TODO: notify ServiceProvider
        if let Some((plugin, config)) = self.plugins.get_mut(name) {
            if plugin.is_active() {
                plugin.deactive();
                if config.daemon {
                    self.daemon_processes.remove(name);
                }
            }
            Ok(())
        } else {
            Err(format!("Plugin not found: {}", name))
        }
    }
    pub fn install(&mut self, tmp_path: PathBuf, active: bool) -> Result<PluginConfig, String> {
        let tmp_plugin = Plugin::new(tmp_path, Vec::new(), active);
        let config = tmp_plugin.register()?;
        let base_dir = if active {
            self.plugin_dir.clone()
        } else {
            self.plugin_dir.join(INACTIVE_DIRNAME)
        };
        let path = base_dir.join(format!("{}.{}", config.name, PLUGIN_FILENAME_EXT));
        fs::copy(tmp_plugin.path(), &path).map_err(|err| err.to_string())?;
        // TODO: change this address to executable
        let plugin = Plugin::new(path, Vec::new(), active);
        self.plugins
            .insert(config.name.clone(), (plugin, config.clone()));

        for role in &config.roles {
            match role {
                PluginRole::KeyStore(_) => {
                    self.keystores.push(config.name.clone());
                }
                PluginRole::Indexer => {
                    self.indexers.push(config.name.clone());
                }
                PluginRole::SubCommand(command_name) => {
                    self.sub_commands
                        .insert(command_name.clone(), config.name.clone());
                }
                PluginRole::Callback(name) => {
                    let callback_name = CallbackName::from_str(name.as_str()).unwrap();
                    self.callbacks.insert(callback_name, config.name.clone());
                }
            }
        }
        if active {
            self.active(&config.name)?;
        }
        Ok(config)
    }
    pub fn uninstall(&mut self, name: &str) -> Result<(), String> {
        self.deactive(name)?;
        if let Some((plugin, _config)) = self.plugins.remove(name) {
            fs::remove_file(plugin.path()).map_err(|err| err.to_string())?;
            // TODO: clean up role configs
        }
        Ok(())
    }

    /// Handle sub-command and callback call
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
                    PluginProcess::start(plugin.clone(), config.clone(), service_handler).unwrap();
                func(process.handler())
            } else {
                Err(format!("Plugin {} is inactive", name))
            }
        } else {
            Err(format!("Plugin name not found: {}", name))
        }
    }

    pub fn rpc_url_changed(&self, new_url: String) -> Result<(), String> {
        match Request::call(
            self.service_provider.handler(),
            ServiceRequest::RpcUrlChanged(new_url.clone()),
        )
        .unwrap()
        {
            ServiceResponse::Ok => Ok(()),
            _ => Err(format!("Invalid plugin response")),
        }
    }

    pub fn sub_command(&self, command_name: &str, rest_args: String) -> Result<String, String> {
        if let Some(plugin_name) = self.sub_commands.get(command_name) {
            self.handle(plugin_name.as_str(), |handler| {
                let request = PluginRequest::SubCommand(rest_args);
                if let PluginResponse::SubCommand(output) = Request::call(handler, request).unwrap()
                {
                    Ok(output)
                } else {
                    Err("Invalid plugin response".to_string())
                }
            })
        } else {
            Err(format!(
                "plugin for sub-command {} not found or inactive",
                command_name
            ))
        }
    }
    pub fn callback(
        &self,
        callback_name: CallbackName,
        arguments: CallbackRequest,
    ) -> Result<CallbackResponse, String> {
        if let Some(plugin_name) = self.callbacks.get(&callback_name) {
            self.handle(plugin_name.as_str(), |handler| {
                let request = PluginRequest::Callback(arguments);
                if let PluginResponse::Callback(response) = Request::call(handler, request).unwrap()
                {
                    Ok(response)
                } else {
                    Err("Invalid plugin response".to_string())
                }
            })
        } else {
            Err(format!(
                "callback plugin for {} hook not found or inactive",
                callback_name
            ))
        }
    }

    pub fn plugin_dir(&self) -> &PathBuf {
        &self.plugin_dir
    }
    pub fn plugins(&self) -> &HashMap<String, (Plugin, PluginConfig)> {
        &self.plugins
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
    thread: JoinHandle<()>,
}

pub enum ServiceRequest {
    Request {
        // The request is from plugin or ckb-cli
        is_from_plugin: bool,
        plugin_name: String,
        request: PluginRequest,
    },
    KeyStoreChanged {
        plugin: Plugin,
        config: PluginConfig,
    },
    IndexerChanged {
        plugin: Plugin,
        config: PluginConfig,
    },
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
                    let response = match arguments {
                        ServiceRequest::KeyStoreChanged { plugin, config } => {
                            keystore_plugin = Some((plugin, config));
                            // TODO: error handle
                            keystore_daemon =
                                start_daemon(&keystore_plugin, &service_handler).unwrap();
                            ServiceResponse::Ok
                        }
                        ServiceRequest::IndexerChanged { plugin, config } => {
                            indexer_plugin = Some((plugin, config));
                            // TODO: error handle
                            indexer_daemon =
                                start_daemon(&indexer_plugin, &service_handler).unwrap();
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
                                    let keystore_process = keystore_plugin
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
                                        .unwrap();
                                    let handler = keystore_daemon
                                        .as_ref()
                                        .or_else(|| keystore_process.as_ref())
                                        .map(|process| process.handler())
                                        .unwrap_or_else(|| default_keystore.handler());
                                    Request::call(handler, request.clone()).unwrap()
                                }
                                PluginRequest::Indexer { .. } => {
                                    let indexer_process = indexer_plugin
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
                                        .unwrap();
                                    let handler = indexer_daemon
                                        .as_ref()
                                        .or_else(|| indexer_process.as_ref())
                                        .map(|process| process.handler())
                                        .unwrap_or_else(|| default_indexer.handler());
                                    Request::call(handler, request.clone()).unwrap()
                                }
                                PluginRequest::Rpc(rpc_request) => {
                                    let response = match rpc_request {
                                        RpcRequest::GetBlock { hash } => {
                                            // TODO: handle error
                                            RpcResponse::BlockView(
                                                rpc_client.get_block(hash).unwrap(),
                                            )
                                        }
                                        RpcRequest::GetBlockByNumber { number } => {
                                            RpcResponse::BlockView(
                                                rpc_client.get_block_by_number(number).unwrap(),
                                            )
                                        }
                                        RpcRequest::GetBlockHash { number } => {
                                            RpcResponse::BlockHash(
                                                rpc_client.get_block_hash(number).unwrap(),
                                            )
                                        }
                                        RpcRequest::GetCellbaseOutputCapacityDetails { hash } => {
                                            RpcResponse::BlockReward(
                                                rpc_client
                                                    .get_cellbase_output_capacity_details(hash)
                                                    .unwrap(),
                                            )
                                        } // TODO: more rpc methods
                                    };
                                    PluginResponse::Rpc(response)
                                }
                                PluginRequest::ReadPassword(prompt) => {
                                    let password =
                                        read_password(false, Some(prompt.as_str())).unwrap();
                                    PluginResponse::Password(password)
                                }
                                PluginRequest::PrintStdout(content) => {
                                    print!("{}", content);
                                    io::stdout().flush().unwrap();
                                    PluginResponse::Ok
                                }
                                PluginRequest::PrintStderr(content) => {
                                    eprint!("{}", content);
                                    io::stdout().flush().unwrap();
                                    PluginResponse::Ok
                                }
                                _ => {
                                    // TODO: error
                                    break;
                                }
                            };
                            ServiceResponse::Response(response)
                        }
                    };
                    responder.send(response).unwrap();
                }
                Err(_err) => {
                    break;
                }
            }
        });
        Ok(ServiceProvider {
            thread: handle,
            handler: sender,
        })
    }

    fn handler(&self) -> &ServiceHandler {
        &self.handler
    }
}

pub struct PluginProcess {
    // For kill the process
    child: Child,
    stdin_thread: JoinHandle<()>,
    stdout_thread: JoinHandle<()>,
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
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let daemon = config.daemon;

        let (request_sender, request_receiver) = bounded(1);
        let (stdout_sender, stdout_receiver) = bounded(1);
        let (service_sender, service_receiver) = bounded(1);
        let (stop_sender, stop_receiver) = bounded(1);

        let stdin_thread = thread::spawn(move || loop {
            select! {
                // Send response requested by ckb-cli to plugin
                recv(request_receiver) -> msg => {
                    if let Ok(Request { responder, arguments }) = msg {
                        let request_string = format!("{}\n", serde_json::to_string(&arguments).unwrap());
                        stdin.write_all(request_string.as_bytes()).unwrap();
                        stdin.flush().unwrap();
                        if let Ok(response) = stdout_receiver.recv() {
                            responder.send(response).unwrap();
                            if !daemon {
                                stop_sender.send(()).unwrap();
                                break;
                            }
                        } else {
                            // TODO: error handling
                            break;
                        }
                    } else {
                        // TODO: error handling
                        break;
                    }
                }
                // Send repsonse requested by plugin to ckb-cli (ServiceProvider)
                recv(service_receiver) -> msg => {
                    if let Ok(response) = msg {
                        let response_string = format!("{}\n", serde_json::to_string(&response).unwrap());
                        stdin.write_all(response_string.as_bytes()).unwrap();
                        stdin.flush().unwrap();
                    } else {
                        // TODO: error handling
                        break;
                    }
                }
            }
        });

        let mut buf_reader = BufReader::new(stdout);
        let stdout_thread = thread::spawn(move || loop {
            if stop_receiver.try_recv().is_ok() {
                break;
            }
            let mut content = String::new();
            if buf_reader.read_line(&mut content).unwrap() == 0 {
                // EOF
                break;
            }
            let result: Result<PluginResponse, _> = serde_json::from_str(&content);
            if let Ok(response) = result {
                stdout_sender.send(response).unwrap();
            } else {
                let request: PluginRequest = serde_json::from_str(&content).unwrap();
                let service_request = ServiceRequest::Request {
                    is_from_plugin: true,
                    plugin_name: config.name.clone(),
                    request,
                };
                if let ServiceResponse::Response(response) =
                    Request::call(&service_handler, service_request).unwrap()
                {
                    service_sender.send(response).unwrap();
                }
            }
        });

        Ok(PluginProcess {
            child,
            stdin_thread,
            stdout_thread,
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
    pub fn register(&self) -> Result<PluginConfig, String> {
        let mut child = Command::new(&self.path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let request_string = format!(
            "{}\n",
            serde_json::to_string(&PluginRequest::Register).unwrap()
        );
        stdin.write_all(request_string.as_bytes()).unwrap();
        stdin.flush().unwrap();
        let mut buf_reader = BufReader::new(stdout);
        let mut response_string = String::new();
        buf_reader.read_line(&mut response_string).unwrap();
        // TODO: make sure process exit
        let response: PluginResponse = serde_json::from_str(&response_string).unwrap();
        if let PluginResponse::PluginConfig(config) = response {
            Ok(config)
        } else {
            Err(format!(
                "Invalid response for register call to plugin {:?}, response: {}",
                self.path, response_string
            ))
        }
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
    handler: ServiceHandler,
}

impl KeyStoreHandler {
    fn new(handler: ServiceHandler) -> KeyStoreHandler {
        KeyStoreHandler { handler }
    }

    pub fn inner(&self) -> &ServiceHandler {
        &self.handler
    }

    fn call(&self, request: KeyStoreRequest) -> Result<PluginResponse, String> {
        let request = ServiceRequest::Request {
            is_from_plugin: false,
            plugin_name: String::from("default_keystore"),
            request: PluginRequest::KeyStore(request),
        };
        match Request::call(&self.handler, request) {
            Some(ServiceResponse::Response(PluginResponse::Error(error))) => Err(error),
            Some(ServiceResponse::Response(response)) => Ok(response),
            Some(_) => Err(String::from("Mismatch plugin response")),
            None => Err(String::from("Send request error")),
        }
    }

    pub fn create_account(&self, password: Option<String>) -> Result<H160, String> {
        let request = KeyStoreRequest::CreateAccount(password);
        if let PluginResponse::KeyStore(KeyStoreResponse::AccountCreated(hash160)) =
            self.call(request)?
        {
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
        if let PluginResponse::KeyStore(KeyStoreResponse::AccountImported(lock_arg)) =
            self.call(request)?
        {
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
        if let PluginResponse::KeyStore(KeyStoreResponse::AccountExported {
            privkey,
            chain_code,
        }) = self.call(request)?
        {
            let mut data = [0u8; 64];
            data[0..32].copy_from_slice(&privkey[..]);
            data[32..64].copy_from_slice(&chain_code[..]);
            let master_privkey = MasterPrivKey::from_bytes(data).unwrap();
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
            hash160,
            external_max_len,
            change_last,
            change_max_len,
            password,
        };
        if let PluginResponse::KeyStore(KeyStoreResponse::DerivedKeySet { external, change }) =
            self.call(request)?
        {
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
            hash160,
            external_start,
            external_length,
            change_start,
            change_length,
            password,
        };
        if let PluginResponse::KeyStore(KeyStoreResponse::DerivedKeySet { external, change }) =
            self.call(request)?
        {
            let external = deserilize_key_set(external)?;
            let change = deserilize_key_set(change)?;
            Ok(DerivedKeySet { external, change })
        } else {
            Err("Mismatch keystore response".to_string())
        }
    }
    pub fn list_account(&self) -> Result<Vec<H160>, String> {
        let request = KeyStoreRequest::ListAccount;
        if let PluginResponse::KeyStore(KeyStoreResponse::Accounts(accounts)) =
            self.call(request)?
        {
            Ok(accounts)
        } else {
            Err("Mismatch keystore response".to_string())
        }
    }
    pub fn sign<P: ?Sized + AsRef<[ChildNumber]>>(
        &self,
        hash160: H160,
        path: &P,
        message: H256,
        password: Option<String>,
        recoverable: bool,
    ) -> Result<Vec<u8>, String> {
        let path = DerivationPath::from(path.as_ref().to_vec()).to_string();
        let request = KeyStoreRequest::Sign {
            hash160,
            path,
            message,
            password,
            recoverable,
        };
        if let PluginResponse::KeyStore(KeyStoreResponse::Signature(data)) = self.call(request)? {
            Ok(data)
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
            hash160,
            path,
            password,
        };
        if let PluginResponse::KeyStore(KeyStoreResponse::ExtendedPubkey(data)) =
            self.call(request)?
        {
            Ok(secp256k1::PublicKey::from_slice(&data).unwrap())
        } else {
            Err("Mismatch keystore response".to_string())
        }
    }
}

#[derive(Clone)]
pub struct IndexerHandler {
    handler: ServiceHandler,
}

impl IndexerHandler {
    fn new(handler: ServiceHandler) -> IndexerHandler {
        IndexerHandler { handler }
    }

    pub fn inner(&self) -> &ServiceHandler {
        &self.handler
    }

    fn call(&self, request: PluginRequest) -> Result<PluginResponse, String> {
        let request = ServiceRequest::Request {
            is_from_plugin: false,
            plugin_name: String::from("default_indexer"),
            request,
        };
        match Request::call(&self.handler, request) {
            Some(ServiceResponse::Response(PluginResponse::Error(error))) => Err(error),
            Some(ServiceResponse::Response(response)) => Ok(response),
            Some(_) => Err(String::from("Mismatch plugin response")),
            None => Err(String::from("Send request error")),
        }
    }

    pub fn tip_header(&self, genesis_hash: H256) -> Result<HeaderView, String> {
        let request = PluginRequest::Indexer {
            genesis_hash,
            request: IndexerRequest::TipHeader,
        };
        if let PluginResponse::Indexer(IndexerResponse::TipHeader(header_view)) =
            self.call(request)?
        {
            Ok(header_view)
        } else {
            Err("Invalid plugin response".to_string())
        }
    }
    pub fn last_header(&self, genesis_hash: H256) -> Result<Option<HeaderView>, String> {
        let request = PluginRequest::Indexer {
            genesis_hash,
            request: IndexerRequest::LastHeader,
        };
        if let PluginResponse::Indexer(IndexerResponse::LastHeader(header_view_opt)) =
            self.call(request)?
        {
            Ok(header_view_opt)
        } else {
            Err("Invalid plugin response".to_string())
        }
    }
    pub fn get_capacity(&self, genesis_hash: H256, lock_hash: H256) -> Result<u64, String> {
        let request = PluginRequest::Indexer {
            genesis_hash,
            request: IndexerRequest::Capacity(lock_hash),
        };
        if let PluginResponse::Indexer(IndexerResponse::Capacity(capacity)) = self.call(request)? {
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
        if let PluginResponse::Indexer(IndexerResponse::LiveCells(infos)) = self.call(request)? {
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
        if let PluginResponse::Indexer(IndexerResponse::TopN(infos)) = self.call(request)? {
            Ok(infos)
        } else {
            Err("Invalid plugin response".to_string())
        }
    }
    // JSON format indexer status info
    pub fn get_indexer_info(&self, genesis_hash: H256) -> Result<String, String> {
        let request = PluginRequest::Indexer {
            genesis_hash,
            request: IndexerRequest::IndexerInfo,
        };
        if let PluginResponse::Indexer(IndexerResponse::IndexerInfo(info)) = self.call(request)? {
            Ok(info)
        } else {
            Err("Invalid plugin response".to_string())
        }
    }
}
