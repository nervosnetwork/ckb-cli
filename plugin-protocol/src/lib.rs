mod convert;
mod jsonrpc;
pub mod method;

use std::fmt;
use std::str::FromStr;

use ckb_index::LiveCellInfo;
use ckb_jsonrpc_types::{BlockReward, BlockView, HeaderView, JsonBytes, Script, Transaction};
use ckb_types::{H160, H256};
use serde_derive::{Deserialize, Serialize};

pub use jsonrpc::{JsonrpcError, JsonrpcRequest, JsonrpcResponse, JSONRPC_VERSION};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginConfig {
    pub name: String,
    pub description: String,
    pub daemon: bool,
    pub roles: Vec<PluginRole>,
}

impl PluginConfig {
    pub fn validate(&self) -> Result<(), String> {
        // TODO: validate PluginConfig.name
        if self.roles.is_empty() {
            return Err(String::from("Role list can not be empty"));
        }
        for role in &self.roles {
            role.validate()?;
        }
        Ok(())
    }

    pub fn is_normal_daemon(&self) -> bool {
        if !self.daemon {
            return false;
        }
        for role in &self.roles {
            match role {
                PluginRole::KeyStore { .. } => (),
                PluginRole::Indexer => (),
                _ => {
                    return true;
                }
            }
        }
        false
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum PluginRole {
    // The argument is for if keystore need password
    KeyStore { require_password: bool },
    Indexer,
    // The argument is for where the sub-command is injected to.
    SubCommand { name: String },
    // The argument is for the callback function name
    Callback { name: CallbackName },
}

impl PluginRole {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::SubCommand { .. } => {
                // TODO: check sub-command name
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PluginRequest {
    // == Send from ckb-cli to plugin
    // Tell a daemon plugin to quit
    Quit,
    GetConfig,
    // Notify all daemon plugins and indexer when rpc url changed
    RpcUrlChanged(String),
    // The plugin need to parse the rest command line arguments
    SubCommand(String),
    Callback(CallbackRequest),
    // == Send from plugin to ckb-cli
    Rpc(RpcRequest),
    ReadPassword(String),
    PrintStdout(String),
    PrintStderr(String),
    // == Can send from both direction
    KeyStore(KeyStoreRequest),
    Indexer {
        genesis_hash: H256,
        request: IndexerRequest,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "snake_case", content = "content")]
pub enum PluginResponse {
    Error(JsonrpcError),
    Ok,
    // For get_config request
    PluginConfig(PluginConfig),
    JsonValue(serde_json::Value),
    Boolean(bool),
    String(String),
    Integer64(u64),

    H256Opt(Option<H256>),
    H160(H160),
    H160Vec(Vec<H160>),
    HeaderView(Box<HeaderView>),
    HeaderViewOpt(Box<Option<HeaderView>>),
    BlockViewOpt(Box<Option<BlockView>>),
    BlockRewardOpt(Option<BlockReward>),
    Bytes(JsonBytes),
    BytesVec(Vec<JsonBytes>),

    Callback(CallbackResponse),
    MasterPrivateKey {
        privkey: JsonBytes,
        chain_code: JsonBytes,
    },
    DerivedKeySet {
        external: Vec<(String, H160)>,
        change: Vec<(String, H160)>,
    },

    LiveCells(Vec<LiveCellInfo>),
    TopN(Vec<(H256, Option<Script>, u64)>),
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CallbackName {
    SendTransaction,
}
impl fmt::Display for CallbackName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let repr = match self {
            CallbackName::SendTransaction => "send_transaction",
        };
        write!(f, "{}", repr)
    }
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum CallbackRequest {
    SendTransaction {
        tx: Transaction,
        // Send in which subcommand: transfer/deposite/withdraw/prepare/tx
        sub_command: String,
    },
    // TODO: add more
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "snake_case", content = "content")]
pub enum CallbackResponse {
    SendTransaction {
        accepted: bool,
        error_message: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "snake_case", content = "content")]
pub enum SignTarget {
    Transaction {
        tx: Transaction,
        inputs: Vec<Transaction>,
        change_path: String,
    },
    AnyMessage(H256),
    AnyString(String),
    AnyData(JsonBytes),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum KeyStoreRequest {
    // return: PluginResponse::Bytes
    ListAccount,
    // return: PluginResponse::Boolean
    HasAccount(H160),
    // return: PluginResponse::H160
    CreateAccount(Option<String>),
    // return: PluginResponse::Ok
    UpdatePassword {
        hash160: H160,
        password: String,
        new_password: String,
    },
    // return: PluginResponse::H160
    Import {
        privkey: [u8; 32],
        chain_code: [u8; 32],
        password: Option<String>,
    },
    // return: PluginResponse::H160
    ImportAccount {
        account_id: JsonBytes,
        password: Option<String>,
    },
    // return: PluginResponse::MasterPrivateKey
    Export {
        hash160: H160,
        password: Option<String>,
    },
    // return: PluginResponse::Bytes
    Sign {
        hash160: H160,
        path: String,
        message: H256,
        target: Box<SignTarget>,
        recoverable: bool,
        password: Option<String>,
    },
    // return: PluginResponse::Bytes
    ExtendedPubkey {
        hash160: H160,
        path: String,
        password: Option<String>,
    },
    // return: PluginResponse::DerivedKeySet
    DerivedKeySet {
        hash160: H160,
        external_max_len: u32,
        change_last: H160,
        change_max_len: u32,
        password: Option<String>,
    },
    // return: PluginResponse::DerivedKeySet
    DerivedKeySetByIndex {
        hash160: H160,
        external_start: u32,
        external_length: u32,
        change_start: u32,
        change_length: u32,
        password: Option<String>,
    },
    // For plugin to use custom keystore
    // return: PluginResponse::JsonValue
    Any(serde_json::Value),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RpcRequest {
    GetBlock { hash: H256 },
    GetBlockByNumber { number: u64 },
    GetBlockHash { number: u64 },
    GetCellbaseOutputCapacityDetails { hash: H256 },
    // TODO: add more
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum LiveCellIndexType {
    LockHash,
    TypeHash,
    // Code hash of type script
    CodeHash,
}
impl fmt::Display for LiveCellIndexType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let repr = match self {
            LiveCellIndexType::LockHash => "lock_hash",
            LiveCellIndexType::TypeHash => "type_hash",
            LiveCellIndexType::CodeHash => "code_hash",
        };
        write!(f, "{}", repr)
    }
}
impl FromStr for LiveCellIndexType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "lock_hash" => Ok(LiveCellIndexType::LockHash),
            "type_hash" => Ok(LiveCellIndexType::TypeHash),
            "code_hash" => Ok(LiveCellIndexType::CodeHash),
            _ => Err(format!("Invalid index type: {}", s)),
        }
    }
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum IndexerRequest {
    TipHeader,
    LastHeader,
    // Get total capacity by lock hash
    GetCapacity(H256),
    LiveCells {
        index: LiveCellIndexType,
        hash: H256,
        from_number: Option<u64>,
        to_number: Option<u64>,
        limit: u64,
    },
    TopN(u64),
    IndexerInfo,
    // For plugin to use custom indexer
    Any(serde_json::Value),
}
