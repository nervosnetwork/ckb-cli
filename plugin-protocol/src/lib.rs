use ckb_index::LiveCellInfo;
use ckb_sdk::rpc::{BlockReward, BlockView, HeaderView, Script, Transaction};
use ckb_types::{H160, H256};
use serde_derive::{Deserialize, Serialize};
use std::fmt;

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
                PluginRole::KeyStore(_) => (),
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
pub enum PluginRole {
    // The argument is for if keystore need password
    KeyStore(bool),
    Indexer,
    // The argument is for where the sub-command is injected to.
    SubCommand(String),
    // The argument is for the callback function name
    Callback(CallbackName),
}

impl PluginRole {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::SubCommand(_name) => {
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
    Register,
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
pub enum PluginResponse {
    Error(String),
    Ok,
    // For register request
    PluginConfig(PluginConfig),
    SubCommand(String),
    Callback(CallbackResponse),
    Rpc(RpcResponse),
    Password(String),
    KeyStore(KeyStoreResponse),
    Indexer(IndexerResponse),
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
pub enum CallbackName {
    SendTransaction,
}
impl CallbackName {
    pub fn from_str(name: &str) -> Option<CallbackName> {
        match name {
            "send_transaction" => Some(CallbackName::SendTransaction),
            _ => None,
        }
    }
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
        subcommand: String,
    },
    // TODO: add more
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum CallbackResponse {
    SendTransaction {
        accepted: bool,
        error_message: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum KeyStoreRequest {
    ListAccount,
    CreateAccount(Option<String>),
    UpdatePassword {
        hash160: H160,
        password: String,
        new_password: String,
    },
    Import {
        privkey: [u8; 32],
        chain_code: [u8; 32],
        password: Option<String>,
    },
    Export {
        hash160: H160,
        password: Option<String>,
    },
    Sign {
        hash160: H160,
        path: String,
        message: H256,
        recoverable: bool,
        password: Option<String>,
    },
    ExtendedPubkey {
        hash160: H160,
        path: String,
        password: Option<String>,
    },
    DerivedKeySet {
        hash160: H160,
        external_max_len: u32,
        change_last: H160,
        change_max_len: u32,
        password: Option<String>,
    },
    DerivedKeySetByIndex {
        hash160: H160,
        external_start: u32,
        external_length: u32,
        change_start: u32,
        change_length: u32,
        password: Option<String>,
    },
    // For plugin to use custom keystore
    Any(Vec<u8>),
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum KeyStoreResponse {
    AccountCreated(H160),
    AccountImported(H160),
    AccountExported {
        privkey: [u8; 32],
        chain_code: [u8; 32],
    },
    Accounts(Vec<H160>),
    Signature(Vec<u8>),
    ExtendedPubkey(Vec<u8>),
    DerivedKeySet {
        external: Vec<(String, H160)>,
        change: Vec<(String, H160)>,
    },
    Any(Vec<u8>),
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
pub enum RpcResponse {
    BlockView(Option<BlockView>),
    BlockHash(Option<H256>),
    BlockReward(Option<BlockReward>),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum LiveCellIndexType {
    LockHash,
    TypeHash,
    // Code hash of type script
    CodeHash,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum IndexerRequest {
    TipHeader,
    LastHeader,
    // Get total capacity by lock hash
    Capacity(H256),
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
    Any(Vec<u8>),
}
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum IndexerResponse {
    TipHeader(HeaderView),
    LastHeader(Option<HeaderView>),
    Capacity(u64),
    LiveCells(Vec<LiveCellInfo>),
    // AddressPayload is molecule serialized
    TopN(Vec<(H256, Option<Script>, u64)>),
    IndexerInfo(String),
    Any(Vec<u8>),
}
