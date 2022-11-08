use ckb_jsonrpc_types::{JsonBytes, Transaction};
use faster_hex::{hex_decode, hex_string};
use serde::de::DeserializeOwned;
use std::convert::TryFrom;

use super::{
    method, CallbackRequest, JsonrpcRequest, JsonrpcResponse, KeyStoreRequest, PluginRequest,
    PluginResponse, JSONRPC_VERSION,
};

impl From<(u64, PluginRequest)> for JsonrpcRequest {
    fn from((id, request): (u64, PluginRequest)) -> JsonrpcRequest {
        let (method, params) = match request {
            PluginRequest::Quit => (method::QUIT, Vec::new()),
            PluginRequest::GetConfig => (method::GET_CONFIG, Vec::new()),
            PluginRequest::ReadPassword(prompt) => {
                (method::READ_PASSWORD, vec![serde_json::json!(prompt)])
            }
            PluginRequest::PrintStdout(content) => {
                (method::PRINT_STDOUT, vec![serde_json::json!(content)])
            }
            PluginRequest::PrintStderr(content) => {
                (method::PRINT_STDERR, vec![serde_json::json!(content)])
            }
            PluginRequest::RpcUrlChanged(url) => {
                (method::RPC_URL_CHANGED, vec![serde_json::json!(url)])
            }
            PluginRequest::SubCommand(args) => (method::SUB_COMMAND, vec![serde_json::json!(args)]),
            PluginRequest::Callback(callback_request) => callback_request.into(),
            PluginRequest::KeyStore(keystore_request) => keystore_request.into(),
        };
        JsonrpcRequest {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: serde_json::json!(id),
            method: method.to_string(),
            params,
        }
    }
}

impl TryFrom<JsonrpcRequest> for (u64, PluginRequest) {
    type Error = String;
    fn try_from(data: JsonrpcRequest) -> Result<(u64, PluginRequest), Self::Error> {
        if data.jsonrpc != JSONRPC_VERSION {
            return Err(format!("Invalid jsonrpc field: {}", data.jsonrpc));
        }
        let request_id: u64 = serde_json::from_value(data.id.clone())
            .map_err(|err| format!("Request id must be integer number, error={}", err))?;

        let request = match data.method.as_str() {
            method::QUIT => PluginRequest::Quit,
            method::GET_CONFIG => PluginRequest::GetConfig,
            method::READ_PASSWORD => PluginRequest::ReadPassword(parse_param(&data, 0, "prompt")?),
            method::PRINT_STDOUT => PluginRequest::PrintStdout(parse_param(&data, 0, "content")?),
            method::PRINT_STDERR => PluginRequest::PrintStderr(parse_param(&data, 0, "content")?),
            method::RPC_URL_CHANGED => PluginRequest::RpcUrlChanged(parse_param(&data, 0, "url")?),
            method::SUB_COMMAND => PluginRequest::SubCommand(parse_param(&data, 0, "args")?),
            method if method.starts_with(method::CALLBACK_PREFIX) => {
                CallbackRequest::try_from(&data).map(PluginRequest::Callback)?
            }
            method if method.starts_with(method::KEYSTORE_PREFIX) => {
                KeyStoreRequest::try_from(&data).map(PluginRequest::KeyStore)?
            }
            method => {
                return Err(format!("Invalid request method: {}", method));
            }
        };
        Ok((request_id, request))
    }
}

impl From<CallbackRequest> for (&'static str, Vec<serde_json::Value>) {
    fn from(request: CallbackRequest) -> (&'static str, Vec<serde_json::Value>) {
        match request {
            CallbackRequest::SendTransaction { tx, sub_command } => {
                let params = vec![
                    serde_json::to_value(&tx).expect("Serialize json failed"),
                    serde_json::json!(sub_command),
                ];
                (method::CALLBACK_SEND_TRANSACTION, params)
            }
        }
    }
}
impl TryFrom<&JsonrpcRequest> for CallbackRequest {
    type Error = String;
    fn try_from(data: &JsonrpcRequest) -> Result<CallbackRequest, Self::Error> {
        let request = match data.method.as_str() {
            method::CALLBACK_SEND_TRANSACTION => {
                let tx: Transaction = parse_param(data, 0, "transaction")?;
                let sub_command: String = parse_param(data, 1, "sub-command")?;
                CallbackRequest::SendTransaction { tx, sub_command }
            }
            _ => {
                return Err(format!("Invalid request method: {}", data.method));
            }
        };
        Ok(request)
    }
}

impl From<KeyStoreRequest> for (&'static str, Vec<serde_json::Value>) {
    fn from(request: KeyStoreRequest) -> (&'static str, Vec<serde_json::Value>) {
        match request {
            KeyStoreRequest::ListAccount => (method::KEYSTORE_LIST_ACCOUNT, Vec::new()),
            KeyStoreRequest::HasAccount(hash160) => (
                method::KEYSTORE_HAS_ACCOUNT,
                vec![serde_json::json!(hash160)],
            ),
            KeyStoreRequest::CreateAccount(password) => (
                method::KEYSTORE_CREATE_ACCOUNT,
                vec![serde_json::json!(password)],
            ),
            KeyStoreRequest::UpdatePassword {
                hash160,
                password,
                new_password,
            } => {
                let params = vec![
                    serde_json::json!(hash160),
                    serde_json::json!(password),
                    serde_json::json!(new_password),
                ];
                (method::KEYSTORE_UPDATE_PASSWORD, params)
            }
            KeyStoreRequest::Import {
                privkey,
                chain_code,
                password,
            } => {
                let privkey = format!("0x{}", hex_string(&privkey));
                let chain_code = format!("0x{}", hex_string(&chain_code));
                let params = vec![
                    serde_json::json!(privkey),
                    serde_json::json!(chain_code),
                    serde_json::json!(password),
                ];
                (method::KEYSTORE_IMPORT, params)
            }
            KeyStoreRequest::ImportAccount {
                account_id,
                password,
            } => {
                let account_id = format!("0x{}", hex_string(account_id.as_bytes()));
                let params = vec![serde_json::json!(account_id), serde_json::json!(password)];
                (method::KEYSTORE_IMPORT_ACCOUNT, params)
            }
            KeyStoreRequest::Export { hash160, password } => {
                let params = vec![serde_json::json!(hash160), serde_json::json!(password)];
                (method::KEYSTORE_EXPORT, params)
            }
            KeyStoreRequest::Sign {
                hash160,
                path,
                message,
                target,
                recoverable,
                password,
            } => {
                let params = vec![
                    serde_json::json!(hash160),
                    serde_json::json!(path),
                    serde_json::json!(message),
                    serde_json::json!(target),
                    serde_json::json!(recoverable),
                    serde_json::json!(password),
                ];
                (method::KEYSTORE_SIGN, params)
            }
            KeyStoreRequest::ExtendedPubkey {
                hash160,
                path,
                password,
            } => {
                let params = vec![
                    serde_json::json!(hash160),
                    serde_json::json!(path),
                    serde_json::json!(password),
                ];
                (method::KEYSTORE_EXTENDED_PUBKEY, params)
            }
            KeyStoreRequest::DerivedKeySet {
                hash160,
                external_max_len,
                change_last,
                change_max_len,
                password,
            } => {
                let params = vec![
                    serde_json::json!(hash160),
                    serde_json::json!(external_max_len),
                    serde_json::json!(change_last),
                    serde_json::json!(change_max_len),
                    serde_json::json!(password),
                ];
                (method::KEYSTORE_DERIVED_KEY_SET, params)
            }
            KeyStoreRequest::DerivedKeySetByIndex {
                hash160,
                external_start,
                external_length,
                change_start,
                change_length,
                password,
            } => {
                let params = vec![
                    serde_json::json!(hash160),
                    serde_json::json!(external_start),
                    serde_json::json!(external_length),
                    serde_json::json!(change_start),
                    serde_json::json!(change_length),
                    serde_json::json!(password),
                ];
                (method::KEYSTORE_DERIVED_KEY_SET_BY_INDEX, params)
            }
            KeyStoreRequest::Any(value) => (method::KEYSTORE_ANY, vec![value]),
        }
    }
}
impl TryFrom<&JsonrpcRequest> for KeyStoreRequest {
    type Error = String;
    fn try_from(data: &JsonrpcRequest) -> Result<KeyStoreRequest, Self::Error> {
        let request = match data.method.as_str() {
            method::KEYSTORE_LIST_ACCOUNT => KeyStoreRequest::ListAccount,
            method::KEYSTORE_HAS_ACCOUNT => {
                KeyStoreRequest::HasAccount(parse_param(data, 0, "hash160")?)
            }
            method::KEYSTORE_CREATE_ACCOUNT => {
                KeyStoreRequest::CreateAccount(parse_param(data, 0, "password")?)
            }
            method::KEYSTORE_UPDATE_PASSWORD => KeyStoreRequest::UpdatePassword {
                hash160: parse_param(data, 0, "hash160")?,
                password: parse_param(data, 1, "hash160")?,
                new_password: parse_param(data, 2, "hash160")?,
            },
            method::KEYSTORE_IMPORT => KeyStoreRequest::Import {
                privkey: parse_h256(data, 0, "privkey")?,
                chain_code: parse_h256(data, 1, "chain_code")?,
                password: parse_param(data, 2, "password")?,
            },
            method::KEYSTORE_IMPORT_ACCOUNT => KeyStoreRequest::ImportAccount {
                account_id: JsonBytes::from_vec(parse_bytes(data, 0, "account_id")?),
                password: parse_param(data, 1, "password")?,
            },
            method::KEYSTORE_EXPORT => KeyStoreRequest::Export {
                hash160: parse_param(data, 0, "hash160")?,
                password: parse_param(data, 1, "password")?,
            },
            method::KEYSTORE_SIGN => KeyStoreRequest::Sign {
                hash160: parse_param(data, 0, "hash160")?,
                path: parse_param(data, 1, "path")?,
                message: parse_param(data, 2, "message")?,
                target: parse_param(data, 3, "target")?,
                recoverable: parse_param(data, 4, "recoverable")?,
                password: parse_param(data, 5, "password")?,
            },
            method::KEYSTORE_EXTENDED_PUBKEY => KeyStoreRequest::ExtendedPubkey {
                hash160: parse_param(data, 0, "hash160")?,
                path: parse_param(data, 1, "path")?,
                password: parse_param(data, 2, "password")?,
            },
            method::KEYSTORE_DERIVED_KEY_SET => KeyStoreRequest::DerivedKeySet {
                hash160: parse_param(data, 0, "hash160")?,
                external_max_len: parse_param(data, 1, "external_max_len")?,
                change_last: parse_param(data, 2, "change_last")?,
                change_max_len: parse_param(data, 3, "change_max_len")?,
                password: parse_param(data, 4, "password")?,
            },
            method::KEYSTORE_DERIVED_KEY_SET_BY_INDEX => KeyStoreRequest::DerivedKeySetByIndex {
                hash160: parse_param(data, 0, "hash160")?,
                external_start: parse_param(data, 1, "external_start")?,
                external_length: parse_param(data, 2, "external_length")?,
                change_start: parse_param(data, 3, "change_start")?,
                change_length: parse_param(data, 4, "change_length")?,
                password: parse_param(data, 5, "password")?,
            },
            method::KEYSTORE_ANY => KeyStoreRequest::Any(parse_param(data, 0, "value")?),
            _ => {
                return Err(format!("Invalid request method: {}", data.method));
            }
        };
        Ok(request)
    }
}

fn parse_param<T: DeserializeOwned>(
    data: &JsonrpcRequest,
    index: usize,
    field_name: &str,
) -> Result<T, String> {
    data.params
        .get(index)
        .cloned()
        .map(|value| {
            let content: T = serde_json::from_value(value.clone()).map_err(|err| {
                format!(
                    "Parse {}'s parameter(field={}, index={}) value: {:?}, failed: {}",
                    data.method, field_name, index, value, err
                )
            })?;
            Ok(content)
        })
        .unwrap_or_else(|| {
            Err(format!(
                "Not enough parameter for {}, length: {}, expected: {}",
                data.method,
                data.params.len(),
                index + 1
            ))
        })
}

fn parse_bytes(data: &JsonrpcRequest, index: usize, field: &str) -> Result<Vec<u8>, String> {
    let hex: String = parse_param(data, index, field)?;
    if !hex.starts_with("0x") || hex.len() % 2 == 1 {
        return Err(format!(
            "Field {} is not valid hex string, method={} (0x prefix is required)",
            field, data.method
        ));
    }
    let mut dst = vec![0u8; hex.len() / 2 - 1];
    hex_decode(&hex.as_bytes()[2..], &mut dst).map_err(|err| err.to_string())?;
    Ok(dst)
}

fn parse_h256(data: &JsonrpcRequest, index: usize, field: &str) -> Result<[u8; 32], String> {
    let vec = parse_bytes(data, index, field)?;
    if vec.len() != 32 {
        return Err(format!(
            "Invalid data length for field {}, method={}, expected 32bytes data hex string",
            field, data.method
        ));
    }
    let mut dst = [0u8; 32];
    dst.copy_from_slice(&vec);
    Ok(dst)
}

impl From<(u64, PluginResponse)> for JsonrpcResponse {
    fn from((id, response): (u64, PluginResponse)) -> JsonrpcResponse {
        let (result, error) = match response {
            PluginResponse::Error(err) => (None, Some(err)),
            response => (
                Some(serde_json::to_value(response).expect("Serialize failed")),
                None,
            ),
        };
        JsonrpcResponse {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: serde_json::json!(id),
            result,
            error,
        }
    }
}

impl TryFrom<JsonrpcResponse> for (u64, PluginResponse) {
    type Error = String;
    fn try_from(data: JsonrpcResponse) -> Result<(u64, PluginResponse), Self::Error> {
        if data.jsonrpc != JSONRPC_VERSION {
            return Err(format!("Invalid jsonrpc field: {}", data.jsonrpc));
        }
        let request_id: u64 = serde_json::from_value(data.id)
            .map_err(|err| format!("Request id must be integer number, error={}", err))?;
        let response: PluginResponse = if let Some(result) = data.result {
            serde_json::from_value(result)
                .map_err(|err| format!("Deserialize response failed, error={}", err))?
        } else if let Some(error) = data.error {
            PluginResponse::Error(error)
        } else {
            return Err(String::from("Invalid jsonrpc response"));
        };
        Ok((request_id, response))
    }
}
