use std::path::PathBuf;
use std::str::FromStr;
use std::thread::{self, JoinHandle};

use ckb_sdk::{
    rpc::JsonBytes,
    wallet::{DerivationPath, DerivedKeySet, Key, KeyStore, MasterPrivKey},
};
use ckb_types::core::service::Request;
use crossbeam_channel::bounded;
use plugin_protocol::{JsonrpcError, KeyStoreRequest, PluginRequest, PluginResponse};

use super::manager::PluginHandler;
use crate::utils::other::{get_key_store, serialize_signature};

pub const ERROR_KEYSTORE_REQUIRE_PASSWORD: &str = "keystore require password";

pub(crate) struct DefaultKeyStore {
    handler: PluginHandler,
    _thread: JoinHandle<()>,
}

impl DefaultKeyStore {
    pub(crate) fn start(ckb_cli_dir: &PathBuf) -> Result<DefaultKeyStore, String> {
        fn serilize_key_set(key_set: DerivedKeySet) -> PluginResponse {
            let external = key_set
                .external
                .into_iter()
                .map(|(path, hash160)| (path.to_string(), hash160))
                .collect::<Vec<_>>();
            let change = key_set
                .change
                .into_iter()
                .map(|(path, hash160)| (path.to_string(), hash160))
                .collect::<Vec<_>>();
            PluginResponse::DerivedKeySet { external, change }
        }

        fn handle_request(
            keystore: &mut KeyStore,
            request: KeyStoreRequest,
        ) -> Result<PluginResponse, String> {
            match request {
                KeyStoreRequest::CreateAccount(password) => {
                    let password =
                        password.ok_or_else(|| String::from(ERROR_KEYSTORE_REQUIRE_PASSWORD))?;
                    keystore
                        .new_account(password.as_bytes())
                        .map(PluginResponse::H160)
                        .map_err(|err| err.to_string())
                }
                KeyStoreRequest::HasAccount(hash160) => Ok(PluginResponse::Boolean(
                    keystore.has_account(&hash160, true),
                )),
                KeyStoreRequest::UpdatePassword {
                    hash160,
                    password,
                    new_password,
                } => keystore
                    .update(&hash160, password.as_bytes(), new_password.as_bytes())
                    .map(|_| PluginResponse::Ok)
                    .map_err(|err| err.to_string()),
                KeyStoreRequest::Import {
                    privkey,
                    chain_code,
                    password,
                } => {
                    let password =
                        password.ok_or_else(|| String::from(ERROR_KEYSTORE_REQUIRE_PASSWORD))?;
                    let privkey = secp256k1::SecretKey::from_slice(&privkey)
                        .map_err(|err| err.to_string())?;
                    let mut data = [0u8; 64];
                    data[0..32].copy_from_slice(&privkey[..]);
                    data[32..64].copy_from_slice(&chain_code[..]);
                    let master_privkey =
                        MasterPrivKey::from_bytes(data).map_err(|err| err.to_string())?;
                    let key = Key::new(master_privkey);
                    let lock_arg = keystore
                        .import_key(&key, password.as_bytes())
                        .map_err(|err| err.to_string())?;
                    Ok(PluginResponse::H160(lock_arg))
                }
                KeyStoreRequest::ImportAccount { .. } => {
                    Err("Not supported in file based keystore".to_string())
                }
                KeyStoreRequest::Export { hash160, password } => {
                    let password =
                        password.ok_or_else(|| String::from(ERROR_KEYSTORE_REQUIRE_PASSWORD))?;
                    keystore
                        .export_key(&hash160, password.as_bytes())
                        .map(|master_privkey| {
                            let data = master_privkey.to_bytes();
                            let mut privkey = vec![0u8; 32];
                            let mut chain_code = vec![0u8; 32];
                            privkey.copy_from_slice(&data[0..32]);
                            chain_code.copy_from_slice(&data[32..64]);
                            PluginResponse::MasterPrivateKey {
                                privkey: JsonBytes::from_vec(privkey),
                                chain_code: JsonBytes::from_vec(chain_code),
                            }
                        })
                        .map_err(|err| err.to_string())
                }
                KeyStoreRequest::DerivedKeySet {
                    hash160,
                    external_max_len,
                    change_last,
                    change_max_len,
                    password,
                } => keystore
                    .get_ckb_root(&hash160, true)
                    .cloned()
                    .map_or_else(
                        || {
                            let password = password
                                .ok_or_else(|| String::from(ERROR_KEYSTORE_REQUIRE_PASSWORD))?;
                            keystore
                                .ckb_root_with_password(&hash160, password.as_bytes())
                                .map_err(|err| err.to_string())
                        },
                        Ok,
                    )
                    .map(|ckb_root| {
                        ckb_root.derived_key_set(external_max_len, &change_last, change_max_len)
                    })?
                    .map(serilize_key_set)
                    .map_err(|err| err.to_string()),
                KeyStoreRequest::DerivedKeySetByIndex {
                    hash160,
                    external_start,
                    external_length,
                    change_start,
                    change_length,
                    password,
                } => keystore
                    .get_ckb_root(&hash160, true)
                    .cloned()
                    .map_or_else(
                        || {
                            let password = password
                                .ok_or_else(|| String::from(ERROR_KEYSTORE_REQUIRE_PASSWORD))?;
                            keystore
                                .ckb_root_with_password(&hash160, password.as_bytes())
                                .map_err(|err| err.to_string())
                        },
                        Ok,
                    )
                    .map(|ckb_root| {
                        ckb_root.derived_key_set_by_index(
                            external_start,
                            external_length,
                            change_start,
                            change_length,
                        )
                    })
                    .map(serilize_key_set),
                KeyStoreRequest::ListAccount => {
                    let mut accounts = keystore.get_accounts().iter().collect::<Vec<_>>();
                    accounts.sort_by(|a, b| a.1.cmp(&b.1));
                    let accounts = accounts
                        .into_iter()
                        .map(|(lock_arg, _)| lock_arg.clone())
                        .collect::<Vec<_>>();
                    Ok(PluginResponse::H160Vec(accounts))
                }
                KeyStoreRequest::Sign {
                    hash160,
                    path,
                    message,
                    target: _target,
                    password,
                    recoverable,
                } => {
                    let password =
                        password.ok_or_else(|| String::from(ERROR_KEYSTORE_REQUIRE_PASSWORD))?;
                    let path = DerivationPath::from_str(&path).map_err(|err| err.to_string())?;
                    let signature = if recoverable {
                        keystore
                            .sign_recoverable_with_password(
                                &hash160,
                                path.as_ref(),
                                &message,
                                password.as_bytes(),
                            )
                            .map(|sig| serialize_signature(&sig).to_vec())
                            .map_err(|err| err.to_string())?
                    } else {
                        keystore
                            .sign_with_password(
                                &hash160,
                                path.as_ref(),
                                &message,
                                password.as_bytes(),
                            )
                            .map_err(|err| err.to_string())?
                            .serialize_compact()
                            .to_vec()
                    };
                    Ok(PluginResponse::Bytes(JsonBytes::from_vec(signature)))
                }
                KeyStoreRequest::ExtendedPubkey {
                    hash160,
                    path,
                    password,
                } => {
                    let password =
                        password.ok_or_else(|| String::from(ERROR_KEYSTORE_REQUIRE_PASSWORD))?;
                    let path = DerivationPath::from_str(&path).map_err(|err| err.to_string())?;
                    let data = keystore
                        .extended_pubkey_with_password(&hash160, path.as_ref(), password.as_bytes())
                        .map_err(|err| err.to_string())?
                        .public_key
                        .serialize()
                        .to_vec();
                    Ok(PluginResponse::Bytes(JsonBytes::from_vec(data)))
                }
                KeyStoreRequest::Any(_) => {
                    // TODO: handle any request
                    Ok(PluginResponse::JsonValue(serde_json::Value::Null))
                }
            }
        }

        let (keystore_sender, keystore_receiver) = bounded(1);
        let mut keystore = get_key_store(ckb_cli_dir)?;

        let keystore_thread = thread::spawn(move || loop {
            match keystore_receiver.recv() {
                Ok(Request {
                    responder,
                    arguments,
                }) => {
                    let (id, plugin_request) = arguments;
                    let response = if let PluginRequest::KeyStore(request) = plugin_request {
                        handle_request(&mut keystore, request).unwrap_or_else(|err| {
                            PluginResponse::Error(JsonrpcError {
                                code: 0,
                                message: err,
                                data: None,
                            })
                        })
                    } else {
                        PluginResponse::Error(JsonrpcError {
                            code: 0,
                            message: format!(
                                "Invalid request for keystore: {}",
                                serde_json::to_string(&plugin_request)
                                    .expect("Serialize request error")
                            ),
                            data: None,
                        })
                    };
                    if let Err(err) = responder.send((id, response)) {
                        log::warn!("Default keystore send response err: {:?}", err);
                    }
                }
                Err(err) => {
                    log::warn!("Default keystore receive request error: {:?}", err);
                    break;
                }
            }
        });

        Ok(DefaultKeyStore {
            handler: keystore_sender,
            _thread: keystore_thread,
        })
    }

    pub(crate) fn handler(&self) -> &PluginHandler {
        &self.handler
    }
}

pub(crate) struct DefaultIndexer {
    handler: PluginHandler,
    _thread: JoinHandle<()>,
}

impl DefaultIndexer {
    pub(crate) fn start() -> Result<DefaultIndexer, String> {
        // TODO:
        let (sender, _receiver) = bounded(1);
        let thread = thread::spawn(|| {});
        Ok(DefaultIndexer {
            handler: sender,
            _thread: thread,
        })
    }

    pub(crate) fn handler(&self) -> &PluginHandler {
        &self.handler
    }
}
