use ckb_types::{h160, H160};
use plugin_protocol::{
    KeyStoreRequest, KeyStoreResponse, PluginConfig, PluginRequest, PluginResponse, PluginRole,
};
use std::io::{self, Write};

fn main() {
    loop {
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(0) => {
                break;
            }
            Ok(_n) => {
                let request: PluginRequest = serde_json::from_str(&line).unwrap();
                if let Some(response) = handle(request) {
                    let response_string =
                        format!("{}\n", serde_json::to_string(&response).unwrap());
                    io::stdout().write_all(response_string.as_bytes()).unwrap();
                    io::stdout().flush().unwrap();
                }
            }
            Err(_err) => {}
        }
    }
}

fn handle(request: PluginRequest) -> Option<PluginResponse> {
    match request {
        PluginRequest::Quit => None,
        PluginRequest::Register => {
            let config = PluginConfig {
                name: String::from("demo_keystore"),
                description: String::from("It's a keystore for demo"),
                daemon: true,
                roles: vec![PluginRole::KeyStore(true)],
            };
            Some(PluginResponse::PluginConfig(config))
        }
        PluginRequest::KeyStore(keystore_request) => {
            let keystore_response = match keystore_request {
                KeyStoreRequest::ListAccount => {
                    let accounts = vec![
                        h160!("0xe22f7f385830a75e50ab7fc5fd4c35b134f1e84b"),
                        h160!("0x13e41d6F9292555916f17B4882a5477C01270142"),
                        h160!("0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64"),
                    ];
                    KeyStoreResponse::Accounts(accounts)
                }
                KeyStoreRequest::CreateAccount(_) => KeyStoreResponse::AccountCreated(h160!(
                    "0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64"
                )),
                KeyStoreRequest::Sign { recoverable, .. } => {
                    let signature = if recoverable {
                        vec![1u8; 65]
                    } else {
                        vec![2u8; 64]
                    };
                    KeyStoreResponse::Signature(signature)
                }
                _ => {
                    return Some(PluginResponse::Error(String::from("Not supported yet")));
                }
            };
            Some(PluginResponse::KeyStore(keystore_response))
        }
        _ => Some(PluginResponse::Error(String::from(
            "Invalid request to keystore",
        ))),
    }
}
