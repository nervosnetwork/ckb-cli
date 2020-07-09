use ckb_cli_plugin_protocol::{
    JsonrpcError, JsonrpcRequest, JsonrpcResponse, PluginConfig, PluginRequest, PluginResponse,
    PluginRole,
};
use std::convert::TryInto;
use std::io::{self, Write};

fn main() {
    loop {
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(0) => {
                break;
            }
            Ok(_n) => {
                let jsonrpc_request: JsonrpcRequest = serde_json::from_str(&line).unwrap();
                let (id, request) = jsonrpc_request.try_into().unwrap();
                if let Some(response) = handle(request) {
                    let jsonrpc_response = JsonrpcResponse::from((id, response));
                    let response_string =
                        format!("{}\n", serde_json::to_string(&jsonrpc_response).unwrap());
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
        PluginRequest::GetConfig => {
            let config = PluginConfig {
                name: String::from("debugger"),
                description: String::from("It's a demo debugger sub-command plugin"),
                daemon: false,
                roles: vec![PluginRole::SubCommand {
                    name: "debugger".to_string(),
                }],
            };
            Some(PluginResponse::PluginConfig(config))
        }
        PluginRequest::SubCommand(rest_args) => {
            let req = PluginRequest::ReadPassword("Your Password:".to_string());
            let jsonrpc_request = JsonrpcRequest::from((0, req));
            let request_string = format!("{}\n", serde_json::to_string(&jsonrpc_request).unwrap());
            // Write message to stderr for plugin debugging
            io::stdout().write_all(request_string.as_bytes()).unwrap();
            io::stdout().flush().unwrap();
            let mut line = String::new();
            io::stdin().read_line(&mut line).unwrap();
            let jsonrpc_response: JsonrpcResponse = serde_json::from_str(&line).unwrap();
            let (_id, response) = jsonrpc_response.try_into().unwrap();
            if let PluginResponse::String(password) = response {
                if password == "bad" {
                    return Some(PluginResponse::Error(JsonrpcError {
                        code: 0,
                        message: String::from("Error password"),
                        data: None,
                    }));
                }
            }

            Some(PluginResponse::JsonValue(serde_json::json!({
                "debug": format!("This is debugger plugin, args: {}", rest_args)
            })))
        }
        _ => Some(PluginResponse::Error(JsonrpcError {
            code: 0,
            message: String::from("Invalid request to keystore"),
            data: None,
        })),
    }
}
