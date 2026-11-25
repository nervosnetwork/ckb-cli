use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::setup::Setup;
use crate::spec::wallet::{ACCOUNT1_ADDRESS, ACCOUNT1_PRIVKEY};
use crate::spec::Spec;
use crate::util::ProcessGuard;

pub struct ApiServerOrigins;

impl Spec for ApiServerOrigins {
    fn run(&self, setup: &mut Setup) {
        let tempdir = tempfile::tempdir().expect("create temporary key directory");
        let key = tempdir.path().join("privkey");
        std::fs::write(&key, ACCOUNT1_PRIVKEY).expect("write test private key");
        let listener = TcpListener::bind("127.0.0.1:0").expect("reserve server port");
        let address = listener.local_addr().unwrap();
        drop(listener);
        let child = Command::new(setup.cli_bin())
            .args([
                "--url",
                &setup.rpc_url(),
                "server",
                "--listen",
                &address.to_string(),
                "--privkey-path",
                key.to_str().unwrap(),
                "--allowed-origin",
                "https://wallet.example",
            ])
            .stdin(Stdio::null())
            .spawn()
            .expect("start signing server");
        let mut server = ProcessGuard(child);
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if TcpStream::connect(address).is_ok() {
                break;
            }
            if let Some(status) = server.0.try_wait().expect("check server process") {
                panic!("signing server exited before starting: {}", status);
            }
            assert!(Instant::now() < deadline, "signing server did not start");
            thread::sleep(Duration::from_millis(100));
        }

        for origin in [
            "https://evil.example".to_string(),
            "null".to_string(),
            format!("http://{}", address),
        ] {
            let headers = format!("Origin: {}\r\n", origin);
            assert!(request(address, "POST", &headers).starts_with("HTTP/1.1 403"));
            assert!(request(address, "OPTIONS", &headers).starts_with("HTTP/1.1 403"));
        }
        assert!(request(
            address,
            "POST",
            "Origin: https://wallet.example\r\nOrigin: https://evil.example\r\n"
        )
        .starts_with("HTTP/1.1 403"));

        let allowed = "Origin: https://wallet.example\r\n";
        let preflight = request(
            address,
            "OPTIONS",
            &format!("{}Access-Control-Request-Method: POST\r\n", allowed),
        );
        assert!(preflight.starts_with("HTTP/1.1 200"));
        assert!(preflight
            .to_lowercase()
            .contains("access-control-allow-origin: https://wallet.example"));
        for headers in [allowed, ""] {
            let response = request(address, "POST", headers);
            let body = response.split_once("\r\n\r\n").unwrap().1;
            let json: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(json["error"]["code"], -32602, "{}", response);
        }
    }

    fn spec_name(&self) -> &'static str {
        "ApiServerOrigins"
    }
}

fn request(address: SocketAddr, method: &str, headers: &str) -> String {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "transfer",
        "params": [{
            "capacity": 10000000000u64,
            "fee_rate": 1000u64,
            "to_address": ACCOUNT1_ADDRESS,
            "force_small_change_as_fee": "NOT_A_CAPACITY"
        }],
        "id": 1
    })
    .to_string();
    let mut stream = TcpStream::connect(address).expect("connect to signing server");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "{} / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        method, address, headers, body.len(), body
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}
