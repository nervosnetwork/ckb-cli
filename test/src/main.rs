use std::env;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use clap::{App, Arg};
use tempfile::{tempdir, TempDir};

fn main() {
    let _ = {
        let filter = env::var("CKB_LOG").unwrap_or_else(|_| "info".to_string());
        env_logger::builder().parse_filters(&filter).try_init()
    };
    let matches = App::new("ckb-cli-test")
        .arg(
            Arg::with_name("ckb-bin")
                .long("ckb-bin")
                .takes_value(true)
                .required(true)
                .value_name("PATH")
                .help("Path to ckb executable"),
        )
        .arg(
            Arg::with_name("cli-bin")
                .long("cli-bin")
                .takes_value(true)
                .required(true)
                .value_name("PATH")
                .help("Path to ckb-cli executable"),
        )
        .get_matches();
    let ckb_bin = matches.value_of("ckb-bin").unwrap();
    let cli_bin = matches.value_of("cli-bin").unwrap();
    assert!(
        Path::new(ckb_bin).exists(),
        "ckb binary not exists: {}",
        ckb_bin
    );
    assert!(
        Path::new(cli_bin).exists(),
        "ckb-cli binary not exists: {}",
        cli_bin
    );

    let (tmpdir, ckb_dir) = temp_dir();
    log::info!("ckb init: {}", ckb_dir);
    let _stdout = run_cmd(
        ckb_bin,
        vec![
            "-C",
            ckb_dir.as_str(),
            "init",
            "--chain",
            "dev",
            "--rpc-port",
            "9000",
            "--p2p-port",
            "9001",
        ],
    );

    log::info!("ckb run");
    let child_process = Command::new(ckb_bin.to_owned())
        .env("RUST_BACKTRACE", "full")
        .args(&["-C", ckb_dir.as_str(), "run", "--ba-advanced"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Run `ckb run` failed");
    let _guard = ProcessGuard(child_process);
    thread::sleep(Duration::from_secs(3));

    log::info!(
        "[Output]:\n{}",
        run_cmd(
            cli_bin,
            vec!["--url", "http://127.0.0.1:9000", "rpc", "get_tip_header"]
        )
    );
    tmpdir.close().expect("Close tmp dir failed");
}

fn run_cmd(bin: &str, args: Vec<&str>) -> String {
    log::info!("[Execute]: {:?}", args);
    let init_output = Command::new(bin.to_owned())
        .env("RUST_BACKTRACE", "full")
        .args(&args)
        .output()
        .expect("Run command failed");

    if !init_output.status.success() {
        log::error!("{}", String::from_utf8_lossy(init_output.stderr.as_slice()));
        panic!("Fail to execute command");
    }
    String::from_utf8_lossy(init_output.stdout.as_slice()).to_string()
}

struct ProcessGuard(pub Child);

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        match self.0.kill() {
            Err(e) => log::error!("Could not kill ckb process: {}", e),
            Ok(_) => log::debug!("Successfully killed ckb process"),
        }
        let _ = self.0.wait();
    }
}

pub fn temp_dir() -> (TempDir, String) {
    let tempdir = tempdir().expect("create tempdir failed");
    let path = tempdir.path().to_str().unwrap().to_owned();
    (tempdir, path)
}
