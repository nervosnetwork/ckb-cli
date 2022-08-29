use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use tempfile::{tempdir, TempDir};

pub struct ProcessGuard(pub Child);

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        match self.0.kill() {
            Err(e) => log::error!("Could not kill ckb process: {}", e),
            Ok(_) => log::debug!("Successfully killed ckb process"),
        }
        let _ = self.0.wait();
    }
}

pub fn run_cmd(bin: &str, args: Vec<&str>) -> String {
    log::info!("[Execute]: {} {:?}", bin, args.join(" "));
    let init_output = Command::new(bin)
        .env("RUST_BACKTRACE", "full")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Run command failed");

    if !init_output.status.success() {
        log::error!("output: {:?}", init_output);
        panic!("Fail to execute command");
    }
    String::from_utf8_lossy(init_output.stdout.as_slice()).to_string()
}

pub fn find_available_port(start: u16, end: u16) -> u16 {
    for port in start..=end {
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    unreachable!()
}

pub fn temp_dir() -> (TempDir, String) {
    let tempdir = tempdir().expect("create tempdir failed");
    let path = tempdir.path().to_str().unwrap().to_owned();
    (tempdir, path)
}
