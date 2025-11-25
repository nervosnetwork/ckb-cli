use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use tempfile::{tempdir, TempDir};

pub struct ProcessGuard(pub Option<Child>);

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            match child.kill() {
                Err(e) => log::error!("Could not kill ckb process: {}", e),
                Ok(_) => log::debug!("Successfully killed ckb process"),
            }
            let _ = child.wait();
        }
    }
}

pub fn run_cmd(bin: &str, args: Vec<&str>) -> String {
    log::info!("[Executing]: {} {:?}", bin, args.join(" "));
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
