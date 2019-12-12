use crate::miner::Miner;
use crate::spec::Spec;
use crate::util::ProcessGuard;
use ckb_app_config::CKBAppConfig;
use ckb_chain_spec::consensus::Consensus;
use ckb_chain_spec::ChainSpec;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

pub struct Setup {
    ckb_bin: String,
    cli_bin: String,
    ckb_dir: String,
    rpc_port: u16,
    miner: Option<Miner>,
}

// TODO Make CLI base_dir configurable
impl Setup {
    pub fn new(ckb_bin: String, cli_bin: String, ckb_dir: String, rpc_port: u16) -> Self {
        Self {
            ckb_bin,
            cli_bin,
            ckb_dir,
            rpc_port,
            miner: None,
        }
    }

    pub fn ready(&mut self, spec: &dyn Spec) -> ProcessGuard {
        self.modify_ckb_toml(&*spec);
        self.modify_spec_toml(&*spec);

        let child_process = Command::new(&self.ckb_bin)
            .env("RUST_BACKTRACE", "full")
            .args(&["-C", &self.ckb_dir, "run", "--ba-advanced"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Run `ckb run` failed");
        sleep(Duration::from_secs(3)); // Wait for ckb starting RPC thread
        ProcessGuard(child_process)
    }

    pub fn miner(&mut self) -> &Miner {
        if self.miner.is_none() {
            self.miner = Some(Miner::init(self.rpc_url()));
        }
        self.miner.as_ref().unwrap()
    }

    pub fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpc_port)
    }

    pub fn consensus(&self) -> Consensus {
        let path = Path::new(&self.ckb_dir).join("specs").join("dev.toml");
        let content = fs::read_to_string(&path).unwrap();
        let spec_toml: ChainSpec = toml::from_str(&content).unwrap();
        spec_toml.build_consensus().unwrap()
    }

    pub fn cli(&self, command: &str) -> String {
        log::info!("[Execute]: {}", command);
        loop {
            let mut child = Command::new(&self.cli_bin)
                .args(vec!["--url", &self.rpc_url()])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("Failed to spawn child process");
            {
                let stdin = child.stdin.as_mut().expect("Failed to open stdin");
                stdin
                    .write_all(command.as_bytes())
                    .expect("Failed to write to stdin");
            }
            let output = child.wait_with_output().expect("Failed to read stdout");
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stderr.contains("index database may not ready") {
                continue;
            } else if !stderr.is_empty() && !stderr.contains("No previous history.") {
                return stderr.to_string();
            } else {
                return extract_output(stdout.to_string());
            }
        }
    }

    fn modify_ckb_toml(&self, spec: &dyn Spec) {
        let path = Path::new(&self.ckb_dir).join("ckb.toml");
        let content = fs::read_to_string(&path).unwrap();
        let mut ckb_toml: CKBAppConfig = toml::from_str(&content).unwrap();

        // Setup [block_assembler]
        ckb_toml.block_assembler = Some(Miner::block_assembler());

        spec.modify_ckb_toml(&mut ckb_toml);
        fs::write(&path, toml::to_string(&ckb_toml).unwrap()).expect("Dump ckb.toml");
    }

    fn modify_spec_toml(&self, spec: &dyn Spec) {
        let path = Path::new(&self.ckb_dir).join("specs").join("dev.toml");
        let content = fs::read_to_string(&path).unwrap();
        let mut spec_toml: ChainSpec = toml::from_str(&content).unwrap();

        // Setup genesis message to generate a random genesis hash
        spec_toml.genesis.genesis_cell.message = format!("{:?}", Instant::now());

        spec.modify_spec_toml(&mut spec_toml);
        fs::write(&path, toml::to_string(&spec_toml).unwrap()).expect("Dump dev.toml");
    }
}

fn extract_output(content: String) -> String {
    //    _   _   ______   _____   __      __   ____     _____
    //  | \ | | |  ____| |  __ \  \ \    / /  / __ \   / ____|
    //  |  \| | | |__    | |__) |  \ \  / /  | |  | | | (___
    //  | . ` | |  __|   |  _  /    \ \/ /   | |  | |  \___ \
    //  | |\  | | |____  | | \ \     \  /    | |__| |  ____) |
    //  |_| \_| |______| |_|  \_\     \/      \____/  |_____/
    //
    // [  ckb-cli version ]: 0.25.0 (a458296-dirty 2019-11-18)
    // [              url ]: http://127.0.0.1:8114
    // [              pwd ]: /ckb-cli/test
    // [            color ]: true
    // [            debug ]: false
    // [    output format ]: yaml
    // [ completion style ]: List
    // [       edit style ]: Emacs
    // [   index db state ]: Waiting for first query
    // 0x2470ebe5dda09518498376a047e3560e4521ec70d7fc349f1c7bfc716450c6dd
    // CTRL-D

    let lines = content.lines();
    let lines =
        lines.skip_while(|line| !regex::Regex::new(r#"\[.*\]: .*"#).unwrap().is_match(line));
    let lines = lines.skip_while(|line| regex::Regex::new(r#"\[.*\]: .*"#).unwrap().is_match(line));
    let lines = lines.take_while(|line| *line != "CTRL-D");
    let output: String = lines.collect::<Vec<_>>().join("\n");
    if !output.is_empty() {
        output
    } else {
        content
    }
}
