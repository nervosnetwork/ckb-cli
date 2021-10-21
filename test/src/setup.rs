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
    ckb_indexer_bin: String,
    cli_bin: String,
    pub keystore_plugin_bin: String,
    ckb_dir: String,
    ckb_indexer_dir: String,
    _ckb_cli_dir: String,
    rpc_port: u16,
    indexer_port: u16,
    miner: Option<Miner>,
}

// TODO Make CLI base_dir configurable
impl Setup {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ckb_bin: String,
        ckb_indexer_bin: String,
        cli_bin: String,
        keystore_plugin_bin: String,
        ckb_dir: String,
        ckb_indexer_dir: String,
        ckb_cli_dir: String,
        rpc_port: u16,
        indexer_port: u16,
    ) -> Self {
        Self {
            ckb_bin,
            ckb_indexer_bin,
            cli_bin,
            keystore_plugin_bin,
            ckb_dir,
            ckb_indexer_dir,
            _ckb_cli_dir: ckb_cli_dir,
            rpc_port,
            indexer_port,
            miner: None,
        }
    }

    pub fn ready(&mut self, spec: &dyn Spec) -> (ProcessGuard, Option<ProcessGuard>) {
        self.modify_ckb_toml(&*spec);
        self.modify_spec_toml(&*spec);

        let ckb_child_process = Command::new(&self.ckb_bin)
            .env("RUST_BACKTRACE", "full")
            .args(&["-C", &self.ckb_dir, "run", "--ba-advanced"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Run `ckb run` failed");
        sleep(Duration::from_secs(1)); // Wait for ckb starting RPC thread
        let ckb_indexer_guard = if self.ckb_indexer_bin.is_empty() {
            None
        } else {
            Some(ProcessGuard(
                Command::new(&self.ckb_indexer_bin)
                    .env("RUST_BACKTRACE", "full")
                    .args(&[
                        "-c",
                        self.rpc_url().as_str(),
                        "-s",
                        self.ckb_indexer_dir.as_str(),
                        "-l",
                        self.indexer_addr().as_str(),
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .expect("Run `ckb-indexer` failed"),
            ))
        };
        sleep(Duration::from_secs(2)); // Wait for ckb starting RPC thread
        (ProcessGuard(ckb_child_process), ckb_indexer_guard)
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
    pub fn indexer_url(&self) -> String {
        format!("http://{}", self.indexer_addr())
    }
    pub fn indexer_addr(&self) -> String {
        format!("127.0.0.1:{}", self.indexer_port)
    }

    pub fn consensus(&self) -> Consensus {
        let path = Path::new(&self.ckb_dir).join("specs").join("dev.toml");
        let content = fs::read_to_string(&path).unwrap();
        let spec_toml: ChainSpec = toml::from_str(&content).unwrap();
        spec_toml.build_consensus().unwrap()
    }

    pub fn cli(&self, command: &str) -> String {
        log::info!("[Execute]: {}", command);
        let rpc_url = self.rpc_url();
        let indexer_url = self.indexer_url();
        loop {
            let mut args = vec!["--url", &rpc_url];
            if !self.ckb_indexer_bin.is_empty() {
                args.push("--ckb-indexer-url");
                args.push(&indexer_url);
            }
            let mut child = Command::new(&self.cli_bin)
                .args(&args)
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
            let output = extract_output(stdout.to_string());
            if !output.trim().is_empty() {
                return output;
            } else if !stderr.trim().is_empty() {
                return stderr.to_string();
            }
        }
    }

    fn modify_ckb_toml(&self, spec: &dyn Spec) {
        let path = Path::new(&self.ckb_dir).join("ckb.toml");
        let content = fs::read_to_string(&path).unwrap();
        let mut ckb_toml: CKBAppConfig = CKBAppConfig::load_from_slice(content.as_bytes()).unwrap();

        // Setup [block_assembler]
        ckb_toml.block_assembler = Some(Miner::block_assembler());

        spec.modify_ckb_toml(&mut ckb_toml);
        let mut value = toml::Value::try_from(&ckb_toml).unwrap();
        // FIXME: remove this when use v0.101.0 ckb binary
        let tx_pool = value["tx_pool"].as_table_mut().unwrap();
        let _ = tx_pool.remove("keep_rejected_tx_hashes_count");
        let _ = tx_pool.remove("keep_rejected_tx_hashes_days");
        let _ = tx_pool.remove("recent_reject");
        fs::write(&path, toml::to_string(&value).unwrap()).expect("Dump ckb.toml");
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
    lines.collect::<Vec<_>>().join("\n")
}
