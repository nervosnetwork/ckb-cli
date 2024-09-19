use crate::miner::Miner;
use crate::spec::Spec;
use crate::util::ProcessGuard;
use ckb_app_config::CKBAppConfig;
use ckb_chain_spec::consensus::Consensus;
use ckb_chain_spec::ChainSpec;
use log::info;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

pub struct Setup {
    ckb_bin: String,
    cli_bin: String,
    pub keystore_plugin_bin: String,
    ckb_dir: String,
    rpc_port: u16,
    miner: Option<Miner>,
    success: bool,
    tempdir: PathBuf,
}

// TODO Make CLI base_dir configurable
impl Setup {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ckb_bin: String,
        cli_bin: String,
        keystore_plugin_bin: String,
        ckb_dir: String,
        rpc_port: u16,
        tempdir: tempfile::TempDir,
    ) -> Self {
        Self {
            ckb_bin,
            cli_bin,
            keystore_plugin_bin,
            ckb_dir,
            rpc_port,
            miner: None,
            success: false,
            tempdir: tempdir.into_path(),
        }
    }

    pub fn ready(&mut self, spec: &dyn Spec) -> ProcessGuard {
        self.modify_ckb_toml(spec);
        self.modify_spec_toml(spec);

        let mut ckb_cmd = Command::new(&self.ckb_bin);
        ckb_cmd.args(["-C", &self.ckb_dir, "run", "--indexer", "--ba-advanced"]);

        log::info!("run ckb: {:?}", ckb_cmd);

        let ckb_child_process = ckb_cmd
            .env("RUST_BACKTRACE", "full")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Run `ckb run` failed");

        sleep(Duration::from_secs(3)); // Wait for ckb starting RPC thread
        ProcessGuard(ckb_child_process)
    }

    pub fn miner(&mut self) -> &Miner {
        if self.miner.is_none() {
            self.miner = Some(Miner::init(self.rpc_url()));
        }
        self.miner.as_ref().unwrap()
    }

    pub fn success(&mut self) {
        self.success = true;
    }

    pub fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpc_port)
    }

    pub fn consensus(&self) -> Consensus {
        let path = Path::new(&self.ckb_dir).join("specs").join("dev.toml");
        let content = fs::read_to_string(path).unwrap();
        let spec_toml: ChainSpec = toml::from_str(&content).unwrap();
        spec_toml.build_consensus().unwrap()
    }

    pub fn cli(&self, command: &str) -> String {
        log::info!("[Execute]: {}", command);
        loop {
            let mut child = Command::new(&self.cli_bin)
                .env("RUST_BACKTRACE", "full")
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
            let output = extract_output(stdout.to_string());
            if !output.trim().is_empty() {
                return output;
            } else if !stderr.trim().is_empty() {
                return stderr.to_string();
            }
        }
    }

    pub fn cli_command(&self, command: &[&str], inputs: &[&str]) -> String {
        info!("Execute: {:?}, with stdin: {:?}", command, inputs);
        let rpc_url = self.rpc_url();
        let mut args = vec!["--url", &rpc_url];
        args.append(&mut command.to_vec());
        let mut child = Command::new(&self.cli_bin)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn child process");
        let mut stdin = child.stdin.take().expect("Failed to open stdin");
        let pass_jh = std::thread::spawn({
            let inputs: Vec<String> = inputs.iter().map(|&s| s.to_string()).collect();
            move || {
                inputs.iter().for_each(|input| {
                    stdin
                        .write_all(input.as_bytes())
                        .expect("Failed to write to stdin");
                    stdin
                        .write_all(b"\n")
                        .expect("Failed to write newline to stdin");
                    info!("write to stdin: {}", input);
                });
            }
        });
        pass_jh.join().expect("Failed to join pass stdin thread");

        let output = child.wait_with_output().expect("Failed to read stdout");

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.to_string() + &stderr
    }

    fn modify_ckb_toml(&self, spec: &dyn Spec) {
        let path = Path::new(&self.ckb_dir).join("ckb.toml");
        let content = fs::read_to_string(&path).unwrap();

        let mut ckb_toml: CKBAppConfig = CKBAppConfig::load_from_slice(content.as_bytes()).unwrap();
        // Setup [block_assembler]
        ckb_toml.block_assembler = Some(Miner::block_assembler());
        spec.modify_ckb_toml(&mut ckb_toml);

        let mut value = toml::Value::try_from(&ckb_toml).unwrap();
        value["rpc"]["modules"]
            .as_array_mut()
            .unwrap()
            .push(toml::Value::String("Indexer".to_string()));
        value["rpc"]["modules"]
            .as_array_mut()
            .unwrap()
            .push(toml::Value::String("IntegrationTest".to_string()));
        // value["indexer_v2"]["index_tx_pool"] = true;
        value
            .as_table_mut()
            .unwrap()
            .entry("indexer_v2")
            .or_insert(toml::Value::Table(toml::value::Table::new()))
            .as_table_mut()
            .unwrap()
            .entry("index_tx_pool")
            .or_insert(toml::Value::Boolean(true));

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

impl Drop for Setup {
    fn drop(&mut self) {
        if self.success {
            log::info!("remove directory: {:?}", self.tempdir);
            fs::remove_dir_all(&self.tempdir).unwrap();
        }
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
