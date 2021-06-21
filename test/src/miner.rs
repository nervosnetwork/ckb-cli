use crate::util::temp_dir;
use ckb_app_config::BlockAssemblerConfig;
use ckb_sdk::{Address, AddressPayload, HttpRpcClient, NetworkType};
use ckb_types::packed::Block;
use ckb_types::{H160, H256};
use std::fs;
use std::sync::Mutex;
use tempfile::TempDir;

pub const MINER_PRIVATE_KEY: &str =
    "d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc";
pub const MINER_BLOCK_ASSEMBLER: &str = r#"
code_hash = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
hash_type = "type"
args = "0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7"
message = "0x"
"#;

pub struct Miner {
    rpc: Mutex<HttpRpcClient>,
    privkey_path: (TempDir, String),
}

impl Miner {
    pub fn init(uri: String) -> Self {
        let (tempdir, _) = temp_dir();
        let privkey_path = tempdir.path().join("pk");
        fs::write(&privkey_path, MINER_PRIVATE_KEY).unwrap();
        Self {
            rpc: Mutex::new(HttpRpcClient::new(uri)),
            privkey_path: (tempdir, privkey_path.to_string_lossy().to_string()),
        }
    }

    pub fn generate_block(&self) -> H256 {
        let template = self
            .rpc
            .lock()
            .unwrap()
            .get_block_template(None, None, None)
            .expect("RPC get_block_template");
        let work_id = template.work_id.value();
        let block = Into::<Block>::into(template);
        self.rpc
            .lock()
            .unwrap()
            .submit_block(work_id.to_string(), block)
            .expect("RPC submit_block")
    }

    pub fn generate_blocks(&self, count: u64) {
        (0..count).for_each(|_| {
            self.generate_block();
        })
    }

    pub fn privkey_path(&self) -> &str {
        &self.privkey_path.1
    }

    pub fn block_assembler() -> BlockAssemblerConfig {
        toml::from_str(MINER_BLOCK_ASSEMBLER).unwrap()
    }

    pub fn address() -> Address {
        let lock_arg = {
            let mut lock_arg = [0u8; 20];
            lock_arg.copy_from_slice(Self::block_assembler().args.as_bytes());
            H160(lock_arg)
        };
        let payload = AddressPayload::new_short_sighash(lock_arg);
        Address::new(NetworkType::Dev, payload)
    }
}
