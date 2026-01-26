use crate::miner::Miner;
use crate::setup::Setup;
use crate::spec::udt::ACP_BIN;
use crate::spec::Spec;
use ckb_types::H256;
use serde_json::{Map, Value};
use std::fs;
use tempfile::tempdir;

pub struct DeployInfoOrdering;

impl Spec for DeployInfoOrdering {
    fn run(&self, setup: &mut Setup) {
        let temp_dir = tempdir().expect("create tempdir failed");

        let deployment_config = format!(
            r#"
[[cells]]
name = "test_cell"
enable_type_id = false
location = {{ file = "{}/test_cell.bin" }}

[[dep_groups]]
name = "test_dep_group"
enable_type_id = false
cells = ["test_cell"]

[lock]
code_hash = "0x{}"
args = "0x{}"
hash_type = "type"

[multisig_config]
sighash_addresses = []
require_first_n = 0
threshold = 1
"#,
            temp_dir.path().display(),
            "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
            "c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7"
        );

        fs::write(temp_dir.path().join("test_cell.bin"), ACP_BIN).unwrap();
        let config_path = temp_dir.path().join("deployment.toml");
        fs::write(&config_path, deployment_config).unwrap();

        let info_file = temp_dir.path().join("deployment_info.json");
        let migration_dir = temp_dir.path().join("migrations");
        fs::create_dir_all(&migration_dir).unwrap();

        setup.cli(&format!(
            "deploy gen-txs --deployment-config {} --info-file {} --migration-dir {} --from-address {} --fee-rate 1000",
            config_path.display(),
            info_file.display(),
            migration_dir.display(),
            Miner::address()
        ));

        let info_content = fs::read_to_string(&info_file).unwrap();
        let mut info_json: Value = serde_json::from_str(&info_content).unwrap();
        let used_input_txs = info_json["used_input_txs"]
            .as_object()
            .expect("used_input_txs should be a map");
        assert!(
            !used_input_txs.is_empty(),
            "used_input_txs should not be empty"
        );

        let sample_tx = used_input_txs.values().next().cloned().unwrap();
        let mut reordered_map = Map::new();
        let extra_keys = vec![
            H256::from_low_u64_be(3),
            H256::from_low_u64_be(1),
            H256::from_low_u64_be(4),
            H256::from_low_u64_be(2),
        ];
        for key in &extra_keys {
            reordered_map.insert(format!("{:#x}", key), sample_tx.clone());
        }
        for (key, value) in used_input_txs.iter() {
            reordered_map.insert(key.clone(), value.clone());
        }
        info_json["used_input_txs"] = Value::Object(reordered_map);
        fs::write(
            &info_file,
            serde_json::to_string_pretty(&info_json).unwrap(),
        )
        .unwrap();

        let privkey_path = setup.miner().privkey_path().to_string();
        setup.cli(&format!(
            "deploy sign-txs --info-file {} --privkey-path {} --add-signatures",
            info_file.display(),
            privkey_path
        ));

        let updated_content = fs::read_to_string(&info_file).unwrap();
        let updated_json: Value = serde_json::from_str(&updated_content).unwrap();
        let updated_map = updated_json["used_input_txs"]
            .as_object()
            .expect("used_input_txs should be a map");
        let ordered_keys: Vec<String> = updated_map.keys().cloned().collect();

        let mut sorted_keys: Vec<H256> = ordered_keys
            .iter()
            .map(|key| serde_json::from_str::<H256>(&format!("\"{}\"", key)).unwrap())
            .collect();
        sorted_keys.sort();
        let sorted_key_strings: Vec<String> = sorted_keys
            .iter()
            .map(|key| format!("{:#x}", key))
            .collect();

        assert_eq!(
            ordered_keys, sorted_key_strings,
            "used_input_txs keys should be sorted for stable JSON output"
        );
    }

    fn spec_name(&self) -> &'static str {
        "DeployInfoOrdering"
    }
}
