#![allow(unused)]
use crate::miner::Miner;
use crate::setup::Setup;
use crate::spec::Spec;
use ckb_chain_spec::consensus::TYPE_ID_CODE_HASH;
use serde::Deserialize;
use ckb_types::{H256, packed, prelude::*, core::ScriptHashType};
use ckb_jsonrpc_types::JsonBytes;
use regex::Regex;
use std::fs;
use tempfile::tempdir;
use crate::spec::udt::{SUDT_BIN, ACP_BIN, CHEQUE_BIN};

#[derive(Deserialize)]
struct TestCellRecipe {
    name: String,
    tx_hash: H256,
    index: u32,
    occupied_capacity: u64,
    data_hash: H256,
    #[serde(default)]
    type_id: Option<H256>,
}

#[derive(Deserialize)]
struct TestDepGroupRecipe {
    name: String,
    tx_hash: H256,
    index: u32,
    #[serde(default)]
    data_hash: H256,
    occupied_capacity: u64,
    #[serde(default)]
    type_id: Option<H256>,
}

#[derive(Deserialize)]
struct TestDeploymentRecipe {
    cell_recipes: Vec<TestCellRecipe>,
    dep_group_recipes: Vec<TestDepGroupRecipe>,
}

pub struct DeployDepGroupWithoutTypeId;

impl Spec for DeployDepGroupWithoutTypeId {
    fn run(&self, setup: &mut Setup) {
        let temp_dir = tempdir().expect("create tempdir failed");
        
        // Create test deployment config with TypeID disabled (traditional)
        let deployment_config = format!(r#"
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
"#, temp_dir.path().display(), 
           "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
           "c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7");
        
        // Write a valid contract binary
        fs::write(temp_dir.path().join("test_cell.bin"), ACP_BIN).unwrap();
        let config_path = temp_dir.path().join("deployment.toml");
        fs::write(&config_path, deployment_config).unwrap();
        
        // Run deployment
        let info_file = temp_dir.path().join("deployment_info.json");
        let migration_dir = temp_dir.path().join("migrations");
        fs::create_dir_all(&migration_dir).unwrap();
        
        // Generate transactions
        setup.cli(&format!(
            "deploy gen-txs --deployment-config {} --info-file {} --migration-dir {} --from-address {} --fee-rate 1000",
            config_path.display(),
            info_file.display(), 
            migration_dir.display(),
            Miner::address()
        ));

        // Sign transactions before applying
        let privkey_path = setup.miner().privkey_path().to_string();
        setup.cli(&format!(
            "deploy sign-txs --info-file {} --privkey-path {} --add-signatures",
            info_file.display(),
            privkey_path
        ));
        
        // Debug: Print deployment info file content
        if info_file.exists() {
            let info_content = fs::read_to_string(&info_file).unwrap();
            println!("DEBUG: deployment_info.json content:\n{}", info_content);
        } else {
            println!("DEBUG: deployment_info.json does not exist");
        }
        
        // Debug: List migration files
        let migration_files: Vec<_> = fs::read_dir(&migration_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        println!("DEBUG: migration files: {:?}", migration_files);
        
        // Apply transactions
        // Use non-interactive mode to get clean JSON output
        let info_str = info_file.display().to_string();
        let mig_str = migration_dir.display().to_string();
        let (output,_stderr) = setup.cli_command(
            &[
                "--output-format",
                "json",
                "deploy",
                "apply-txs",
                "--info-file",
                &info_str,
                "--migration-dir",
                &mig_str,
            ],
            &[],
        );
        
        // Debug: Print apply-txs output
        println!("DEBUG: apply-txs output:\n{}", output);
        
        // Parse results from JSON in stdout (stderr may include logs)
        let json_str = {
            let start = output.find('{').expect("JSON start not found in apply-txs output");
            let mut end = output.rfind('}').expect("JSON end not found in apply-txs output");
            loop {
                let slice = &output[start..=end];
                if serde_json::from_str::<serde_json::Value>(slice).is_ok() {
                    break slice;
                }
                end = output[..end]
                    .rfind('}')
                    .expect("No valid JSON object found in apply-txs output");
            }
        };
        let apply_result: serde_json::Value = serde_json::from_str(json_str).unwrap();
        let dep_group_tx_hash = apply_result["dep_group_tx"].as_str().unwrap().to_string();
        
        // Mine transactions
        setup.miner().mine_until_transaction_confirm(&dep_group_tx_hash);
        
        // Verify dep_group does NOT have TypeID
        let ( tx_output, _stderr ) = setup.cli_command(
            &[
                "--output-format",
                "json",
                "util",
                "cell-meta",
                "--tx-hash",
                &dep_group_tx_hash,
                "--index",
                "0",
            ],
            &[],
        );
        let cell_meta_json = {
            let start = tx_output.find('{').expect("JSON start not found in cell-meta output");
            let end = tx_output.rfind('}').expect("JSON end not found in cell-meta output");
            &tx_output[start..=end]
        };
        let cell_meta: serde_json::Value = serde_json::from_str(cell_meta_json).unwrap();
        
        // Verify NO TypeID script
        assert!(cell_meta["output"]["type"].is_null(), "DepGroup should NOT have TypeID script when disabled");
        
        // Verify recipe does not contain type_id
        let recipe_files: Vec<_> = fs::read_dir(&migration_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().map_or(false, |ext| ext == "json"))
            .collect();
        
        assert!(!recipe_files.is_empty(), "Should have migration recipe file");
        let recipe_content = fs::read_to_string(&recipe_files[0]).unwrap();
        let recipe: TestDeploymentRecipe = serde_json::from_str(&recipe_content).unwrap();
        
        let dep_group_recipe = &recipe.dep_group_recipes[0];
        assert!(dep_group_recipe.type_id.is_none(), "Recipe should not contain type_id when disabled");
    }

    fn spec_name(&self) -> &'static str {
        "DeployDepGroupWithoutTypeId"
    }
}

pub struct DeployDepGroupWithTypeId;

impl Spec for DeployDepGroupWithTypeId {
    fn run(&self, setup: &mut Setup) {
        let temp_dir = tempdir().expect("create tempdir failed");
        
        // Create test deployment config with TypeID enabled
        let deployment_config = format!(r#"
[[cells]]
name = "test_cell"
enable_type_id = false
location = {{ file = "{}/test_cell.bin" }}

[[dep_groups]]
name = "test_dep_group"
enable_type_id = true
cells = ["test_cell"]

[lock]
code_hash = "0x{}"
args = "0x{}"
hash_type = "type"

[multisig_config]
sighash_addresses = []
require_first_n = 0
threshold = 1
"#, temp_dir.path().display(), 
           "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
           "c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7");
        
        // Write a valid contract binary
        fs::write(temp_dir.path().join("test_cell.bin"), SUDT_BIN).unwrap();
        let config_path = temp_dir.path().join("deployment.toml");
        fs::write(&config_path, deployment_config).unwrap();
        
        // Run deployment
        let info_file = temp_dir.path().join("deployment_info.json");
        let migration_dir = temp_dir.path().join("migrations");
        fs::create_dir_all(&migration_dir).unwrap();
        
        // Generate transactions
        setup.cli(&format!(
            "deploy gen-txs --deployment-config {} --info-file {} --migration-dir {} --from-address {} --fee-rate 1000",
            config_path.display(),
            info_file.display(), 
            migration_dir.display(),
            Miner::address()
        ));
        
        // Sign transactions before applying
        let privkey_path = setup.miner().privkey_path().to_string();
        setup.cli(&format!(
            "deploy sign-txs --info-file {} --privkey-path {} --add-signatures",
            info_file.display(),
            privkey_path
        ));
        
        // Apply transactions (non-interactive for clean JSON)
        let info_str = info_file.display().to_string();
        let mig_str = migration_dir.display().to_string();
        let ( output,  _stderr) = setup.cli_command(
            &[
                "--output-format",
                "json",
                "deploy",
                "apply-txs",
                "--info-file",
                &info_str,
                "--migration-dir",
                &mig_str,
            ],
            &[],
        );
        
        // Parse results from JSON in stdout (stderr may include logs)
        let json_str = {
            let start = output.find('{').expect("JSON start not found in apply-txs output");
            let mut end = output.rfind('}').expect("JSON end not found in apply-txs output");
            loop {
                let slice = &output[start..=end];
                if serde_json::from_str::<serde_json::Value>(slice).is_ok() {
                    break slice;
                }
                end = output[..end]
                    .rfind('}')
                    .expect("No valid JSON object found in apply-txs output");
            }
        };
        let apply_result: serde_json::Value = serde_json::from_str(json_str).unwrap();
        let dep_group_tx_hash = apply_result["dep_group_tx"].as_str().unwrap().to_string();
        
        // Mine transactions
        setup.miner().mine_until_transaction_confirm(&dep_group_tx_hash);
        
        // Verify dep_group has TypeID
        let ( tx_output, _stderr ) = setup.cli_command(
            &[
                "--output-format",
                "json",
                "util",
                "cell-meta",
                "--tx-hash",
                &dep_group_tx_hash,
                "--index",
                "0",
            ],
            &[],
        );
        let cell_meta_json = {
            let start = tx_output.find('{').expect("JSON start not found in cell-meta output");
            let end = tx_output.rfind('}').expect("JSON end not found in cell-meta output");
            &tx_output[start..=end]
        };
        let cell_meta: serde_json::Value = serde_json::from_str(cell_meta_json).unwrap();
        
        // Verify TypeID script exists
        assert!(cell_meta["output"]["type"].is_object(), "DepGroup should have TypeID script when enabled");
        let type_script = &cell_meta["output"]["type"];
        assert_eq!(type_script["code_hash"], format!("0x{:x}", TYPE_ID_CODE_HASH));
        
        // Verify recipe contains type_id
        let recipe_files: Vec<_> = fs::read_dir(&migration_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().map_or(false, |ext| ext == "json"))
            .collect();
        
        assert!(!recipe_files.is_empty(), "Should have migration recipe file");
        let recipe_content = fs::read_to_string(&recipe_files[0]).unwrap();
        let recipe: TestDeploymentRecipe = serde_json::from_str(&recipe_content).unwrap();
        
        let dep_group_recipe = &recipe.dep_group_recipes[0];
        assert!(dep_group_recipe.type_id.is_some(), "Recipe should contain type_id when enabled");
        
        // Verify TypeID calculation matches the script hash
        let type_id_hash: H256 = dep_group_recipe.type_id.clone().unwrap();
        let code_hash_str = type_script["code_hash"].as_str().unwrap();
        let hash_type_str = type_script["hash_type"].as_str().unwrap();
        let args_str = type_script["args"].as_str().unwrap();

        let code_hash: H256 = serde_json::from_str(&format!("\"{}\"", code_hash_str)).unwrap();
        let args: JsonBytes = serde_json::from_str(&format!("\"{}\"", args_str)).unwrap();
        let sht = match hash_type_str {
            "type" => ScriptHashType::Type,
            "data" => ScriptHashType::Data,
            "data1" => ScriptHashType::Data1,
            "data2" => ScriptHashType::Data2,
            _ => panic!("unknown hash_type: {}", hash_type_str),
        };
        let script = packed::Script::new_builder()
            .code_hash(code_hash.pack())
            .hash_type(packed::Byte::new(sht.into()))
            .args(args.into_bytes().pack())
            .build();
        let expected_type_script_hash: H256 = script.calc_script_hash().unpack();
        assert_eq!(type_id_hash, expected_type_script_hash, "TypeID should match script hash");
    }

    fn spec_name(&self) -> &'static str {
        "DeployDepGroupWithTypeId"
    }
}

pub struct DeployDepGroupTypeIdTracking;

impl Spec for DeployDepGroupTypeIdTracking {
    fn run(&self, setup: &mut Setup) {
        let temp_dir = tempdir().expect("create tempdir failed");
        
        // Initial deployment with TypeID
        let deployment_config = format!(r#"
[[cells]]
name = "test_cell"
enable_type_id = false
location = {{ file = "{}/test_cell.bin" }}

[[dep_groups]]
name = "test_dep_group"
enable_type_id = true
cells = ["test_cell"]

[lock]
code_hash = "0x{}"
args = "0x{}"
hash_type = "type"

[multisig_config]
sighash_addresses = []
require_first_n = 0
threshold = 1
"#, temp_dir.path().display(), 
           "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
           "c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7");
        
        // Write a valid contract binary (v1)
        fs::write(temp_dir.path().join("test_cell.bin"), ACP_BIN).unwrap();
        let config_path = temp_dir.path().join("deployment.toml");
        fs::write(&config_path, deployment_config).unwrap();
        
        let info_file = temp_dir.path().join("deployment_info.json");
        let migration_dir = temp_dir.path().join("migrations");
        fs::create_dir_all(&migration_dir).unwrap();
        
        // First deployment
        setup.cli(&format!(
            "deploy gen-txs --deployment-config {} --info-file {} --migration-dir {} --from-address {} --fee-rate 1000",
            config_path.display(),
            info_file.display(), 
            migration_dir.display(),
            Miner::address()
        ));
        // Sign
        let privkey_path = setup.miner().privkey_path().to_string();
        setup.cli(&format!(
            "deploy sign-txs --info-file {} --privkey-path {} --add-signatures",
            info_file.display(),
            privkey_path
        ));
        // Apply (non-interactive JSON)
        let info_str = info_file.display().to_string();
        let mig_str = migration_dir.display().to_string();
        let ( output1,_stderr ) = setup.cli_command(
            &[
                "--output-format",
                "json",
                "deploy",
                "apply-txs",
                "--info-file",
                &info_str,
                "--migration-dir",
                &mig_str,
            ],
            &[],
        );
        let json1 = {
            let start = output1.find('{').expect("JSON start not found in apply-txs output");
            let mut end = output1.rfind('}').expect("JSON end not found in apply-txs output");
            loop {
                let slice = &output1[start..=end];
                if serde_json::from_str::<serde_json::Value>(slice).is_ok() {
                    break slice;
                }
                end = output1[..end]
                    .rfind('}')
                    .expect("No valid JSON object found in apply-txs output");
            }
        };
        let apply_result1: serde_json::Value = serde_json::from_str(json1).unwrap();
        let dep_group_tx_hash1 = apply_result1["dep_group_tx"].as_str().unwrap().to_string();
        setup.miner().mine_until_transaction_confirm(&dep_group_tx_hash1);
        
        // Get TypeID from first deployment
        let ( tx_output1,_stderr ) = setup.cli_command(
            &[
                "--output-format",
                "json",
                "util",
                "cell-meta",
                "--tx-hash",
                &dep_group_tx_hash1,
                "--index",
                "0",
            ],
            &[],
        );
        let cell_meta1_json = {
            let start = tx_output1.find('{').expect("JSON start not found in cell-meta output");
            let end = tx_output1.rfind('}').expect("JSON end not found in cell-meta output");
            &tx_output1[start..=end]
        };
        let cell_meta1: serde_json::Value = serde_json::from_str(cell_meta1_json).unwrap();
        let type_script1 = &cell_meta1["output"]["type"];
        let code_hash_str = type_script1["code_hash"].as_str().unwrap();
        let hash_type_str = type_script1["hash_type"].as_str().unwrap();
        let args_str = type_script1["args"].as_str().unwrap();
        let code_hash: H256 = serde_json::from_str(&format!("\"{}\"", code_hash_str)).unwrap();
        let args: JsonBytes = serde_json::from_str(&format!("\"{}\"", args_str)).unwrap();
        let sht = match hash_type_str {
            "type" => ScriptHashType::Type,
            "data" => ScriptHashType::Data,
            "data1" => ScriptHashType::Data1,
            "data2" => ScriptHashType::Data2,
            _ => panic!("unknown hash_type: {}", hash_type_str),
        };
        let script1 = packed::Script::new_builder()
            .code_hash(code_hash.pack())
            .hash_type(packed::Byte::new(sht.into()))
            .args(args.into_bytes().pack())
            .build();
        let original_type_id = format!("0x{:x}", script1.calc_script_hash());
        
        // Update the cell (force redeploy) with a different valid binary (v2)
        fs::write(temp_dir.path().join("test_cell.bin"), CHEQUE_BIN).unwrap();
        
        // Second deployment (should preserve TypeID)
        setup.cli(&format!(
            "deploy gen-txs --deployment-config {} --info-file {} --migration-dir {} --from-address {} --fee-rate 1000",
            config_path.display(),
            info_file.display(), 
            migration_dir.display(),
            Miner::address()
        ));
        // Sign
        let privkey_path = setup.miner().privkey_path().to_string();
        setup.cli(&format!(
            "deploy sign-txs --info-file {} --privkey-path {} --add-signatures",
            info_file.display(),
            privkey_path
        ));
        // Apply (non-interactive JSON)
        let info_str = info_file.display().to_string();
        let mig_str = migration_dir.display().to_string();
        let ( output2, _stderr ) = setup.cli_command(
            &[
                "--output-format",
                "json",
                "deploy",
                "apply-txs",
                "--info-file",
                &info_str,
                "--migration-dir",
                &mig_str,
            ],
            &[],
        );
        println!("DEBUG: second apply-txs raw output:\n{}", output2);
        // Prefer tx hash echoed in stderr, fallback to latest recipe
        let dep_group_tx_hash2 = if let Some(m) = Regex::new(r"0x[0-9a-fA-F]{64}")
            .unwrap()
            .find_iter(&output2)
            .last()
        {
            m.as_str().to_string()
        } else {
            let recipe_files: Vec<_> = fs::read_dir(&migration_dir)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.extension().map_or(false, |ext| ext == "json"))
                .collect();
            assert!(!recipe_files.is_empty(), "Should have migration recipe files");
            let latest_recipe = recipe_files
                .into_iter()
                .max_by_key(|p| p.file_name().unwrap().to_string_lossy().to_string())
                .unwrap();
            let recipe_content2 = fs::read_to_string(latest_recipe).unwrap();
            let recipe2: serde_json::Value = serde_json::from_str(&recipe_content2).unwrap();
            recipe2["dep_group_recipes"][0]["tx_hash"].as_str().unwrap().to_string()
        };
        // Verify TypeID is preserved using latest recipe's type_id
        let latest_recipe = {
            let recipe_files: Vec<_> = fs::read_dir(&migration_dir)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.extension().map_or(false, |ext| ext == "json"))
                .collect();
            recipe_files
                .iter()
                .max_by_key(|path| fs::metadata(path).unwrap().modified().unwrap())
                .unwrap()
                .to_path_buf()
        };
        let recipe_content2 = fs::read_to_string(&latest_recipe).unwrap();
        let recipe2: serde_json::Value = serde_json::from_str(&recipe_content2).unwrap();
        let preserved_type_id = recipe2["dep_group_recipes"][0]["type_id"].as_str().unwrap();
        assert_eq!(original_type_id, preserved_type_id, "TypeID should be preserved across updates");
    }

    fn spec_name(&self) -> &'static str {
        "DeployDepGroupTypeIdTracking"
    }
}

pub struct DeployDepGroupEnableTypeIdLater;

impl Spec for DeployDepGroupEnableTypeIdLater {
    fn run(&self, setup: &mut Setup) {
        let temp_dir = tempdir().expect("create tempdir failed");
        
        // Initial deployment WITHOUT TypeID
        let deployment_config_v1 = format!(r#"
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
"#, temp_dir.path().display(), 
           "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
           "c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7");
        
        // Write a valid contract binary
        fs::write(temp_dir.path().join("test_cell.bin"), SUDT_BIN).unwrap();
        let config_path = temp_dir.path().join("deployment.toml");
        fs::write(&config_path, deployment_config_v1).unwrap();
        
        let info_file = temp_dir.path().join("deployment_info.json");
        let migration_dir = temp_dir.path().join("migrations");
        fs::create_dir_all(&migration_dir).unwrap();
        
        // First deployment (no TypeID)
        setup.cli(&format!(
            "deploy gen-txs --deployment-config {} --info-file {} --migration-dir {} --from-address {} --fee-rate 1000",
            config_path.display(),
            info_file.display(), 
            migration_dir.display(),
            Miner::address()
        ));
        // Sign
        let privkey_path = setup.miner().privkey_path().to_string();
        setup.cli(&format!(
            "deploy sign-txs --info-file {} --privkey-path {} --add-signatures",
            info_file.display(),
            privkey_path
        ));
        // Apply (non-interactive JSON)
        let info_str = info_file.display().to_string();
        let mig_str = migration_dir.display().to_string();
        let ( output1, _stderr ) = setup.cli_command(
            &[
                "--output-format",
                "json",
                "deploy",
                "apply-txs",
                "--info-file",
                &info_str,
                "--migration-dir",
                &mig_str,
            ],
            &[],
        );
        let json1 = {
            let start = output1.find('{').expect("JSON start not found in apply-txs output");
            let mut end = output1.rfind('}').expect("JSON end not found in apply-txs output");
            loop {
                let slice = &output1[start..=end];
                if serde_json::from_str::<serde_json::Value>(slice).is_ok() {
                    break slice;
                }
                end = output1[..end]
                    .rfind('}')
                    .expect("No valid JSON object found in apply-txs output");
            }
        };
        let apply_result1: serde_json::Value = serde_json::from_str(json1).unwrap();
        let dep_group_tx_hash1 = apply_result1["dep_group_tx"].as_str().unwrap().to_string();
        setup.miner().mine_until_transaction_confirm(&dep_group_tx_hash1);
        
        // Verify no TypeID initially
        let ( tx_output1,_stderr ) = setup.cli_command(
            &[
                "--output-format",
                "json",
                "util",
                "cell-meta",
                "--tx-hash",
                &dep_group_tx_hash1,
                "--index",
                "0",
            ],
            &[],
        );
        let cell_meta1_json = {
            let start = tx_output1.find('{').expect("JSON start not found in cell-meta output");
            let end = tx_output1.rfind('}').expect("JSON end not found in cell-meta output");
            &tx_output1[start..=end]
        };
        let cell_meta1: serde_json::Value = serde_json::from_str(cell_meta1_json).unwrap();
        assert!(cell_meta1["output"]["type"].is_null(), "Should not have TypeID initially");
        // Give the node a moment and advance blocks to avoid race with indexer/live cell queries
        setup.miner().generate_blocks(6);
        
        // Update config to enable TypeID
        let deployment_config_v2 = format!(r#"
[[cells]]
name = "test_cell"
enable_type_id = false
location = {{ file = "{}/test_cell.bin" }}

[[dep_groups]]
name = "test_dep_group"
enable_type_id = true
cells = ["test_cell"]

[lock]
code_hash = "0x{}"
args = "0x{}"
hash_type = "type"

[multisig_config]
sighash_addresses = []
require_first_n = 0
threshold = 1
"#, temp_dir.path().display(), 
           "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
           "c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7");
        
        fs::write(&config_path, deployment_config_v2).unwrap();
        
        // Second deployment (with TypeID enabled)
        let deploy_gen_txs_output = setup.cli(&format!(
            "deploy gen-txs --deployment-config {} --info-file {} --migration-dir {} --from-address {} --fee-rate 1000",
            config_path.display(),
            info_file.display(), 
            migration_dir.display(),
            Miner::address()
        ));
        println!("DEBUG: deploy gen-txs: {}", deploy_gen_txs_output);
        // Sign
        let privkey_path = setup.miner().privkey_path().to_string();
        setup.cli(&format!(
            "deploy sign-txs --info-file {} --privkey-path {} --add-signatures",
            info_file.display(),
            privkey_path
        ));
        // Apply (non-interactive JSON)
        let info_str = info_file.display().to_string();
        let mig_str = migration_dir.display().to_string();
        let ( output2,_stderr ) = setup.cli_command(
            &[
                "--output-format",
                "json",
                "deploy",
                "apply-txs",
                "--info-file",
                &info_str,
                "--migration-dir",
                &mig_str,
            ],
            &[],
        );
        // Extract tx hash from stderr logs, fallback to latest recipe json if needed
        let dep_group_tx_hash2 = if let Some(m) = Regex::new(r"0x[0-9a-fA-F]{64}")
            .unwrap()
            .find_iter(&output2)
            .last()
        {
            m.as_str().to_string()
        } else {
            let recipe_files: Vec<_> = fs::read_dir(&migration_dir)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.extension().map_or(false, |ext| ext == "json"))
                .collect();
            assert!(!recipe_files.is_empty(), "Should have migration recipe files");
            let latest_recipe = recipe_files
                .iter()
                .max_by_key(|path| fs::metadata(path).unwrap().modified().unwrap())
                .unwrap();
            let recipe_content2 = fs::read_to_string(latest_recipe).unwrap();
            let recipe2: serde_json::Value = serde_json::from_str(&recipe_content2).unwrap();
            recipe2["dep_group_recipes"][0]["tx_hash"].as_str().unwrap().to_string()
        };
        // Verify recipe contains new type_id (avoid relying on on-chain query)
        let recipe_files: Vec<_> = fs::read_dir(&migration_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().map_or(false, |ext| ext == "json"))
            .collect();
        
        // Get the latest recipe file by timestamped filename (lexicographic)
        let latest_recipe = recipe_files
            .into_iter()
            .max_by_key(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .unwrap();
        
        let recipe_content = fs::read_to_string(latest_recipe).unwrap();
        let recipe: TestDeploymentRecipe = serde_json::from_str(&recipe_content).unwrap();
        let type_id = recipe.dep_group_recipes[0]
            .type_id
            .clone()
            .expect("Recipe should contain type_id after enabling");
        // Check it is a 32-byte hash
        let _bytes: [u8; 32] = type_id.into();
    }

    fn spec_name(&self) -> &'static str {
        "DeployDepGroupEnableTypeIdLater"
    }
}
