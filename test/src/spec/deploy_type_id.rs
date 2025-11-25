#![allow(unused)]
use crate::miner::Miner;
use crate::setup::Setup;
use crate::spec::udt::{ACP_BIN, CHEQUE_BIN, SUDT_BIN};
use crate::spec::Spec;
use ckb_chain_spec::consensus::TYPE_ID_CODE_HASH;
use ckb_jsonrpc_types::{JsonBytes, ScriptHashType as JsonScriptHashType};
use ckb_types::{core::ScriptHashType, packed, prelude::*, H256};
use serde::Deserialize;
use serde_yaml::Value as YamlValue;
use std::fs;
use tempfile::tempdir;

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
struct TestDeploymentResult {
    cell_tx: Option<H256>,
    dep_group_tx: H256,
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
        let (output, _stderr) = setup.cli_command(
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

        // Parse results directly from JSON output
        let apply_result: TestDeploymentResult = serde_json::from_str(&output).unwrap();
        let dep_group_tx_hash = format!("{:#x}", apply_result.dep_group_tx);

        // Mine transactions
        setup
            .miner()
            .mine_until_transaction_confirm(&dep_group_tx_hash);

        // Verify dep_group does NOT have TypeID
        let (tx_output, _stderr) = setup.cli_command(
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
        let cell_meta: serde_json::Value = serde_json::from_str(&tx_output).unwrap();

        // Verify NO TypeID script
        assert!(
            cell_meta["output"]["type"].is_null(),
            "DepGroup should NOT have TypeID script when disabled"
        );

        // Verify recipe does not contain type_id
        let recipe_files: Vec<_> = fs::read_dir(&migration_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .collect();

        assert!(
            !recipe_files.is_empty(),
            "Should have migration recipe file"
        );
        let recipe_content = fs::read_to_string(&recipe_files[0]).unwrap();
        let recipe: TestDeploymentRecipe = serde_json::from_str(&recipe_content).unwrap();

        let dep_group_recipe = &recipe.dep_group_recipes[0];
        assert!(
            dep_group_recipe.type_id.is_none(),
            "Recipe should not contain type_id when disabled"
        );
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
        let deployment_config = format!(
            r#"
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
"#,
            temp_dir.path().display(),
            "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
            "c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7"
        );

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
        let (output, _stderr) = setup.cli_command(
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

        // Parse results directly from JSON output
        let apply_result: TestDeploymentResult = serde_json::from_str(&output).unwrap();
        let dep_group_tx_hash = format!("{:#x}", apply_result.dep_group_tx);

        // Mine transactions
        setup
            .miner()
            .mine_until_transaction_confirm(&dep_group_tx_hash);

        // Verify dep_group has TypeID
        let (tx_output, _stderr) = setup.cli_command(
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
        let cell_meta: serde_json::Value = serde_json::from_str(&tx_output).unwrap();

        // Verify TypeID script exists
        assert!(
            cell_meta["output"]["type"].is_object(),
            "DepGroup should have TypeID script when enabled"
        );
        let type_script = &cell_meta["output"]["type"];
        assert_eq!(
            type_script["code_hash"],
            format!("0x{:x}", TYPE_ID_CODE_HASH)
        );

        // Verify recipe contains type_id
        let recipe_files: Vec<_> = fs::read_dir(&migration_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .collect();

        assert!(
            !recipe_files.is_empty(),
            "Should have migration recipe file"
        );
        let recipe_content = fs::read_to_string(&recipe_files[0]).unwrap();
        let recipe: TestDeploymentRecipe = serde_json::from_str(&recipe_content).unwrap();

        let dep_group_recipe = &recipe.dep_group_recipes[0];
        assert!(
            dep_group_recipe.type_id.is_some(),
            "Recipe should contain type_id when enabled"
        );

        // Verify TypeID calculation matches the script hash
        let type_id_hash: H256 = dep_group_recipe.type_id.clone().unwrap();
        let code_hash_str = type_script["code_hash"].as_str().unwrap();
        let hash_type_str = type_script["hash_type"].as_str().unwrap();
        let args_str = type_script["args"].as_str().unwrap();

        let code_hash: H256 = serde_json::from_str(&format!("\"{}\"", code_hash_str)).unwrap();
        let args: JsonBytes = serde_json::from_str(&format!("\"{}\"", args_str)).unwrap();
        let json_hash_type: JsonScriptHashType =
            serde_json::from_str(&format!("\"{}\"", hash_type_str)).unwrap();
        let sht: ScriptHashType = json_hash_type.into();
        let script = packed::Script::new_builder()
            .code_hash(code_hash.pack())
            .hash_type(packed::Byte::new(sht.into()))
            .args(args.into_bytes().pack())
            .build();
        let expected_type_script_hash: H256 = script.calc_script_hash().unpack();
        assert_eq!(
            type_id_hash, expected_type_script_hash,
            "TypeID should match script hash"
        );
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
        let deployment_config = format!(
            r#"
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
"#,
            temp_dir.path().display(),
            "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
            "c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7"
        );

        // Write a valid contract binary (v1)
        fs::write(temp_dir.path().join("test_cell.bin"), ACP_BIN).unwrap();
        let config_path = temp_dir.path().join("deployment.toml");
        fs::write(&config_path, &deployment_config).unwrap();

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
        let (output1, _stderr) = setup.cli_command(
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
        let apply_result1: TestDeploymentResult = serde_json::from_str(&output1).unwrap();
        let dep_group_tx_hash1 = format!("{:#x}", apply_result1.dep_group_tx);
        setup
            .miner()
            .mine_until_transaction_confirm(&dep_group_tx_hash1);

        // Get TypeID from first deployment
        let (tx_output1, _stderr) = setup.cli_command(
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
        let cell_meta1: serde_json::Value = serde_json::from_str(&tx_output1).unwrap();
        let type_script1 = &cell_meta1["output"]["type"];
        let code_hash_str = type_script1["code_hash"].as_str().unwrap();
        let hash_type_str = type_script1["hash_type"].as_str().unwrap();
        let args_str = type_script1["args"].as_str().unwrap();
        let code_hash: H256 = serde_json::from_str(&format!("\"{}\"", code_hash_str)).unwrap();
        let args: JsonBytes = serde_json::from_str(&format!("\"{}\"", args_str)).unwrap();
        let json_hash_type: JsonScriptHashType =
            serde_json::from_str(&format!("\"{}\"", hash_type_str)).unwrap();
        let sht: ScriptHashType = json_hash_type.into();
        let script1 = packed::Script::new_builder()
            .code_hash(code_hash.pack())
            .hash_type(packed::Byte::new(sht.into()))
            .args(args.into_bytes().pack())
            .build();
        let original_type_id = format!("0x{:x}", script1.calc_script_hash());

        setup.miner().generate_blocks(8);

        // Update the cell (force redeploy) with a different valid binary (v2)
        fs::write(temp_dir.path().join("test_cell.bin"), CHEQUE_BIN).unwrap();

        // Second deployment (should preserve TypeID)

        let info_file = temp_dir.path().join("deployment_info2.json");

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
        let (output2, _stderr) = setup.cli_command(
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
        // Deserialize apply-txs result into TestDeploymentResult (output is valid JSON)
        let apply_result2: TestDeploymentResult = serde_json::from_str(&output2).unwrap();
        let dep_group_tx_hash2 = format!("{:#x}", apply_result2.dep_group_tx);
        // Verify TypeID is preserved using latest recipe's type_id
        let latest_recipe = {
            let recipe_files: Vec<_> = fs::read_dir(&migration_dir)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
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
        assert_eq!(
            original_type_id, preserved_type_id,
            "TypeID should be preserved across updates"
        );
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
        let deployment_config_v1 = format!(
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
        let (output1, _stderr) = setup.cli_command(
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
        let apply_result1: TestDeploymentResult = serde_json::from_str(&output1).unwrap();
        let dep_group_tx_hash1 = format!("{:#x}", apply_result1.dep_group_tx);
        setup
            .miner()
            .mine_until_transaction_confirm(&dep_group_tx_hash1);

        // Verify no TypeID initially
        let (tx_output1, _stderr) = setup.cli_command(
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
        let cell_meta1: serde_json::Value = serde_json::from_str(&tx_output1).unwrap();
        assert!(
            cell_meta1["output"]["type"].is_null(),
            "Should not have TypeID initially"
        );
        // Give the node a moment and advance blocks to avoid race with indexer/live cell queries
        setup.miner().generate_blocks(6);

        // Update config to enable TypeID
        let deployment_config_v2 = format!(
            r#"
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
"#,
            temp_dir.path().display(),
            "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
            "c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7"
        );

        fs::write(&config_path, deployment_config_v2).unwrap();

        // Second deployment (with TypeID enabled)
        let info_file = temp_dir.path().join("deployment_info2.json");
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
        let (output2, _stderr) = setup.cli_command(
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
        // Deserialize apply-txs result into TestDeploymentResult (output is valid JSON)
        let apply_result2: TestDeploymentResult = serde_json::from_str(&output2).unwrap();
        let dep_group_tx_hash2 = format!("{:#x}", apply_result2.dep_group_tx);
        // Verify recipe contains new type_id (avoid relying on on-chain query)
        let recipe_files: Vec<_> = fs::read_dir(&migration_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
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
