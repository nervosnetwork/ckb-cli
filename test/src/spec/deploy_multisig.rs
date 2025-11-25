use crate::miner::Miner;
use crate::setup::Setup;
use crate::spec::wallet::{ACCOUNT1_ADDRESS, ACCOUNT1_PRIVKEY, ACCOUNT2_ADDRESS, ACCOUNT2_PRIVKEY};
use crate::spec::Spec;
use ckb_jsonrpc_types::{ScriptHashType as JsonScriptHashType, Status};
use ckb_sdk::{constants::MultisigScript, unlock::MultisigConfig, Address, CkbRpcClient};
use ckb_system_scripts_v0_6_0::BUNDLED_CELL;
use ckb_types::{packed, prelude::*, H160, H256};
use faster_hex::hex_string;
use serde_yaml::Value as YamlValue;
use std::{env, fs, path::Path, str::FromStr, thread, time::Duration};
use tempfile::tempdir;

const ALWAYS_SUCCESS_BAK_BIN: &[u8] = include_bytes!("../script-bins/bak-always-success");
const ALWAYS_SUCCESS_BIN: &[u8] = include_bytes!("../script-bins/always-success");

pub struct DeployMultisigV2Upgrade;

impl Spec for DeployMultisigV2Upgrade {
    fn run(&self, setup: &mut Setup) {
        let temp_dir = tempdir().expect("create tempdir failed");
        let config_path = temp_dir.path().join("deployment.toml");
        let initial_info = temp_dir.path().join("deploy-info.json");
        let updated_info = temp_dir.path().join("update-info.json");
        let migration_dir = temp_dir.path().join("migrations");
        fs::create_dir_all(&migration_dir).unwrap();
        setup.miner().generate_blocks(30);

        let multisig_dep_group_tx = deploy_multisig_v2(setup, temp_dir.path());
        let _multisig_env_guard = EnvVarGuard::set(
            "MULTISIG_V2_DEP_GROUP",
            format!("{},0", multisig_dep_group_tx),
        );

        // Prepare privkey files for multisig participants
        let account1_key = temp_dir.path().join("account1.key");
        let account2_key = temp_dir.path().join("account2.key");
        fs::write(&account1_key, ACCOUNT1_PRIVKEY).unwrap();
        fs::write(&account2_key, ACCOUNT2_PRIVKEY).unwrap();

        // Fund the first multisig participant so we can pay deployment fees
        let miner_privkey = setup.miner().privkey_path().to_string();
        // Miner -> account1 large funding
        transfer_and_confirm(
            setup,
            &format!(
                "wallet transfer --privkey-path {} --to-address {} --capacity 100000 --fee-rate 1000",
                miner_privkey, ACCOUNT1_ADDRESS
            ),
        );
        // Miner -> account2 small funding for signing fees
        transfer_and_confirm(
            setup,
            &format!(
                "wallet transfer --privkey-path {} --to-address {} --capacity 1000 --fee-rate 1000",
                miner_privkey, ACCOUNT2_ADDRESS
            ),
        );

        let multisig_script = MultisigScript::V2;
        let sighash_lock_args = vec![
            parse_sighash_lock_arg(ACCOUNT1_ADDRESS),
            parse_sighash_lock_arg(ACCOUNT2_ADDRESS),
        ];
        let multisig_config =
            MultisigConfig::new_with(multisig_script, sighash_lock_args, 0, 2).unwrap();
        let lock_args = format!("{:#x}", multisig_config.hash160());
        let lock_code_hash = format!("{:#x}", multisig_config.lock_code_hash());
        let lock_hash_type = script_hash_type_to_str(multisig_config.lock_hash_type());

        // Initial version of the deployed binary (bak)
        let cell_path_v1 = temp_dir.path().join("multisig-cell-bak.bin");
        let cell_path_v2 = temp_dir.path().join("multisig-cell.bin");
        fs::write(&cell_path_v1, ALWAYS_SUCCESS_BAK_BIN).unwrap();

        let deployment_config_v1 = format!(
            r#"
[[cells]]
name = "bak-always-success"
enable_type_id = false
location = {{ file = "{cell_path}" }}

[lock]
code_hash = "{code_hash}"
args = "{lock_args}"
hash_type = "{hash_type}"

[multisig_config]
lock_code_hash = "{code_hash}"
sighash_addresses = ["{addr1}", "{addr2}"]
            require_first_n = 0
            threshold = 2
"#,
            cell_path = cell_path_v1.display(),
            code_hash = lock_code_hash,
            hash_type = lock_hash_type,
            addr1 = ACCOUNT1_ADDRESS,
            addr2 = ACCOUNT2_ADDRESS,
        );
        fs::write(&config_path, &deployment_config_v1).unwrap();
        println!("deployment.toml (v1):\n{}", deployment_config_v1);

        // === First deployment ===
        setup.cli(&format!(
            "deploy gen-txs --deployment-config {} --info-file {} --migration-dir {} --from-address {} --fee-rate 1000",
            config_path.display(),
            initial_info.display(),
            migration_dir.display(),
            ACCOUNT1_ADDRESS,
        ));
        setup.cli(&format!(
            "deploy sign-txs --info-file {} --privkey-path {} --add-signatures",
            initial_info.display(),
            account1_key.display(),
        ));

        let (first_stdout, _first_stderr) = setup.cli_command(
            &[
                "--output-format",
                "json",
                "deploy",
                "apply-txs",
                "--info-file",
                &initial_info.display().to_string(),
                "--migration-dir",
                &migration_dir.display().to_string(),
            ],
            &[],
        );
        let first_apply: serde_json::Value = serde_json::from_str(&first_stdout).unwrap();
        let first_cell_tx = first_apply["cell_tx"]
            .as_str()
            .expect("cell transaction hash should exist")
            .to_string();
        setup.miner().mine_until_transaction_confirm(&first_cell_tx);

        // The updated binary is larger, so add extra capacity before building the upgrade.
        transfer_and_confirm(
            setup,
            &format!(
                "wallet transfer --privkey-path {} --to-address {} --capacity 40000 --fee-rate 1000",
                miner_privkey, ACCOUNT1_ADDRESS
            ),
        );

        // === Prepare update that consumes the multisig output ===
        fs::write(&cell_path_v2, ALWAYS_SUCCESS_BIN).unwrap();
        let deployment_config_v2 = format!(
            r#"
[[cells]]
name = "always-success"
enable_type_id = false
location = {{ file = "{cell_path}" }}

[lock]
code_hash = "{code_hash}"
args = "{lock_args}"
hash_type = "{hash_type}"

[multisig_config]
lock_code_hash = "{code_hash}"
sighash_addresses = ["{addr1}", "{addr2}"]
require_first_n = 0
threshold = 2
"#,
            cell_path = cell_path_v2.display(),
            code_hash = lock_code_hash,
            hash_type = lock_hash_type,
            addr1 = ACCOUNT1_ADDRESS,
            addr2 = ACCOUNT2_ADDRESS,
        );
        fs::write(&config_path, &deployment_config_v2).unwrap();
        println!("deployment.toml (v2):\n{}", deployment_config_v2);
        setup.cli(&format!(
            "deploy gen-txs --deployment-config {} --info-file {} --migration-dir {} --from-address {} --fee-rate 1000",
            config_path.display(),
            updated_info.display(),
            migration_dir.display(),
            ACCOUNT1_ADDRESS,
        ));

        // Signatures from both multisig participants are required
        for key_path in [&account1_key, &account2_key] {
            setup.cli(&format!(
                "deploy sign-txs --info-file {} --privkey-path {} --add-signatures",
                updated_info.display(),
                key_path.display(),
            ));
        }

        // Applying the update should succeed, but currently fails due to not accounting for larger multisig witnesses
        let (update_stdout, update_stderr) = setup.cli_command(
            &[
                "--output-format",
                "json",
                "deploy",
                "apply-txs",
                "--info-file",
                &updated_info.display().to_string(),
                "--migration-dir",
                &migration_dir.display().to_string(),
            ],
            &[],
        );
        assert!(
            !update_stderr.contains("PoolRejectedTransactionByMinFeeRate"),
            "deploy apply-txs unexpectedly failed with min fee rejection.\nstdout: {}\nstderr: {}",
            update_stdout,
            update_stderr
        );
        let update_apply: serde_json::Value = serde_json::from_str(&update_stdout).unwrap();
        let update_cell_tx = update_apply["cell_tx"]
            .as_str()
            .expect("cell transaction hash should exist after the fix")
            .to_string();
        setup
            .miner()
            .mine_until_transaction_confirm(&update_cell_tx);
    }

    fn spec_name(&self) -> &'static str {
        "DeployMultisigV2Upgrade"
    }
}

pub struct DeployMultisigV2UpgradeTestnet;

impl Spec for DeployMultisigV2UpgradeTestnet {
    fn run(&self, setup: &mut Setup) {
        let chain = current_chain(setup);
        assert_eq!(
            chain, "ckb_testnet",
            "DeployMultisigV2UpgradeTestnet should run against testnet"
        );

        let temp_dir = tempdir().expect("create tempdir failed");
        let config_path = temp_dir.path().join("deployment.toml");
        let initial_info = temp_dir.path().join("deploy-info.json");
        let updated_info = temp_dir.path().join("update-info.json");
        let migration_dir = temp_dir.path().join("migrations");
        fs::create_dir_all(&migration_dir).unwrap();

        let account1_key = temp_dir.path().join("account1.key");
        let account2_key = temp_dir.path().join("account2.key");
        fs::write(&account1_key, ACCOUNT1_PRIVKEY).unwrap();
        fs::write(&account2_key, ACCOUNT2_PRIVKEY).unwrap();

        let multisig_script = MultisigScript::V2;
        let sighash_lock_args = vec![
            parse_sighash_lock_arg(ACCOUNT1_ADDRESS),
            parse_sighash_lock_arg(ACCOUNT2_ADDRESS),
        ];
        let multisig_config =
            MultisigConfig::new_with(multisig_script, sighash_lock_args, 0, 2).unwrap();
        let lock_args = format!("{:#x}", multisig_config.hash160());
        let lock_code_hash = format!("{:#x}", multisig_config.lock_code_hash());
        let lock_hash_type = script_hash_type_to_str(multisig_config.lock_hash_type());

        let cell_path_v1 = temp_dir.path().join("always-success-bak.bin");
        let cell_path_v2 = temp_dir.path().join("always-success.bin");
        fs::write(&cell_path_v1, ALWAYS_SUCCESS_BAK_BIN).unwrap();

        let deployment_config_v1 = format!(
            r#"
[[cells]]
name = "bak-always-success"
enable_type_id = false
location = {{ file = "{cell_path}" }}

[lock]
code_hash = "{code_hash}"
args = "{lock_args}"
hash_type = "{hash_type}"

[multisig_config]
lock_code_hash = "{code_hash}"
sighash_addresses = ["{addr1}", "{addr2}"]
require_first_n = 0
threshold = 2
"#,
            cell_path = cell_path_v1.display(),
            code_hash = lock_code_hash,
            hash_type = lock_hash_type,
            addr1 = ACCOUNT1_ADDRESS,
            addr2 = ACCOUNT2_ADDRESS,
        );
        fs::write(&config_path, &deployment_config_v1).unwrap();
        println!("deployment.toml (v1):\n{}", deployment_config_v1);

        setup.cli(&format!(
            "deploy gen-txs --deployment-config {} --info-file {} --migration-dir {} --from-address {} --fee-rate 1000",
            config_path.display(),
            initial_info.display(),
            migration_dir.display(),
            ACCOUNT1_ADDRESS,
        ));
        setup.cli(&format!(
            "deploy sign-txs --info-file {} --privkey-path {} --add-signatures",
            initial_info.display(),
            account1_key.display(),
        ));

        let (first_stdout, _) = setup.cli_command(
            &[
                "--output-format",
                "json",
                "deploy",
                "apply-txs",
                "--info-file",
                &initial_info.display().to_string(),
                "--migration-dir",
                &migration_dir.display().to_string(),
            ],
            &[],
        );
        let first_apply: serde_json::Value = serde_json::from_str(&first_stdout).unwrap();
        let first_cell_tx = first_apply["cell_tx"]
            .as_str()
            .expect("cell transaction hash should exist")
            .to_string();
        wait_for_tx_committed(setup, &first_cell_tx);

        fs::write(&cell_path_v2, ALWAYS_SUCCESS_BIN).unwrap();
        let deployment_config_v2 = format!(
            r#"
[[cells]]
name = "always-success"
enable_type_id = false
location = {{ file = "{cell_path}" }}

[lock]
code_hash = "{code_hash}"
args = "{lock_args}"
hash_type = "{hash_type}"

[multisig_config]
lock_code_hash = "{code_hash}"
sighash_addresses = ["{addr1}", "{addr2}"]
require_first_n = 0
threshold = 2
"#,
            cell_path = cell_path_v2.display(),
            code_hash = lock_code_hash,
            hash_type = lock_hash_type,
            addr1 = ACCOUNT1_ADDRESS,
            addr2 = ACCOUNT2_ADDRESS,
        );
        fs::write(&config_path, &deployment_config_v2).unwrap();
        println!("deployment.toml (v2):\n{}", deployment_config_v2);

        setup.cli(&format!(
            "deploy gen-txs --deployment-config {} --info-file {} --migration-dir {} --from-address {} --fee-rate 1000",
            config_path.display(),
            updated_info.display(),
            migration_dir.display(),
            ACCOUNT1_ADDRESS,
        ));
        for key_path in [&account1_key, &account2_key] {
            setup.cli(&format!(
                "deploy sign-txs --info-file {} --privkey-path {} --add-signatures",
                updated_info.display(),
                key_path.display(),
            ));
        }

        let (update_stdout, update_stderr) = setup.cli_command(
            &[
                "--output-format",
                "json",
                "deploy",
                "apply-txs",
                "--info-file",
                &updated_info.display().to_string(),
                "--migration-dir",
                &migration_dir.display().to_string(),
            ],
            &[],
        );
        assert!(
            !update_stderr.contains("PoolRejectedTransactionByMinFeeRate"),
            "deploy apply-txs unexpectedly failed with min fee rejection.\nstdout: {}\nstderr: {}",
            update_stdout,
            update_stderr
        );
        let update_apply: serde_json::Value = serde_json::from_str(&update_stdout).unwrap();
        let update_cell_tx = update_apply["cell_tx"]
            .as_str()
            .expect("cell transaction hash should exist after the fix")
            .to_string();
        wait_for_tx_committed(setup, &update_cell_tx);
    }

    fn spec_name(&self) -> &'static str {
        "DeployMultisigV2UpgradeTestnet"
    }

    fn rpc_override(&self) -> Option<String> {
        Some(
            env::var("CKB_TESTNET_RPC_URL")
                .unwrap_or_else(|_| "https://testnet.ckb.dev".to_string()),
        )
    }
}

fn parse_sighash_lock_arg(address: &str) -> H160 {
    let addr = Address::from_str(address).expect("parse sighash address");
    H160::from_slice(addr.payload().args().as_ref()).expect("extract hash160")
}

fn script_hash_type_to_str(hash_type: JsonScriptHashType) -> String {
    hash_type.to_string()
}

fn transfer_and_confirm(setup: &mut Setup, command: &str) {
    let tx_hash = setup.cli(command).trim().to_string();
    setup.miner().mine_until_transaction_confirm(&tx_hash);
}

fn deploy_multisig_v2(setup: &mut Setup, work_dir: &Path) -> String {
    let multisig_file = BUNDLED_CELL
        .get("specs/cells/secp256k1_blake160_multisig_all")
        .expect("multisig v2 bundled cell");
    let script_bytes = multisig_file.as_ref();
    let script_path = work_dir.join("multisig-v2");
    fs::write(&script_path, script_bytes).expect("write multisig v2 binary");

    let miner_privkey = setup.miner().privkey_path().to_string();
    let miner_address = Miner::address();

    let capacity_ckb = (script_bytes.len() as u64) + 500;
    let code_cell_tx = setup
        .cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --to-data-path {} --capacity {}",
            miner_privkey,
            miner_address,
            script_path.display(),
            capacity_ckb,
        ))
        .trim()
        .to_string();
    setup.miner().mine_until_transaction_confirm(&code_cell_tx);

    let secp_out_point = load_secp_data_out_point(setup);
    let script_out_point = packed::OutPoint::new_builder()
        .tx_hash(parse_h256(&code_cell_tx).pack())
        .index(0u32)
        .build();
    let out_point_vec: packed::OutPointVec = vec![secp_out_point, script_out_point].pack();
    let data_hex = hex_string(out_point_vec.as_slice());

    let dep_group_tx = setup
        .cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --to-data {} --capacity {}",
            miner_privkey, miner_address, data_hex, 320,
        ))
        .trim()
        .to_string();
    setup.miner().mine_until_transaction_confirm(&dep_group_tx);
    dep_group_tx
}

fn load_secp_data_out_point(setup: &Setup) -> packed::OutPoint {
    let output = setup.cli("util genesis-scripts");
    let value: YamlValue = serde_yaml::from_str(&output).expect("parse genesis-scripts");
    let out_point_value = &value["secp256k1_data"]["out_point"];
    let tx_hash = out_point_value["tx_hash"].as_str().expect("tx_hash field");
    let index = out_point_value["index"].as_u64().expect("index field") as u32;
    packed::OutPoint::new_builder()
        .tx_hash(parse_h256(tx_hash).pack())
        .index(index)
        .build()
}

fn parse_h256(input: &str) -> H256 {
    H256::from_str(input.trim().trim_start_matches("0x")).expect("valid h256")
}

fn wait_for_tx_committed(setup: &Setup, tx_hash: &str) {
    let client = CkbRpcClient::new(&setup.rpc_url());
    let hash = parse_h256(tx_hash);
    let mut attempts = 0u64;
    loop {
        let status = client
            .get_transaction_status(hash.clone())
            .expect("rpc get_transaction_status")
            .tx_status
            .status;
        match status {
            Status::Committed => break,
            Status::Rejected => panic!("transaction {} rejected on chain", tx_hash),
            _ => {
                attempts += 1;
                assert!(
                    attempts < 300,
                    "transaction {} not committed within timeout",
                    tx_hash
                );
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

fn current_chain(setup: &Setup) -> String {
    let client = CkbRpcClient::new(&setup.rpc_url());
    client
        .get_blockchain_info()
        .expect("rpc get_blockchain_info")
        .chain
}

struct EnvVarGuard {
    key: &'static str,
    original: Option<String>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: String) -> EnvVarGuard {
        let original = env::var(key).ok();
        env::set_var(key, value);
        EnvVarGuard { key, original }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(ref value) = self.original {
            env::set_var(self.key, value);
        } else {
            env::remove_var(self.key);
        }
    }
}
