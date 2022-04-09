use std::fs;
use std::str::FromStr;

use tempfile::tempdir;

use ckb_chain_spec::ChainSpec;
use ckb_types::{
    packed::{OutPoint, OutPointVec},
    prelude::*,
    H256,
};

use crate::miner::Miner;
use crate::setup::Setup;
use crate::spec::Spec;

const EPOCH_LENGTH: u64 = 32;
const LOCK_PERIOD_EPOCHES: u64 = 6;

const SUDT_BIN: &[u8] = include_bytes!("../script-bins/simple_udt");
const ACP_BIN: &[u8] = include_bytes!("../script-bins/anyone_can_pay");
const CHEQUE_BIN: &[u8] = include_bytes!("../script-bins/ckb-cheque-script");

const OWNER_KEY: &str = "8fdf1d6df54c6c9c0167a657c0f68a9bb3bf4304942ce487880e86ce6099191c";
const OWNER_ADDR: &str = "ckt1qyq86vaa6e8tsruv5ngcd5tp7lcvcewxy7cquuksvj";
const ACCOUNT1_KEY: &str = "dbb62c0f0dd23088dba5ade3b4ed2279f733780de1985d344bf398c1c757ef49";
const ACCOUNT1_ADDR: &str = "ckt1qyqfjslcvyaay029vvfxtn80rxnwmlma43xscrqn85";
const ACCOUNT2_KEY: &str = "5f9eceb1af9fe48b97e2df350450d7416887ccca62f537733f1377ee9efb8906";
const ACCOUNT2_ADDR: &str = "ckt1qyq9qaekmruccau7u3eff4wsv8v74gxmlptqj2lcte";

pub struct SudtIssueToCheque;

impl Spec for SudtIssueToCheque {
    fn run(&self, setup: &mut Setup) {
        let tempdir = tempdir().expect("create tempdir failed");
        let path = tempdir.path().to_str().unwrap();
        let owner_key_path = format!("{}/owner", path);
        let account1_key_path = format!("{}/account1", path);
        let account2_key_path = format!("{}/account2", path);
        let cell_deps_path = format!("{}/cell_deps.json", path);
        prepare(setup, path);

        let output = setup.cli(&format!(
            "sudt issue --owner {} --udt-to {}:2000 --to-cheque-address --cell-deps {} --privkey-path {}",
            OWNER_ADDR, ACCOUNT1_ADDR, cell_deps_path, owner_key_path
        ));
        log::info!("Issue 2000 SUDT to a cheque address which the sender is the sudt owner and the receiver is account 1:\n{}", output);
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        let cheque_addr = value["receivers"][0]["address"]
            .as_str()
            .unwrap()
            .to_string();
        setup.miner().generate_blocks(3);

        check_amount(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            cheque_addr.as_str(),
            2000,
        );

        let account1_acp_addr = create_acp_cell(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            ACCOUNT1_ADDR,
            account1_key_path.as_str(),
        );

        let output = setup.cli(&format!(
            "sudt cheque-claim --owner {} --sender {} --receiver {} --cell-deps {} --privkey-path {}",
            OWNER_ADDR,
            OWNER_ADDR,
            ACCOUNT1_ADDR,
            cell_deps_path,
            account1_key_path,
        ));
        log::info!(
            "Claim the SUDT to the new created anyone-can-pay-cell:\n{}",
            output
        );
        setup.miner().generate_blocks(3);

        check_amount(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            account1_acp_addr.as_str(),
            2000,
        );

        let account2_acp_addr = create_acp_cell(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            ACCOUNT2_ADDR,
            account2_key_path.as_str(),
        );

        let output = setup.cli(&format!(
            "sudt transfer --owner {} --sender {} --udt-to {}:600 --to-acp-address --cell-deps {} --capacity-provider {} --privkey-path {} --privkey-path {}",
            OWNER_ADDR,
            account1_acp_addr,
            account2_acp_addr,
            cell_deps_path,
            ACCOUNT2_ADDR,
            account1_key_path,
            account2_key_path,
        ));
        log::info!(
            "Transfer a part of the claimd SUDT to new cell:\n{}",
            output
        );
        setup.miner().generate_blocks(3);

        check_amount(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            account1_acp_addr.as_str(),
            1400,
        );
        check_amount(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            account2_acp_addr.as_str(),
            600,
        );
    }

    fn modify_spec_toml(&self, spec_toml: &mut ChainSpec) {
        spec_toml.params.genesis_epoch_length = Some(EPOCH_LENGTH);
        spec_toml.params.permanent_difficulty_in_dummy = Some(true);
    }
}

pub struct SudtIssueToAcp;

impl Spec for SudtIssueToAcp {
    fn run(&self, setup: &mut Setup) {
        let tempdir = tempdir().expect("create tempdir failed");
        let path = tempdir.path().to_str().unwrap();
        let owner_key_path = format!("{}/owner", path);
        let account1_key_path = format!("{}/account1", path);
        let cell_deps_path = format!("{}/cell_deps.json", path);
        prepare(setup, path);

        let account1_acp_addr = create_acp_cell(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            ACCOUNT1_ADDR,
            account1_key_path.as_str(),
        );
        check_amount(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            account1_acp_addr.as_str(),
            0,
        );
        let output = setup.cli(&format!(
            "sudt issue --owner {} --udt-to {}:300 --to-acp-address --cell-deps {} --privkey-path {}",
            OWNER_ADDR,
            account1_acp_addr,
            cell_deps_path,
            owner_key_path,
        ));
        log::info!(
            "Issue 300 SUDT to account 1's anyone-can-pay address:\n{}",
            output
        );
        setup.miner().generate_blocks(3);
        check_amount(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            account1_acp_addr.as_str(),
            300,
        );
    }

    fn modify_spec_toml(&self, spec_toml: &mut ChainSpec) {
        spec_toml.params.genesis_epoch_length = Some(EPOCH_LENGTH);
        spec_toml.params.permanent_difficulty_in_dummy = Some(true);
    }
}

pub struct SudtTransferToChequeForClaim;

impl Spec for SudtTransferToChequeForClaim {
    fn run(&self, setup: &mut Setup) {
        let tempdir = tempdir().expect("create tempdir failed");
        let path = tempdir.path().to_str().unwrap();
        let owner_key_path = format!("{}/owner", path);
        let account1_key_path = format!("{}/account1", path);
        let account2_key_path = format!("{}/account2", path);
        let cell_deps_path = format!("{}/cell_deps.json", path);
        prepare(setup, path);

        let account1_acp_addr = create_acp_cell(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            ACCOUNT1_ADDR,
            account1_key_path.as_str(),
        );
        let account2_acp_addr = create_acp_cell(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            ACCOUNT2_ADDR,
            account2_key_path.as_str(),
        );

        let output = setup.cli(&format!(
            "sudt issue --owner {} --udt-to {}:1100 --to-acp-address --cell-deps {} --privkey-path {}",
            OWNER_ADDR,
            account1_acp_addr,
            cell_deps_path,
            owner_key_path,
        ));
        log::info!(
            "Issue 1100 SUDT to account 1's anyone-can-pay address:\n{}",
            output
        );
        setup.miner().generate_blocks(3);

        check_amount(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            account1_acp_addr.as_str(),
            1100,
        );

        let output = setup.cli(&format!(
            "sudt transfer --owner {} --sender {} --udt-to {}:500 --to-cheque-address --cell-deps {} --privkey-path {}",
            OWNER_ADDR,
            account1_acp_addr,
            ACCOUNT2_ADDR,
            cell_deps_path,
            account1_key_path,
        ));
        log::info!("Transfer 500 SUDT from account 1 anyone-can-pay address to account 2 cheque address:\n{}", output);
        setup.miner().generate_blocks(3);

        check_amount(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            account1_acp_addr.as_str(),
            600,
        );
        check_amount(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            account2_acp_addr.as_str(),
            0,
        );

        let output = setup.cli(&format!(
            "sudt cheque-claim --owner {} --sender {} --receiver {} --cell-deps {} --privkey-path {}",
            OWNER_ADDR,
            ACCOUNT1_ADDR,
            ACCOUNT2_ADDR,
            cell_deps_path,
            account2_key_path,
        ));
        log::info!("Claim the SUDT to account 2:\n{}", output);
        setup.miner().generate_blocks(3);

        check_amount(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            account1_acp_addr.as_str(),
            600,
        );
        check_amount(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            account2_acp_addr.as_str(),
            500,
        );
    }

    fn modify_spec_toml(&self, spec_toml: &mut ChainSpec) {
        spec_toml.params.genesis_epoch_length = Some(EPOCH_LENGTH);
        spec_toml.params.permanent_difficulty_in_dummy = Some(true);
    }
}

pub struct SudtTransferToChequeForWithdraw;

impl Spec for SudtTransferToChequeForWithdraw {
    fn run(&self, setup: &mut Setup) {
        let tempdir = tempdir().expect("create tempdir failed");
        let path = tempdir.path().to_str().unwrap();
        let owner_key_path = format!("{}/owner", path);
        let account1_key_path = format!("{}/account1", path);
        let cell_deps_path = format!("{}/cell_deps.json", path);
        prepare(setup, path);

        let account1_acp_addr = create_acp_cell(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            ACCOUNT1_ADDR,
            account1_key_path.as_str(),
        );
        let output = setup.cli(&format!(
            "sudt issue --owner {} --udt-to {}:1100 --to-acp-address --cell-deps {} --privkey-path {}",
            OWNER_ADDR,
            account1_acp_addr,
            cell_deps_path,
            owner_key_path,
        ));
        log::info!(
            "Issue 1100 SUDT to account 1's anyone-can-pay address:\n{}",
            output
        );
        setup.miner().generate_blocks(3);

        check_amount(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            account1_acp_addr.as_str(),
            1100,
        );

        let output = setup.cli(&format!(
            "sudt transfer --owner {} --sender {} --udt-to {}:500 --to-cheque-address --cell-deps {} --privkey-path {}",
            OWNER_ADDR,
            account1_acp_addr,
            ACCOUNT2_ADDR,
            cell_deps_path,
            account1_key_path,
        ));
        log::info!("Transfer 500 SUDT from account 1 anyone-can-pay address to account 2 cheque address:\n{}", output);
        setup.miner().generate_blocks(3);

        check_amount(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            account1_acp_addr.as_str(),
            600,
        );

        let output = setup.cli(&format!(
            "sudt cheque-withdraw --owner {} --sender {} --receiver {} --to-acp-address --cell-deps {} --privkey-path {}",
            OWNER_ADDR,
            ACCOUNT1_ADDR,
            ACCOUNT2_ADDR,
            cell_deps_path,
            account1_key_path,
        ));
        assert!(output.contains("the transaction is immature because of the since requirement"));

        setup
            .miner()
            .generate_blocks(EPOCH_LENGTH * LOCK_PERIOD_EPOCHES);
        let output = setup.cli(&format!(
            "sudt cheque-withdraw --owner {} --sender {} --receiver {} --to-acp-address --cell-deps {} --privkey-path {}",
            OWNER_ADDR,
            ACCOUNT1_ADDR,
            ACCOUNT2_ADDR,
            cell_deps_path,
            account1_key_path,
        ));
        log::info!("Withdraw the SUDT amount:\n{}", output);
        setup.miner().generate_blocks(3);

        check_amount(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            account1_acp_addr.as_str(),
            1100,
        );
    }
    fn modify_spec_toml(&self, spec_toml: &mut ChainSpec) {
        spec_toml.params.genesis_epoch_length = Some(EPOCH_LENGTH);
        spec_toml.params.permanent_difficulty_in_dummy = Some(true);
    }
}

fn prepare(setup: &mut Setup, tmp_path: &str) {
    let owner_key = format!("{}/owner", tmp_path);
    let account1_key = format!("{}/account1", tmp_path);
    let account2_key = format!("{}/account2", tmp_path);
    fs::write(&owner_key, OWNER_KEY).unwrap();
    fs::write(&account1_key, ACCOUNT1_KEY).unwrap();
    fs::write(&account2_key, ACCOUNT2_KEY).unwrap();

    let sudt_bin = format!("{}/sudt", tmp_path);
    let acp_bin = format!("{}/acp", tmp_path);
    let cheque_bin = format!("{}/cheque", tmp_path);
    fs::write(&sudt_bin, SUDT_BIN).unwrap();
    fs::write(&acp_bin, ACP_BIN).unwrap();
    fs::write(&cheque_bin, CHEQUE_BIN).unwrap();

    let miner_privkey = setup.miner().privkey_path().to_string();
    let miner_address = Miner::address();

    setup.miner().generate_blocks(30);

    // Deploy script binaries
    let mut tx_hashes = Vec::with_capacity(3);
    for (size, bin_path) in [
        (SUDT_BIN.len(), sudt_bin),
        (ACP_BIN.len(), acp_bin),
        (CHEQUE_BIN.len(), cheque_bin),
    ] {
        let capacity_ckb = size + 200;
        let tx_hash = setup.cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --to-data-path {} --capacity {} --type-id",
            miner_privkey,
            miner_address,
            bin_path,
            capacity_ckb,
        ));
        log::info!("deploy script binary {}, tx_hash: {}", bin_path, tx_hash);
        setup.miner().generate_blocks(3);
        let code_hash = {
            let output = setup.cli(&format!("util cell-meta --tx-hash {} --index 0", tx_hash));
            let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
            value["type_hash"].as_str().unwrap().to_string()
        };
        tx_hashes.push((tx_hash, code_hash));
    }

    let secp_data_out_point = {
        let output = setup.cli("util genesis-scripts");
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        let out_point_value = &value["secp256k1_data"]["out_point"];
        let tx_hash = H256::from_str(&out_point_value["tx_hash"].as_str().unwrap()[2..]).unwrap();
        let index = out_point_value["index"].as_u64().unwrap() as u32;
        OutPoint::new_builder()
            .tx_hash(tx_hash.pack())
            .index(index.pack())
            .build()
    };

    // Deploy dep group
    let mut dep_group_tx_hashes = Vec::with_capacity(2);
    for (tx_hash, _) in &tx_hashes[1..] {
        let script_out_point = OutPoint::new_builder()
            .tx_hash(H256::from_str(&tx_hash[2..]).unwrap().pack())
            .index(0u32.pack())
            .build();
        let out_point_vec: OutPointVec = vec![secp_data_out_point.clone(), script_out_point].pack();
        let data_hex = faster_hex::hex_string(out_point_vec.as_slice());
        let dep_group_tx_hash = setup.cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --to-data {} --capacity {}",
            miner_privkey, miner_address, data_hex, 320,
        ));
        log::info!(
            "deploy dep group for {}, tx_hash: {}",
            tx_hash,
            dep_group_tx_hash
        );
        setup.miner().generate_blocks(3);
        dep_group_tx_hashes.push(dep_group_tx_hash);
    }

    // Build cell_deps.json
    let cell_deps = serde_json::json!({
        "items": {
            "sudt": {
                "script_id": {
                    "hash_type": "type",
                    "code_hash": tx_hashes[0].1,
                },
                "cell_dep": {
                    "out_point": {
                        "tx_hash": tx_hashes[0].0,
                        "index": "0x0"
                    },
                    "dep_type": "code"
                }
            },
            "acp": {
                "script_id": {
                    "hash_type": "type",
                    "code_hash": tx_hashes[1].1,
                },
                "cell_dep": {
                    "out_point": {
                        "tx_hash": dep_group_tx_hashes[0],
                        "index": "0x0"
                    },
                    "dep_type": "dep_group"
                }
            },
            "cheque": {
                "script_id": {
                    "hash_type": "type",
                    "code_hash": tx_hashes[2].1,
                },
                "cell_dep": {
                    "out_point": {
                        "tx_hash": dep_group_tx_hashes[1],
                        "index": "0x0"
                    },
                    "dep_type": "dep_group"
                }
            }
        }
    });
    let cell_deps_path = format!("{}/cell_deps.json", tmp_path);
    fs::write(
        cell_deps_path,
        &serde_json::to_string_pretty(&cell_deps).unwrap(),
    )
    .unwrap();

    // Transfer 2000 ckb to 3 addresses
    for addr in [OWNER_ADDR, ACCOUNT1_ADDR, ACCOUNT2_ADDR] {
        setup.cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --capacity 2000",
            miner_privkey, addr,
        ));
        log::info!("transfer 2000 CKB from miner to {}", addr);
        setup.miner().generate_blocks(3);
    }
}

fn check_amount(
    setup: &mut Setup,
    owner_addr: &str,
    cell_deps_path: &str,
    addr: &str,
    expected_amount: u128,
) {
    let output = setup.cli(&format!(
        "sudt get-amount --owner {} --address {} --cell-deps {}",
        owner_addr, addr, cell_deps_path,
    ));
    log::debug!("get amount:\n{}", output);
    setup.miner().generate_blocks(3);
    let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
    assert_eq!(
        value["total_amount"].as_str().unwrap(),
        expected_amount.to_string()
    );
    assert_eq!(value["cell_count"].as_u64().unwrap(), 1);
}

fn create_acp_cell(
    setup: &mut Setup,
    owner_addr: &str,
    cell_deps_path: &str,
    addr: &str,
    privkey_path: &str,
) -> String {
    let output = setup.cli(&format!(
        "sudt new-empty-acp --owner {} --to {} --cell-deps {} --privkey-path {}",
        owner_addr, addr, cell_deps_path, privkey_path,
    ));
    log::info!("create empty acp cell for {}:\n{}", addr, output);
    setup.miner().generate_blocks(3);
    let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
    value["acp-address"].as_str().unwrap().to_string()
}
