mod sudt;

pub use sudt::{
    SudtIssueToAcp, SudtIssueToCheque, SudtTransferToChequeForClaim,
    SudtTransferToChequeForWithdraw, SudtTransferToMultiAcp,
};

use core::panic;
use std::str::FromStr;
use std::time::Duration;
use std::{fs, thread};

use crate::miner::Miner;
use crate::setup::Setup;
use ckb_types::{
    packed::{OutPoint, OutPointVec},
    prelude::*,
    H256,
};

const SUDT_BIN: &[u8] = include_bytes!("../../script-bins/simple_udt");
const ACP_BIN: &[u8] = include_bytes!("../../script-bins/anyone_can_pay");
const CHEQUE_BIN: &[u8] = include_bytes!("../../script-bins/ckb-cheque-script");

const OWNER_KEY: &str = "8fdf1d6df54c6c9c0167a657c0f68a9bb3bf4304942ce487880e86ce6099191c";
pub const OWNER_ADDR: &str = "ckt1qyq86vaa6e8tsruv5ngcd5tp7lcvcewxy7cquuksvj";
const ACCOUNT1_KEY: &str = "dbb62c0f0dd23088dba5ade3b4ed2279f733780de1985d344bf398c1c757ef49";
pub const ACCOUNT1_ADDR: &str = "ckt1qyqfjslcvyaay029vvfxtn80rxnwmlma43xscrqn85";
const ACCOUNT2_KEY: &str = "5f9eceb1af9fe48b97e2df350450d7416887ccca62f537733f1377ee9efb8906";
pub const ACCOUNT2_ADDR: &str = "ckt1qyq9qaekmruccau7u3eff4wsv8v74gxmlptqj2lcte";

pub fn prepare(setup: &mut Setup, tmp_path: &str) {
    let owner_key = format!("{}/owner", tmp_path);
    let account1_key = format!("{}/account1", tmp_path);
    let account2_key = format!("{}/account2", tmp_path);
    fs::write(&owner_key, OWNER_KEY).unwrap();
    fs::write(&account1_key, ACCOUNT1_KEY).unwrap();
    fs::write(&account2_key, ACCOUNT2_KEY).unwrap();

    let acp_bin = format!("{}/acp", tmp_path);
    let cheque_bin = format!("{}/cheque", tmp_path);
    let sudt_bin = format!("{}/sudt", tmp_path);
    fs::write(&acp_bin, ACP_BIN).unwrap();
    fs::write(&cheque_bin, CHEQUE_BIN).unwrap();
    fs::write(&sudt_bin, SUDT_BIN).unwrap();

    let miner_privkey = setup.miner().privkey_path().to_string();
    let miner_address = Miner::address();

    setup.miner().generate_blocks(30);

    // Deploy script binaries
    let mut tx_hashes = Vec::with_capacity(5);
    for (size, bin_path) in [
        (ACP_BIN.len(), acp_bin),
        (CHEQUE_BIN.len(), cheque_bin),
        (SUDT_BIN.len(), sudt_bin),
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
        setup.miner().mine_until_transaction_confirm(&tx_hash);
        let code_hash = {
            let output = setup.cli(&format!("util cell-meta --tx-hash {} --index 0", tx_hash));
            log::info!("cell-meta output: {}", output);
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
    for (tx_hash, _) in &tx_hashes[0..2] {
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
        setup
            .miner()
            .mine_until_transaction_confirm(&dep_group_tx_hash);
        dep_group_tx_hashes.push(dep_group_tx_hash);
    }

    // Build cell_deps.json
    let cell_deps = serde_json::json!({
        "items": {
            "acp": {
                "script_id": {
                    "hash_type": "type",
                    "code_hash": tx_hashes[0].1,
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
                    "code_hash": tx_hashes[1].1,
                },
                "cell_dep": {
                    "out_point": {
                        "tx_hash": dep_group_tx_hashes[1],
                        "index": "0x0"
                    },
                    "dep_type": "dep_group"
                }
            },
            "sudt": {
                "script_id": {
                    "hash_type": "type",
                    "code_hash": tx_hashes[2].1,
                },
                "cell_dep": {
                    "out_point": {
                        "tx_hash": tx_hashes[2].0,
                        "index": "0x0"
                    },
                    "dep_type": "code"
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
        let mut tx_hash = setup.cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --capacity 2000",
            miner_privkey, addr,
        ));
        let mut cnt = 0;
        while !tx_hash.starts_with("0x") {
            log::error!(
                "transfer 2000 CKB from miner to {} got \"{}\"",
                addr,
                tx_hash
            );
            cnt += 1;
            if cnt > 50 {
                panic!(
                    "transfer 2000 CKB from miner to {} failed after tried 50 times",
                    addr
                );
            }
            thread::sleep(Duration::from_millis(200));
            tx_hash = setup.cli(&format!(
                "wallet transfer --privkey-path {} --to-address {} --capacity 2000",
                miner_privkey, addr,
            ))
        }
        log::info!("transfer 2000 CKB from miner to {}", addr);
        setup.miner().mine_until_transaction_confirm(&tx_hash);
    }
}

pub fn check_amount(
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
    setup.miner().generate_blocks(6);
    let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
    assert_eq!(
        value["total_amount"].as_str().unwrap(),
        expected_amount.to_string()
    );
    assert_eq!(value["cell_count"].as_u64().unwrap(), 1);
}

pub fn create_acp_cell(
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
    setup.miner().generate_blocks(6);
    let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
    value["acp-address"].as_str().unwrap().to_string()
}
