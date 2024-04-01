use crate::miner::Miner;
use crate::setup::Setup;
use crate::spec::Spec;
use ckb_chain_spec::consensus::TYPE_ID_CODE_HASH;
use ckb_sdk::{constants::ONE_CKB, HumanCapacity};
use tempfile::tempdir;

use std::{fs, str::FromStr, thread, time::Duration};

// Random private key just for tests
pub const ACCOUNT1_PRIVKEY: &str =
    "0x3b5ca3bd98b6a57f36b3f6fa138c4004e92a37dee39069606ee65c742e5f9170";
pub const ACCOUNT1_ADDRESS: &str = "ckt1qyqp76jus2sst4qy57nnphuqgsmlmzkv2l7s8ksggy";
pub const ACCOUNT2_PRIVKEY: &str =
    "0x11e86559b6d71abcf9fe2d6dd4f5e6d2fb8a1ef79db0d4b535244ceb13add189";
pub const ACCOUNT2_ADDRESS: &str = "ckt1qyq2em03yml8thgy6wthjfvfgepds9e63pxs0zc6k7";

fn get_capacity(setup: &mut Setup, address: &str, target: &str) -> String {
    let cli = format!("wallet get-capacity --address {}", address);
    let mut cnt = 0;
    loop {
        let output = setup.cli(&cli);
        if output == target {
            return output;
        }
        if cnt > 100 {
            panic!("get capacity failed");
        }
        cnt += 1;
        thread::sleep(Duration::from_millis(20));
    }
}

pub struct WalletTransfer;

impl Spec for WalletTransfer {
    fn run(&self, setup: &mut Setup) {
        let tempdir = tempdir().expect("create tempdir failed");
        let path = tempdir.path().to_str().unwrap().to_owned();
        let account1_privkey = format!("{}/account1", path);
        let account2_privkey = format!("{}/account2", path);
        fs::write(&account1_privkey, ACCOUNT1_PRIVKEY).unwrap();
        fs::write(&account2_privkey, ACCOUNT2_PRIVKEY).unwrap();

        let miner_privkey = setup.miner().privkey_path().to_string();
        let miner_address = Miner::address();

        // There is only one cell owned by miner
        let output = setup.cli(&format!(
            "wallet get-live-cells --address {}",
            miner_address
        ));
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        assert_eq!(value["live_cells"].as_sequence().unwrap().len(), 1);

        setup.miner().generate_blocks(30);

        // Simple transfer
        let tx_hash = setup.cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --capacity 20000 --fee-rate 1000",
            miner_privkey, ACCOUNT1_ADDRESS,
        ));
        log::info!(
            "transfer from miner to account1 with 20000 CKB: {}",
            tx_hash
        );
        setup.miner().mine_until_transaction_confirm(&tx_hash);
        let output = get_capacity(setup, ACCOUNT1_ADDRESS, "total: 20000.0 (CKB)");
        assert_eq!(output, "total: 20000.0 (CKB)");
        let output = setup.cli(&format!(
            "wallet get-live-cells --address {}",
            ACCOUNT1_ADDRESS
        ));
        assert!(output.contains(&tx_hash));

        // Transfer from account 1 to account 2
        let tx_hash = setup.cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --capacity 2000 --fee-rate 2000",
            account1_privkey, ACCOUNT2_ADDRESS,
        ));
        log::info!("transfer 2000.0 CKB from account1 to account2: {}", tx_hash);
        setup.miner().mine_until_transaction_confirm(&tx_hash);
        let output = get_capacity(setup, ACCOUNT1_ADDRESS, "total: 17999.99999072 (CKB)");
        assert_eq!(output, "total: 17999.99999072 (CKB)");
        let output = get_capacity(setup, ACCOUNT2_ADDRESS, "total: 2000.0 (CKB)");
        assert_eq!(output, "total: 2000.0 (CKB)");
        let output = setup.cli(&format!(
            "wallet get-live-cells --address {}",
            ACCOUNT2_ADDRESS
        ));
        assert!(output.contains(&tx_hash));

        // Transaction fee more than 1.0 CKB because change cell not reach 61.0 CKB
        let output = setup.cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --capacity 17997.99998",
            account1_privkey, ACCOUNT2_ADDRESS,
        ));
        log::info!(
            "transfer from account1 to account2 can not create change cell: {}",
            output
        );
        assert!(
            output.contains("can not create change cell, left capacity=2.00000717"),
            "{}",
            output
        );

        // Transfer from miner to account2 (include input maturity filter)
        let tx_hash = setup.cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --capacity 30000",
            miner_privkey, ACCOUNT2_ADDRESS,
        ));
        log::info!(
            "transfer from miner to account2 with 30000.0 CKB (include input maturity filter): {}",
            tx_hash
        );
        setup.miner().mine_until_transaction_confirm(&tx_hash);

        let output = get_capacity(setup, ACCOUNT2_ADDRESS, "total: 32000.0 (CKB)");
        assert_eq!(output, "total: 32000.0 (CKB)");
        let output = setup.cli(&format!(
            "wallet get-live-cells --address {}",
            ACCOUNT2_ADDRESS
        ));
        assert!(output.contains(&tx_hash));

        // create type id cell with transfer
        let tx_hash = setup.cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --capacity 20000 --type-id",
            miner_privkey, ACCOUNT1_ADDRESS,
        ));
        log::info!(
            "transfer from miner to account1 with 20000 CKB: {}, and with type_id lock script",
            tx_hash
        );
        setup.miner().mine_until_transaction_confirm(&tx_hash);
        let output = get_capacity(setup, ACCOUNT1_ADDRESS, "total: 37999.99999072 (CKB)");
        assert_eq!(output, "total: 37999.99999072 (CKB)");
        let output = setup.cli(&format!(
            "wallet get-live-cells --address {}",
            ACCOUNT1_ADDRESS
        ));
        assert!(output.contains(&tx_hash));
        assert!(output.contains(&format!("{:x}", TYPE_ID_CODE_HASH)));

        let output = setup.cli(&format!(
            "wallet get-live-cells --address {} --limit 1",
            ACCOUNT2_ADDRESS
        ));
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        let capacity_str = value["live_cells"][0]["capacity"]
            .as_str()
            .unwrap()
            .split(' ')
            .next()
            .unwrap();
        let capacity = HumanCapacity::from_str(capacity_str).unwrap();
        let target_capacity_str = HumanCapacity(capacity.0 - 5 * ONE_CKB).to_string();

        let tx_hash = setup.cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --capacity {}",
            account2_privkey, ACCOUNT1_ADDRESS, target_capacity_str,
        ));
        // Transaction can be sent
        assert!(tx_hash.starts_with("0x"));

        // test skip check to-address
        let anyone_can_pay_address = "ckt1qg8mxsu48mncexvxkzgaa7mz2g25uza4zpz062relhjmyuc52ps3rjpj324umxu73ej0h3txcsu9cw77kgvawjvpsjg";
        let output = setup.cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --capacity 180",
            miner_privkey, anyone_can_pay_address,
        ));
        assert!(output.contains(format!("Invalid to-address: {}", anyone_can_pay_address).as_str()));

        let tx_hash = setup.cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --capacity 180 --skip-check-to-address",
            miner_privkey, anyone_can_pay_address,
        ));
        log::info!(
            "transfer from miner to an anyone-can-pay address with 180 CKB: {}",
            tx_hash
        );
        setup.miner().mine_until_transaction_confirm(&tx_hash);
        let output = get_capacity(setup, anyone_can_pay_address, "total: 180.0 (CKB)");
        assert_eq!(output, "total: 180.0 (CKB)");
    }

    fn spec_name(&self) -> &'static str {
        "WalletTransfer"
    }
}

pub struct WalletTimelockedAddress;

impl Spec for WalletTimelockedAddress {
    fn run(&self, setup: &mut Setup) {
        let tempdir = tempdir().expect("create tempdir failed");
        let path = tempdir.path().to_str().unwrap().to_owned();
        let account1_privkey = format!("{}/account1", path);
        let account2_privkey = format!("{}/account2", path);
        fs::write(&account1_privkey, ACCOUNT1_PRIVKEY).unwrap();
        fs::write(&account2_privkey, ACCOUNT2_PRIVKEY).unwrap();

        let miner_privkey = setup.miner().privkey_path().to_string();
        setup.miner().generate_blocks(30);

        for _ in 0..4 {
            let tx_hash = setup.cli(&format!(
                "wallet transfer --privkey-path {} --to-address {} --capacity 500",
                miner_privkey, ACCOUNT1_ADDRESS,
            ));
            log::info!("transfer from miner to account1 with 500 CKB: {}", tx_hash);
            setup.miner().mine_until_transaction_confirm(&tx_hash);
        }

        let output = get_capacity(setup, ACCOUNT1_ADDRESS, "total: 2000.0 (CKB)");
        assert_eq!(output, "total: 2000.0 (CKB)");

        // Generate a timelocked address (a past time)
        let output = setup.cli(&format!(
            r#"util to-multisig-addr --sighash-address {} --locktime "2020-01-02T21:00:00+08:00""#,
            ACCOUNT2_ADDRESS,
        ));
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        let account2_locked_address = value["address"]["testnet"].as_str().unwrap();

        let output = setup.cli(&format!(
            "wallet get-capacity --address {}",
            ACCOUNT2_ADDRESS
        ));
        assert_eq!(output, "total: 0.0 (CKB)");
        let output = setup.cli(&format!(
            "wallet get-capacity --address {}",
            account2_locked_address
        ));
        assert_eq!(output, "total: 0.0 (CKB)");

        // Transfer some capacity to timelocked address
        let tx_hash = setup.cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --capacity 300",
            account1_privkey, account2_locked_address,
        ));
        log::info!("transfer from miner to account1 with 300 CKB: {}", tx_hash);
        setup.miner().mine_until_transaction_confirm(&tx_hash);

        let output = get_capacity(setup, ACCOUNT1_ADDRESS, "total: 1699.99999528 (CKB)");
        assert_eq!(output, "total: 1699.99999528 (CKB)");
        let output = get_capacity(setup, account2_locked_address, "total: 300.0 (CKB)");
        assert_eq!(output, "total: 300.0 (CKB)");

        // Transfer from this time locked address to normal address
        let tx_hash = setup.cli(&format!(
            "wallet transfer --privkey-path {} --from-locked-address {} --to-address {} --capacity 299.99999621",
            account2_privkey,
            account2_locked_address,
            ACCOUNT2_ADDRESS
        ));
        log::info!(
            "transfer from account2 timelocked address to account2 with 30000 CKB: {}",
            tx_hash
        );
        setup.miner().mine_until_transaction_confirm(&tx_hash);

        let output = get_capacity(setup, ACCOUNT2_ADDRESS, "total: 299.99999621 (CKB)");
        assert_eq!(output, "total: 299.99999621 (CKB)");
        let output = get_capacity(setup, account2_locked_address, "total: 0.0 (CKB)");
        assert_eq!(output, "total: 0.0 (CKB)");
    }

    fn spec_name(&self) -> &'static str {
        "WalletTimelockedAddress"
    }
}
