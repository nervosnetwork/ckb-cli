use crate::miner::Miner;
use crate::setup::Setup;
use crate::spec::Spec;
use ckb_chain_spec::consensus::TYPE_ID_CODE_HASH;
use std::fs;
use tempfile::tempdir;

// Random private key just for tests
pub const ACCOUNT1_PRIVKEY: &str =
    "0x3b5ca3bd98b6a57f36b3f6fa138c4004e92a37dee39069606ee65c742e5f9170";
pub const ACCOUNT1_ADDRESS: &str = "ckt1qyqp76jus2sst4qy57nnphuqgsmlmzkv2l7s8ksggy";
pub const ACCOUNT2_PRIVKEY: &str =
    "0x11e86559b6d71abcf9fe2d6dd4f5e6d2fb8a1ef79db0d4b535244ceb13add189";
pub const ACCOUNT2_ADDRESS: &str = "ckt1qyq2em03yml8thgy6wthjfvfgepds9e63pxs0zc6k7";

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
        assert!(output.contains("current_count: 1\n"));
        assert!(output.contains("total_count: 1"));

        setup.miner().generate_blocks(30);

        // Simple transfer
        let tx_hash = setup.cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --capacity 20000 --tx-fee 0.00001",
            miner_privkey, ACCOUNT1_ADDRESS,
        ));
        log::info!(
            "transfer from miner to account1 with 20000 CKB: {}",
            tx_hash
        );
        setup.miner().generate_blocks(3);
        let output = setup.cli(&format!(
            "wallet get-capacity --address {}",
            ACCOUNT1_ADDRESS
        ));
        assert_eq!(output, "total: 20000.0 (CKB)");
        let output = setup.cli(&format!(
            "wallet get-live-cells --address {}",
            ACCOUNT1_ADDRESS
        ));
        assert!(output.contains(&tx_hash));

        // Transaction fee can not be more than 1.0 CKB
        let output = setup.cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --capacity 2000 --tx-fee 1.001",
            miner_privkey, ACCOUNT1_ADDRESS,
        ));
        log::info!(
            "transfer from miner to account 1 with 1.001 CKB tx fee: {}",
            output
        );
        assert!(output.contains("Transaction fee can not be more than 1.0 CKB"));

        // Transfer from account 1 to account 2
        let tx_hash = setup.cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --capacity 2000 --tx-fee 0.00001",
            account1_privkey, ACCOUNT2_ADDRESS,
        ));
        log::info!("transfer 2000.0 CKB from account1 to account2: {}", tx_hash);
        setup.miner().generate_blocks(3);
        let output = setup.cli(&format!(
            "wallet get-capacity --address {}",
            ACCOUNT1_ADDRESS
        ));
        assert_eq!(output, "total: 17999.99999 (CKB)");
        let output = setup.cli(&format!(
            "wallet get-capacity --address {}",
            ACCOUNT2_ADDRESS
        ));
        assert_eq!(output, "total: 2000.0 (CKB)");
        let output = setup.cli(&format!(
            "wallet get-live-cells --address {}",
            ACCOUNT2_ADDRESS
        ));
        assert!(output.contains(&tx_hash));

        // Transaction fee more than 1.0 CKB because change cell not reach 61.0 CKB
        let output = setup.cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --capacity 17997.99998 --tx-fee 0.00001",
            account1_privkey, ACCOUNT2_ADDRESS,
        ));
        log::info!(
            "transfer from account1 to account2 with more than 1.0 CKB tx fee: {}",
            output
        );
        assert!(output.contains("Transaction fee can not be more than 1.0 CKB, please change to-capacity value to adjust"));

        // Transfer from miner to account2 (include input maturity filter)
        let tx_hash = setup.cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --capacity 30000 --tx-fee 0.00001",
            miner_privkey, ACCOUNT2_ADDRESS,
        ));
        log::info!(
            "transfer from miner to account2 with 30000.0 CKB (include input maturity filter): {}",
            tx_hash
        );
        setup.miner().generate_blocks(3);
        let output = setup.cli(&format!(
            "wallet get-capacity --address {}",
            ACCOUNT2_ADDRESS
        ));
        assert_eq!(output, "total: 32000.0 (CKB)");
        let output = setup.cli(&format!(
            "wallet get-live-cells --address {}",
            ACCOUNT2_ADDRESS
        ));
        assert!(output.contains(&tx_hash));

        // create type id cell with transfer
        let tx_hash = setup.cli(&format!(
            "wallet transfer --privkey-path {} --to-address {} --capacity 20000 --tx-fee 0.00001 --type-id",
            miner_privkey, ACCOUNT1_ADDRESS,
        ));
        log::info!(
            "transfer from miner to account1 with 20000 CKB: {}, and with type_id lock script",
            tx_hash
        );
        setup.miner().generate_blocks(3);
        let output = setup.cli(&format!(
            "wallet get-capacity --address {}",
            ACCOUNT1_ADDRESS
        ));
        assert_eq!(output, "total: 37999.99999 (CKB)");
        let output = setup.cli(&format!(
            "wallet get-live-cells --address {}",
            ACCOUNT1_ADDRESS
        ));
        assert!(output.contains(&tx_hash));
        assert!(output.contains(&format!("{:x}", TYPE_ID_CODE_HASH)));
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
                "wallet transfer --privkey-path {} --to-address {} --capacity 50000 --tx-fee 0.00001",
                miner_privkey,
                ACCOUNT1_ADDRESS,
            ));
            log::info!(
                "transfer from miner to account1 with 50000 CKB: {}",
                tx_hash
            );
            setup.miner().generate_blocks(3);
        }
        let output = setup.cli(&format!(
            "wallet get-capacity --address {}",
            ACCOUNT1_ADDRESS
        ));
        assert_eq!(output, "total: 200000.0 (CKB)");

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
            "wallet transfer --privkey-path {} --to-address {} --capacity 30000 --tx-fee 0.00001",
            account1_privkey, account2_locked_address,
        ));
        log::info!(
            "transfer from miner to account1 with 30000 CKB: {}",
            tx_hash
        );
        setup.miner().generate_blocks(3);

        let output = setup.cli(&format!(
            "wallet get-capacity --address {}",
            ACCOUNT1_ADDRESS
        ));
        assert_eq!(output, "total: 169999.99999 (CKB)");
        let output = setup.cli(&format!(
            "wallet get-capacity --address {}",
            account2_locked_address
        ));
        assert_eq!(output, "total: 30000.0 (CKB)");

        // Transfer from this time locked address to normal address
        let tx_hash = setup.cli(&format!(
            "wallet transfer --privkey-path {} --from-locked-address {} --to-address {} --capacity 29999.99999 --tx-fee 0.00001",
            account2_privkey,
            account2_locked_address,
            ACCOUNT2_ADDRESS
        ));
        log::info!(
            "transfer from account2 timelocked address to account2 with 30000 CKB: {}",
            tx_hash
        );
        setup.miner().generate_blocks(3);

        let output = setup.cli(&format!(
            "wallet get-capacity --address {}",
            ACCOUNT2_ADDRESS
        ));
        assert_eq!(output, "total: 29999.99999 (CKB)");
        let output = setup.cli(&format!(
            "wallet get-capacity --address {}",
            account2_locked_address
        ));
        assert_eq!(output, "total: 0.0 (CKB)");
    }
}
