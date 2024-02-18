use tempfile::tempdir;

use ckb_chain_spec::ChainSpec;

use super::{check_amount, create_acp_cell, prepare, ACCOUNT1_ADDR, ACCOUNT2_ADDR, OWNER_ADDR};
use crate::setup::Setup;
use crate::spec::Spec;

const EPOCH_LENGTH: u64 = 32;
const LOCK_PERIOD_EPOCHES: u64 = 6;

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
        setup.miner().generate_blocks(6);

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
        setup.miner().generate_blocks(6);

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
        setup.miner().generate_blocks(6);

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

    fn spec_name(&self) -> &'static str {
        "SudtIssueToCheque"
    }
}

pub struct SudtIssueToAcp;

impl Spec for SudtIssueToAcp {
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
        setup.miner().generate_blocks(6);
        check_amount(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            account1_acp_addr.as_str(),
            300,
        );

        // issue to multiple acp addresses
        let account2_acp_addr = create_acp_cell(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            ACCOUNT2_ADDR,
            account2_key_path.as_str(),
        );
        let output = setup.cli(&format!(
            "sudt issue --owner {} --udt-to {}:200 --udt-to {}:400 --to-acp-address --cell-deps {} --privkey-path {}",
            OWNER_ADDR,
            account1_acp_addr,
            account2_acp_addr,
            cell_deps_path,
            owner_key_path,
        ));
        log::info!(
            "Issue 200 SUDT to account 1 and 400 to account 2:\n{}",
            output
        );
        setup.miner().generate_blocks(6);

        check_amount(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            account1_acp_addr.as_str(),
            500,
        );
        check_amount(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            account2_acp_addr.as_str(),
            400,
        );
    }

    fn spec_name(&self) -> &'static str {
        "SudtIssueToAcp"
    }
}

pub struct SudtTransferToMultiAcp;

impl Spec for SudtTransferToMultiAcp {
    fn run(&self, setup: &mut Setup) {
        let tempdir = tempdir().expect("create tempdir failed");
        let path = tempdir.path().to_str().unwrap();
        let owner_key_path = format!("{}/owner", path);
        let account1_key_path = format!("{}/account1", path);
        let account2_key_path = format!("{}/account2", path);
        let cell_deps_path = format!("{}/cell_deps.json", path);
        prepare(setup, path);

        let owner_acp_addr = create_acp_cell(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            OWNER_ADDR,
            owner_key_path.as_str(),
        );
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
            "sudt issue --owner {} --udt-to {}:300 --to-acp-address --cell-deps {} --privkey-path {}",
            OWNER_ADDR,
            account1_acp_addr,
            cell_deps_path,
            owner_key_path,
        ));
        log::info!("Issue 300 SUDT to account 1's acp address:\n{}", output);
        setup.miner().generate_blocks(6);
        let output = setup.cli(&format!(
            "sudt transfer --owner {} --sender {} --udt-to {}:150 --udt-to {}:100 --to-acp-address --cell-deps {} --privkey-path {}",
            OWNER_ADDR,
            account1_acp_addr,
            owner_acp_addr,
            account2_acp_addr,
            cell_deps_path,
            account1_key_path,
        ));
        log::info!(
            "Transfer 150 SUDT to owner, 100 SUDT to account 2, from account 1:\n{}",
            output
        );
        setup.miner().generate_blocks(6);
        check_amount(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            owner_acp_addr.as_str(),
            150,
        );
        check_amount(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            account1_acp_addr.as_str(),
            50,
        );
        check_amount(
            setup,
            OWNER_ADDR,
            cell_deps_path.as_str(),
            account2_acp_addr.as_str(),
            100,
        );
    }

    fn spec_name(&self) -> &'static str {
        "SudtTransferToMultiAcp"
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
        setup.miner().generate_blocks(6);

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
        setup.miner().generate_blocks(6);

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
        setup.miner().generate_blocks(6);

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

    fn spec_name(&self) -> &'static str {
        "SudtTransferToChequeForClaim"
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
        setup.miner().generate_blocks(6);

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
        setup.miner().generate_blocks(6);

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
        setup.miner().generate_blocks(6);

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
        spec_toml.params.epoch_duration_target = Some(EPOCH_LENGTH * 8);
        spec_toml.params.permanent_difficulty_in_dummy = Some(true);
    }

    fn spec_name(&self) -> &'static str {
        "SudtTransferToChequeForWithdraw"
    }
}
