use crate::miner::Miner;
use crate::setup::Setup;
use crate::spec::Spec;
use ckb_chain_spec::ChainSpec;

const EPOCH_LENGTH: u64 = 32;
const LOCK_PERIOD_EPOCHES: u64 = 180;

pub struct DaoNormal;

impl Spec for DaoNormal {
    fn run(&self, setup: &mut Setup) {
        let privkey_path = setup.miner().privkey_path().to_string();
        assert_eq!(deposited_capacity(setup), 0);
        assert_eq!(prepared_capacity(setup), 0);

        let deposit_tx_hash = setup.cli(&format!(
            "dao deposit --tx-fee 0.00001 --capacity 102 --privkey-path {}",
            privkey_path,
        ));
        assert!(deposit_tx_hash.starts_with("0x"));
        setup.miner().generate_blocks(3);
        assert_eq!(deposited_capacity(setup), 10_200_000_000);
        assert_eq!(prepared_capacity(setup), 0);

        let prepare_tx_hash = setup.cli(&format!(
            "dao prepare --tx-fee 0.00001 --out-point {}-{} --privkey-path {}",
            deposit_tx_hash, 0, privkey_path,
        ));
        assert!(prepare_tx_hash.starts_with("0x"));
        setup.miner().generate_blocks(3);
        assert_eq!(deposited_capacity(setup), 0);
        assert_eq!(prepared_capacity(setup), 10_200_000_000);

        let output = setup.cli(&format!(
            "dao withdraw --tx-fee 0.00001 --out-point {}-{} --privkey-path {}",
            prepare_tx_hash, 0, privkey_path,
        ));
        assert!(!output.starts_with("0x")); // withdraw failed because of since immature

        setup
            .miner()
            .generate_blocks(LOCK_PERIOD_EPOCHES * EPOCH_LENGTH);

        let withdraw_tx_hash = setup.cli(&format!(
            "dao withdraw --tx-fee 0.00001 --out-point {}-{} --privkey-path {}",
            prepare_tx_hash, 0, privkey_path,
        ));
        setup.miner().generate_blocks(3);
        assert!(withdraw_tx_hash.starts_with("0x"));
        assert_eq!(deposited_capacity(setup), 0);
        assert_eq!(prepared_capacity(setup), 0);

        let output = setup.cli(&format!(
            "wallet get-live-cells --address {} --limit 10000000",
            Miner::address(),
        ));
        assert!(output.contains(&withdraw_tx_hash));
    }

    fn modify_spec_toml(&self, spec_toml: &mut ChainSpec) {
        spec_toml.params.genesis_epoch_length = EPOCH_LENGTH;
        spec_toml.params.permanent_difficulty_in_dummy = true;
    }
}

fn deposited_capacity(setup: &Setup) -> u64 {
    let output = setup.cli(&format!(
        "dao query-deposited-cells --address {}",
        Miner::address(),
    ));
    // "total_capacity: 10200000000"
    if let Some(line) = output
        .lines()
        .find(|line| line.contains("total_capacity: "))
    {
        line.trim_end()[line.find(' ').unwrap() + 1..]
            .parse()
            .unwrap()
    } else {
        0
    }
}

fn prepared_capacity(setup: &Setup) -> u64 {
    let output = setup.cli(&format!(
        "dao query-prepared-cells --address {}",
        Miner::address(),
    ));
    // "total_maximum_withdraw: 10200000000"
    if let Some(line) = output
        .lines()
        .find(|line| line.contains("total_maximum_withdraw: "))
    {
        line.trim_end()[line.find(' ').unwrap() + 1..]
            .parse()
            .unwrap()
    } else {
        0
    }
}
