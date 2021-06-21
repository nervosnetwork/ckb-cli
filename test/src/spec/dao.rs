use crate::miner::Miner;
use crate::setup::Setup;
use crate::spec::Spec;
use ckb_chain_spec::ChainSpec;

const EPOCH_LENGTH: u64 = 32;
const LOCK_PERIOD_EPOCHES: u64 = 180;

pub struct DaoPrepareOne;

impl Spec for DaoPrepareOne {
    fn run(&self, setup: &mut Setup) {
        let privkey_path = setup.miner().privkey_path().to_string();
        assert_eq!(deposited_capacity(setup), 0);
        assert_eq!(prepared_capacity(setup), 0);

        let shannons = [10_200_000_000];
        let deposit_tx_hashes = deposit(setup, &shannons);
        assert_eq!(deposited_capacity(setup), 10_200_000_000);
        assert_eq!(prepared_capacity(setup), 0);

        let out_points = deposit_tx_hashes
            .into_iter()
            .map(|hash| format!("{}-0", hash))
            .collect::<Vec<_>>();
        let prepare_tx_hash = prepare(setup, &out_points);
        assert_eq!(deposited_capacity(setup), 0);
        assert_eq!(prepared_capacity(setup), 10_200_000_000);

        // Withdraw failed because of since immature
        let output = setup.cli(&format!(
            "dao withdraw --tx-fee 0.00002 --out-point {}-{} --privkey-path {}",
            prepare_tx_hash, 0, privkey_path,
        ));
        assert!(!output.starts_with("0x")); // withdraw failed because of since immature
        assert!(output.contains("Immature"));

        // Drive the chain until since mature and then withdraw
        setup
            .miner()
            .generate_blocks(LOCK_PERIOD_EPOCHES * EPOCH_LENGTH);
        let out_points = vec![new_out_point(prepare_tx_hash, 0)];
        let _withdraw_tx_hash = withdraw(setup, &out_points);
        assert_eq!(deposited_capacity(setup), 0);
        assert_eq!(prepared_capacity(setup), 0);
    }

    fn modify_spec_toml(&self, spec_toml: &mut ChainSpec) {
        spec_toml.params.genesis_epoch_length = Some(EPOCH_LENGTH);
        spec_toml.params.permanent_difficulty_in_dummy = Some(true);
    }
}

pub struct DaoPrepareMultiple;

impl Spec for DaoPrepareMultiple {
    fn run(&self, setup: &mut Setup) {
        let privkey_path = setup.miner().privkey_path().to_string();
        assert_eq!(deposited_capacity(setup), 0);
        assert_eq!(prepared_capacity(setup), 0);

        let shannons = [10_200_000_000, 10_200_000_000, 40_000_000_000_000];
        let deposit_tx_hashes = deposit(setup, &shannons);
        assert_eq!(deposited_capacity(setup), 40_020_400_000_000);
        assert_eq!(prepared_capacity(setup), 0);

        let out_points = deposit_tx_hashes
            .into_iter()
            .map(|hash| format!("{}-0", hash))
            .collect::<Vec<_>>();
        let prepare_tx_hash = prepare(setup, &out_points);
        assert_eq!(deposited_capacity(setup), 0);
        assert_eq!(prepared_capacity(setup), 40_020_468_473_950);

        // Withdraw failed because of since immature
        let output = setup.cli(&format!(
            "dao withdraw --tx-fee 0.00002 --out-point {}-{} --privkey-path {}",
            prepare_tx_hash, 0, privkey_path,
        ));
        assert!(!output.starts_with("0x")); // withdraw failed because of since immature
        assert!(output.contains("Immature"));

        // Drive the chain until since mature and then withdraw
        setup
            .miner()
            .generate_blocks(LOCK_PERIOD_EPOCHES * EPOCH_LENGTH);
        let out_points = (0..shannons.len())
            .map(|i| new_out_point(&prepare_tx_hash, i))
            .collect::<Vec<_>>();
        let _withdraw_tx_hash = withdraw(setup, &out_points);
        assert_eq!(deposited_capacity(setup), 0);
        assert_eq!(prepared_capacity(setup), 0);
    }

    fn modify_spec_toml(&self, spec_toml: &mut ChainSpec) {
        spec_toml.params.genesis_epoch_length = Some(EPOCH_LENGTH);
        spec_toml.params.permanent_difficulty_in_dummy = Some(true);
    }
}

pub struct DaoWithdrawMultiple;

impl Spec for DaoWithdrawMultiple {
    #[allow(clippy::needless_collect)]
    fn run(&self, setup: &mut Setup) {
        assert_eq!(deposited_capacity(setup), 0);
        assert_eq!(prepared_capacity(setup), 0);

        let shannons = [10_200_000_000, 40_000_000_000_000];
        let deposit_tx_hashes = deposit(setup, &shannons);
        assert_eq!(deposited_capacity(setup), 40_010_200_000_000);
        assert_eq!(prepared_capacity(setup), 0);

        let prepare_tx_hashes = deposit_tx_hashes
            .into_iter()
            .map(|hash| {
                let out_points = new_out_point(hash, 0);
                prepare(setup, &[out_points])
            })
            .collect::<Vec<_>>();
        assert_eq!(deposited_capacity(setup), 0);
        assert_eq!(prepared_capacity(setup), 40_010_336_948_502);

        // Drive the chain until since mature and then withdraw
        setup
            .miner()
            .generate_blocks(LOCK_PERIOD_EPOCHES * EPOCH_LENGTH);
        let out_points = prepare_tx_hashes
            .into_iter()
            .map(|hash| new_out_point(hash, 0))
            .collect::<Vec<_>>();
        let _withdraw_tx_hash = withdraw(setup, &out_points);

        assert_eq!(deposited_capacity(setup), 0);
        assert_eq!(prepared_capacity(setup), 0);
    }

    fn modify_spec_toml(&self, spec_toml: &mut ChainSpec) {
        spec_toml.params.genesis_epoch_length = Some(EPOCH_LENGTH);
        spec_toml.params.permanent_difficulty_in_dummy = Some(true);
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

fn shannon2ckb(shannon: u64) -> f64 {
    shannon as f64 / 100_000_000.0
}

fn new_out_point<S: ToString>(tx_hash: S, index: usize) -> String {
    format!("{}-{}", tx_hash.to_string(), index)
}

// Deposit multiple cells corresponding to the capacity
fn deposit(setup: &mut Setup, shannons: &[u64]) -> Vec<String> {
    let privkey_path = setup.miner().privkey_path().to_string();
    let mut deposit_tx_hashes = Vec::with_capacity(shannons.len());
    for shannon in shannons {
        let deposit_tx_hash = setup.cli(&format!(
            "dao deposit --tx-fee 0.00002 --capacity {} --privkey-path {}",
            shannon2ckb(*shannon),
            privkey_path,
        ));
        assert!(deposit_tx_hash.starts_with("0x"), "{}", deposit_tx_hash);
        setup.miner().generate_blocks(3);
        deposit_tx_hashes.push(deposit_tx_hash);
    }
    deposit_tx_hashes
}

// Prepare the given out-points within the one transaction
fn prepare(setup: &mut Setup, out_points: &[String]) -> String {
    let privkey_path = setup.miner().privkey_path().to_string();
    let mut command = format!(
        "dao prepare --tx-fee 0.00002 --privkey-path {}",
        privkey_path,
    );
    for out_point in out_points {
        command = format!("{} --out-point {}", command, out_point);
    }

    let prepare_tx_hash = setup.cli(&command);
    assert!(prepare_tx_hash.starts_with("0x"), "{}", prepare_tx_hash);
    setup.miner().generate_blocks(3);
    prepare_tx_hash
}

// Withdraw the given out-points within the one transaction
fn withdraw(setup: &mut Setup, out_points: &[String]) -> String {
    let privkey_path = setup.miner().privkey_path().to_string();
    let mut command = format!(
        "dao withdraw --tx-fee 0.00002 --privkey-path {}",
        privkey_path,
    );
    for out_point in out_points {
        command = format!("{} --out-point {}", command, out_point);
    }

    let withdraw_tx_hash = setup.cli(&command);
    setup.miner().generate_blocks(3);
    assert!(withdraw_tx_hash.starts_with("0x"), "{}", withdraw_tx_hash);

    let output = setup.cli(&format!(
        "wallet get-live-cells --address {} --limit 99999999",
        Miner::address(),
    ));
    assert!(output.contains(&withdraw_tx_hash), "{}", output);
    withdraw_tx_hash
}
