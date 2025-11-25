pub mod app;
pub mod miner;
pub mod setup;
pub mod spec;
pub mod util;

use crate::app::App;
use crate::setup::Setup;
use crate::spec::{
    AccountKeystoreExportPerm, AccountKeystorePerm, AccountKeystoreUpdatePassword,
    DaoPrepareMultiple, DaoPrepareOne, DaoWithdrawMultiple, DeployMultisigV2Upgrade,
    DeployMultisigV2UpgradeTestnet, DeployDepGroupEnableTypeIdLater,
    DeployDepGroupTypeIdTracking, DeployDepGroupWithTypeId, DeployDepGroupWithoutTypeId, Plugin,
    RpcGetTipBlockNumber, Spec, SudtIssueToAcp,
    SudtIssueToCheque, SudtTransferToChequeForClaim, SudtTransferToChequeForWithdraw,
    SudtTransferToMultiAcp, Util, WalletTimelockedAddress, WalletTransfer,
};
use crate::util::{find_available_port, run_cmd, temp_dir};
use std::env;
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    env::set_var("RUST_BACKTRACE", "full");
    let _ = {
        let filter = env::var("CKB_LOG").unwrap_or_else(|_| "info".to_string());
        env_logger::builder().parse_filters(&filter).try_init()
    };
    let app = app::App::init();

    // Get spec filter from app (command line) or environment variable
    let spec_filter = app
        .spec_filter()
        .map(|s| s.to_string())
        .or_else(|| env::var("SPEC_FILTER").ok());

    let available_specs = all_specs();
    let specs: Vec<_> = match &spec_filter {
        Some(filter) => {
            let has_exact = available_specs
                .iter()
                .any(|spec| spec.spec_name() == filter.as_str());
            available_specs
                .into_iter()
                .filter(|spec| {
                    if has_exact {
                        spec.spec_name() == filter
                    } else {
                        spec.spec_name().contains(filter)
                    }
                })
                .collect()
        }
        None => available_specs
            .into_iter()
            .filter(|spec| !spec.spec_name().to_lowercase().contains("testnet"))
            .collect(),
    };

    if specs.is_empty() {
        if let Some(filter) = &spec_filter {
            eprintln!("No specs matching filter '{}' found", filter);
            eprintln!("Available specs:");
            for spec in all_specs() {
                eprintln!("  - {}", spec.spec_name());
            }
            std::process::exit(1);
        }
    }

    eprintln!("Running {} spec(s)", specs.len());
    if let Some(filter) = &spec_filter {
        eprintln!("Filter: {}", filter);
    }

    for spec in specs {
        log::info!(
            "==================== {} ====================\n",
            spec.spec_name()
        );
        run_spec(spec, &app);
    }
}

fn run_spec(spec: Box<dyn Spec>, app: &App) {
    let (tempdir, ckb_dir) = temp_dir();
    let rpc_override = spec.rpc_override();
    let (rpc_port, p2p_port) = if rpc_override.is_none() {
        (
            find_available_port(8000, 8099),
            find_available_port(8100, 8199),
        )
    } else {
        (0, 0)
    };
    if rpc_override.is_none() {
        let _stdout = run_cmd(
            app.ckb_bin(),
            vec![
                "-C",
                ckb_dir.as_str(),
                "init",
                "--chain",
                "dev",
                "--rpc-port",
                &rpc_port.to_string(),
                "--p2p-port",
                &p2p_port.to_string(),
            ],
        );
    }

    let mut ckb_cli_dir = PathBuf::from(ckb_dir.as_str());
    ckb_cli_dir.push("ckb-cli");
    env::set_var("CKB_CLI_HOME", ckb_cli_dir.as_os_str());

    let mut setup = Setup::new(
        app.ckb_bin().to_string(),
        app.cli_bin().to_string(),
        app.keystore_plugin_bin().to_string(),
        ckb_dir,
        rpc_port,
        rpc_override,
        tempdir,
    );
    let _ckb_guard = setup.ready(&*spec);
    spec.run(&mut setup);
    setup.success();
}

fn all_specs() -> Vec<Box<dyn Spec>> {
    vec![
        Box::new(AccountKeystorePerm),
        Box::new(AccountKeystoreExportPerm),
        Box::new(AccountKeystoreUpdatePassword),
        Box::new(SudtIssueToCheque),
        Box::new(SudtIssueToAcp),
        Box::new(SudtTransferToMultiAcp),
        Box::new(SudtTransferToChequeForClaim),
        Box::new(SudtTransferToChequeForWithdraw),
        Box::new(WalletTransfer),
        Box::new(WalletTimelockedAddress),
        Box::new(Util),
        Box::new(Plugin),
        Box::new(RpcGetTipBlockNumber),
        Box::new(DaoPrepareOne),
        Box::new(DaoPrepareMultiple),
        Box::new(DaoWithdrawMultiple),
        // Deploy TypeID tests
        Box::new(DeployDepGroupWithoutTypeId),
        Box::new(DeployDepGroupWithTypeId),
        Box::new(DeployDepGroupTypeIdTracking),
        Box::new(DeployDepGroupEnableTypeIdLater),
        Box::new(DeployMultisigV2Upgrade),
        Box::new(DeployMultisigV2UpgradeTestnet),
    ]
}
