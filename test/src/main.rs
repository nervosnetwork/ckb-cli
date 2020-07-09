pub mod app;
pub mod miner;
pub mod setup;
pub mod spec;
pub mod util;

use crate::app::App;
use crate::setup::Setup;
use crate::spec::{
    DaoPrepareMultiple, DaoPrepareOne, DaoWithdrawMultiple, Plugin, RpcGetTipBlockNumber, Spec,
    Util, WalletTimelockedAddress, WalletTransfer,
};
use crate::util::{find_available_port, run_cmd, temp_dir};
use std::env;
use std::path::PathBuf;

fn main() {
    env::set_var("RUST_BACKTRACE", "full");
    let _ = {
        let filter = env::var("CKB_LOG").unwrap_or_else(|_| "info".to_string());
        env_logger::builder().parse_filters(&filter).try_init()
    };
    let app = app::App::init();
    for spec in all_specs() {
        run_spec(spec, &app);
    }
}

fn run_spec(spec: Box<dyn Spec>, app: &App) {
    let (_tempdir, ckb_dir) = temp_dir();
    let rpc_port = find_available_port(8000, 8999);
    let p2p_port = find_available_port(9000, 9999);
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

    let mut ckb_cli_dir = PathBuf::from(ckb_dir.as_str());
    ckb_cli_dir.push("ckb-cli");
    env::set_var("CKB_CLI_HOME", ckb_cli_dir.as_os_str());

    let mut setup = Setup::new(
        app.ckb_bin().to_string(),
        app.cli_bin().to_string(),
        app.keystore_plugin_bin().to_string(),
        ckb_dir,
        ckb_cli_dir.to_str().unwrap().to_owned(),
        rpc_port,
    );
    let _guard = setup.ready(&*spec);
    spec.run(&mut setup);
}

fn all_specs() -> Vec<Box<dyn Spec>> {
    vec![
        Box::new(Plugin),
        Box::new(RpcGetTipBlockNumber),
        Box::new(WalletTransfer),
        Box::new(WalletTimelockedAddress),
        Box::new(DaoPrepareOne),
        Box::new(DaoPrepareMultiple),
        Box::new(DaoWithdrawMultiple),
        Box::new(Util),
    ]
}
