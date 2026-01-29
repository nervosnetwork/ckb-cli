pub mod account;
pub mod api_server;
pub mod dao;
pub mod deploy;
pub mod mock_tx;
pub mod molecule;
pub mod plugin;
pub mod pubsub;
pub mod rpc;
pub mod sudt;
pub mod tx;
pub mod util;
pub mod wallet;

pub use account::AccountSubCommand;
pub use api_server::ApiServerSubCommand;
use ckb_sdk::constants::MultisigScript;
use ckb_types::H256;
pub use dao::DAOSubCommand;
pub use deploy::DeploySubCommand;
pub use mock_tx::MockTxSubCommand;
pub use molecule::MoleculeSubCommand;
pub use plugin::PluginSubCommand;
pub use pubsub::PubSubCommand;
pub use rpc::RpcSubCommand;
pub use sudt::SudtSubCommand;
pub use tx::TxSubCommand;
pub use util::UtilSubCommand;
pub use wallet::{TransferArgs, WalletSubCommand};

use clap::{Arg, ArgMatches};
use serde::Serialize;

use crate::utils::{
    arg_parser::{ArgMatchesExt, ArgParser, FixedHashParser},
    printer::{OutputFormat, Printable},
};

pub struct Output {
    stdout: Option<serde_json::Value>,
    stderr: Option<serde_json::Value>,
    success: bool,
}

impl Output {
    pub fn new_success() -> Output {
        Output {
            stdout: None,
            stderr: None,
            success: true,
        }
    }

    pub fn new_output<T: Serialize>(value: T) -> Output {
        Output {
            stdout: Some(serde_json::to_value(value).expect("serialize stdout error")),
            stderr: None,
            success: false,
        }
    }

    pub fn new_error<T: Serialize>(value: T) -> Output {
        Output {
            stdout: None,
            stderr: Some(serde_json::to_value(value).expect("serialize stderr error")),
            success: false,
        }
    }

    pub fn print(&self, format: OutputFormat, color: bool) {
        if let Some(ref stdout) = self.stdout {
            println!("{}", stdout.render(format, color));
        }
        if let Some(ref stderr) = self.stderr {
            eprintln!("{}", stderr.render(format, color));
        }
        if self.success {
            let resp = serde_json::json!({
                "status": "success",
            });
            eprintln!("{}", resp.render(OutputFormat::Yaml, color));
        }
    }
}

pub trait CliSubCommand {
    fn process(&mut self, matches: &ArgMatches, debug: bool) -> Result<Output, String>;
}

pub(crate) static ALLOW_ZERO_LOCK_HELP_MSG: &str = "The --zero-lock option allows users to deploy a script permanently locked with an unspendable lock script. This lock script is defined with the following parameters:

- code_hash: 0x0000000000000000000000000000000000000000000000000000000000000000
- hash_type: data/data1/data2
- args: 0x

Once activated, the script becomes immutable and irreversible, ensuring no modifications or revocations can be made post-deployment.

Key Considerations:

- Permanent Immutability: Script logic and data will be permanently fixed on-chain.
- No Recovery Mechanism: If vulnerabilities or defects exist in the script, there is no way to upgrade, patch, or revoke it.
- Use with Caution: Thoroughly audit and test the script before deployment. This option is recommended only for scenarios requiring absolute finality, where script behavior must remain tamper-proof indefinitely.";

fn arg_multisig_code_hash() -> Arg {
    let arg_multisig_code_hash = Arg::new("multisig-code-hash")
            .long("multisig-code-hash")
            .num_args(1)
            
            .required(true)
            .value_parser([
                // legacy code hash
                "legacy",
                "0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8",
                // V2 code hash
                "v2",
                "0x36c971b8d41fbd94aabca77dc75e826729ac98447b46f91e00796155dddb0d29",
            ])
        .help("Specifies the multisig code hash to use:\n    - v2(default): `0x36c971b8d41fbd94aabca77dc75e826729ac98447b46f91e00796155dddb0d29`. \n    - legacy(deprecated): `0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8` is NOT recommended for use.\n\n");
    arg_multisig_code_hash
}

fn arg_get_multisig_code_hash(m: &ArgMatches) -> Result<H256, String> {
    match m.value_of("multisig-code-hash").unwrap() {
        "legacy" => Ok(MultisigScript::Legacy.script_id().code_hash),
        "v2" => Ok(MultisigScript::V2.script_id().code_hash),
        _ => FixedHashParser::<H256>::default().from_matches(m, "multisig-code-hash"),
    }
}
