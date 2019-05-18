pub mod index;

use clap::{App, Arg, ArgMatches, SubCommand};

use super::{from_matches, CliSubCommand};
use crate::utils::printer::Printable;
use crate::utils::rpc_client::HttpRpcClient;

pub use index::{UtxoDatabase, NetworkType, AddressFormat, Address, SecpUtxoInfo, IndexError};

pub struct WalletSubCommand<'a> {
    #[allow(dead_code)]
    rpc_client: &'a mut HttpRpcClient,
}

impl<'a> WalletSubCommand<'a> {
    pub fn new(rpc_client: &'a mut HttpRpcClient) -> WalletSubCommand<'a> {
        WalletSubCommand { rpc_client }
    }

    pub fn subcommand() -> App<'static, 'static> {
        SubCommand::with_name("wallet").subcommands(vec![SubCommand::with_name("transfer")
            .arg(
                Arg::with_name("privkey")
                    .long("privkey")
                    .takes_value(true)
                    .required(true)
                    .help("Private key file path"),
            )
            .arg(
                Arg::with_name("address")
                    .long("address")
                    .takes_value(true)
                    .required(true)
                    .help("Target address"),
            )
            .arg(
                Arg::with_name("capacity")
                    .long("capacity")
                    .takes_value(true)
                    .required(true)
                    .help("The capacity (default unit: CKB)"),
            )
            .arg(
                Arg::with_name("unit")
                    .long("unit")
                    .takes_value(true)
                    .possible_values(&["CKB", "shannon"])
                    .default_value("CKB")
                    .help("Capacity unit, 1CKB = 10^8 shanon"),
            )])
    }
}

impl<'a> CliSubCommand for WalletSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches) -> Result<Box<dyn Printable>, String> {
        match matches.subcommand() {
            ("transfer", Some(m)) => {
                let _privkey_path: String = from_matches(m, "privkey");
                let _address: String = from_matches(m, "address");
                let _capacity: u64 = m.value_of("capacity").unwrap().parse().unwrap();
                let _unit: String = from_matches(m, "unit");
                Ok(Box::new("null".to_string()))
            }
            _ => Err(matches.usage().to_owned()),
        }
    }
}
