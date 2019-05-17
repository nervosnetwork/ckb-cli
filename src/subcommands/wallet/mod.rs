
use clap::{SubCommand, App, Arg, ArgMatches};

use crate::utils::rpc_client::HttpRpcClient;
use crate::utils::printer::Printable;
use super::{CliSubCommand, from_matches, from_matches_opt, from_string};

pub struct WalletSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
}

impl<'a> WalletSubCommand<'a> {
    pub fn new(rpc_client: &'a mut HttpRpcClient) -> WalletSubCommand<'a> {
        WalletSubCommand { rpc_client }
    }

    pub fn subcommand() -> App<'static, 'static> {
        SubCommand::with_name("wallet")
            .subcommands(vec![
                SubCommand::with_name("transfer")
                    .arg(
                        Arg::with_name("privkey")
                            .long("privkey")
                            .takes_value(true)
                            .required(true)
                            .help("Private key file path")
                    )
                    .arg(Arg::with_name("address")
                         .long("address")
                         .takes_value(true)
                         .required(true)
                         .help("Target address")
                    )
                    .arg(
                        Arg::with_name("capacity")
                            .long("capacity")
                            .takes_value(true)
                            .required(true)
                            .help("The capacity (default unit: CKB)")
                    )
                    .arg(Arg::with_name("unit")
                         .long("unit")
                         .takes_value(true)
                         .possible_values(&["CKB", "shannon"])
                         .default_value("CKB")
                         .help("Capacity unit, 1CKB = 10^8 shanon")
                    )
            ])
    }
}

impl<'a> CliSubCommand for WalletSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches) -> Result<Box<dyn Printable>, String> {
        match matches.subcommand() {
            ("transfer", Some(m)) => {
                let privkey_path: String = from_matches(m, "privkey");
                let address: String = from_matches(m, "address");
                let capacity: u64 = m.value_of("capacity").unwrap().parse().unwrap();
                let unit: String = from_matches(m, "unit");
                Ok(Box::new("null".to_string()))
            }
            (cmd, _) => Err(matches.usage().to_owned())
        }
    }
}
