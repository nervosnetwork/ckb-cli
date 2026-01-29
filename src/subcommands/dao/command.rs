use crate::subcommands::dao::util::{calculate_dao_maximum_withdraw, send_transaction};
use crate::subcommands::{CliSubCommand, DAOSubCommand, Output};
use crate::utils::{
    arg_parser::{
        AddressParser, ArgParser, CapacityParser, FixedHashParser, FromStrParser, OutPointParser,
        PrivkeyPathParser, PrivkeyWrapper,
    },
    other::{get_address, get_network_type},
};
use ckb_crypto::secp::SECP256K1;
use ckb_sdk::{Address, AddressPayload, HumanCapacity, NetworkType};
use ckb_types::{packed::Script, H160};
use clap::{ArgAction, ArgMatches, Args, Command, CommandFactory, Parser, Subcommand};
use std::collections::HashSet;

fn parse_privkey_path(input: &str) -> Result<String, String> {
    PrivkeyPathParser.validate(input).map(|_| input.to_string())
}

fn parse_address(input: &str) -> Result<String, String> {
    AddressParser::default().validate(input).map(|_| input.to_string())
}

fn parse_capacity(input: &str) -> Result<String, String> {
    CapacityParser.validate(input).map(|_| input.to_string())
}

fn parse_out_point(input: &str) -> Result<String, String> {
    OutPointParser.validate(input).map(|_| input.to_string())
}

#[derive(Parser, Debug)]
#[command(
    name = "dao",
    about = "Deposit / prepare / withdraw / query NervosDAO balance (with local index) / key utils"
)]
pub struct DaoCmd {
    #[command(subcommand)]
    pub command: DaoSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum DaoSubcommands {
    /// Deposit capacity into NervosDAO
    Deposit(DaoDepositArgs),
    /// Prepare specified cells from NervosDAO
    Prepare(DaoOutPointArgs),
    /// Withdraw specified cells from NervosDAO
    Withdraw(DaoOutPointArgs),
    /// Query NervosDAO deposited capacity by address
    QueryDepositedCells(DaoAddressArgs),
    /// Query NervosDAO prepared capacity by address
    QueryPreparedCells(DaoAddressArgs),
}

#[derive(Args, Debug)]
pub struct DaoTransactArgs {
    #[arg(long = "privkey-path", id = "privkey-path", required_unless_present = "from-account", value_parser = parse_privkey_path)]
    pub privkey_path: Option<String>,
    #[arg(long = "from-account", id = "from-account", required_unless_present = "privkey-path")]
    pub from_account: Option<String>,
    #[arg(long = "fee-rate", id = "fee-rate", default_value = "1000")]
    pub fee_rate: String,
    #[arg(long = "max-tx-fee", id = "max-tx-fee", value_parser = parse_capacity)]
    pub max_tx_fee: Option<String>,
}

#[derive(Args, Debug)]
pub struct DaoDepositArgs {
    #[command(flatten)]
    pub tx: DaoTransactArgs,
    #[arg(long, value_parser = parse_capacity)]
    pub capacity: String,
}

#[derive(Args, Debug)]
pub struct DaoOutPointArgs {
    #[command(flatten)]
    pub tx: DaoTransactArgs,
    #[arg(long = "out-point", id = "out-point", action = ArgAction::Append, num_args = 1.., value_parser = parse_out_point)]
    pub out_point: Vec<String>,
}

#[derive(Args, Debug)]
pub struct DaoAddressArgs {
    #[arg(long, value_parser = parse_address)]
    pub address: String,
}

impl CliSubCommand for DAOSubCommand<'_> {
    fn process(&mut self, matches: &ArgMatches, debug: bool) -> Result<Output, String> {
        let network_type = get_network_type(self.rpc_client)?;
        match matches.subcommand() {
            Some(("deposit", m)) => {
                let args = TransactArgs::from_matches(m, network_type)?;
                let capacity: u64 = CapacityParser.from_matches(m, "capacity")?;
                let transaction = self.deposit(&args, capacity)?;
                send_transaction(self.rpc_client, transaction, debug)
            }
            Some(("prepare", m)) => {
                let args = TransactArgs::from_matches(m, network_type)?;
                let out_points = OutPointParser.from_matches_vec(m, "out-point")?;
                if out_points.len() != out_points.iter().collect::<HashSet<_>>().len() {
                    return Err("Duplicated out-points".to_string());
                }
                let transaction = self.prepare(&args, out_points)?;
                send_transaction(self.rpc_client, transaction, debug)
            }
            Some(("withdraw", m)) => {
                let args = TransactArgs::from_matches(m, network_type)?;
                let out_points = OutPointParser.from_matches_vec(m, "out-point")?;
                if out_points.len() != out_points.iter().collect::<HashSet<_>>().len() {
                    return Err("Duplicated out-points".to_string());
                }
                let transaction = self.withdraw(&args, out_points)?;
                send_transaction(self.rpc_client, transaction, debug)
            }
            Some(("query-deposited-cells", m)) => {
                let address_payload = get_address(Some(network_type), m)?;
                let cells = self.query_deposit_cells(Script::from(&address_payload))?;
                let total_capacity = cells.iter().map(|live| live.capacity).sum::<u64>();
                let resp = serde_json::json!({
                    "live_cells": cells.into_iter().map(|info| {
                        serde_json::to_value(info).unwrap()
                    }).collect::<Vec<_>>(),
                    "total_capacity": total_capacity,
                });
                Ok(Output::new_output(resp))
            }
            Some(("query-prepared-cells", m)) => {
                let address_payload = get_address(Some(network_type), m)?;
                let cells = self.query_prepare_cells(Script::from(&address_payload))?;
                let maximum_withdraws: Vec<_> = cells
                    .iter()
                    .map(|cell| calculate_dao_maximum_withdraw(self.rpc_client, cell))
                    .collect::<Result<Vec<u64>, String>>()?;
                let total_maximum_withdraw = maximum_withdraws.iter().sum::<u64>();
                let resp = serde_json::json!({
                    "live_cells": (0..cells.len()).map(|i| {
                        let mut value = serde_json::to_value(&cells[i]).unwrap();
                        let obj = value.as_object_mut().unwrap();
                        obj.insert("maximum_withdraw".to_owned(), serde_json::json!(maximum_withdraws[i]));
                        value
                    }).collect::<Vec<_>>(),
                    "total_maximum_withdraw": total_maximum_withdraw,
                });
                Ok(Output::new_output(resp))
            }
            _ => Err(Self::subcommand().render_usage().to_string()),
        }
    }
}

impl DAOSubCommand<'_> {
    pub fn subcommand() -> Command {
        DaoCmd::command()
    }
}

pub struct TransactArgs {
    pub(crate) privkey: Option<PrivkeyWrapper>,
    pub(crate) address: Address,
    pub(crate) fee_rate: u64,
    pub(crate) force_small_change_as_fee: Option<u64>,
}

impl TransactArgs {
    fn from_matches(m: &ArgMatches, network_type: NetworkType) -> Result<Self, String> {
        let privkey: Option<PrivkeyWrapper> =
            PrivkeyPathParser.from_matches_opt(m, "privkey-path")?;
        let address = if let Some(privkey) = privkey.as_ref() {
            let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, privkey);
            let payload = AddressPayload::from_pubkey(&pubkey);
            Address::new(network_type, payload, false)
        } else {
            let account: H160 = FixedHashParser::<H160>::default()
                .from_matches_opt(m, "from-account")
                .or_else(|err| {
                    let result: Result<Option<Address>, String> = AddressParser::new_sighash()
                        .set_network(network_type)
                        .from_matches_opt(m, "from-account");
                    result
                        .map(|address_opt| {
                            address_opt
                                .map(|address| H160::from_slice(&address.payload().args()).unwrap())
                        })
                        .map_err(|_| format!("Invalid value for '--from-account': {}", err))
                })?
                .ok_or_else(|| {
                    // It's a bug of clap, otherwise if <privkey-path> is not given <from-account> must required.
                    // The bug only happen when put <fee-rate> before <out-point>.
                    String::from("<privkey-path> or <from-account> is required!")
                })?;
            let payload = AddressPayload::from_pubkey_hash(account);
            Address::new(network_type, payload, false)
        };
        let fee_rate: u64 = FromStrParser::<u64>::default().from_matches(m, "fee-rate")?;

        let force_small_change_as_fee =
            FromStrParser::<HumanCapacity>::default().from_matches_opt(m, "max-tx-fee")?;
        Ok(Self {
            privkey,
            address,
            fee_rate,
            force_small_change_as_fee,
        })
    }

}
