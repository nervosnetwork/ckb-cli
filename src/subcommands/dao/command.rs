use clap::{App, Arg, ArgMatches, SubCommand};
use either::Either;
use std::collections::HashSet;

use crate::subcommands::{
    account::AccountId,
    dao::util::{calculate_dao_maximum_withdraw, send_transaction},
    CliSubCommand, DAOSubCommand,
};
use crate::utils::{
    arg,
    arg_parser::{
        ArgParser, CapacityParser, DerivationPathParser, FixedHashParser, OutPointParser,
        PrivkeyWrapper,
    },
    other::{get_address, get_network_type, privkey_or_from_account},
    printer::{OutputFormat, Printable},
};

use ckb_sdk::{wallet::DerivationPath, NetworkType};
use ckb_types::{
    packed::{Byte32, Script},
    prelude::*,
    H256,
};

impl<'a> CliSubCommand for DAOSubCommand<'a> {
    fn process(
        &mut self,
        matches: &ArgMatches,
        format: OutputFormat,
        color: bool,
        debug: bool,
    ) -> Result<String, String> {
        let network_type = get_network_type(&mut self.rpc_client)?;
        match matches.subcommand() {
            ("deposit", Some(m)) => {
                let capacity: u64 = CapacityParser.from_matches(m, "capacity")?;
                let transaction = self
                    .with_transact_args(TransactArgs::from_matches(m, network_type)?)?
                    .deposit(capacity)?;
                send_transaction(self.rpc_client(), transaction, format, color, debug)
            }
            ("prepare", Some(m)) => {
                let out_points = OutPointParser.from_matches_vec(m, "out-point")?;
                if out_points.len() != out_points.iter().collect::<HashSet<_>>().len() {
                    return Err("Duplicated out-points".to_string());
                }
                let transaction = self
                    .with_transact_args(TransactArgs::from_matches(m, network_type)?)?
                    .prepare(out_points)?;
                send_transaction(self.rpc_client(), transaction, format, color, debug)
            }
            ("withdraw", Some(m)) => {
                let out_points = OutPointParser.from_matches_vec(m, "out-point")?;
                if out_points.len() != out_points.iter().collect::<HashSet<_>>().len() {
                    return Err("Duplicated out-points".to_string());
                }
                let transaction = self
                    .with_transact_args(TransactArgs::from_matches(m, network_type)?)?
                    .withdraw(out_points)?;
                send_transaction(self.rpc_client(), transaction, format, color, debug)
            }
            ("query-deposited-cells", Some(m)) => {
                let query_args = QueryArgs::from_matches(m, network_type)?;
                let lock_hash = query_args.lock_hash;
                let cells = self.query_deposit_cells(lock_hash)?;
                let total_capacity = cells.iter().map(|live| live.capacity).sum::<u64>();
                let resp = serde_json::json!({
                    "live_cells": cells.into_iter().map(|info| {
                        serde_json::to_value(&info).unwrap()
                    }).collect::<Vec<_>>(),
                    "total_capacity": total_capacity,
                });
                Ok(resp.render(format, color))
            }
            ("query-prepared-cells", Some(m)) => {
                let query_args = QueryArgs::from_matches(m, network_type)?;
                let lock_hash = query_args.lock_hash;
                let cells = self.query_prepare_cells(lock_hash)?;
                let maximum_withdraws: Vec<_> = cells
                    .iter()
                    .map(|cell| calculate_dao_maximum_withdraw(self.rpc_client(), cell))
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
                Ok(resp.render(format, color))
            }
            _ => Err(matches.usage().to_owned()),
        }
    }
}

impl<'a> DAOSubCommand<'a> {
    pub fn subcommand() -> App<'static, 'static> {
        SubCommand::with_name("dao")
            .about("Deposit / prepare / withdraw / query NervosDAO balance (with local index) / key utils")
            .subcommands(vec![
                SubCommand::with_name("deposit")
                    .about("Deposit capacity into NervosDAO")
                    .args(&TransactArgs::args())
                    .arg(arg::capacity().required(true)),
                SubCommand::with_name("prepare")
                    .about("Prepare specified cells from NervosDAO")
                    .args(&TransactArgs::args())
                    .arg(arg::out_point().required(true).multiple(true)),
                SubCommand::with_name("withdraw")
                    .about("Withdraw specified cells from NervosDAO")
                    .args(&TransactArgs::args())
                    .arg(arg::out_point().required(true).multiple(true)),
                SubCommand::with_name("query-deposited-cells")
                    .about("Query NervosDAO deposited capacity by lock script hash or address")
                    .args(&QueryArgs::args()),
                SubCommand::with_name("query-prepared-cells")
                    .about("Query NervosDAO prepared capacity by lock script hash or address")
                    .args(&QueryArgs::args())
            ])
    }
}

pub(crate) struct QueryArgs {
    pub(crate) lock_hash: Byte32,
}

pub(crate) struct TransactArgs {
    pub(crate) account: Either<PrivkeyWrapper, AccountId>,
    pub(crate) path: DerivationPath,
    pub(crate) tx_fee: u64,
    pub(crate) network_type: NetworkType,
}

impl QueryArgs {
    fn from_matches(m: &ArgMatches, network_type: NetworkType) -> Result<Self, String> {
        let lock_hash_opt: Option<H256> =
            FixedHashParser::<H256>::default().from_matches_opt(m, "lock-hash", false)?;
        let lock_hash = if let Some(lock_hash) = lock_hash_opt {
            lock_hash.pack()
        } else {
            let address = get_address(Some(network_type), m)?;
            Script::from(&address).calc_script_hash()
        };

        Ok(Self { lock_hash })
    }

    fn args<'a, 'b>() -> Vec<Arg<'a, 'b>> {
        vec![arg::lock_hash(), arg::address()]
    }
}

impl TransactArgs {
    fn from_matches(m: &ArgMatches, network_type: NetworkType) -> Result<Self, String> {
        let account = privkey_or_from_account(m)?;
        let path = match account {
            Either::Left(_) => DerivationPath::empty(),
            _ => DerivationPathParser.from_matches(m, "path")?,
        };
        let tx_fee: u64 = CapacityParser.from_matches(m, "tx-fee")?;
        Ok(Self {
            account,
            path,
            tx_fee,
            network_type,
        })
    }

    fn args<'a, 'b>() -> Vec<Arg<'a, 'b>> {
        vec![
            arg::privkey_path().required_unless(arg::from_account().b.name),
            arg::from_account()
                .required_unless(arg::privkey_path().b.name)
                .conflicts_with(arg::privkey_path().b.name),
            arg::derivation_path().conflicts_with(arg::privkey_path().b.name),
            arg::tx_fee().required(true),
        ]
    }
}
