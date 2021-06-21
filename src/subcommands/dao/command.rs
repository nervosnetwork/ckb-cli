use crate::subcommands::dao::util::{calculate_dao_maximum_withdraw, send_transaction};
use crate::subcommands::{CliSubCommand, DAOSubCommand, Output};
use crate::utils::{
    arg,
    arg_parser::{
        AcpConfigParser, AddressParser, ArgParser, CapacityParser, FixedHashParser, OutPointParser,
        PrivkeyPathParser, PrivkeyWrapper,
    },
    other::{get_address, get_network_type},
};
use ckb_crypto::secp::SECP256K1;
use ckb_sdk::{constants::SIGHASH_TYPE_HASH, AcpConfig, Address, AddressPayload, NetworkType};
use ckb_types::{packed::Byte32, prelude::*, H160, H256};
use clap::{App, Arg, ArgMatches};
use std::collections::HashSet;

impl<'a> CliSubCommand for DAOSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches, debug: bool) -> Result<Output, String> {
        let network_type = get_network_type(&mut self.rpc_client)?;
        match matches.subcommand() {
            ("deposit", Some(m)) => {
                self.transact_args = Some(TransactArgs::from_matches(m, network_type)?);
                let capacity: u64 = CapacityParser.from_matches(m, "capacity")?;
                let transaction = self.deposit(capacity)?;
                send_transaction(self.rpc_client(), transaction, debug)
            }
            ("prepare", Some(m)) => {
                self.transact_args = Some(TransactArgs::from_matches(m, network_type)?);
                let out_points = OutPointParser.from_matches_vec(m, "out-point")?;
                if out_points.len() != out_points.iter().collect::<HashSet<_>>().len() {
                    return Err("Duplicated out-points".to_string());
                }
                let transaction = self.prepare(out_points)?;
                send_transaction(self.rpc_client(), transaction, debug)
            }
            ("withdraw", Some(m)) => {
                self.transact_args = Some(TransactArgs::from_matches(m, network_type)?);
                let out_points = OutPointParser.from_matches_vec(m, "out-point")?;
                if out_points.len() != out_points.iter().collect::<HashSet<_>>().len() {
                    return Err("Duplicated out-points".to_string());
                }
                let transaction = self.withdraw(out_points)?;
                send_transaction(self.rpc_client(), transaction, debug)
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
                Ok(Output::new_output(resp))
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
                Ok(Output::new_output(resp))
            }
            _ => Err(Self::subcommand().generate_usage()),
        }
    }
}

impl<'a> DAOSubCommand<'a> {
    pub fn subcommand() -> App<'static> {
        App::new("dao")
            .about("Deposit / prepare / withdraw / query NervosDAO balance (with local index) / key utils")
            .subcommands(vec![
                App::new("deposit")
                    .about("Deposit capacity into NervosDAO")
                    .args(&TransactArgs::args())
                    .arg(arg::capacity().required(true)),
                App::new("prepare")
                    .about("Prepare specified cells from NervosDAO")
                    .args(&TransactArgs::args())
                    .arg(arg::out_point().required(true).multiple(true)),
                App::new("withdraw")
                    .about("Withdraw specified cells from NervosDAO")
                    .args(&TransactArgs::args())
                    .arg(arg::out_point().required(true).multiple(true)),
                App::new("query-deposited-cells")
                    .about("Query NervosDAO deposited capacity by lock script hash or address")
                    .args(&QueryArgs::args()),
                App::new("query-prepared-cells")
                    .about("Query NervosDAO prepared capacity by lock script hash or address")
                    .args(&QueryArgs::args())
            ])
    }
}

pub(crate) struct QueryArgs {
    pub(crate) lock_hash: Byte32,
}

pub(crate) struct TransactArgs {
    pub(crate) privkey: Option<PrivkeyWrapper>,
    pub(crate) address: Address,
    pub(crate) lock_hash: Byte32,
    pub(crate) tx_fee: u64,
}

impl QueryArgs {
    fn from_matches(m: &ArgMatches, network_type: NetworkType) -> Result<Self, String> {
        let acp_config: Option<AcpConfig> =
            AcpConfigParser::default().from_matches_opt(m, "acp-config", false)?;
        let lock_hash_opt: Option<H256> =
            FixedHashParser::<H256>::default().from_matches_opt(m, "lock-hash", false)?;
        let lock_hash = if let Some(lock_hash) = lock_hash_opt {
            lock_hash.pack()
        } else {
            let address = get_address(Some(network_type), m)?;
            address
                .try_to_script(acp_config.as_ref())?
                .calc_script_hash()
        };

        Ok(Self { lock_hash })
    }

    fn args<'a>() -> Vec<Arg<'a>> {
        vec![arg::acp_config(), arg::lock_hash(), arg::address()]
    }
}

impl TransactArgs {
    fn from_matches(m: &ArgMatches, network_type: NetworkType) -> Result<Self, String> {
        let acp_config: Option<AcpConfig> =
            AcpConfigParser::default().from_matches_opt(m, "acp-config", false)?;
        let privkey: Option<PrivkeyWrapper> =
            PrivkeyPathParser.from_matches_opt(m, "privkey-path", false)?;
        let address = if let Some(privkey) = privkey.as_ref() {
            let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, privkey);
            let payload = AddressPayload::from_pubkey(&pubkey);
            Address::new(network_type, payload)
        } else {
            let account: H160 = FixedHashParser::<H160>::default()
                .from_matches_opt(m, "from-account", false)
                .or_else(|err| {
                    let result: Result<Option<Address>, String> =
                        AddressParser::new_short_sighash()
                            .set_network(network_type)
                            .from_matches_opt(m, "from-account", false);
                    result
                        .map(|address_opt| {
                            address_opt
                                .map(|address| H160::from_slice(&address.payload().args()).unwrap())
                        })
                        .map_err(|_| format!("Invalid value for '--from-account': {}", err))
                })?
                .ok_or_else(|| {
                    // It's a bug of clap, otherwise if <privkey-path> is not given <from-account> must required.
                    // The bug only happen when put <tx-fee> before <out-point>.
                    String::from("<privkey-path> or <from-account> is required!")
                })?;
            let payload = AddressPayload::new_short_sighash(account);
            Address::new(network_type, payload)
        };
        assert_eq!(
            address.payload().code_hash(&Default::default()),
            SIGHASH_TYPE_HASH.pack()
        );
        let lock_hash = address
            .payload()
            .try_to_script(acp_config.as_ref())?
            .calc_script_hash();
        let tx_fee: u64 = CapacityParser.from_matches(m, "tx-fee")?;
        Ok(Self {
            privkey,
            address,
            lock_hash,
            tx_fee,
        })
    }

    fn args<'a>() -> Vec<Arg<'a>> {
        vec![
            arg::acp_config(),
            arg::privkey_path().required_unless(arg::from_account().get_name()),
            arg::from_account().required_unless(arg::privkey_path().get_name()),
            arg::tx_fee().required(true),
        ]
    }

    pub(crate) fn sighash_args(&self) -> H160 {
        H160::from_slice(self.address.payload().args().as_ref()).unwrap()
    }
}
