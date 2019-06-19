use std::path::PathBuf;

use ckb_core::transaction::{CellInput, CellOutput, OutPoint, TransactionBuilder, Witness};
use ckb_sdk::{
    with_rocksdb, CellInputManager, CellManager, HttpRpcClient, KeyManager, TransactionManager,
};
use clap::{App, Arg, ArgMatches, SubCommand};
use jsonrpc_types::TransactionView;
use numext_fixed_hash::H256;

use super::super::CliSubCommand;
use crate::utils::arg_parser::{
    ArgParser, EitherParser, EitherValue, FixedHashParser, NullParser, OutPointParser,
};
use crate::utils::printer::{OutputFormat, Printable};

pub struct LocalTxSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    db_path: PathBuf,
}

impl<'a> LocalTxSubCommand<'a> {
    pub fn new(rpc_client: &'a mut HttpRpcClient, db_path: PathBuf) -> LocalTxSubCommand<'a> {
        LocalTxSubCommand {
            rpc_client,
            db_path,
        }
    }

    pub fn subcommand() -> App<'static, 'static> {
        let arg_tx_hash = Arg::with_name("tx-hash")
            .long("tx-hash")
            .takes_value(true)
            .validator(|input| FixedHashParser::<H256>::default().validate(input))
            .required(true)
            .help("Transaction hash");
        SubCommand::with_name("tx").subcommands(vec![
            SubCommand::with_name("add")
                .arg(
                    Arg::with_name("deps")
                        .long("deps")
                        .takes_value(true)
                        .validator(|input| OutPointParser.validate(input))
                        .multiple(true)
                        .help("Dependency cells"),
                )
                .arg(
                    Arg::with_name("inputs")
                        .long("inputs")
                        .takes_value(true)
                        .validator(|input| {
                            EitherParser::new(OutPointParser, NullParser).validate(input)
                        })
                        .multiple(true)
                        .help("Input cells"),
                )
                .arg(
                    Arg::with_name("outputs")
                        .long("outputs")
                        .takes_value(true)
                        .multiple(true)
                        .help("Output cells"),
                )
                .arg(
                    Arg::with_name("set-witnesses-by-keys")
                        .long("set-witnesses-by-keys")
                        .help("Set input witnesses by saved private keys"),
                ),
            SubCommand::with_name("set-witness")
                .arg(arg_tx_hash.clone())
                .arg(
                    Arg::with_name("input")
                        .long("input")
                        .takes_value(true)
                        .required(true)
                        .help("Set witnesses for which input"),
                )
                .arg(
                    Arg::with_name("witness")
                        .long("witness")
                        .takes_value(true)
                        .multiple(true)
                        .help("Witness data list"),
                ),
            SubCommand::with_name("set-witnesses-by-keys").arg(arg_tx_hash.clone()),
            SubCommand::with_name("show").arg(arg_tx_hash.clone()),
            SubCommand::with_name("remove").arg(arg_tx_hash.clone()),
            SubCommand::with_name("verify").arg(arg_tx_hash.clone()),
            SubCommand::with_name("list"),
        ])
    }
}

impl<'a> CliSubCommand for LocalTxSubCommand<'a> {
    fn process(
        &mut self,
        matches: &ArgMatches,
        format: OutputFormat,
        color: bool,
    ) -> Result<String, String> {
        match matches.subcommand() {
            ("add", Some(m)) => {
                let deps: Vec<OutPoint> = OutPointParser.from_matches_vec(m, "deps")?;
                let inputs: Vec<EitherValue<OutPoint, String>> =
                    EitherParser::new(OutPointParser, NullParser).from_matches_vec(m, "inputs")?;
                let inputs: Vec<CellInput> = inputs
                    .into_iter()
                    .map(|value| match value {
                        EitherValue::A(out_point) => Ok(CellInput {
                            previous_output: out_point,
                            // TODO: Use a non-zero since
                            since: 0,
                        }),
                        EitherValue::B(input_name) => with_rocksdb(&self.db_path, None, |db| {
                            CellInputManager::new(db)
                                .get(&input_name)
                                .map_err(Into::into)
                        })
                        .map_err(|err| format!("{:?}", err)),
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                let outputs_result: Result<Vec<CellOutput>, String> = m
                    .values_of_lossy("outputs")
                    .unwrap_or_else(Vec::new)
                    .into_iter()
                    .map(|output_name| {
                        let input = with_rocksdb(&self.db_path, None, |db| {
                            CellManager::new(db).get(&output_name).map_err(Into::into)
                        })
                        .map_err(|err| format!("{:?}", err))?;
                        Ok(input)
                    })
                    .collect();
                let outputs = outputs_result?;
                let set_witnesses_by_keys = m.is_present("set-witnesses-by-keys");

                let witnesses = inputs.iter().map(|_| Witness::new()).collect::<Vec<_>>();
                let mut tx = TransactionBuilder::default()
                    .deps(deps)
                    .inputs(inputs)
                    .outputs(outputs)
                    .witnesses(witnesses)
                    .build();
                with_rocksdb(&self.db_path, None, |db| {
                    TransactionManager::new(db).add(&tx).map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;
                if set_witnesses_by_keys {
                    let db_path = self.db_path.clone();
                    tx = with_rocksdb(&db_path, None, |db| {
                        let keys = KeyManager::new(db).list()?;
                        TransactionManager::new(db)
                            .set_witnesses_by_keys(tx.hash(), &keys, self.rpc_client)
                            .map_err(Into::into)
                    })
                    .map_err(|err| format!("{:?}", err))?;
                }
                let tx_view: TransactionView = (&tx).into();
                Ok(tx_view.render(format, color))
            }
            ("set-witness", Some(_m)) => Ok("null".to_string()),
            ("set-witnesses-by-keys", Some(m)) => {
                let tx_hash: H256 =
                    FixedHashParser::<H256>::default().from_matches(m, "tx-hash")?;
                let db_path = self.db_path.clone();
                let tx = with_rocksdb(&db_path, None, |db| {
                    let keys = KeyManager::new(db).list()?;
                    TransactionManager::new(db)
                        .set_witnesses_by_keys(&tx_hash, &keys, self.rpc_client)
                        .map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;
                let tx_view: TransactionView = (&tx).into();
                Ok(tx_view.render(format, color))
            }
            ("show", Some(m)) => {
                let tx_hash: H256 =
                    FixedHashParser::<H256>::default().from_matches(m, "tx-hash")?;
                let tx = with_rocksdb(&self.db_path, None, |db| {
                    TransactionManager::new(db)
                        .get(&tx_hash)
                        .map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;
                let tx_view: TransactionView = (&tx).into();
                Ok(tx_view.render(format, color))
            }
            ("remove", Some(m)) => {
                let tx_hash: H256 =
                    FixedHashParser::<H256>::default().from_matches(m, "tx-hash")?;
                let tx = with_rocksdb(&self.db_path, None, |db| {
                    TransactionManager::new(db)
                        .remove(&tx_hash)
                        .map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;
                let tx_view: TransactionView = (&tx).into();
                Ok(tx_view.render(format, color))
            }
            ("verify", Some(m)) => {
                let tx_hash: H256 =
                    FixedHashParser::<H256>::default().from_matches(m, "tx-hash")?;
                let db_path = self.db_path.clone();
                let result = with_rocksdb(&db_path, None, |db| {
                    TransactionManager::new(db)
                        .verify(&tx_hash, std::u64::MAX, self.rpc_client)
                        .map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;
                Ok(result.render(format, color))
            }
            ("list", Some(_m)) => {
                let txs = with_rocksdb(&self.db_path, None, |db| {
                    TransactionManager::new(db).list().map_err(Into::into)
                })
                .map_err(|err| format!("{:?}", err))?;
                let txs = txs
                    .into_iter()
                    .map(|tx| {
                        let tx_view: TransactionView = (&tx).into();
                        serde_json::json!({
                            "tx": serde_json::to_value(&tx_view).unwrap(),
                            "tx-hash": tx.hash(),
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(txs.render(format, color))
            }
            _ => Err(matches.usage().to_owned()),
        }
    }
}
