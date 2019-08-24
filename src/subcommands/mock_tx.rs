use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use ckb_types::{
    core::{Capacity, capacity_bytes, ScriptHashType},
    packed::{Header, Script, CellInput, CellOutput, OutPoint},
    h256, H160, H256,
    bytes::Bytes,
};
use ckb_sdk::{
    wallet::KeyStore, GenesisInfo, HttpRpcClient, MockDep, MockInput, MockResourceLoader,
    MockTransaction, MockTransactionHelper, ReprMockTransaction,
};
use clap::{App, Arg, ArgMatches, SubCommand};

use super::CliSubCommand;
use crate::utils::{
    arg_parser::{ArgParser, FilePathParser, FixedHashParser},
    other::{get_genesis_info, get_singer},
    printer::{OutputFormat, Printable},
};

pub struct MockTxSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    key_store: &'a mut KeyStore,
    genesis_info: Option<GenesisInfo>,
}

impl<'a> MockTxSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        key_store: &'a mut KeyStore,
        genesis_info: Option<GenesisInfo>,
    ) -> MockTxSubCommand<'a> {
        MockTxSubCommand {
            rpc_client,
            key_store,
            genesis_info,
        }
    }

    pub fn subcommand(name: &'static str) -> App<'static, 'static> {
        let arg_tx_file = Arg::with_name("tx-file")
            .long("tx-file")
            .takes_value(true)
            .required(true)
            .validator(|input| FilePathParser::new(true).validate(input))
            .help("Mock transaction data file (format: json,yaml)");
        let arg_output_file = Arg::with_name("output-file")
            .long("output-file")
            .takes_value(true)
            .validator(|input| FilePathParser::new(false).validate(input))
            .help("Completed mock transaction data file (format: json,yaml)");
        let arg_lock_arg = Arg::with_name("lock-arg")
            .long("lock-arg")
            .takes_value(true)
            .validator(|input| FixedHashParser::<H160>::default().validate(input))
            .required(true)
            .help("The lock_arg (identifier) of the account");
        SubCommand::with_name(name)
            .about("Handle mock transactions (verify/send)")
            .subcommands(vec![
                SubCommand::with_name("template")
                    .about("Print mock transaction template")
                    .arg(arg_lock_arg.clone().required(false))
                    .arg(arg_output_file.clone().help("Save to a output file")),
                SubCommand::with_name("complete")
                    .about("Complete the mock transaction")
                    .arg(arg_tx_file.clone())
                    .arg(
                        arg_output_file
                            .clone()
                            .help("Completed mock transaction data file (format: json,yaml)"),
                    ),
                SubCommand::with_name("verify")
                    .about("Verify a mock transaction in local")
                    .arg(arg_tx_file.clone()),
                SubCommand::with_name("send")
                    .about("Complete then send a transaction")
                    .arg(arg_tx_file.clone()),
            ])
    }
}

impl<'a> CliSubCommand for MockTxSubCommand<'a> {
    fn process(
        &mut self,
        matches: &ArgMatches,
        format: OutputFormat,
        color: bool,
    ) -> Result<String, String> {
        let genesis_info = get_genesis_info(&mut self.genesis_info, self.rpc_client)?;

        let mut complete_tx =
            |m: &ArgMatches, verify: bool| -> Result<(MockTransaction, u64), String> {
                let path: PathBuf = FilePathParser::new(true).from_matches(m, "tx-file")?;
                let mut content = String::new();
                let mut file = fs::File::open(path).map_err(|err| err.to_string())?;
                file.read_to_string(&mut content)
                    .map_err(|err| err.to_string())?;
                let repr_tx: ReprMockTransaction = serde_yaml::from_str(content.as_str())
                    .map_err(|err| err.to_string())
                    .or_else(|_| {
                        serde_json::from_str(content.as_str()).map_err(|err| err.to_string())
                    })?;
                let mut mock_tx: MockTransaction = repr_tx.into();

                let signer = get_singer(self.key_store.clone());
                let mut loader = Loader {
                    rpc_client: self.rpc_client,
                };
                let cycle = {
                    let mut helper = MockTransactionHelper::new(&mut mock_tx);
                    helper.complete_tx(None, &genesis_info, &signer, |out_point| {
                        loader.get_live_cell(out_point)
                    })?;
                    if verify {
                        helper.verify(u64::max_value(), loader)?
                    } else {
                        0
                    }
                };
                Ok((mock_tx, cycle))
            };

        let output_tx = |m: &ArgMatches, mock_tx: &MockTransaction| -> Result<(), String> {
            let output_opt: Option<PathBuf> =
                FilePathParser::new(false).from_matches_opt(m, "output-file", false)?;
            let output_color = output_opt.as_ref().map(|_| false).unwrap_or(color);
            let output_content =
                ReprMockTransaction::from(mock_tx.clone()).render(format, output_color);
            if let Some(output) = output_opt {
                let mut out_file = fs::File::create(output).map_err(|err| err.to_string())?;
                out_file
                    .write_all(output_content.as_bytes())
                    .map_err(|err| err.to_string())?;
            } else {
                println!("{}", output_content);
            }
            Ok(())
        };

        match matches.subcommand() {
            ("template", Some(m)) => {
                let lock_arg_opt: Option<H160> =
                    FixedHashParser::<H160>::default().from_matches_opt(m, "lock-arg", false)?;
                let lock_arg = lock_arg_opt.unwrap_or_else(H160::zero);
                let secp_code_hash = genesis_info.secp_code_hash();
                let sample_script = || {
                    Script::new(
                        vec![Bytes::from(lock_arg.as_ref())],
                        secp_code_hash.clone(),
                        ScriptHashType::Data,
                    )
                };
                let mock_dep = MockDep {
                    out_point: OutPoint::new_cell(h256!("0xff01"), 0),
                    cell: CellOutput {
                        capacity: capacity_bytes!(600),
                        data: Bytes::default(),
                        lock: sample_script(),
                        type_: None,
                    },
                };
                let input = CellInput::new(OutPoint::new_cell(h256!("0xff02"), 0), 0);
                let mock_input = MockInput {
                    input: input.clone(),
                    cell: CellOutput {
                        capacity: capacity_bytes!(300),
                        data: Bytes::default(),
                        lock: sample_script(),
                        type_: None,
                    },
                };
                let output = CellOutput {
                    capacity: capacity_bytes!(120),
                    data: Bytes::default(),
                    lock: sample_script(),
                    type_: Some(sample_script()),
                };

                let mut mock_tx = MockTransaction::default();
                mock_tx.mock_deps = vec![mock_dep];
                mock_tx.mock_inputs = vec![mock_input];
                mock_tx.inputs = vec![input];
                mock_tx.outputs = vec![output];
                mock_tx.witnesses = vec![vec![Bytes::from("abc")]];
                {
                    let mut helper = MockTransactionHelper::new(&mut mock_tx);
                    helper.fill_deps(&genesis_info, |_| unreachable!())?;
                }
                output_tx(m, &mock_tx)?;

                Ok(String::new())
            }
            ("complete", Some(m)) => {
                let (mock_tx, _cycle) = complete_tx(m, false)?;
                output_tx(m, &mock_tx)?;
                let resp = serde_json::json!({
                    "tx-hash": mock_tx.core_transaction().hash(),
                });
                Ok(resp.render(format, color))
            }
            ("verify", Some(m)) => {
                let (mock_tx, cycle) = complete_tx(m, true)?;
                let resp = serde_json::json!({
                    "tx-hash": mock_tx.core_transaction().hash(),
                    "cycle": cycle,
                });
                Ok(resp.render(format, color))
            }
            ("send", Some(m)) => {
                let (mock_tx, _cycle) = complete_tx(m, true)?;
                let resp = self
                    .rpc_client
                    .send_transaction((&mock_tx.core_transaction()).into())
                    .call()
                    .map_err(|err| format!("Send transaction error: {}", err))?;
                Ok(resp.render(format, color))
            }
            _ => Err(matches.usage().to_owned()),
        }
    }
}

struct Loader<'a> {
    rpc_client: &'a mut HttpRpcClient,
}

impl<'a> MockResourceLoader for Loader<'a> {
    fn get_header(&mut self, hash: H256) -> Result<Option<Header>, String> {
        self.rpc_client
            .get_header(hash)
            .call()
            .map(|header_opt| header_opt.0.map(Into::into))
            .map_err(|err| err.to_string())
    }
    fn get_live_cell(&mut self, out_point: OutPoint) -> Result<Option<CellOutput>, String> {
        self.rpc_client
            .get_live_cell(out_point.into())
            .call()
            .map(|resp| resp.cell.map(Into::into))
            .map_err(|err| err.to_string())
    }
}
