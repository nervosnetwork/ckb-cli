use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use ckb_sdk::{
    wallet::KeyStore, GenesisInfo, HttpRpcClient, MockCellDep, MockInfo, MockInput,
    MockResourceLoader, MockTransaction, MockTransactionHelper, ReprMockTransaction,
};
use ckb_types::{
    bytes::Bytes,
    core::{
        capacity_bytes, Capacity, HeaderBuilder, HeaderView, ScriptHashType, TransactionBuilder,
    },
    h256,
    packed::{CellDep, CellInput, CellOutput, OutPoint, Script},
    prelude::*,
    H160, H256,
};
use clap::{App, Arg, ArgMatches};

use super::CliSubCommand;
use crate::utils::{
    arg::lock_arg,
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

    pub fn subcommand(name: &'static str) -> App<'static> {
        let arg_tx_file = Arg::with_name("tx-file")
            .long("tx-file")
            .takes_value(true)
            .required(true)
            .validator(|input| FilePathParser::new(true).validate(input))
            .about("Mock transaction data file (format: json)");
        let arg_output_file = Arg::with_name("output-file")
            .long("output-file")
            .takes_value(true)
            .validator(|input| FilePathParser::new(false).validate(input))
            .about("Completed mock transaction data file (format: json)");
        App::new(name)
            .about("Handle mock transactions (verify/send)")
            .subcommands(vec![
                App::new("template")
                    .about("Print mock transaction template")
                    .arg(lock_arg().required(true).clone().required(false))
                    .arg(arg_output_file.clone().about("Save to a output file")),
                App::new("complete")
                    .about("Complete the mock transaction")
                    .arg(arg_tx_file.clone())
                    .arg(
                        arg_output_file
                            .clone()
                            .about("Completed mock transaction data file (format: json)"),
                    ),
                App::new("verify")
                    .about("Verify a mock transaction in local")
                    .arg(arg_tx_file.clone()),
                App::new("send")
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
        _debug: bool,
    ) -> Result<String, String> {
        let genesis_info = get_genesis_info(&self.genesis_info, self.rpc_client)?;

        let mut complete_tx = |m: &ArgMatches,
                               complete: bool,
                               verify: bool|
         -> Result<(MockTransaction, u64), String> {
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
                if complete {
                    helper.complete_tx(None, &genesis_info, &signer, |out_point| {
                        loader.get_live_cell(out_point)
                    })?;
                }
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
                ReprMockTransaction::from(mock_tx.clone()).render(OutputFormat::Json, output_color);
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
                let lock_arg = lock_arg_opt.unwrap_or_else(H160::default);
                let sighash_type_hash = genesis_info.sighash_type_hash();
                let sample_script = || {
                    Script::new_builder()
                        .code_hash(sighash_type_hash.clone())
                        .hash_type(ScriptHashType::Type.into())
                        .args(Bytes::from(lock_arg.as_bytes().to_vec()).pack())
                        .build()
                };
                let mock_cell_dep = MockCellDep {
                    cell_dep: CellDep::new_builder()
                        .out_point(OutPoint::new(h256!("0xff01").pack(), 0))
                        .build(),
                    output: CellOutput::new_builder()
                        .capacity(capacity_bytes!(600).pack())
                        .lock(sample_script())
                        .build(),
                    data: Bytes::from("1234"),
                };
                let input = CellInput::new(OutPoint::new(h256!("0xff02").pack(), 0), 0);
                let mock_input = MockInput {
                    input: input.clone(),
                    output: CellOutput::new_builder()
                        .capacity(capacity_bytes!(300).pack())
                        .lock(sample_script())
                        .build(),
                    data: Bytes::from("abcd"),
                };
                let output = CellOutput::new_builder()
                    .capacity(capacity_bytes!(120).pack())
                    .lock(sample_script())
                    .type_(Some(sample_script()).pack())
                    .build();

                let mock_info = MockInfo {
                    inputs: vec![mock_input],
                    cell_deps: vec![mock_cell_dep],
                    header_deps: vec![HeaderBuilder::default().build()],
                };
                let tx = TransactionBuilder::default()
                    .input(input)
                    .output(output)
                    .output_data(Default::default())
                    .witness(Bytes::from("abc").pack())
                    .build()
                    .data();
                let mut mock_tx = MockTransaction { mock_info, tx };
                {
                    let mut helper = MockTransactionHelper::new(&mut mock_tx);
                    helper.fill_deps(&genesis_info, |_| unreachable!())?;
                }
                output_tx(m, &mock_tx)?;

                Ok(String::new())
            }
            ("complete", Some(m)) => {
                let (mock_tx, _cycle) = complete_tx(m, true, false)?;
                output_tx(m, &mock_tx)?;
                let tx_hash: H256 = mock_tx.core_transaction().hash().unpack();
                let resp = serde_json::json!({
                    "tx-hash": tx_hash,
                });
                Ok(resp.render(format, color))
            }
            ("verify", Some(m)) => {
                let (mock_tx, cycle) = complete_tx(m, false, true)?;
                let tx_hash: H256 = mock_tx.core_transaction().hash().unpack();
                let resp = serde_json::json!({
                    "tx-hash": tx_hash,
                    "cycle": cycle,
                });
                Ok(resp.render(format, color))
            }
            ("send", Some(m)) => {
                let (mock_tx, _cycle) = complete_tx(m, false, true)?;
                let resp = self
                    .rpc_client
                    .send_transaction(mock_tx.core_transaction().data())
                    .map_err(|err| format!("Send transaction error: {}", err))?;
                Ok(resp.render(format, color))
            }
            _ => Err(Self::subcommand("mock-tx").generate_usage()),
        }
    }
}

struct Loader<'a> {
    rpc_client: &'a mut HttpRpcClient,
}

impl<'a> MockResourceLoader for Loader<'a> {
    fn get_header(&mut self, hash: H256) -> Result<Option<HeaderView>, String> {
        self.rpc_client
            .get_header(hash)
            .map(|header_opt| header_opt.map(Into::into))
    }

    fn get_live_cell(
        &mut self,
        out_point: OutPoint,
    ) -> Result<Option<(CellOutput, Bytes)>, String> {
        let output: Option<CellOutput> = self
            .rpc_client
            .get_live_cell(out_point.clone(), true)
            .map(|resp| resp.cell.map(|info| info.output.into()))?;
        if let Some(output) = output {
            Ok(self
                .rpc_client
                .get_transaction(out_point.tx_hash().unpack())?
                .and_then(|tx_with_status| {
                    let output_index: u32 = out_point.index().unpack();
                    tx_with_status
                        .transaction
                        .inner
                        .outputs_data
                        .get(output_index as usize)
                        .map(|data| (output, data.clone().into_bytes()))
                }))
        } else {
            Ok(None)
        }
    }
}
