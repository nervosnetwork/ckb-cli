use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    GenesisInfo, HttpRpcClient, MockCellDep, MockInfo, MockInput, MockResourceLoader,
    MockTransaction, MockTransactionHelper, ReprMockCellDep, ReprMockInfo, ReprMockInput,
    ReprMockTransaction,
};
use ckb_types::{
    bytes::Bytes,
    core::{
        capacity_bytes, Capacity, HeaderBuilder, HeaderView, ScriptHashType, TransactionBuilder,
    },
    h256,
    packed::{self, CellDep, CellInput, CellOutput, OutPoint, Script},
    prelude::*,
    H160, H256,
};
use clap::{App, Arg, ArgMatches};

use super::{CliSubCommand, Output};
use crate::plugin::PluginManager;
use crate::utils::{
    arg::lock_arg,
    arg_parser::{ArgParser, FilePathParser, FixedHashParser},
    other::{get_genesis_info, get_signer},
};

pub struct MockTxSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    plugin_mgr: &'a mut PluginManager,
    genesis_info: Option<GenesisInfo>,
}

impl<'a> MockTxSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        plugin_mgr: &'a mut PluginManager,
        genesis_info: Option<GenesisInfo>,
    ) -> MockTxSubCommand<'a> {
        MockTxSubCommand {
            rpc_client,
            plugin_mgr,
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
                App::new("dump")
                    .about("Dump all on-chain data(inputs/cell_deps/header_deps) into mock_info")
                    .arg(
                        Arg::with_name("tx-hash")
                            .long("tx-hash")
                            .takes_value(true)
                            .validator(|input| FixedHashParser::<H256>::default().validate(input))
                            .required_unless("tx-file")
                            .conflicts_with("tx-file")
                            .about("The hash of transaction which is on the chain"),
                    )
                    .arg(
                        arg_tx_file
                            .clone()
                            .required_unless("tx-hash")
                            .conflicts_with("tx-hash")
                            .about("CKB transaction data file (format: json)"),
                    )
                    .arg(
                        arg_output_file
                            .clone()
                            .required(true)
                            .about("Dumped mock transaction data file (format: json)"),
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
    fn process(&mut self, matches: &ArgMatches, _debug: bool) -> Result<Output, String> {
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

            let signer = get_signer(
                self.plugin_mgr.keystore_handler(),
                self.plugin_mgr.keystore_require_password(),
            );
            let mut rpc_client = HttpRpcClient::new(self.rpc_client.url().to_string());
            let mut loader = Loader {
                rpc_client: self.rpc_client,
            };
            let cycle = {
                let mut helper = MockTransactionHelper::new(&mut mock_tx);
                if complete {
                    let genesis_info = get_genesis_info(&self.genesis_info, &mut rpc_client)?;
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

        let output_tx = |m: &ArgMatches,
                         mock_tx: &MockTransaction|
         -> Result<Option<ReprMockTransaction>, String> {
            let output_opt: Option<PathBuf> =
                FilePathParser::new(false).from_matches_opt(m, "output-file", false)?;
            let repr_mock_tx = ReprMockTransaction::from(mock_tx.clone());
            if let Some(output) = output_opt {
                let mut out_file = fs::File::create(output).map_err(|err| err.to_string())?;
                out_file
                    .write_all(
                        serde_json::to_string_pretty(&repr_mock_tx)
                            .unwrap()
                            .as_bytes(),
                    )
                    .map_err(|err| err.to_string())?;
                Ok(None)
            } else {
                Ok(Some(repr_mock_tx))
            }
        };

        match matches.subcommand() {
            ("template", Some(m)) => {
                let lock_arg_opt: Option<H160> =
                    FixedHashParser::<H160>::default().from_matches_opt(m, "lock-arg", false)?;
                let lock_arg = lock_arg_opt.unwrap_or_else(H160::default);

                let genesis_info = get_genesis_info(&self.genesis_info, self.rpc_client)?;
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
                    block_hash: H256::default(),
                };
                let input = CellInput::new(OutPoint::new(h256!("0xff02").pack(), 0), 0);
                let mock_input = MockInput {
                    input: input.clone(),
                    output: CellOutput::new_builder()
                        .capacity(capacity_bytes!(300).pack())
                        .lock(sample_script())
                        .build(),
                    data: Bytes::from("abcd"),
                    block_hash: H256::default(),
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
                if let Some(output) = output_tx(m, &mock_tx)? {
                    Ok(Output::new_output(output))
                } else {
                    Ok(Output::new_success())
                }
            }
            ("complete", Some(m)) => {
                let (mock_tx, _cycle) = complete_tx(m, true, false)?;
                let tx_hash: H256 = mock_tx.core_transaction().hash().unpack();
                if let Some(repr_mock_tx) = output_tx(m, &mock_tx)? {
                    let mut value = serde_json::to_value(repr_mock_tx).unwrap();
                    value["tx-hash"] = serde_json::json!(tx_hash);
                    Ok(Output::new_output(value))
                } else {
                    let resp = serde_json::json!({
                        "tx-hash": tx_hash,
                    });
                    Ok(Output::new_output(resp))
                }
            }
            ("dump", Some(m)) => {
                let output_path: PathBuf =
                    FilePathParser::new(false).from_matches(m, "output-file")?;
                let tx_hash_opt: Option<H256> =
                    FixedHashParser::<H256>::default().from_matches_opt(m, "tx-hash", false)?;
                let tx_file_opt: Option<PathBuf> =
                    FilePathParser::new(true).from_matches_opt(m, "tx-file", false)?;

                let src_tx: json_types::Transaction = if let Some(path) = tx_file_opt {
                    let mut content = String::new();
                    let mut file = fs::File::open(path).map_err(|err| err.to_string())?;
                    file.read_to_string(&mut content)
                        .map_err(|err| err.to_string())?;
                    serde_json::from_str(content.as_str()).map_err(|err| err.to_string())?
                } else if let Some(tx_hash) = tx_hash_opt {
                    self.rpc_client
                        .get_transaction(tx_hash.clone())?
                        .map(|tx_with_status| {
                            packed::Transaction::from(tx_with_status.transaction.inner)
                        })
                        .ok_or_else(|| format!("Transaction not found on chain: {:x}", tx_hash))?
                        .into()
                } else {
                    return Err(String::from("<tx-hash> or <tx-file> is required"));
                };
                fn load_output_and_data(
                    rpc_client: &mut HttpRpcClient,
                    out_point: json_types::OutPoint,
                ) -> Result<(json_types::CellOutput, json_types::JsonBytes, H256), String>
                {
                    let tx_hash = out_point.tx_hash;
                    let index = out_point.index.value() as usize;
                    let (tx, block_hash) = rpc_client
                        .get_transaction(tx_hash.clone())?
                        .filter(|tx_with_status| tx_with_status.tx_status.block_hash.is_some())
                        .map(|tx_with_status| {
                            let tx = json_types::Transaction::from(packed::Transaction::from(
                                tx_with_status.transaction.inner,
                            ));
                            let block_hash = tx_with_status
                                .tx_status
                                .block_hash
                                .expect("block_hash exists");
                            (tx, block_hash)
                        })
                        .ok_or_else(|| {
                            format!("transaction not exists or not mined: {:x}", tx_hash)
                        })?;
                    let output = tx.outputs.get(index).cloned().ok_or_else(|| {
                        format!(
                            "can not found output tx-hash={:x}, index={}",
                            tx_hash, index
                        )
                    })?;
                    let data = tx.outputs_data.get(index).cloned().ok_or_else(|| {
                        format!("can not found data tx-hash={:x}, index={}", tx_hash, index)
                    })?;
                    Ok((output, data, block_hash))
                }
                let mock_inputs = src_tx
                    .inputs
                    .iter()
                    .map(|input| {
                        let (output, data, block_hash) =
                            load_output_and_data(self.rpc_client, input.previous_output.clone())?;
                        Ok(ReprMockInput {
                            input: input.clone(),
                            output,
                            data,
                            block_hash: Some(block_hash),
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                let mock_cell_deps = src_tx
                    .cell_deps
                    .iter()
                    .flat_map(|cell_dep| {
                        let (output, data, block_hash) =
                            match load_output_and_data(self.rpc_client, cell_dep.out_point.clone())
                            {
                                Ok((output, data, block_hash)) => (output, data, block_hash),
                                Err(err) => return vec![Err(err)],
                            };
                        let mut cell_deps = if cell_dep.dep_type == json_types::DepType::DepGroup {
                            let out_points = match packed::OutPointVec::from_slice(data.as_bytes())
                            {
                                Ok(out_points) => out_points,
                                Err(err) => return vec![Err(err.to_string())],
                            };
                            out_points
                                .into_iter()
                                .map(json_types::OutPoint::from)
                                .map(|out_point| {
                                    let (output, data, block_hash) =
                                        load_output_and_data(self.rpc_client, out_point.clone())?;
                                    Ok(ReprMockCellDep {
                                        cell_dep: json_types::CellDep {
                                            out_point,
                                            dep_type: json_types::DepType::Code,
                                        },
                                        output,
                                        data,
                                        block_hash: Some(block_hash),
                                    })
                                })
                                .collect::<Vec<_>>()
                        } else {
                            Vec::new()
                        };
                        cell_deps.push(Ok(ReprMockCellDep {
                            cell_dep: cell_dep.clone(),
                            output,
                            data,
                            block_hash: Some(block_hash),
                        }));
                        cell_deps
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                let mock_header_deps = src_tx
                    .header_deps
                    .iter()
                    .map(|block_hash| {
                        self.rpc_client
                            .get_header(block_hash.clone())?
                            .map(HeaderView::from)
                            .map(json_types::HeaderView::from)
                            .ok_or_else(|| format!("header not exists: {:x}", block_hash))
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                let repr_tx = ReprMockTransaction {
                    mock_info: ReprMockInfo {
                        inputs: mock_inputs,
                        cell_deps: mock_cell_deps,
                        header_deps: mock_header_deps,
                    },
                    tx: src_tx,
                };
                let content =
                    serde_json::to_string_pretty(&repr_tx).map_err(|err| err.to_string())?;
                let mut out_file = fs::File::create(output_path).map_err(|err| err.to_string())?;
                out_file
                    .write_all(content.as_bytes())
                    .map_err(|err| err.to_string())?;
                Ok(Output::new_success())
            }
            ("verify", Some(m)) => {
                let (mock_tx, cycle) = complete_tx(m, false, true)?;
                let tx_hash: H256 = mock_tx.core_transaction().hash().unpack();
                let resp = serde_json::json!({
                    "tx-hash": tx_hash,
                    "cycle": cycle,
                });
                Ok(Output::new_output(resp))
            }
            ("send", Some(m)) => {
                let (mock_tx, _cycle) = complete_tx(m, false, true)?;
                let resp = self
                    .rpc_client
                    .send_transaction(mock_tx.core_transaction().data())
                    .map_err(|err| format!("Send transaction error: {}", err))?;
                Ok(Output::new_output(resp))
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
    ) -> Result<Option<(CellOutput, Bytes, H256)>, String> {
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
                    let block_hash = tx_with_status.tx_status.block_hash.unwrap_or_default();
                    tx_with_status
                        .transaction
                        .inner
                        .outputs_data
                        .get(output_index as usize)
                        .map(|data| (output, data.clone().into_bytes(), block_hash))
                }))
        } else {
            Ok(None)
        }
    }
}
