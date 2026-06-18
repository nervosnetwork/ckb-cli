use std::convert::TryFrom;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use ckb_jsonrpc_types as json_types;
use ckb_mock_tx_types::{
    MockCellDep, MockInfo, MockInput, MockResourceLoader, MockTransaction, ReprMockCellDep,
    ReprMockInfo, ReprMockInput, ReprMockTransaction,
};
use ckb_sdk::constants::SIGHASH_TYPE_HASH;
use ckb_types::{
    bytes::Bytes,
    core::{
        capacity_bytes, Capacity, HeaderBuilder, HeaderView, ScriptHashType, TransactionBuilder,
    },
    h256,
    packed::{self, Byte32, CellDep, CellInput, CellOutput, OutPoint, Script},
    prelude::*,
    H160, H256,
};
use clap::{ArgMatches, Args, Command, CommandFactory, FromArgMatches, Parser, Subcommand};

use super::{tx::ReprTxHelper, CliSubCommand, Output};
use crate::plugin::PluginManager;
use crate::utils::{
    arg_parser::{ArgParser, FilePathParser, FixedHashParser},
    genesis_info::GenesisInfo,
    mock_tx_helper::MockTransactionHelper,
    other::{get_genesis_info, get_signer},
    rpc::HttpRpcClient,
    tx_helper::TxHelper,
};

fn parse_file_path_exists(input: &str) -> Result<String, String> {
    FilePathParser::new(true)
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_file_path_optional(input: &str) -> Result<String, String> {
    FilePathParser::new(false)
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_tx_hash(input: &str) -> Result<String, String> {
    FixedHashParser::<H256>::default()
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_lock_arg(input: &str) -> Result<String, String> {
    FixedHashParser::<H160>::default()
        .validate(input)
        .map(|_| input.to_string())
}

#[derive(Parser, Debug)]
#[command(name = "mock-tx", about = "Handle mock transactions (verify/send)")]
pub struct MockTxCmd {
    #[command(subcommand)]
    pub command: MockTxSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum MockTxSubcommands {
    /// Print mock transaction template
    Template(MockTxTemplateArgs),
    /// Complete the mock transaction
    Complete(MockTxCompleteArgs),
    /// Dump all on-chain data(inputs/cell_deps/header_deps) into mock_info
    Dump(MockTxDumpArgs),
    /// Verify a mock transaction in local
    Verify(MockTxFileArgs),
    /// Complete then send a transaction
    Send(MockTxFileArgs),
}

#[derive(Args, Debug)]
pub struct MockTxTemplateArgs {
    #[arg(long = "lock-arg", id = "lock-arg", value_parser = parse_lock_arg)]
    pub lock_arg: Option<String>,
    #[arg(long = "output-file", id = "output-file", value_parser = parse_file_path_optional)]
    pub output_file: Option<String>,
}

#[derive(Args, Debug)]
pub struct MockTxCompleteArgs {
    #[arg(long = "tx-file", id = "tx-file", value_parser = parse_file_path_exists)]
    pub tx_file: String,
    #[arg(long = "output-file", id = "output-file", value_parser = parse_file_path_optional)]
    pub output_file: Option<String>,
}

#[derive(Args, Debug)]
pub struct MockTxFileArgs {
    #[arg(long = "tx-file", id = "tx-file", value_parser = parse_file_path_exists)]
    pub tx_file: String,
}

#[derive(Args, Debug)]
pub struct MockTxDumpArgs {
    #[arg(long = "tx-hash", id = "tx-hash", value_parser = parse_tx_hash, required_unless_present = "tx-file", conflicts_with = "tx-file")]
    pub tx_hash: Option<String>,
    #[arg(long = "tx-file", id = "tx-file", value_parser = parse_file_path_exists, required_unless_present = "tx-hash", conflicts_with = "tx-hash")]
    pub tx_file: Option<String>,
    #[arg(long = "output-file", id = "output-file", value_parser = parse_file_path_optional)]
    pub output_file: String,
}

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

    pub fn subcommand(name: &'static str) -> Command {
        MockTxCmd::command().name(name)
    }
}

impl CliSubCommand for MockTxSubCommand<'_> {
    fn process(&mut self, matches: &ArgMatches, _debug: bool) -> Result<Output, String> {
        let mut complete_tx = |tx_file: &str,
                               complete: bool,
                               verify: bool|
         -> Result<(MockTransaction, u64), String> {
            let path: PathBuf = FilePathParser::new(true).parse(tx_file)?;
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
                    helper.verify(u64::MAX, loader)?
                } else {
                    0
                }
            };
            Ok((mock_tx, cycle))
        };

        let output_tx = |output_file: Option<&String>,
                         mock_tx: &MockTransaction|
         -> Result<Option<ReprMockTransaction>, String> {
            let output_opt: Option<PathBuf> = output_file
                .map(|path| FilePathParser::new(false).parse(path))
                .transpose()?;
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

        let cmd = MockTxCmd::from_arg_matches(matches).map_err(|err| err.to_string())?;
        match cmd.command {
            MockTxSubcommands::Template(args) => {
                let lock_arg_opt: Option<H160> = args
                    .lock_arg
                    .as_ref()
                    .map(|value| FixedHashParser::<H160>::default().parse(value))
                    .transpose()?;
                let lock_arg = lock_arg_opt.unwrap_or_default();

                let genesis_info = get_genesis_info(&self.genesis_info, self.rpc_client)?;
                let sample_script = || {
                    Script::new_builder()
                        .code_hash(SIGHASH_TYPE_HASH.pack())
                        .hash_type(ScriptHashType::Type)
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
                    header: None,
                };
                let input = CellInput::new(OutPoint::new(h256!("0xff02").pack(), 0), 0);
                let mock_input = MockInput {
                    input: input.clone(),
                    output: CellOutput::new_builder()
                        .capacity(capacity_bytes!(300).pack())
                        .lock(sample_script())
                        .build(),
                    data: Bytes::from("abcd"),
                    header: None,
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
                    extensions: vec![],
                };
                let tx = TransactionBuilder::default()
                    .input(input)
                    .output(output)
                    .output_data(ckb_types::packed::Bytes::default())
                    .witness(Bytes::from("abc").pack())
                    .build()
                    .data();
                let mut mock_tx = MockTransaction { mock_info, tx };
                {
                    let mut helper = MockTransactionHelper::new(&mut mock_tx);
                    helper.fill_deps(&genesis_info, |_| unreachable!())?;
                }
                if let Some(output) = output_tx(args.output_file.as_ref(), &mock_tx)? {
                    Ok(Output::new_output(output))
                } else {
                    Ok(Output::new_success())
                }
            }
            MockTxSubcommands::Complete(args) => {
                let (mock_tx, _cycle) = complete_tx(&args.tx_file, true, false)?;
                let tx_hash: H256 = mock_tx.core_transaction().hash().unpack();
                if let Some(repr_mock_tx) = output_tx(args.output_file.as_ref(), &mock_tx)? {
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
            MockTxSubcommands::Dump(args) => {
                let output_path: PathBuf = FilePathParser::new(false).parse(&args.output_file)?;
                let tx_hash_opt: Option<H256> = args
                    .tx_hash
                    .as_ref()
                    .map(|value| FixedHashParser::<H256>::default().parse(value))
                    .transpose()?;
                let tx_file_opt: Option<PathBuf> = args
                    .tx_file
                    .as_ref()
                    .map(|value| FilePathParser::new(true).parse(value))
                    .transpose()?;

                let src_tx: json_types::Transaction = if let Some(path) = tx_file_opt {
                    let mut content = String::new();
                    let mut file = fs::File::open(path).map_err(|err| err.to_string())?;
                    file.read_to_string(&mut content)
                        .map_err(|err| err.to_string())?;
                    let repr_result: Result<ReprTxHelper, String> =
                        serde_json::from_str(content.as_str()).map_err(|err| err.to_string());
                    if let Ok(repr) = repr_result {
                        let helper = TxHelper::try_from(repr)?;
                        let mut get_live_cell = |out_point: OutPoint, _with_data: bool| {
                            load_output_and_data(self.rpc_client, out_point.into())
                                .map(|(output, _data, _)| output.into())
                        };
                        let tx = helper.build_tx(&mut get_live_cell, true)?;
                        tx.data().into()
                    } else {
                        serde_json::from_str(content.as_str()).map_err(|err| err.to_string())?
                    }
                } else if let Some(tx_hash) = tx_hash_opt {
                    self.rpc_client
                        .get_transaction(tx_hash.clone())?
                        .filter(|tx_with_status| tx_with_status.transaction.is_some())
                        .map(|tx_with_status| {
                            packed::Transaction::from(tx_with_status.transaction.unwrap().inner)
                        })
                        .ok_or_else(|| format!("Transaction not found on chain: {:x}", tx_hash))?
                        .into()
                } else {
                    return Err(String::from("<tx-hash> or <tx-file> is required"));
                };
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
                            header: Some(block_hash),
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
                                        header: Some(block_hash),
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
                            header: Some(block_hash),
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
                        extensions: vec![],
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
            MockTxSubcommands::Verify(args) => {
                let (mock_tx, cycle) = complete_tx(&args.tx_file, false, true)?;
                let tx_hash: H256 = mock_tx.core_transaction().hash().unpack();
                let resp = serde_json::json!({
                    "tx-hash": tx_hash,
                    "cycle": cycle,
                });
                Ok(Output::new_output(resp))
            }
            MockTxSubcommands::Send(args) => {
                let (mock_tx, _cycle) = complete_tx(&args.tx_file, false, true)?;
                let resp = self
                    .rpc_client
                    .send_transaction(
                        mock_tx.core_transaction().data(),
                        Some(json_types::OutputsValidator::Passthrough),
                    )
                    .map_err(|err| format!("Send transaction error: {}", err))?;
                Ok(Output::new_output(resp))
            }
        }
    }
}

fn load_output_and_data(
    rpc_client: &mut HttpRpcClient,
    out_point: json_types::OutPoint,
) -> Result<(json_types::CellOutput, json_types::JsonBytes, H256), String> {
    let tx_hash = out_point.tx_hash;
    let index = out_point.index.value() as usize;
    let (tx, block_hash) = rpc_client
        .get_transaction(tx_hash.clone())?
        .filter(|tx_with_status| tx_with_status.tx_status.block_hash.is_some())
        .filter(|tx_with_status| tx_with_status.transaction.is_some())
        .map(|tx_with_status| {
            let tx = json_types::Transaction::from(packed::Transaction::from(
                tx_with_status.transaction.unwrap().inner,
            ));
            let block_hash = tx_with_status
                .tx_status
                .block_hash
                .expect("block_hash exists");
            (tx, block_hash)
        })
        .ok_or_else(|| format!("transaction not exists or not mined: {:x}", tx_hash))?;
    let output = tx.outputs.get(index).cloned().ok_or_else(|| {
        format!(
            "can not found output tx-hash={:x}, index={}",
            tx_hash, index
        )
    })?;
    let data = tx
        .outputs_data
        .get(index)
        .cloned()
        .ok_or_else(|| format!("can not found data tx-hash={:x}, index={}", tx_hash, index))?;
    Ok((output, data, block_hash))
}

struct Loader<'a> {
    rpc_client: &'a mut HttpRpcClient,
}

impl MockResourceLoader for Loader<'_> {
    fn get_header(&mut self, hash: H256) -> Result<Option<HeaderView>, String> {
        self.rpc_client
            .get_header(hash)
            .map(|header_opt| header_opt.map(Into::into))
    }

    fn get_live_cell(
        &mut self,
        out_point: OutPoint,
    ) -> Result<Option<(CellOutput, Bytes, Option<Byte32>)>, String> {
        let output: Option<CellOutput> = self
            .rpc_client
            .get_live_cell(out_point.clone(), true, None)
            .map(|resp| resp.cell.map(|info| info.output.into()))?;
        if let Some(output) = output {
            Ok(self
                .rpc_client
                .get_transaction(out_point.tx_hash().unpack())?
                .filter(|tx_with_status| tx_with_status.transaction.is_some())
                .and_then(|tx_with_status| {
                    let output_index: u32 = out_point.index().unpack();
                    let block_hash = tx_with_status.tx_status.block_hash.unwrap_or_default();
                    tx_with_status
                        .transaction
                        .unwrap()
                        .inner
                        .outputs_data
                        .get(output_index as usize)
                        .map(|data| (output, data.clone().into_bytes(), Some(block_hash.pack())))
                }))
        } else {
            Ok(None)
        }
    }
}
