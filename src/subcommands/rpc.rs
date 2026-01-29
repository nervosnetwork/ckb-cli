use ckb_jsonrpc_types::{
    self as rpc_types, Alert, BlockNumber, EpochNumber, JsonBytes, Transaction,
};
use ckb_types::packed::{CellOutput, OutPoint};
use ckb_types::{bytes::Bytes, packed, prelude::*, H256};
use clap::{ArgAction, ArgMatches, Args, Command, CommandFactory, Parser, Subcommand};
use ipnetwork::IpNetwork;
use multiaddr::Multiaddr;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use super::tx::ReprTxHelper;
use super::{CliSubCommand, Output};
use crate::utils::arg_parser::ArgMatchesExt;
use crate::utils::arg_parser::{
    ArgParser, DurationParser, FeeRateStatisticsTargetParser, FilePathParser, FixedHashParser,
    FromStrParser, HexParser,
};
use crate::utils::other::get_live_cell_with_cache;
use crate::utils::rpc::{
    parse_order, BannedAddr, BlockEconomicState, BlockView, EpochView, HeaderView, HttpRpcClient,
    RawHttpRpcClient, RemoteNode, Timestamp, TransactionProof, TransactionWithStatus,
};
use crate::utils::tx_helper::TxHelper;

pub struct RpcSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    raw_rpc_client: &'a mut RawHttpRpcClient,
}

fn parse_h256(input: &str) -> Result<String, String> {
    FixedHashParser::<H256>::default()
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_u64(input: &str) -> Result<String, String> {
    FromStrParser::<u64>::default()
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_u32(input: &str) -> Result<String, String> {
    FromStrParser::<u32>::default()
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_ip_network(input: &str) -> Result<String, String> {
    FromStrParser::<IpNetwork>::new()
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_multiaddr(input: &str) -> Result<String, String> {
    FromStrParser::<Multiaddr>::new()
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_duration(input: &str) -> Result<String, String> {
    DurationParser.validate(input).map(|_| input.to_string())
}

fn parse_file_path(input: &str) -> Result<String, String> {
    FilePathParser::new(true)
        .validate(input)
        .map(|_| input.to_string())
}

fn parse_hex(input: &str) -> Result<String, String> {
    HexParser.validate(input).map(|_| input.to_string())
}

fn parse_fee_rate_target(input: &str) -> Result<String, String> {
    FeeRateStatisticsTargetParser {}
        .validate(input)
        .map(|_| input.to_string())
}

#[derive(Parser, Debug)]
#[command(name = "rpc", about = "Invoke RPC call to node")]
pub struct RpcCmd {
    #[arg(long = "raw-data", global = true)]
    pub raw_data: bool,
    #[command(subcommand)]
    pub command: RpcSubcommands,
}

#[derive(Subcommand, Debug)]
#[command(rename_all = "snake_case")]
pub enum RpcSubcommands {
    GetBlock(RpcGetBlockArgs),
    GetBlockByNumber(RpcGetBlockByNumberArgs),
    GetBlockHash(RpcGetBlockHashArgs),
    GetCurrentEpoch,
    GetEpochByNumber(RpcGetEpochByNumberArgs),
    GetHeader(RpcGetHeaderArgs),
    GetHeaderByNumber(RpcGetHeaderByNumberArgs),
    GetLiveCell(RpcGetLiveCellArgs),
    GetTipBlockNumber,
    GetTipHeader(RpcGetTipHeaderArgs),
    GetTransaction(RpcGetTransactionArgs),
    GetTransactionProof(RpcGetTransactionProofArgs),
    VerifyTransactionProof(RpcVerifyTransactionProofArgs),
    GetForkBlock(RpcGetForkBlockArgs),
    GetConsensus,
    GetBlockMedianTime(RpcGetBlockMedianTimeArgs),
    GetBlockEconomicState(RpcGetBlockEconomicStateArgs),
    EstimateCycles(RpcEstimateCyclesArgs),
    GetFeeRateStatics(RpcGetFeeRateStaticsArgs),
    GetFeeRateStatistics(RpcGetFeeRateStatisticsArgs),
    GetDeploymentsInfo,
    GetTransactionAndWitnessProof(RpcGetTransactionAndWitnessProofArgs),
    VerifyTransactionAndWitnessProof(RpcVerifyTransactionAndWitnessProofArgs),
    GetBannedAddresses,
    GetPeers,
    LocalNodeInfo,
    SetBan(RpcSetBanArgs),
    SyncState,
    SetNetworkActive(RpcSetNetworkActiveArgs),
    AddNode(RpcAddNodeArgs),
    RemoveNode(RpcRemoveNodeArgs),
    ClearBannedAddresses,
    PingPeers,
    RemoveTransaction(RpcRemoveTransactionArgs),
    TxPoolInfo,
    ClearTxVerifyQueue,
    TestTxPoolAccept(RpcTestTxPoolAcceptArgs),
    ClearTxPool,
    GetRawTxPool(RpcGetRawTxPoolArgs),
    TxPoolReady,
    GetBlockchainInfo,
    SendAlert(RpcSendAlertArgs),
    NotifyTransaction(RpcNotifyTransactionArgs),
    Truncate(RpcTruncateArgs),
    GenerateBlock,
    GenerateEpochs(RpcGenerateEpochsArgs),
    GetIndexerTip,
    GetCells(RpcGetCellsArgs),
    GetTransactions(RpcGetTransactionsArgs),
    GetCellsCapacity(RpcGetCellsCapacityArgs),
}

#[derive(Args, Debug)]
pub struct RpcGetBlockArgs {
    #[arg(long = "hash", id = "hash", value_parser = parse_h256)]
    pub hash: String,
    #[arg(long = "with-cycles", id = "with-cycles")]
    pub with_cycles: bool,
    #[arg(long = "packed", id = "packed")]
    pub packed: bool,
}

#[derive(Args, Debug)]
pub struct RpcGetBlockByNumberArgs {
    #[arg(long = "number", id = "number", value_parser = parse_u64)]
    pub number: String,
    #[arg(long = "with-cycles", id = "with-cycles")]
    pub with_cycles: bool,
    #[arg(long = "packed", id = "packed")]
    pub packed: bool,
}

#[derive(Args, Debug)]
pub struct RpcGetBlockHashArgs {
    #[arg(long = "number", id = "number", value_parser = parse_u64)]
    pub number: String,
}

#[derive(Args, Debug)]
pub struct RpcGetEpochByNumberArgs {
    #[arg(long = "number", id = "number", value_parser = parse_u64)]
    pub number: String,
}

#[derive(Args, Debug)]
pub struct RpcGetHeaderArgs {
    #[arg(long = "hash", id = "hash", value_parser = parse_h256)]
    pub hash: String,
    #[arg(long = "packed", id = "packed")]
    pub packed: bool,
}

#[derive(Args, Debug)]
pub struct RpcGetHeaderByNumberArgs {
    #[arg(long = "number", id = "number", value_parser = parse_u64)]
    pub number: String,
    #[arg(long = "packed", id = "packed")]
    pub packed: bool,
}

#[derive(Args, Debug)]
pub struct RpcGetLiveCellArgs {
    #[arg(long = "tx-hash", id = "tx-hash", value_parser = parse_h256)]
    pub tx_hash: String,
    #[arg(long = "index", id = "index", value_parser = parse_u32)]
    pub index: String,
    #[arg(long = "include-tx-pool", id = "include-tx-pool")]
    pub include_tx_pool: bool,
    #[arg(long = "with-data", id = "with-data")]
    pub with_data: bool,
}

#[derive(Args, Debug)]
pub struct RpcGetTipHeaderArgs {
    #[arg(long = "packed", id = "packed")]
    pub packed: bool,
}

#[derive(Args, Debug)]
pub struct RpcGetTransactionArgs {
    #[arg(long = "hash", id = "hash", value_parser = parse_h256)]
    pub hash: String,
    #[arg(long = "packed", id = "packed")]
    pub packed: bool,
}

#[derive(Args, Debug)]
pub struct RpcGetTransactionProofArgs {
    #[arg(long = "tx-hash", id = "tx-hash", action = ArgAction::Append, num_args = 1.., value_parser = parse_h256)]
    pub tx_hash: Vec<String>,
    #[arg(long = "block-hash", id = "block-hash", value_parser = parse_h256)]
    pub block_hash: Option<String>,
}

#[derive(Args, Debug)]
pub struct RpcVerifyTransactionProofArgs {
    #[arg(long = "tx-proof-path", id = "tx-proof-path", value_parser = parse_file_path)]
    pub tx_proof_path: String,
}

#[derive(Args, Debug)]
pub struct RpcGetForkBlockArgs {
    #[arg(long = "hash", id = "hash", value_parser = parse_h256)]
    pub hash: String,
    #[arg(long = "packed", id = "packed")]
    pub packed: bool,
}

#[derive(Args, Debug)]
pub struct RpcGetBlockMedianTimeArgs {
    #[arg(long = "hash", id = "hash", value_parser = parse_h256)]
    pub hash: String,
}

#[derive(Args, Debug)]
pub struct RpcGetBlockEconomicStateArgs {
    #[arg(long = "hash", id = "hash", value_parser = parse_h256)]
    pub hash: String,
}

#[derive(Args, Debug)]
pub struct RpcEstimateCyclesArgs {
    #[arg(long = "json-path", id = "json-path", value_parser = parse_file_path)]
    pub json_path: String,
}

#[derive(Args, Debug)]
pub struct RpcGetFeeRateStaticsArgs {
    #[arg(long = "target", id = "target", value_parser = parse_fee_rate_target)]
    pub target: Option<String>,
}

#[derive(Args, Debug)]
pub struct RpcGetFeeRateStatisticsArgs {
    #[arg(long = "target", id = "target", value_parser = parse_fee_rate_target)]
    pub target: Option<String>,
}

#[derive(Args, Debug)]
pub struct RpcGetTransactionAndWitnessProofArgs {
    #[arg(long = "tx-hash", id = "tx-hash", action = ArgAction::Append, num_args = 1.., value_parser = parse_h256)]
    pub tx_hash: Vec<String>,
    #[arg(long = "block-hash", id = "block-hash", value_parser = parse_h256)]
    pub block_hash: Option<String>,
}

#[derive(Args, Debug)]
pub struct RpcVerifyTransactionAndWitnessProofArgs {
    #[arg(long = "json-path", id = "json-path", value_parser = parse_file_path)]
    pub json_path: String,
}

#[derive(Args, Debug)]
pub struct RpcSetBanArgs {
    #[arg(long = "address", id = "address", value_parser = parse_ip_network)]
    pub address: String,
    #[arg(long = "command", id = "command", value_parser = ["insert", "delete"])]
    pub command: String,
    #[arg(long = "ban_time", id = "ban_time", default_value = "24h", value_parser = parse_duration)]
    pub ban_time: String,
    #[arg(long = "reason", id = "reason")]
    pub reason: Option<String>,
}

#[derive(Args, Debug)]
pub struct RpcSetNetworkActiveArgs {
    #[arg(long = "state", id = "state", value_parser = ["enable", "disable"])]
    pub state: String,
}

#[derive(Args, Debug)]
pub struct RpcAddNodeArgs {
    #[arg(long = "peer-id", id = "peer-id")]
    pub peer_id: String,
    #[arg(long = "address", id = "address", value_parser = parse_multiaddr)]
    pub address: String,
}

#[derive(Args, Debug)]
pub struct RpcRemoveNodeArgs {
    #[arg(long = "peer-id", id = "peer-id")]
    pub peer_id: String,
}

#[derive(Args, Debug)]
pub struct RpcRemoveTransactionArgs {
    #[arg(long = "tx-hash", id = "tx-hash", value_parser = parse_h256)]
    pub tx_hash: String,
}

#[derive(Args, Debug)]
pub struct RpcTestTxPoolAcceptArgs {
    #[arg(long = "tx-file", id = "tx-file")]
    pub tx_file: String,
}

#[derive(Args, Debug)]
pub struct RpcGetRawTxPoolArgs {
    #[arg(long = "verbose", id = "verbose")]
    pub verbose: bool,
}

#[derive(Args, Debug)]
pub struct RpcSendAlertArgs {
    #[arg(long = "json-path", id = "json-path", value_parser = parse_file_path)]
    pub json_path: String,
}

#[derive(Args, Debug)]
pub struct RpcNotifyTransactionArgs {
    #[arg(long = "json-path", id = "json-path", value_parser = parse_file_path)]
    pub json_path: String,
}

#[derive(Args, Debug)]
pub struct RpcTruncateArgs {
    #[arg(long = "tip-hash", id = "tip-hash", value_parser = parse_h256)]
    pub tip_hash: String,
}

#[derive(Args, Debug)]
pub struct RpcGenerateEpochsArgs {
    #[arg(long = "num-epochs", id = "num-epochs")]
    pub num_epochs: String,
}

#[derive(Args, Debug)]
pub struct RpcGetCellsArgs {
    #[arg(long = "json-path", id = "json-path", value_parser = parse_file_path)]
    pub json_path: String,
    #[arg(long = "order", id = "order", value_parser = ["asc", "desc"])]
    pub order: String,
    #[arg(long = "limit", id = "limit", value_parser = parse_u64)]
    pub limit: String,
    #[arg(long = "after", id = "after", value_parser = parse_hex)]
    pub after: Option<String>,
}

#[derive(Args, Debug)]
pub struct RpcGetTransactionsArgs {
    #[arg(long = "json-path", id = "json-path", value_parser = parse_file_path)]
    pub json_path: String,
    #[arg(long = "order", id = "order", value_parser = ["asc", "desc"])]
    pub order: String,
    #[arg(long = "limit", id = "limit", value_parser = parse_u64)]
    pub limit: String,
    #[arg(long = "after", id = "after", value_parser = parse_hex)]
    pub after: Option<String>,
}

#[derive(Args, Debug)]
pub struct RpcGetCellsCapacityArgs {
    #[arg(long = "json-path", id = "json-path", value_parser = parse_file_path)]
    pub json_path: String,
}

impl<'a> RpcSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        raw_rpc_client: &'a mut RawHttpRpcClient,
    ) -> RpcSubCommand<'a> {
        RpcSubCommand {
            rpc_client,
            raw_rpc_client,
        }
    }

    pub fn subcommand() -> Command {
        RpcCmd::command()
    }
}

impl CliSubCommand for RpcSubCommand<'_> {
    fn process(&mut self, matches: &ArgMatches, _debug: bool) -> Result<Output, String> {
        let is_raw_data = matches.is_present("raw-data");
        match matches.subcommand() {
            // [Chain]
            Some(("get_block", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let with_cycles = m.is_present("with-cycles");
                let packed = m.is_present("packed");
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;

                if is_raw_data {
                    let verbose = if packed {
                        Some("0x0")
                    } else {
                        None /* Some("0x2") */
                    };
                    let resp = self
                        .raw_rpc_client
                        .post::<_, Option<rpc_types::BlockResponse>>(
                            "get_block",
                            (hash, verbose, with_cycles),
                        )
                        .map(RawOptionBlockResponse)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    match (packed, with_cycles) {
                        (true, true) => {
                            let resp = self
                                .rpc_client
                                .get_packed_block_with_cycles(hash)
                                .map(OptionPackedBlockResponse)?;
                            Ok(Output::new_output(resp))
                        }
                        (true, false) => {
                            let resp = self
                                .rpc_client
                                .get_packed_block(hash)
                                .map(OptionJsonBytes)?;
                            Ok(Output::new_output(resp))
                        }
                        (false, true) => {
                            let resp = self.rpc_client.get_block_with_cycles(hash)?;
                            Ok(Output::new_output(resp))
                        }
                        (false, false) => {
                            let resp = self.rpc_client.get_block(hash).map(OptionBlockView)?;
                            Ok(Output::new_output(resp))
                        }
                    }
                }
            }
            Some(("get_block_by_number", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let with_cycles = m.is_present("with-cycles");
                let packed = m.is_present("packed");
                let number: u64 = FromStrParser::<u64>::default().from_matches(m, "number")?;

                if is_raw_data {
                    let verbose = if packed {
                        Some("0x0")
                    } else {
                        None /* Some("0x2") */
                    };
                    let resp = self
                        .raw_rpc_client
                        .post::<_, Option<rpc_types::BlockResponse>>(
                            "get_block_by_number",
                            (BlockNumber::from(number), verbose, with_cycles),
                        )
                        .map(RawOptionBlockResponse)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    match (packed, with_cycles) {
                        (true, true) => {
                            let resp = self
                                .rpc_client
                                .get_packed_block_by_number_with_cycles(number)
                                .map(OptionPackedBlockResponse)?;
                            Ok(Output::new_output(resp))
                        }
                        (true, false) => {
                            let resp = self
                                .rpc_client
                                .get_packed_block_by_number(number)
                                .map(OptionJsonBytes)?;
                            Ok(Output::new_output(resp))
                        }
                        (false, true) => {
                            let resp = self.rpc_client.get_block_by_number_with_cycles(number)?;
                            Ok(Output::new_output(resp))
                        }
                        (false, false) => {
                            let resp = self
                                .rpc_client
                                .get_block_by_number(number)
                                .map(OptionBlockView)?;
                            Ok(Output::new_output(resp))
                        }
                    }
                }
            }
            Some(("get_block_hash", m)) => {
                let number: u64 = FromStrParser::<u64>::default().from_matches(m, "number")?;

                let resp = self.rpc_client.get_block_hash(number).map(OptionH256)?;
                Ok(Output::new_output(resp))
            }
            Some(("get_current_epoch", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_current_epoch()
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.get_current_epoch()?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("get_epoch_by_number", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let number: u64 = FromStrParser::<u64>::default().from_matches(m, "number")?;

                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_epoch_by_number(EpochNumber::from(number))
                        .map(RawOptionEpochView)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self
                        .rpc_client
                        .get_epoch_by_number(number)
                        .map(OptionEpochView)?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("get_header", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let packed = m.is_present("packed");
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;

                if is_raw_data {
                    if packed {
                        let resp = self
                            .raw_rpc_client
                            .get_packed_header(hash)
                            .map(OptionJsonBytes)
                            .map_err(|err| err.to_string())?;
                        Ok(Output::new_output(resp))
                    } else {
                        let resp = self
                            .raw_rpc_client
                            .get_header(hash)
                            .map(RawOptionHeaderView)
                            .map_err(|err| err.to_string())?;
                        Ok(Output::new_output(resp))
                    }
                } else if packed {
                    let resp = self
                        .rpc_client
                        .get_packed_header(hash)
                        .map(OptionJsonBytes)?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.get_header(hash).map(OptionHeaderView)?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("get_header_by_number", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let packed = m.is_present("packed");
                let number: u64 = FromStrParser::<u64>::default().from_matches(m, "number")?;

                if is_raw_data {
                    if packed {
                        let resp = self
                            .raw_rpc_client
                            .get_packed_header_by_number(BlockNumber::from(number))
                            .map(OptionJsonBytes)
                            .map_err(|err| err.to_string())?;
                        Ok(Output::new_output(resp))
                    } else {
                        let resp = self
                            .raw_rpc_client
                            .get_header_by_number(BlockNumber::from(number))
                            .map(RawOptionHeaderView)
                            .map_err(|err| err.to_string())?;
                        Ok(Output::new_output(resp))
                    }
                } else if packed {
                    let resp = self
                        .rpc_client
                        .get_packed_header_by_number(number)
                        .map(OptionJsonBytes)?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self
                        .rpc_client
                        .get_header_by_number(number)
                        .map(OptionHeaderView)?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("get_live_cell", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let include_tx_pool = m.is_present("include-tx-pool");
                let tx_hash: H256 =
                    FixedHashParser::<H256>::default().from_matches(m, "tx-hash")?;
                let index: u32 = FromStrParser::<u32>::default().from_matches(m, "index")?;
                let with_data = m.is_present("with-data");

                let out_point = packed::OutPoint::new_builder()
                    .tx_hash(tx_hash.pack())
                    .index(index)
                    .build();
                if is_raw_data {
                    let resp = {
                        if include_tx_pool {
                            self.raw_rpc_client
                                .get_live_cell_with_include_tx_pool(
                                    out_point.into(),
                                    with_data,
                                    include_tx_pool,
                                )
                                .map_err(|err| err.to_string())?
                        } else {
                            self.raw_rpc_client
                                .get_live_cell(out_point.into(), with_data)
                                .map_err(|err| err.to_string())?
                        }
                    };
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.get_live_cell(
                        out_point,
                        with_data,
                        Some(include_tx_pool),
                    )?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("get_tip_block_number", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_tip_block_number()
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self
                        .rpc_client
                        .get_tip_block_number()
                        .map(|number| serde_json::json!(number))?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("get_tip_header", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let packed = m.is_present("packed");
                if is_raw_data {
                    if packed {
                        let resp = self
                            .raw_rpc_client
                            .get_packed_tip_header()
                            .map(Some)
                            .map(OptionJsonBytes)
                            .map_err(|err| err.to_string())?;
                        Ok(Output::new_output(resp))
                    } else {
                        let resp = self
                            .raw_rpc_client
                            .get_tip_header()
                            .map_err(|err| err.to_string())?;
                        Ok(Output::new_output(resp))
                    }
                } else if packed {
                    let resp = self.rpc_client.get_packed_tip_header()?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.get_tip_header()?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("get_transaction", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let packed = m.is_present("packed");
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;

                if is_raw_data {
                    let verbosity = if packed { Some("0x0") } else { None };
                    let resp = self
                        .raw_rpc_client
                        .post::<_, Option<rpc_types::TransactionWithStatusResponse>>(
                            "get_transaction",
                            (hash, verbosity),
                        )
                        .map(RawOptionTransactionWithStatusResponse)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else if packed {
                    let resp = self.rpc_client.get_packed_transaction(hash)?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self
                        .rpc_client
                        .get_transaction(hash)
                        .map(OptionTransactionWithStatus)?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("get_transaction_proof", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let tx_hashes: Vec<H256> =
                    FixedHashParser::<H256>::default().from_matches_vec(m, "tx-hash")?;
                let block_hash: Option<H256> =
                    FixedHashParser::<H256>::default().from_matches_opt(m, "block-hash")?;

                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_transaction_proof(tx_hashes, block_hash)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self
                        .rpc_client
                        .get_transaction_proof(tx_hashes, block_hash)?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("verify_transaction_proof", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let path: PathBuf = FilePathParser::new(true).from_matches(m, "tx-proof-path")?;
                let content = fs::read_to_string(path).map_err(|err| err.to_string())?;

                if is_raw_data {
                    let proof: rpc_types::TransactionProof =
                        serde_json::from_str(&content).map_err(|err| err.to_string())?;
                    let resp = self
                        .raw_rpc_client
                        .verify_transaction_proof(proof)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let proof: TransactionProof =
                        serde_json::from_str(&content).map_err(|err| err.to_string())?;
                    let resp = self.rpc_client.verify_transaction_proof(proof)?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("get_fork_block", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let packed = m.is_present("packed");
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;

                if is_raw_data {
                    if packed {
                        let resp = self
                            .raw_rpc_client
                            .get_packed_fork_block(hash)
                            .map(OptionJsonBytes)
                            .map_err(|err| err.to_string())?;
                        Ok(Output::new_output(resp))
                    } else {
                        let resp = self
                            .raw_rpc_client
                            .get_fork_block(hash)
                            .map(RawOptionBlockView)
                            .map_err(|err| err.to_string())?;
                        Ok(Output::new_output(resp))
                    }
                } else {
                    let resp = self.rpc_client.get_fork_block(hash).map(OptionBlockView)?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("get_consensus", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_consensus()
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.get_consensus()?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("get_block_median_time", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;

                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_block_median_time(hash)
                        .map(RawOptionTimestamp)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self
                        .rpc_client
                        .get_block_median_time(hash)
                        .map(OptionTimestamp)?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("get_block_economic_state", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;

                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_block_economic_state(hash)
                        .map(RawOptionBlockEconomicState)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self
                        .rpc_client
                        .get_block_economic_state(hash)
                        .map(OptionBlockEconomicState)?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("estimate_cycles", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let json_path: PathBuf = FilePathParser::new(true).from_matches(m, "json-path")?;
                let content = fs::read_to_string(json_path).map_err(|err| err.to_string())?;
                let tx: Transaction =
                    serde_json::from_str(&content).map_err(|err| err.to_string())?;
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .estimate_cycles(tx)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.estimate_cycles(tx.into())?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("get_fee_rate_statics", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let target: Option<u64> =
                    FeeRateStatisticsTargetParser {}.from_matches_opt(m, "target")?;

                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_fee_rate_statics(target.map(|v| v.into()))
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.get_fee_rate_statistics(target)?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("get_fee_rate_statistics", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let target: Option<u64> =
                    FeeRateStatisticsTargetParser {}.from_matches_opt(m, "target")?;

                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_fee_rate_statics(target.map(|v| v.into()))
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.get_fee_rate_statistics(target)?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("get_deployments_info", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");

                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_deployments_info()
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.get_deployments_info()?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("get_transaction_and_witness_proof", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let tx_hashes: Vec<H256> =
                    FixedHashParser::<H256>::default().from_matches_vec(m, "tx-hash")?;
                let block_hash: Option<H256> =
                    FixedHashParser::<H256>::default().from_matches_opt(m, "block-hash")?;

                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_transaction_and_witness_proof(tx_hashes, block_hash)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self
                        .rpc_client
                        .get_transaction_and_witness_proof(tx_hashes, block_hash)?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("verify_transaction_and_witness_proof", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");

                let json_path: PathBuf = FilePathParser::new(true).from_matches(m, "json-path")?;
                let content = fs::read_to_string(json_path).map_err(|err| err.to_string())?;

                let tx_and_witness_proof: rpc_types::TransactionAndWitnessProof =
                    serde_json::from_str(&content).map_err(|err| err.to_string())?;
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .verify_transaction_and_witness_proof(tx_and_witness_proof)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self
                        .rpc_client
                        .verify_transaction_and_witness_proof(tx_and_witness_proof.into())?;
                    Ok(Output::new_output(resp))
                }
            }
            // [Net]
            Some(("get_banned_addresses", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_banned_addresses()
                        .map(RawBannedAddrList)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.get_banned_addresses().map(BannedAddrList)?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("get_peers", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_peers()
                        .map(RawRemoteNodes)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.get_peers().map(RemoteNodes)?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("local_node_info", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .local_node_info()
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.local_node_info()?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("set_ban", m)) => {
                let address: IpNetwork =
                    FromStrParser::<IpNetwork>::new().from_matches(m, "address")?;
                let ban_time: Duration = DurationParser.from_matches(m, "ban_time")?;
                let command = m.value_of("command").map(|v| v.to_string()).unwrap();
                let reason = m.value_of("reason").map(|v| v.to_string());
                let absolute = Some(false);
                let ban_time = Some(ban_time.as_secs() * 1000);

                self.rpc_client.set_ban(
                    address.to_string(),
                    command,
                    ban_time,
                    absolute,
                    reason,
                )?;
                Ok(Output::new_success())
            }
            Some(("sync_state", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .sync_state()
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.sync_state()?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("set_network_active", m)) => {
                let state = m.value_of("state").unwrap() == "enable";
                self.rpc_client.set_network_active(state)?;
                Ok(Output::new_success())
            }
            Some(("add_node", m)) => {
                let peer_id = m.value_of("peer-id").map(|v| v.to_string()).unwrap();
                let address: Multiaddr =
                    FromStrParser::<Multiaddr>::new().from_matches(m, "address")?;
                self.rpc_client.add_node(peer_id, address.to_string())?;
                Ok(Output::new_success())
            }
            Some(("remove_node", m)) => {
                let peer_id = m.value_of("peer-id").map(|v| v.to_string()).unwrap();
                self.rpc_client.remove_node(peer_id)?;
                Ok(Output::new_success())
            }
            Some(("clear_banned_addresses", _)) => {
                self.rpc_client.clear_banned_addresses()?;
                Ok(Output::new_success())
            }
            Some(("ping_peers", _)) => {
                self.rpc_client.ping_peers()?;
                Ok(Output::new_success())
            }
            // [Pool]
            Some(("remove_transaction", m)) => {
                let tx_hash: H256 =
                    FixedHashParser::<H256>::default().from_matches(m, "tx-hash")?;
                let resp = self.rpc_client.remove_transaction(tx_hash)?;
                Ok(Output::new_output(resp))
            }
            Some(("tx_pool_info", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .tx_pool_info()
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.tx_pool_info()?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("clear_tx_verify_queue", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    self.raw_rpc_client
                        .clear_tx_verify_queue()
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(()))
                } else {
                    let _ = self.rpc_client.clear_tx_verify_queue();
                    Ok(Output::new_output(()))
                }
            }
            Some(("test_tx_pool_accept", m)) => {
                let tx_file: PathBuf = FilePathParser::new(false).from_matches(m, "tx-file")?;

                let mut live_cell_cache: HashMap<(OutPoint, bool), (CellOutput, Bytes)> =
                    Default::default();
                let mut get_live_cell = |out_point: OutPoint, with_data: bool| {
                    get_live_cell_with_cache(
                        &mut live_cell_cache,
                        self.rpc_client,
                        out_point,
                        with_data,
                    )
                    .map(|(output, _)| output)
                };

                let file = fs::File::open(tx_file).map_err(|err| err.to_string())?;
                let repr: ReprTxHelper =
                    serde_json::from_reader(&file).map_err(|err| err.to_string())?;
                let helper = TxHelper::try_from(repr)?;

                let tx_view = helper.build_tx(&mut get_live_cell, true)?;
                let tx = tx_view.data();

                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .test_tx_pool_accept(tx.into(), None)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.test_tx_pool_accept(tx, None)?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("clear_tx_pool", _)) => {
                self.rpc_client.clear_tx_pool()?;
                Ok(Output::new_success())
            }
            Some(("tx_pool_ready", _)) => {
                let resp = self.rpc_client.tx_pool_ready()?;
                Ok(Output::new_output(resp))
            }
            Some(("get_raw_tx_pool", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let verbose = m.is_present("verbose");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_raw_tx_pool(Some(verbose))
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.get_raw_tx_pool(Some(verbose))?;
                    Ok(Output::new_output(resp))
                }
            }
            // [Stats]
            Some(("get_blockchain_info", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_blockchain_info()
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.get_blockchain_info()?;
                    Ok(Output::new_output(resp))
                }
            }
            // [Alert]
            Some(("send_alert", m)) => {
                let json_path: PathBuf = FilePathParser::new(true).from_matches(m, "json-path")?;
                let content = fs::read_to_string(json_path).map_err(|err| err.to_string())?;
                let alert: Alert = serde_json::from_str(&content).map_err(|err| err.to_string())?;
                self.rpc_client.send_alert(alert)?;
                Ok(Output::new_success())
            }
            // [IntegrationTest]
            Some(("notify_transaction", m)) => {
                let json_path: PathBuf = FilePathParser::new(true).from_matches(m, "json-path")?;
                let content = fs::read_to_string(json_path).map_err(|err| err.to_string())?;
                let tx: Transaction =
                    serde_json::from_str(&content).map_err(|err| err.to_string())?;
                let resp = self.rpc_client.notify_transaction(tx.into())?;
                Ok(Output::new_output(resp))
            }
            Some(("truncate", m)) => {
                let target_tip_hash: H256 =
                    FixedHashParser::<H256>::default().from_matches(m, "tip-hash")?;
                self.rpc_client.truncate(target_tip_hash)?;
                Ok(Output::new_success())
            }
            Some(("generate_block", _m)) => {
                let resp = self.rpc_client.generate_block()?;
                Ok(Output::new_output(resp))
            }
            Some(("generate_epochs", m)) => {
                let num_epochs: u64 =
                    FromStrParser::<u64>::default().from_matches(m, "num-epochs")?;
                let resp = self.rpc_client.generate_epochs(num_epochs)?;
                Ok(Output::new_output(resp))
            }
            // [Indexer]
            Some(("get_indexer_tip", m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_indexer_tip()
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.get_indexer_tip()?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("get_cells", m)) => {
                let json_path: PathBuf = FilePathParser::new(true)
                    .from_matches_opt(m, "json-path")?
                    .expect("json-path is required");
                let content = fs::read_to_string(json_path).map_err(|err| err.to_string())?;
                let search_key = serde_json::from_str(&content).map_err(|err| err.to_string())?;
                let order_str = m.value_of("order").expect("order is required");
                let order = parse_order(order_str)?;
                let limit: u32 = FromStrParser::<u32>::default().from_matches(m, "limit")?;
                let after_opt: Option<JsonBytes> = HexParser
                    .from_matches_opt::<Bytes>(m, "after")?
                    .map(JsonBytes::from_bytes);

                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_cells(search_key, order, limit.into(), after_opt)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp =
                        self.rpc_client
                            .get_cells(search_key, order, limit.into(), after_opt)?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("get_transactions", m)) => {
                let json_path: PathBuf = FilePathParser::new(true)
                    .from_matches_opt(m, "json-path")?
                    .expect("json-path is required");
                let content = fs::read_to_string(json_path).map_err(|err| err.to_string())?;
                let search_key = serde_json::from_str(&content).map_err(|err| err.to_string())?;
                let order_str = m.value_of("order").expect("order is required");
                let order = parse_order(order_str)?;
                let limit: u32 = FromStrParser::<u32>::default().from_matches(m, "limit")?;
                let after_opt: Option<JsonBytes> = HexParser
                    .from_matches_opt::<Bytes>(m, "after")?
                    .map(JsonBytes::from_bytes);

                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_transactions(search_key, order, limit.into(), after_opt)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.get_transactions(
                        search_key,
                        order,
                        limit.into(),
                        after_opt,
                    )?;
                    Ok(Output::new_output(resp))
                }
            }
            Some(("get_cells_capacity", m)) => {
                let json_path: PathBuf = FilePathParser::new(true)
                    .from_matches_opt(m, "json-path")?
                    .expect("json-path is required");
                let content = fs::read_to_string(json_path).map_err(|err| err.to_string())?;
                let search_key = serde_json::from_str(&content).map_err(|err| err.to_string())?;

                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_cells_capacity(search_key)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.get_cells_capacity(search_key)?;
                    Ok(Output::new_output(resp))
                }
            }
            _ => Err(Self::subcommand().render_usage().to_string()),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct RemoteNodes(pub Vec<RemoteNode>);

#[derive(Serialize, Deserialize)]
pub struct OptionTransactionWithStatus(pub Option<TransactionWithStatus>);

#[derive(Serialize, Deserialize)]
pub struct OptionTimestamp(pub Option<Timestamp>);

#[derive(Serialize, Deserialize)]
pub struct OptionBlockEconomicState(pub Option<BlockEconomicState>);

#[derive(Serialize, Deserialize)]
pub struct OptionBlockView(pub Option<BlockView>);
#[derive(Serialize, Deserialize)]
pub struct OptionPackedBlockResponse(pub Option<crate::utils::rpc::PackedBlockResponse>);
#[derive(Serialize, Deserialize)]
pub struct OptionJsonBytes(pub Option<rpc_types::JsonBytes>);

#[derive(Serialize, Deserialize)]
pub struct OptionHeaderView(pub Option<HeaderView>);

#[derive(Serialize, Deserialize)]
pub struct OptionH256(pub Option<H256>);

#[derive(Serialize, Deserialize)]
pub struct OptionEpochView(pub Option<EpochView>);

#[derive(Serialize, Deserialize)]
pub struct BannedAddrList(pub Vec<BannedAddr>);

#[derive(Serialize, Deserialize)]
pub struct RawRemoteNodes(pub Vec<rpc_types::RemoteNode>);

#[derive(Serialize, Deserialize)]
pub struct RawOptionTransactionWithStatusResponse(
    pub Option<rpc_types::TransactionWithStatusResponse>,
);

#[derive(Serialize, Deserialize)]
pub struct RawOptionBlockView(pub Option<rpc_types::BlockView>);
#[derive(Serialize, Deserialize)]
pub struct RawOptionBlockResponse(pub Option<rpc_types::BlockResponse>);

#[derive(Serialize, Deserialize)]
pub struct RawOptionHeaderView(pub Option<rpc_types::HeaderView>);

#[derive(Serialize, Deserialize)]
pub struct RawOptionTimestamp(pub Option<rpc_types::Timestamp>);

#[derive(Serialize, Deserialize)]
pub struct RawOptionBlockEconomicState(pub Option<rpc_types::BlockEconomicState>);

#[derive(Serialize, Deserialize)]
pub struct RawOptionEpochView(pub Option<rpc_types::EpochView>);

#[derive(Serialize, Deserialize)]
pub struct RawBannedAddrList(pub Vec<rpc_types::BannedAddr>);
