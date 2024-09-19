use ckb_jsonrpc_types::{
    self as rpc_types, Alert, BlockNumber, EpochNumber, JsonBytes, Transaction,
};
use ckb_types::packed::{CellOutput, OutPoint};
use ckb_types::{bytes::Bytes, packed, prelude::*, H256};
use clap::{App, Arg, ArgMatches};
use ipnetwork::IpNetwork;
use multiaddr::Multiaddr;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use super::tx::ReprTxHelper;
use super::{CliSubCommand, Output};
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

    pub fn subcommand() -> App<'static> {
        let arg_hash = Arg::with_name("hash")
            .long("hash")
            .takes_value(true)
            .validator(|input| FixedHashParser::<H256>::default().validate(input))
            .required(true);
        let arg_number = Arg::with_name("number")
            .long("number")
            .takes_value(true)
            .validator(|input| FromStrParser::<u64>::default().validate(input))
            .required(true)
            .about("Block number");
        let arg_peer_id = Arg::with_name("peer-id")
            .long("peer-id")
            .takes_value(true)
            .required(true)
            .about("Node's peer id");
        let with_cycles = Arg::with_name("with-cycles")
            .long("with-cycles")
            .about("get block info with cycles");
        let packed = Arg::with_name("packed")
            .long("packed")
            .about("returns a 0x-prefixed hex string");

        App::new("rpc")
            .about("Invoke RPC call to node")
            .arg(
                Arg::with_name("raw-data")
                    .long("raw-data")
                    .global(true)
                    .about("Output raw jsonrpc data")
            )
            .subcommands(vec![
                // [Chain]
                App::new("get_block")
                    .about("Get block content by hash")
                    .arg(arg_hash.clone().about("Block hash"))
                    .arg(with_cycles.clone())
                    .arg(packed.clone()),
                App::new("get_block_by_number")
                    .about("Get block content by block number")
                    .arg(arg_number.clone())
                    .arg(with_cycles.clone())
                    .arg(packed.clone()),
                App::new("get_block_hash")
                    .about("Get block hash by block number")
                    .arg(arg_number.clone()),
                App::new("get_current_epoch").about("Get current epoch information"),
                App::new("get_epoch_by_number")
                    .about("Get epoch information by epoch number")
                    .arg(arg_number.clone().about("Epoch number")),
                App::new("get_header")
                    .about("Get block header content by hash")
                    .arg(arg_hash.clone().about("Block hash"))
                    .arg(packed.clone()),
                App::new("get_header_by_number")
                    .about("Get block header by block number")
                    .arg(arg_number.clone())
                    .arg(packed.clone()),
                App::new("get_live_cell")
                    .about("Get live cell (live means unspent)")
                    .arg(
                        Arg::with_name("tx-hash")
                            .long("tx-hash")
                            .takes_value(true)
                            .validator(|input| FixedHashParser::<H256>::default().validate(input))
                            .required(true)
                            .about("Tx hash"),
                    )
                    .arg(
                        Arg::with_name("index")
                            .long("index")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<u32>::default().validate(input))
                            .required(true)
                            .about("Output index"),
                    )
                    .arg(
                        Arg::with_name("include-tx-pool")
                            .long("include-tx-pool")
                            .about("Weather to check live cell in tx-pool")
                    )
                    .arg(
                        Arg::with_name("with-data")
                            .long("with-data")
                            .about("Get live cell with data")
                    ),
                App::new("get_tip_block_number").about("Get tip block number"),
                App::new("get_tip_header").about("Get tip header")
                .arg(packed.clone()),
                App::new("get_transaction")
                    .about("Get transaction content by transaction hash")
                    .arg(arg_hash.clone().about("Tx hash"))
                    .arg(packed.clone()),
                App::new("get_transaction_proof")
                    .about("Returns a Merkle proof that transactions are included in a block")
                    .arg(
                        Arg::with_name("tx-hash")
                            .long("tx-hash")
                            .takes_value(true)
                            .multiple(true)
                            .validator(|input| FixedHashParser::<H256>::default().validate(input))
                            .about("Transaction hashes, all transactions must be in the same block")
                    )
                    .arg(
                        Arg::with_name("block-hash")
                            .long("block-hash")
                            .takes_value(true)
                            .validator(|input| FixedHashParser::<H256>::default().validate(input))
                            .about("Looks for transactions in the block with this hash")
                    ),
                App::new("verify_transaction_proof")
                    .about("Verifies that a proof points to transactions in a block, returning the transaction hashes it commits to")
                    .arg(
                        Arg::with_name("tx-proof-path")
                            .long("tx-proof-path")
                            .takes_value(true)
                            .required(true)
                            .validator(|input| FilePathParser::new(true).validate(input))
                            .about("File path of proof generated by `get_transaction_proof` (JSON format)")
                    ),
                App::new("get_fork_block")
                    .about("Returns the information about a fork block by hash")
                    .arg(arg_hash.clone().about("The fork block hash"))
                    .arg(packed.clone()),
                App::new("get_consensus")
                    .about("Return various consensus parameters"),
                App::new("get_block_median_time")
                    .about("Returns the past median time by block hash")
                    .arg(arg_hash.clone().about("A median time is calculated for a consecutive block sequence. `block_hash` indicates the highest block of the sequence")),
                App::new("get_block_economic_state")
                    .about("Returns increased issuance, miner reward, and the total transaction fee of a block")
                    .arg(arg_hash.clone().about("Specifies the block hash which rewards should be analyzed")),
                App::new("estimate_cycles")
                    .arg(
                        Arg::with_name("json-path")
                        .long("json-path")
                        .takes_value(true)
                        .required(true)
                        .validator(|input| FilePathParser::new(true).validate(input))
                        .about("Transaction content (json format, see rpc estimate_cycles)")
                    )
                    .about("estimate_cycles run a transaction and return the execution consumed cycles."),
                App::new("get_fee_rate_statics")
                    .arg(
                        Arg::with_name("target")
                            .long("target")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<u64>::default().validate(input))
                            .about("[Deprecated! please use get_fee_rate_statistics] Specify the number (1 - 101) of confirmed blocks to be counted. If the number is even, automatically add one. Default is 21.")
                    )
                    .about("[Deprecated! please use get_fee_rate_statistics] Returns the fee_rate statistics of confirmed blocks on the chain."),
                App::new("get_fee_rate_statistics")
                    .arg(
                        Arg::with_name("target")
                            .long("target")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<u64>::default().validate(input))
                            .about("Specify the number (1 - 101) of confirmed blocks to be counted. If the number is even, automatically add one. Default is 21.")
                    )
                    .about("Returns the fee_rate statistics of confirmed blocks on the chain."),
                App::new("get_deployments_info").about("Returns the information about all deployments"),
                App::new("get_transaction_and_witness_proof")
                    .arg(
                        Arg::with_name("tx-hash")
                            .long("tx-hash")
                            .takes_value(true)
                            .multiple(true)
                            .validator(|input| FixedHashParser::<H256>::default().validate(input))
                            .about("Transaction hashes")
                    )
                    .arg(
                        Arg::with_name("block-hash")
                            .long("block-hash")
                            .takes_value(true)
                            .validator(|input| FixedHashParser::<H256>::default().validate(input))
                            .about("Looks for transactions in the block with this hash")
                    ).about("Returns a Merkle proof that transactions and witnesses are included in a block"),
                App::new("verify_transaction_and_witness_proof")
                    .arg(
                        Arg::with_name("json-path")
                            .long("json-path")
                            .takes_value(true)
                            .required(true)
                            .validator(|input| FilePathParser::new(true).validate(input))
                            .about("File path of proof which is a `TransactionAndWitnessProof` (JSON format)")
                    )
                    .about("Verifies that a proof points to transactions in a block, returning the transaction hashes it commits to"),
                // [Net]
                App::new("get_banned_addresses").about("Get all banned IPs/Subnets"),
                App::new("get_peers").about("Get connected peers"),
                App::new("local_node_info").about("Get local node information"),
                App::new("set_ban")
                    .arg(
                        Arg::with_name("address")
                            .long("address")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<IpNetwork>::new().validate(input))
                            .required(true)
                            .about("The IP/Subnet with an optional netmask (default is /32 = single IP)")
                    )
                    .arg(
                        Arg::with_name("command")
                            .long("command")
                            .takes_value(true)
                            .possible_values(&["insert", "delete"])
                            .required(true)
                            .about("`insert` to insert an IP/Subnet to the list, `delete` to delete an IP/Subnet from the list")
                    )
                    .arg(
                        Arg::with_name("ban_time")
                            .long("ban_time")
                            .takes_value(true)
                            .validator(|input| DurationParser.validate(input))
                            .required(true)
                            .default_value("24h")
                            .about("How long the IP is banned")
                    )
                    .arg(
                        Arg::with_name("reason")
                            .long("reason")
                            .takes_value(true)
                            .about("Ban reason, optional parameter")
                    )
                    .about("Insert or delete an IP/Subnet from the banned list"),
                App::new("sync_state").about("Returns sync state of this node"),
                App::new("set_network_active")
                    .arg(
                        Arg::with_name("state")
                            .long("state")
                            .takes_value(true)
                            .possible_values(&["enable", "disable"])
                            .required(true)
                            .about("The network state to set")
                    )
                    .about("Disable/enable all p2p network activity"),
                App::new("add_node")
                    .arg(arg_peer_id.clone())
                    .arg(
                        Arg::with_name("address")
                            .long("address")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<Multiaddr>::new().validate(input))
                            .required(true)
                            .about("Target node's address (multiaddr)")
                    )
                    .about("Connect to a node"),
                App::new("remove_node")
                    .arg(arg_peer_id.clone())
                    .about("Disconnect a node"),
                App::new("clear_banned_addresses").about("Clears all banned IPs/Subnets"),
                App::new("ping_peers").about("Requests that a ping is sent to all connected peers, to measure ping time"),
                // [Pool]
                App::new("remove_transaction")
                    .about("Removes a transaction and all transactions which depends on it from tx pool if it exists")
                    .arg(
                        Arg::with_name("tx-hash")
                            .long("tx-hash")
                            .takes_value(true)
                            .validator(|input| FixedHashParser::<H256>::default().validate(input))
                            .required(true)
                            .about("Hash of a transaction"),
                    ),
                App::new("tx_pool_info").about("Get transaction pool information"),
                App::new("clear_tx_verify_queue").about("Clear TxPool verify_queue"),
                App::new("test_tx_pool_accept")
                .about("Test if transaction can be accepted by Tx Pool")
                .arg(
                    Arg::with_name("tx-file").long("tx-file").takes_value(true).required(true).about("transaction data file(format json)")
                ),
                App::new("clear_tx_pool").about("Removes all transactions from the transaction pool"),
                App::new("get_raw_tx_pool")
                    .about("Returns all transaction ids in tx pool as a json array of string transaction ids")
                    .arg(Arg::with_name("verbose").long("verbose").about("True for a json object, false for array of transaction ids")),
                App::new("tx_pool_ready").about("Returns whether tx-pool service is started, ready for request"),
                // [`Stats`]
                App::new("get_blockchain_info").about("Get chain information"),
                // [Alert]
                App::new("send_alert")
                    .arg(
                        Arg::with_name("json-path")
                            .long("json-path")
                            .takes_value(true)
                            .required(true)
                            .validator(|input| FilePathParser::new(true).validate(input))
                            .about("The alert message (json format)")
                    )
                    .about("Sends an alert"),
                // [`IntegrationTest`]
                App::new("notify_transaction")
                    .arg(
                        Arg::with_name("json-path")
                         .long("json-path")
                         .takes_value(true)
                         .required(true)
                         .validator(|input| FilePathParser::new(true).validate(input))
                         .about("[TEST ONLY] Transaction content (json format, see rpc send_transaction)")
                    )
                    .about("[TEST ONLY] Notify transaction"),
                App::new("truncate")
                    .arg(
                        Arg::with_name("tip-hash")
                            .long("tip-hash")
                            .takes_value(true)
                            .validator(|input| FixedHashParser::<H256>::default().validate(input))
                            .required(true)
                            .about("Target tip block hash")
                    )
                    .about("[TEST ONLY] Truncate blocks to target tip block"),
                App::new("generate_block")
                    .about("[TEST ONLY] Generate an empty block"),
                App::new("generate_epochs")
                    .arg(
                        Arg::with_name("num-epochs")
                            .long("num-epochs")
                            .takes_value(true)
                            .required(true)
                            .about("The number of epochs to generate.")
                    )
                    .about("[TEST ONLY] Generate epochs"),
                // [`Indexer`]
                App::new("get_indexer_tip").about("Returns the indexed tip"),
                App::new("get_cells")
                    .arg(
                        Arg::with_name("json-path")
                        .long("json-path")
                        .takes_value(true)
                        .validator(|input| FilePathParser::new(true).validate(input))
                        .required(true)
                        .about("Indexer search key"))
                    .arg(
                        Arg::with_name("order")
                            .long("order")
                            .takes_value(true)
                            .possible_values(&["asc", "desc"])
                            .required(true)
                            .about("Indexer search order")
                    )
                    .arg(
                        Arg::with_name("limit")
                            .long("limit")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<u64>::default().validate(input))
                            .required(true)
                            .about("Limit the number of results")
                    )
                    .arg(
                        Arg::with_name("after")
                            .long("after")
                            .takes_value(true)
                            .validator(|input| HexParser.validate(input))
                            .about("Pagination parameter")
                    )
                    .about("Returns the live cells collection by the lock or type script"),
                App::new("get_transactions")
                    .arg(
                        Arg::with_name("json-path")
                        .long("json-path")
                        .takes_value(true)
                        .validator(|input| FilePathParser::new(true).validate(input))
                        .required(true)
                        .about("Indexer search key"))
                    .arg(
                        Arg::with_name("order")
                            .long("order")
                            .takes_value(true)
                            .possible_values(&["asc", "desc"])
                            .required(true)
                            .about("Indexer search order")
                    )
                    .arg(
                        Arg::with_name("limit")
                            .long("limit")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<u64>::default().validate(input))
                            .required(true)
                            .about("Limit the number of results")
                    )
                    .arg(
                        Arg::with_name("after")
                            .long("after")
                            .takes_value(true)
                            .validator(|input| HexParser.validate(input))
                            .about("Pagination parameter")
                    )
                    .about("Returns the transactions collection by the lock or type script"),
                App::new("get_cells_capacity")
                    .arg(
                        Arg::with_name("json-path")
                        .long("json-path")
                        .takes_value(true)
                        .validator(|input| FilePathParser::new(true).validate(input))
                        .required(true)
                        .about("Indexer search key"))
                    .about("Returns the live cells capacity by the lock or type script"),
            ])
    }
}

impl<'a> CliSubCommand for RpcSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches, _debug: bool) -> Result<Output, String> {
        let is_raw_data = matches.is_present("raw-data");
        match matches.subcommand() {
            // [Chain]
            ("get_block", Some(m)) => {
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
            ("get_block_by_number", Some(m)) => {
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
            ("get_block_hash", Some(m)) => {
                let number: u64 = FromStrParser::<u64>::default().from_matches(m, "number")?;

                let resp = self.rpc_client.get_block_hash(number).map(OptionH256)?;
                Ok(Output::new_output(resp))
            }
            ("get_current_epoch", Some(m)) => {
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
            ("get_epoch_by_number", Some(m)) => {
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
            ("get_header", Some(m)) => {
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
            ("get_header_by_number", Some(m)) => {
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
            ("get_live_cell", Some(m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let include_tx_pool = m.is_present("include-tx-pool");
                let tx_hash: H256 =
                    FixedHashParser::<H256>::default().from_matches(m, "tx-hash")?;
                let index: u32 = FromStrParser::<u32>::default().from_matches(m, "index")?;
                let with_data = m.is_present("with-data");

                let out_point = packed::OutPoint::new_builder()
                    .tx_hash(tx_hash.pack())
                    .index(index.pack())
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
            ("get_tip_block_number", Some(m)) => {
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
            ("get_tip_header", Some(m)) => {
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
            ("get_transaction", Some(m)) => {
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
            ("get_transaction_proof", Some(m)) => {
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
            ("verify_transaction_proof", Some(m)) => {
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
            ("get_fork_block", Some(m)) => {
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
            ("get_consensus", Some(m)) => {
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
            ("get_block_median_time", Some(m)) => {
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
            ("get_block_economic_state", Some(m)) => {
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
            ("estimate_cycles", Some(m)) => {
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
            ("get_fee_rate_statics", Some(m)) => {
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
            ("get_fee_rate_statistics", Some(m)) => {
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
            ("get_deployments_info", Some(m)) => {
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
            ("get_transaction_and_witness_proof", Some(m)) => {
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
            ("verify_transaction_and_witness_proof", Some(m)) => {
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
            ("get_banned_addresses", Some(m)) => {
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
            ("get_peers", Some(m)) => {
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
            ("local_node_info", Some(m)) => {
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
            ("set_ban", Some(m)) => {
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
            ("sync_state", Some(m)) => {
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
            ("set_network_active", Some(m)) => {
                let state = m.value_of("state").unwrap() == "enable";
                self.rpc_client.set_network_active(state)?;
                Ok(Output::new_success())
            }
            ("add_node", Some(m)) => {
                let peer_id = m.value_of("peer-id").map(|v| v.to_string()).unwrap();
                let address: Multiaddr =
                    FromStrParser::<Multiaddr>::new().from_matches(m, "address")?;
                self.rpc_client.add_node(peer_id, address.to_string())?;
                Ok(Output::new_success())
            }
            ("remove_node", Some(m)) => {
                let peer_id = m.value_of("peer-id").map(|v| v.to_string()).unwrap();
                self.rpc_client.remove_node(peer_id)?;
                Ok(Output::new_success())
            }
            ("clear_banned_addresses", _) => {
                self.rpc_client.clear_banned_addresses()?;
                Ok(Output::new_success())
            }
            ("ping_peers", _) => {
                self.rpc_client.ping_peers()?;
                Ok(Output::new_success())
            }
            // [Pool]
            ("remove_transaction", Some(m)) => {
                let tx_hash: H256 =
                    FixedHashParser::<H256>::default().from_matches(m, "tx-hash")?;
                let resp = self.rpc_client.remove_transaction(tx_hash)?;
                Ok(Output::new_output(resp))
            }
            ("tx_pool_info", Some(m)) => {
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
            ("clear_tx_verify_queue", Some(m)) => {
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
            ("test_tx_pool_accept", Some(m)) => {
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
            ("clear_tx_pool", _) => {
                self.rpc_client.clear_tx_pool()?;
                Ok(Output::new_success())
            }
            ("tx_pool_ready", _) => {
                let resp = self.rpc_client.tx_pool_ready()?;
                Ok(Output::new_output(resp))
            }
            ("get_raw_tx_pool", Some(m)) => {
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
            ("get_blockchain_info", Some(m)) => {
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
            ("send_alert", Some(m)) => {
                let json_path: PathBuf = FilePathParser::new(true).from_matches(m, "json-path")?;
                let content = fs::read_to_string(json_path).map_err(|err| err.to_string())?;
                let alert: Alert = serde_json::from_str(&content).map_err(|err| err.to_string())?;
                self.rpc_client.send_alert(alert)?;
                Ok(Output::new_success())
            }
            // [IntegrationTest]
            ("notify_transaction", Some(m)) => {
                let json_path: PathBuf = FilePathParser::new(true).from_matches(m, "json-path")?;
                let content = fs::read_to_string(json_path).map_err(|err| err.to_string())?;
                let tx: Transaction =
                    serde_json::from_str(&content).map_err(|err| err.to_string())?;
                let resp = self.rpc_client.notify_transaction(tx.into())?;
                Ok(Output::new_output(resp))
            }
            ("truncate", Some(m)) => {
                let target_tip_hash: H256 =
                    FixedHashParser::<H256>::default().from_matches(m, "tip-hash")?;
                self.rpc_client.truncate(target_tip_hash)?;
                Ok(Output::new_success())
            }
            ("generate_block", Some(_m)) => {
                let resp = self.rpc_client.generate_block()?;
                Ok(Output::new_output(resp))
            }
            ("generate_epochs", Some(m)) => {
                let num_epochs: u64 =
                    FromStrParser::<u64>::default().from_matches(m, "num-epochs")?;
                let resp = self.rpc_client.generate_epochs(num_epochs)?;
                Ok(Output::new_output(resp))
            }
            // [Indexer]
            ("get_indexer_tip", Some(m)) => {
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
            ("get_cells", Some(m)) => {
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
            ("get_transactions", Some(m)) => {
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
            ("get_cells_capacity", Some(m)) => {
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
            _ => Err(Self::subcommand().generate_usage()),
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
