use ckb_jsonrpc_types::{
    self as rpc_types, BlockNumber, EpochNumber, JsonBytes, Script, Transaction,
};
use ckb_sdk::{
    rpc::{
        BannedAddr, BlockView, EpochView, HeaderView, RawHttpRpcClient, RemoteNode, Timestamp,
        TransactionProof, TransactionWithStatus,
    },
    HttpRpcClient,
};
use ckb_types::{bytes::Bytes, packed, prelude::*, H256};
use clap::{App, Arg, ArgMatches};
use ipnetwork::IpNetwork;
use multiaddr::Multiaddr;
use serde_derive::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use super::{CliSubCommand, Output};
use crate::utils::arg_parser::{
    ArgParser, DurationParser, FilePathParser, FixedHashParser, FromStrParser, HexParser,
};

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
                    .arg(arg_hash.clone().about("Block hash")),
                App::new("get_block_by_number")
                    .about("Get block content by block number")
                    .arg(arg_number.clone()),
                App::new("get_block_hash")
                    .about("Get block hash by block number")
                    .arg(arg_number.clone()),
                App::new("get_current_epoch").about("Get current epoch information"),
                App::new("get_epoch_by_number")
                    .about("Get epoch information by epoch number")
                    .arg(arg_number.clone().about("Epoch number")),
                App::new("get_header")
                    .about("Get block header content by hash")
                    .arg(arg_hash.clone().about("Block hash")),
                App::new("get_header_by_number")
                    .about("Get block header by block number")
                    .arg(arg_number.clone()),
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
                        Arg::with_name("with-data")
                            .long("with-data")
                            .about("Get live cell with data")
                    ),
                App::new("get_tip_block_number").about("Get tip block number"),
                App::new("get_tip_header").about("Get tip header"),
                App::new("get_transaction")
                    .about("Get transaction content by transaction hash")
                    .arg(arg_hash.clone().about("Tx hash")),
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
                    .arg(arg_hash.clone().about("The fork block hash")),
                App::new("get_consensus")
                    .about("Return various consensus parameters"),
                App::new("get_block_median_time")
                    .about("Returns the past median time by block hash")
                    .arg(arg_hash.clone().about("A median time is calculated for a consecutive block sequence. `block_hash` indicates the highest block of the sequence")),
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
                App::new("tx_pool_info").about("Get transaction pool information"),
                App::new("get_raw_tx_pool")
                    .about("Returns all transaction ids in tx pool as a json array of string transaction ids")
                    .arg(Arg::with_name("verbose").long("verbose").about("True for a json object, false for array of transaction ids")),
                // [`Stats`]
                App::new("get_blockchain_info").about("Get chain information"),
                // [`IntegrationTest`]
                App::new("broadcast_transaction")
                    .arg(
                        Arg::with_name("json-path")
                         .long("json-path")
                         .takes_value(true)
                         .required(true)
                         .validator(|input| FilePathParser::new(true).validate(input))
                         .about("Transaction content (json format, see rpc send_transaction)")
                    )
                    .arg(
                        Arg::with_name("cycles")
                            .long("cycles")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<u64>::default().validate(input))
                            .required(true)
                            .about("The cycles of the transaction")
                    )
                    .about("[TEST ONLY] Broadcast transaction without verify"),
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
                    .arg(
                        Arg::with_name("json-path")
                            .long("json-path")
                            .takes_value(true)
                            .validator(|input| FilePathParser::new(true).validate(input))
                            .about("Block assembler lock script (json format)")
                    )
                    .arg(
                        Arg::with_name("message")
                            .long("message")
                            .takes_value(true)
                            .validator(|input| HexParser.validate(input))
                            .about("Block assembler message (hex format)")
                    )
                    .about("[TEST ONLY] Generate an empty block")
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
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;

                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_block(hash)
                        .map(RawOptionBlockView)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.get_block(hash).map(OptionBlockView)?;
                    Ok(Output::new_output(resp))
                }
            }
            ("get_block_by_number", Some(m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let number: u64 = FromStrParser::<u64>::default().from_matches(m, "number")?;

                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_block_by_number(BlockNumber::from(number))
                        .map(RawOptionBlockView)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self
                        .rpc_client
                        .get_block_by_number(number)
                        .map(OptionBlockView)?;
                    Ok(Output::new_output(resp))
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
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;

                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_header(hash)
                        .map(RawOptionHeaderView)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.get_header(hash).map(OptionHeaderView)?;
                    Ok(Output::new_output(resp))
                }
            }
            ("get_header_by_number", Some(m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let number: u64 = FromStrParser::<u64>::default().from_matches(m, "number")?;

                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_header_by_number(BlockNumber::from(number))
                        .map(RawOptionHeaderView)
                        .map_err(|err| err.to_string())?;
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
                let tx_hash: H256 =
                    FixedHashParser::<H256>::default().from_matches(m, "tx-hash")?;
                let index: u32 = FromStrParser::<u32>::default().from_matches(m, "index")?;
                let with_data = m.is_present("with-data");

                let out_point = packed::OutPoint::new_builder()
                    .tx_hash(tx_hash.pack())
                    .index(index.pack())
                    .build();
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_live_cell(out_point.into(), with_data)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.get_live_cell(out_point, with_data)?;
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
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_tip_header()
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
                } else {
                    let resp = self.rpc_client.get_tip_header()?;
                    Ok(Output::new_output(resp))
                }
            }
            ("get_transaction", Some(m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;

                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_transaction(hash)
                        .map(RawOptionTransactionWithStatus)
                        .map_err(|err| err.to_string())?;
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
                    FixedHashParser::<H256>::default().from_matches_opt(m, "block-hash", false)?;

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
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;

                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_fork_block(hash)
                        .map(RawOptionBlockView)
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_output(resp))
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
            // [IntegrationTest]
            ("broadcast_transaction", Some(m)) => {
                let cycles: u64 = FromStrParser::<u64>::default().from_matches(m, "cycles")?;
                let json_path: PathBuf = FilePathParser::new(true).from_matches(m, "json-path")?;
                let content = fs::read_to_string(json_path).map_err(|err| err.to_string())?;
                let tx: Transaction =
                    serde_json::from_str(&content).map_err(|err| err.to_string())?;

                let resp = self.rpc_client.broadcast_transaction(tx.into(), cycles)?;
                Ok(Output::new_output(resp))
            }
            ("truncate", Some(m)) => {
                let target_tip_hash: H256 =
                    FixedHashParser::<H256>::default().from_matches(m, "tip-hash")?;
                self.rpc_client.truncate(target_tip_hash)?;
                Ok(Output::new_success())
            }
            ("generate_block", Some(m)) => {
                let json_path_opt: Option<PathBuf> =
                    FilePathParser::new(true).from_matches_opt(m, "json-path", false)?;
                let script_opt: Option<Script> = if let Some(json_path) = json_path_opt {
                    let content = fs::read_to_string(json_path).map_err(|err| err.to_string())?;
                    Some(serde_json::from_str(&content).map_err(|err| err.to_string())?)
                } else {
                    None
                };
                let message_opt: Option<Bytes> = HexParser.from_matches_opt(m, "message", false)?;
                let resp = self
                    .rpc_client
                    .generate_block(script_opt, message_opt.map(JsonBytes::from_bytes))?;
                Ok(Output::new_output(resp))
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
pub struct OptionBlockView(pub Option<BlockView>);

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
pub struct RawOptionTransactionWithStatus(pub Option<rpc_types::TransactionWithStatus>);

#[derive(Serialize, Deserialize)]
pub struct RawOptionBlockView(pub Option<rpc_types::BlockView>);

#[derive(Serialize, Deserialize)]
pub struct RawOptionHeaderView(pub Option<rpc_types::HeaderView>);

#[derive(Serialize, Deserialize)]
pub struct RawOptionTimestamp(pub Option<rpc_types::Timestamp>);

#[derive(Serialize, Deserialize)]
pub struct RawOptionEpochView(pub Option<rpc_types::EpochView>);

#[derive(Serialize, Deserialize)]
pub struct RawBannedAddrList(pub Vec<rpc_types::BannedAddr>);
