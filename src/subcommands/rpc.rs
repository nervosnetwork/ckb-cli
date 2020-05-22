use ckb_jsonrpc_types::{
    self as rpc_types, BlockNumber, EpochNumber, PeerState, Transaction, Uint64,
};
use ckb_sdk::{
    rpc::{
        BannedAddr, BlockReward, BlockView, CellOutputWithOutPoint, CellTransaction, EpochView,
        HeaderView, LiveCell, Node, RawHttpRpcClient, TransactionWithStatus,
    },
    HttpRpcClient,
};
use ckb_types::{packed, prelude::*, H256};
use clap::{App, Arg, ArgMatches};
use ipnetwork::IpNetwork;
use multiaddr::Multiaddr;
use serde_derive::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use super::CliSubCommand;
use crate::utils::arg_parser::{
    ArgParser, DurationParser, FilePathParser, FixedHashParser, FromStrParser,
};
use crate::utils::printer::{OutputFormat, Printable};

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

        let arg_page = Arg::with_name("page")
            .long("page")
            .takes_value(true)
            .validator(|input| FromStrParser::<u64>::default().validate(input))
            .required(true)
            .about("Page number");
        let arg_perpage = Arg::with_name("perpage")
            .long("perpage")
            .takes_value(true)
            .validator(|input| FromStrParser::<u8>::default().validate(input))
            .default_value("50")
            .required(true)
            .about("Page size, max value is 50");
        let arg_reverse_order = Arg::with_name("reverse-order")
            .long("reverse-order")
            .about("Returns the live cells collection in reverse order");
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
                App::new("get_cellbase_output_capacity_details")
                    .about("Get block header content by hash")
                    .arg(arg_hash.clone().about("Block hash")),
                App::new("get_cells_by_lock_hash")
                    .about("Get cells by lock script hash")
                    .arg(arg_hash.clone().about("Lock hash"))
                    .arg(
                        Arg::with_name("from")
                            .long("from")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<u64>::default().validate(input))
                            .required(true)
                            .about("From block number"),
                    )
                    .arg(
                        Arg::with_name("to")
                            .long("to")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<u64>::default().validate(input))
                            .required(true)
                            .about("To block number"),
                    ),
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
                // [Indexer]
                App::new("deindex_lock_hash")
                    .arg(arg_hash.clone().about("Lock script hash"))
                    .about("Remove index for live cells and transactions by the hash of lock script"),
                App::new("get_live_cells_by_lock_hash")
                    .arg(arg_hash.clone().about("Lock script hash"))
                    .arg(arg_page.clone())
                    .arg(arg_perpage.clone())
                    .arg(arg_reverse_order.clone())
                    .about("Get the live cells collection by the hash of lock script"),
                App::new("get_transactions_by_lock_hash")
                    .arg(arg_hash.clone().about("Lock script hash"))
                    .arg(arg_page.clone())
                    .arg(arg_perpage.clone())
                    .arg(arg_reverse_order.clone())
                    .about("Get the transactions collection by the hash of lock script. Returns empty array when the `lock_hash` has not been indexed yet"),
                App::new("index_lock_hash")
                    .arg(arg_hash.clone().about("Lock script hash"))
                    .arg(
                        Arg::with_name("index-from")
                            .long("index-from")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<u64>::default().validate(input))
                            .about("Index from the block number")
                    )
                    .about("Create index for live cells and transactions by the hash of lock script"),
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
                // [Pool]
                App::new("tx_pool_info").about("Get transaction pool information"),
                // [`Stats`]
                App::new("get_blockchain_info").about("Get chain information"),
                // [`IntegrationTest`]
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
                App::new("broadcast_transaction")
                    .arg(
                        Arg::with_name("json-path")
                         .long("json-path")
                         .takes_value(true)
                         .required(true)
                         .validator(|input| FilePathParser::new(true).validate(input))
                         .about("Transaction content (json format, see rpc send_transaction)")
                    )
                    .about("Broadcast transaction without verify"),
            ])
    }
}

impl<'a> CliSubCommand for RpcSubCommand<'a> {
    fn process(
        &mut self,
        matches: &ArgMatches,
        format: OutputFormat,
        color: bool,
        _debug: bool,
    ) -> Result<String, String> {
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
                    Ok(resp.render(format, color))
                } else {
                    let resp = self.rpc_client.get_block(hash).map(OptionBlockView)?;
                    Ok(resp.render(format, color))
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
                    Ok(resp.render(format, color))
                } else {
                    let resp = self
                        .rpc_client
                        .get_block_by_number(number)
                        .map(OptionBlockView)?;
                    Ok(resp.render(format, color))
                }
            }
            ("get_block_hash", Some(m)) => {
                let number: u64 = FromStrParser::<u64>::default().from_matches(m, "number")?;

                let resp = self.rpc_client.get_block_hash(number).map(OptionH256)?;
                Ok(resp.render(format, color))
            }
            ("get_cellbase_output_capacity_details", Some(m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;

                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_cellbase_output_capacity_details(hash)
                        .map(RawOptionBlockReward)
                        .map_err(|err| err.to_string())?;
                    Ok(resp.render(format, color))
                } else {
                    let resp = self
                        .rpc_client
                        .get_cellbase_output_capacity_details(hash)
                        .map(OptionBlockReward)?;
                    Ok(resp.render(format, color))
                }
            }
            ("get_cells_by_lock_hash", Some(m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let lock_hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;
                let from_number: u64 = FromStrParser::<u64>::default().from_matches(m, "from")?;
                let to_number: u64 = FromStrParser::<u64>::default().from_matches(m, "to")?;

                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_cells_by_lock_hash(
                            lock_hash,
                            BlockNumber::from(from_number),
                            BlockNumber::from(to_number),
                        )
                        .map(RawCellOutputWithOutPoints)
                        .map_err(|err| err.to_string())?;
                    Ok(resp.render(format, color))
                } else {
                    let resp = self
                        .rpc_client
                        .get_cells_by_lock_hash(lock_hash, from_number, to_number)
                        .map(CellOutputWithOutPoints)?;
                    Ok(resp.render(format, color))
                }
            }
            ("get_current_epoch", Some(m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_current_epoch()
                        .map_err(|err| err.to_string())?;
                    Ok(resp.render(format, color))
                } else {
                    let resp = self.rpc_client.get_current_epoch()?;
                    Ok(resp.render(format, color))
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
                    Ok(resp.render(format, color))
                } else {
                    let resp = self
                        .rpc_client
                        .get_epoch_by_number(number)
                        .map(OptionEpochView)?;
                    Ok(resp.render(format, color))
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
                    Ok(resp.render(format, color))
                } else {
                    let resp = self.rpc_client.get_header(hash).map(OptionHeaderView)?;
                    Ok(resp.render(format, color))
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
                    Ok(resp.render(format, color))
                } else {
                    let resp = self
                        .rpc_client
                        .get_header_by_number(number)
                        .map(OptionHeaderView)?;
                    Ok(resp.render(format, color))
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
                    Ok(resp.render(format, color))
                } else {
                    let resp = self.rpc_client.get_live_cell(out_point, with_data)?;
                    Ok(resp.render(format, color))
                }
            }
            ("get_tip_block_number", Some(m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_tip_block_number()
                        .map_err(|err| err.to_string())?;
                    Ok(resp.render(format, color))
                } else {
                    let resp = self
                        .rpc_client
                        .get_tip_block_number()
                        .map(|number| serde_json::json!(number))?;
                    Ok(resp.render(format, color))
                }
            }
            ("get_tip_header", Some(m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_tip_header()
                        .map_err(|err| err.to_string())?;
                    Ok(resp.render(format, color))
                } else {
                    let resp = self.rpc_client.get_tip_header()?;
                    Ok(resp.render(format, color))
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
                    Ok(resp.render(format, color))
                } else {
                    let resp = self
                        .rpc_client
                        .get_transaction(hash)
                        .map(OptionTransactionWithStatus)?;
                    Ok(resp.render(format, color))
                }
            }
            // [Indexer]
            ("deindex_lock_hash", Some(m)) => {
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;
                self.rpc_client.deindex_lock_hash(hash)?;
                Ok(String::from("ok"))
            }
            ("get_live_cells_by_lock_hash", Some(m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;
                let page: u64 = FromStrParser::<u64>::default().from_matches(m, "page")?;
                let perpage: u8 = FromStrParser::<u8>::default().from_matches(m, "perpage")?;
                let reverse_order = m.is_present("reverse-order");

                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_live_cells_by_lock_hash(
                            hash,
                            Uint64::from(page),
                            Uint64::from(u64::from(perpage)),
                            Some(reverse_order),
                        )
                        .map(RawLiveCells)
                        .map_err(|err| err.to_string())?;
                    Ok(resp.render(format, color))
                } else {
                    let resp = self
                        .rpc_client
                        .get_live_cells_by_lock_hash(
                            hash,
                            page,
                            u64::from(perpage),
                            Some(reverse_order),
                        )
                        .map(LiveCells)?;
                    Ok(resp.render(format, color))
                }
            }
            ("get_transactions_by_lock_hash", Some(m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;
                let page: u64 = FromStrParser::<u64>::default().from_matches(m, "page")?;
                let perpage: u8 = FromStrParser::<u8>::default().from_matches(m, "perpage")?;
                let reverse_order = m.is_present("reverse-order");

                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_transactions_by_lock_hash(
                            hash,
                            Uint64::from(page),
                            Uint64::from(u64::from(perpage)),
                            Some(reverse_order),
                        )
                        .map(RawCellTransactions)
                        .map_err(|err| err.to_string())?;
                    Ok(resp.render(format, color))
                } else {
                    let resp = self
                        .rpc_client
                        .get_transactions_by_lock_hash(
                            hash,
                            page,
                            u64::from(perpage),
                            Some(reverse_order),
                        )
                        .map(CellTransactions)?;
                    Ok(resp.render(format, color))
                }
            }
            ("index_lock_hash", Some(m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;
                let index_from: Option<u64> =
                    FromStrParser::<u64>::default().from_matches_opt(m, "index-from", false)?;

                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .index_lock_hash(hash, index_from.map(BlockNumber::from))
                        .map_err(|err| err.to_string())?;
                    Ok(resp.render(format, color))
                } else {
                    let resp = self.rpc_client.index_lock_hash(hash, index_from)?;
                    Ok(resp.render(format, color))
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
                    Ok(resp.render(format, color))
                } else {
                    let resp = self.rpc_client.get_banned_addresses().map(BannedAddrList)?;
                    Ok(resp.render(format, color))
                }
            }
            ("get_peers", Some(m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .get_peers()
                        .map(RawNodes)
                        .map_err(|err| err.to_string())?;
                    Ok(resp.render(format, color))
                } else {
                    let resp = self.rpc_client.get_peers().map(Nodes)?;
                    Ok(resp.render(format, color))
                }
            }
            ("local_node_info", Some(m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .local_node_info()
                        .map_err(|err| err.to_string())?;
                    Ok(resp.render(format, color))
                } else {
                    let resp = self.rpc_client.local_node_info()?;
                    Ok(resp.render(format, color))
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
                Ok(String::from("ok"))
            }
            // [Pool]
            ("tx_pool_info", Some(m)) => {
                let is_raw_data = is_raw_data || m.is_present("raw-data");
                if is_raw_data {
                    let resp = self
                        .raw_rpc_client
                        .tx_pool_info()
                        .map_err(|err| err.to_string())?;
                    Ok(resp.render(format, color))
                } else {
                    let resp = self.rpc_client.tx_pool_info()?;
                    Ok(resp.render(format, color))
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
                    Ok(resp.render(format, color))
                } else {
                    let resp = self.rpc_client.get_blockchain_info()?;
                    Ok(resp.render(format, color))
                }
            }
            // [IntegrationTest]
            ("add_node", Some(m)) => {
                let peer_id = m.value_of("peer-id").map(|v| v.to_string()).unwrap();
                let address: Multiaddr =
                    FromStrParser::<Multiaddr>::new().from_matches(m, "address")?;
                self.rpc_client.add_node(peer_id, address.to_string())?;
                Ok(String::from("ok"))
            }
            ("remove_node", Some(m)) => {
                let peer_id = m.value_of("peer-id").map(|v| v.to_string()).unwrap();
                self.rpc_client.remove_node(peer_id)?;
                Ok(String::from("ok"))
            }
            ("broadcast_transaction", Some(m)) => {
                let json_path: PathBuf = FilePathParser::new(true).from_matches(m, "json-path")?;
                let content = fs::read_to_string(json_path).map_err(|err| err.to_string())?;
                let tx: Transaction =
                    serde_json::from_str(&content).map_err(|err| err.to_string())?;

                let resp = self.rpc_client.broadcast_transaction(tx.into())?;
                Ok(resp.render(format, color))
            }
            _ => Err(Self::subcommand().generate_usage()),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Nodes(pub Vec<Node>);

#[derive(Serialize, Deserialize)]
pub struct OptionTransactionWithStatus(pub Option<TransactionWithStatus>);

#[derive(Serialize, Deserialize)]
pub struct CellOutputWithOutPoints(pub Vec<CellOutputWithOutPoint>);

#[derive(Serialize, Deserialize)]
pub struct OptionBlockView(pub Option<BlockView>);

#[derive(Serialize, Deserialize)]
pub struct OptionHeaderView(pub Option<HeaderView>);

#[derive(Serialize, Deserialize)]
pub struct OptionH256(pub Option<H256>);

#[derive(Serialize, Deserialize)]
pub struct OptionEpochView(pub Option<EpochView>);

#[derive(Serialize, Deserialize)]
pub struct PeerStates(pub Vec<PeerState>);

#[derive(Serialize, Deserialize)]
pub struct BannedAddrList(pub Vec<BannedAddr>);

#[derive(Serialize, Deserialize)]
pub struct OptionBlockReward(pub Option<BlockReward>);

#[derive(Serialize, Deserialize)]
pub struct LiveCells(pub Vec<LiveCell>);

#[derive(Serialize, Deserialize)]
pub struct CellTransactions(pub Vec<CellTransaction>);

#[derive(Serialize, Deserialize)]
pub struct RawNodes(pub Vec<rpc_types::Node>);

#[derive(Serialize, Deserialize)]
pub struct RawOptionTransactionWithStatus(pub Option<rpc_types::TransactionWithStatus>);

#[derive(Serialize, Deserialize)]
pub struct RawCellOutputWithOutPoints(pub Vec<rpc_types::CellOutputWithOutPoint>);

#[derive(Serialize, Deserialize)]
pub struct RawOptionBlockView(pub Option<rpc_types::BlockView>);

#[derive(Serialize, Deserialize)]
pub struct RawOptionHeaderView(pub Option<rpc_types::HeaderView>);

#[derive(Serialize, Deserialize)]
pub struct RawOptionEpochView(pub Option<rpc_types::EpochView>);

#[derive(Serialize, Deserialize)]
pub struct RawBannedAddrList(pub Vec<rpc_types::BannedAddr>);

#[derive(Serialize, Deserialize)]
pub struct RawOptionBlockReward(pub Option<rpc_types::BlockReward>);

#[derive(Serialize, Deserialize)]
pub struct RawLiveCells(pub Vec<rpc_types::LiveCell>);

#[derive(Serialize, Deserialize)]
pub struct RawCellTransactions(pub Vec<rpc_types::CellTransaction>);
