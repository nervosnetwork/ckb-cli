use ckb_jsonrpc_types::{
    BlockNumber, EpochNumber, OutPoint, Timestamp, Transaction, Uint32, Uint64,
};
use ckb_sdk::HttpRpcClient;
use ckb_types::H256;
use clap::{App, Arg, ArgMatches, SubCommand};
use ipnetwork::IpNetwork;
use multiaddr::Multiaddr;
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
}

impl<'a> RpcSubCommand<'a> {
    pub fn new(rpc_client: &'a mut HttpRpcClient) -> RpcSubCommand<'a> {
        RpcSubCommand { rpc_client }
    }

    pub fn subcommand() -> App<'static, 'static> {
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
            .help("Block number");

        let arg_page = Arg::with_name("page")
            .long("page")
            .takes_value(true)
            .validator(|input| FromStrParser::<u64>::default().validate(input))
            .required(true)
            .help("Page number");
        let arg_perpage = Arg::with_name("perpage")
            .long("perpage")
            .takes_value(true)
            .validator(|input| FromStrParser::<u8>::default().validate(input))
            .default_value("50")
            .required(true)
            .help("Page size, max value is 50");
        let arg_reverse_order = Arg::with_name("reverse-order")
            .long("reverse-order")
            .help("Returns the live cells collection in reverse order");
        let arg_peer_id = Arg::with_name("peer-id")
            .long("peer-id")
            .takes_value(true)
            .required(true)
            .help("Node's peer id");

        SubCommand::with_name("rpc")
            .about("Invoke RPC call to node")
            .subcommands(vec![
                // [Chain]
                SubCommand::with_name("get_block")
                    .about("Get block content by hash")
                    .arg(arg_hash.clone().help("Block hash")),
                SubCommand::with_name("get_block_by_number")
                    .about("Get block content by block number")
                    .arg(arg_number.clone()),
                SubCommand::with_name("get_block_hash")
                    .about("Get block hash by block number")
                    .arg(arg_number.clone()),
                SubCommand::with_name("get_cellbase_output_capacity_details")
                    .about("Get block header content by hash")
                    .arg(arg_hash.clone().help("Block hash")),
                SubCommand::with_name("get_cells_by_lock_hash")
                    .about("Get cells by lock script hash")
                    .arg(arg_hash.clone().help("Lock hash"))
                    .arg(
                        Arg::with_name("from")
                            .long("from")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<u64>::default().validate(input))
                            .required(true)
                            .help("From block number"),
                    )
                    .arg(
                        Arg::with_name("to")
                            .long("to")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<u64>::default().validate(input))
                            .required(true)
                            .help("To block number"),
                    ),
                SubCommand::with_name("get_current_epoch").about("Get current epoch information"),
                SubCommand::with_name("get_epoch_by_number")
                    .about("Get epoch information by epoch number")
                    .arg(arg_number.clone().help("Epoch number")),
                SubCommand::with_name("get_header")
                    .about("Get block header content by hash")
                    .arg(arg_hash.clone().help("Block hash")),
                SubCommand::with_name("get_header_by_number")
                    .about("Get block header by block number")
                    .arg(arg_number.clone()),
                SubCommand::with_name("get_live_cell")
                    .about("Get live cell (live means unspent)")
                    .arg(
                        Arg::with_name("tx-hash")
                            .long("tx-hash")
                            .takes_value(true)
                            .validator(|input| FixedHashParser::<H256>::default().validate(input))
                            .required(true)
                            .help("Tx hash"),
                    )
                    .arg(
                        Arg::with_name("index")
                            .long("index")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<u32>::default().validate(input))
                            .required(true)
                            .help("Output index"),
                    )
                    .arg(
                        Arg::with_name("with-data")
                            .long("with-data")
                            .help("Get live cell with data")
                    ),
                SubCommand::with_name("get_tip_block_number").about("Get tip block number"),
                SubCommand::with_name("get_tip_header").about("Get tip header"),
                SubCommand::with_name("get_transaction")
                    .about("Get transaction content by transaction hash")
                    .arg(arg_hash.clone().help("Tx hash")),
                // [Indexer]
                SubCommand::with_name("deindex_lock_hash")
                    .arg(arg_hash.clone().help("Lock script hash"))
                    .about("Remove index for live cells and transactions by the hash of lock script"),
                SubCommand::with_name("get_live_cells_by_lock_hash")
                    .arg(arg_hash.clone().help("Lock script hash"))
                    .arg(arg_page.clone())
                    .arg(arg_perpage.clone())
                    .arg(arg_reverse_order.clone())
                    .about("Get the live cells collection by the hash of lock script"),
                SubCommand::with_name("get_transactions_by_lock_hash")
                    .arg(arg_hash.clone().help("Lock script hash"))
                    .arg(arg_page.clone())
                    .arg(arg_perpage.clone())
                    .arg(arg_reverse_order.clone())
                    .about("Get the transactions collection by the hash of lock script. Returns empty array when the `lock_hash` has not been indexed yet"),
                SubCommand::with_name("index_lock_hash")
                    .arg(arg_hash.clone().help("Lock script hash"))
                    .arg(
                        Arg::with_name("index-from")
                            .long("index-from")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<u64>::default().validate(input))
                            .help("Index from the block number")
                    )
                    .about("Create index for live cells and transactions by the hash of lock script"),
                // [Net]
                SubCommand::with_name("get_banned_addresses").about("Get all banned IPs/Subnets"),
                SubCommand::with_name("get_peers").about("Get connected peers"),
                SubCommand::with_name("local_node_info").about("Get local node information"),
                SubCommand::with_name("set_ban")
                    .arg(
                        Arg::with_name("address")
                            .long("address")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<IpNetwork>::new().validate(input))
                            .required(true)
                            .help("The IP/Subnet with an optional netmask (default is /32 = single IP)")
                    )
                    .arg(
                        Arg::with_name("command")
                            .long("command")
                            .takes_value(true)
                            .possible_values(&["insert", "delete"])
                            .required(true)
                            .help("`insert` to insert an IP/Subnet to the list, `delete` to delete an IP/Subnet from the list")
                    )
                    .arg(
                        Arg::with_name("ban_time")
                            .long("ban_time")
                            .takes_value(true)
                            .validator(|input| DurationParser.validate(input))
                            .required(true)
                            .default_value("24h")
                            .help("How long the IP is banned")
                    )
                    .arg(
                        Arg::with_name("reason")
                            .long("reason")
                            .takes_value(true)
                            .help("Ban reason, optional parameter")
                    )
                    .about("Insert or delete an IP/Subnet from the banned list"),
                // [Pool]
                SubCommand::with_name("tx_pool_info").about("Get transaction pool information"),
                // [`Stats`]
                SubCommand::with_name("get_blockchain_info").about("Get chain information"),
                // [`IntegrationTest`]
                SubCommand::with_name("add_node")
                    .arg(arg_peer_id.clone())
                    .arg(
                        Arg::with_name("address")
                            .long("address")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<Multiaddr>::new().validate(input))
                            .required(true)
                            .help("Target node's address (multiaddr)")
                    )
                    .about("Connect to a node"),
                SubCommand::with_name("remove_node")
                    .arg(arg_peer_id.clone())
                    .about("Disconnect a node"),
                SubCommand::with_name("broadcast_transaction")
                    .arg(
                        Arg::with_name("json-path")
                         .long("json-path")
                         .takes_value(true)
                         .required(true)
                         .validator(|input| FilePathParser::new(true).validate(input))
                         .help("Transaction content (json format, see rpc send_transaction)")
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
    ) -> Result<String, String> {
        match matches.subcommand() {
            // [Chain]
            ("get_block", Some(m)) => {
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;

                let resp = self
                    .rpc_client
                    .get_block(hash)
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            ("get_block_by_number", Some(m)) => {
                let number: u64 = FromStrParser::<u64>::default().from_matches(m, "number")?;

                let resp = self
                    .rpc_client
                    .get_block_by_number(BlockNumber::from(number))
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            ("get_block_hash", Some(m)) => {
                let number: u64 = FromStrParser::<u64>::default().from_matches(m, "number")?;

                let resp = self
                    .rpc_client
                    .get_block_hash(BlockNumber::from(number))
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            ("get_cellbase_output_capacity_details", Some(m)) => {
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;

                let resp = self
                    .rpc_client
                    .get_cellbase_output_capacity_details(hash)
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            ("get_cells_by_lock_hash", Some(m)) => {
                let lock_hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;
                let from_number: u64 = FromStrParser::<u64>::default().from_matches(m, "from")?;
                let to_number: u64 = FromStrParser::<u64>::default().from_matches(m, "to")?;

                let resp = self
                    .rpc_client
                    .get_cells_by_lock_hash(
                        lock_hash,
                        BlockNumber::from(from_number),
                        BlockNumber::from(to_number),
                    )
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            ("get_current_epoch", _) => {
                let resp = self
                    .rpc_client
                    .get_current_epoch()
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            ("get_epoch_by_number", Some(m)) => {
                let number: u64 = FromStrParser::<u64>::default().from_matches(m, "number")?;
                let resp = self
                    .rpc_client
                    .get_epoch_by_number(EpochNumber::from(number))
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            ("get_header", Some(m)) => {
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;

                let resp = self
                    .rpc_client
                    .get_header(hash)
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            ("get_header_by_number", Some(m)) => {
                let number: u64 = FromStrParser::<u64>::default().from_matches(m, "number")?;

                let resp = self
                    .rpc_client
                    .get_header_by_number(BlockNumber::from(number))
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            ("get_live_cell", Some(m)) => {
                let tx_hash: H256 =
                    FixedHashParser::<H256>::default().from_matches(m, "tx-hash")?;
                let index: u32 = FromStrParser::<u32>::default().from_matches(m, "index")?;
                let with_data = m.is_present("with-data");
                let out_point = OutPoint {
                    tx_hash,
                    index: Uint32::from(index),
                };

                let resp = self
                    .rpc_client
                    .get_live_cell(out_point, with_data)
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            ("get_tip_block_number", _) => {
                let resp = self
                    .rpc_client
                    .get_tip_block_number()
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            ("get_tip_header", _) => {
                let resp = self
                    .rpc_client
                    .get_tip_header()
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            ("get_transaction", Some(m)) => {
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;

                let resp = self
                    .rpc_client
                    .get_transaction(hash)
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            // [Indexer]
            ("deindex_lock_hash", Some(m)) => {
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;

                self.rpc_client
                    .deindex_lock_hash(hash)
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(String::from("DONE"))
            }
            ("get_live_cells_by_lock_hash", Some(m)) => {
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;
                let page: u64 = FromStrParser::<u64>::default().from_matches(m, "page")?;
                let perpage: u8 = FromStrParser::<u8>::default().from_matches(m, "perpage")?;
                let reverse_order = m.is_present("reverse-order");

                let resp = self
                    .rpc_client
                    .get_live_cells_by_lock_hash(
                        hash,
                        Uint64::from(page),
                        Uint64::from(u64::from(perpage)),
                        Some(reverse_order),
                    )
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            ("get_transactions_by_lock_hash", Some(m)) => {
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;
                let page: u64 = FromStrParser::<u64>::default().from_matches(m, "page")?;
                let perpage: u8 = FromStrParser::<u8>::default().from_matches(m, "perpage")?;
                let reverse_order = m.is_present("reverse-order");

                let resp = self
                    .rpc_client
                    .get_transactions_by_lock_hash(
                        hash,
                        Uint64::from(page),
                        Uint64::from(u64::from(perpage)),
                        Some(reverse_order),
                    )
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            ("index_lock_hash", Some(m)) => {
                let hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "hash")?;
                let index_from: Option<u64> =
                    FromStrParser::<u64>::default().from_matches_opt(m, "index-from", false)?;

                let resp = self
                    .rpc_client
                    .index_lock_hash(hash, index_from.map(BlockNumber::from))
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            // [Net]
            ("get_banned_addresses", _) => {
                let resp = self
                    .rpc_client
                    .get_banned_addresses()
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            ("get_peers", _) => {
                let resp = self
                    .rpc_client
                    .get_peers()
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            ("local_node_info", _) => {
                let resp = self
                    .rpc_client
                    .local_node_info()
                    .call()
                    .map_err(|err| err.description().to_string())?;
                Ok(resp.render(format, color))
            }
            ("set_ban", Some(m)) => {
                let address: IpNetwork =
                    FromStrParser::<IpNetwork>::new().from_matches(m, "address")?;
                let ban_time: Duration = DurationParser.from_matches(m, "ban_time")?;
                let command = m.value_of("command").map(|v| v.to_string()).unwrap();
                let reason = m.value_of("reason").map(|v| v.to_string());
                let absolute = Some(false);
                let ban_time = Some(Timestamp::from(ban_time.as_secs() * 1000));

                self.rpc_client
                    .set_ban(address.to_string(), command, ban_time, absolute, reason)
                    .call()
                    .map_err(|err| err.description().to_string())?;
                Ok(String::from("DONE"))
            }
            // [Pool]
            ("tx_pool_info", _) => {
                let resp = self
                    .rpc_client
                    .tx_pool_info()
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            // [Stats]
            ("get_blockchain_info", _) => {
                let resp = self
                    .rpc_client
                    .get_blockchain_info()
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            // [IntegrationTest]
            ("add_node", Some(m)) => {
                let peer_id = m.value_of("peer-id").map(|v| v.to_string()).unwrap();
                let address: Multiaddr =
                    FromStrParser::<Multiaddr>::new().from_matches(m, "address")?;

                self.rpc_client
                    .add_node(peer_id, address.to_string())
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(String::from("DONE"))
            }
            ("remove_node", Some(m)) => {
                let peer_id = m.value_of("peer-id").map(|v| v.to_string()).unwrap();

                self.rpc_client
                    .remove_node(peer_id)
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(String::from("DONE"))
            }
            ("broadcast_transaction", Some(m)) => {
                let json_path: PathBuf = FilePathParser::new(true).from_matches(m, "json-path")?;
                let content = fs::read_to_string(json_path).map_err(|err| err.to_string())?;
                let tx: Transaction =
                    serde_json::from_str(&content).map_err(|err| err.to_string())?;

                let resp = self
                    .rpc_client
                    .broadcast_transaction(tx)
                    .call()
                    .map_err(|err| err.to_string())?;
                Ok(resp.render(format, color))
            }
            _ => Err(matches.usage().to_owned()),
        }
    }
}
