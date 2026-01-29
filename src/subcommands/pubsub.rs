use ckb_jsonrpc_types::{BlockView, HeaderView, PoolTransactionEntry, PoolTransactionReject};
use ckb_sdk::pubsub::Client;
use clap::{ArgAction, ArgMatches, Args, Command, CommandFactory, FromArgMatches, Parser, Subcommand};
use futures::StreamExt;
use std::io;
use std::net::SocketAddr;
use tokio::net::TcpStream;

use super::{CliSubCommand, Output};
use crate::utils::arg_parser::{ArgParser, SocketParser};
use crate::OutputFormat;

fn parse_socket(input: &str) -> Result<String, String> {
    SocketParser.validate(input).map(|_| input.to_string())
}

#[derive(Parser, Debug)]
#[command(name = "subscribe", about = "Subscribe to TCP interface of node")]
pub struct PubSubCmd {
    #[command(subcommand)]
    pub command: PubSubSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum PubSubSubcommands {
    /// Subscribe to new block header notification
    NewTipHeader(PubSubTcpArgs),
    /// Subscribe to new block notification
    NewTipBlock(PubSubTcpArgs),
    /// Subscribe to new transaction notification
    NewTransaction(PubSubTcpArgs),
    /// Subscribe to new proposed transaction notification
    ProposedTransaction(PubSubTcpArgs),
    /// Subscribe to rejected transaction notification
    RejectedTransaction(PubSubTcpArgs),
    /// Subscribe topic list
    List(PubSubListArgs),
}

#[derive(Args, Debug)]
pub struct PubSubTcpArgs {
    #[arg(long, value_parser = parse_socket)]
    pub tcp: String,
}

#[derive(Args, Debug)]
pub struct PubSubListArgs {
    #[arg(long, value_parser = parse_socket)]
    pub tcp: String,
    #[arg(
        short = 't',
        value_parser = [
            "new_tip_header",
            "new_tip_block",
            "new_transaction",
            "proposed_transaction",
            "rejected_transaction",
        ],
        action = ArgAction::Append
    )]
    pub topics: Vec<String>,
}

macro_rules! block_on {
    ($addr:ident, $topic:expr, $output:ty, $format:expr, $color:expr) => {{
        let rt = tokio::runtime::Runtime::new().unwrap();
        let ret: io::Result<Output> = rt.block_on(async {
            let c = new_tcp_client($addr).await?;
            let mut h = c.subscribe_list::<$output, _, _>($topic).await.map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not a subcribe port, please set ckb `tcp_listen_address` to use subcribe rpc feature"))?;
            while let Some(Ok((topic, r))) = h.next().await {
                Output::new_output(SubOutputFormat::new(topic, r)).print($format, $color);
                println!("");
            }
            Ok(Output::new_success())
        });
        ret
    }};
}

pub struct PubSubCommand {
    format: OutputFormat,
    color: bool,
}

impl PubSubCommand {
    pub fn new(format: OutputFormat, color: bool) -> Self {
        PubSubCommand { format, color }
    }

    pub fn subcommand() -> Command {
        PubSubCmd::command()
    }
}

impl CliSubCommand for PubSubCommand {
    fn process(&mut self, matches: &ArgMatches, _debug: bool) -> Result<Output, String> {
        let cmd = PubSubCmd::from_arg_matches(matches).map_err(|err| err.to_string())?;
        match cmd.command {
            PubSubSubcommands::NewTipHeader(args) => {
                let tcp: SocketAddr = SocketParser.parse(&args.tcp)?;
                let ret = block_on!(
                    tcp,
                    ["new_tip_header"].iter(),
                    HeaderView,
                    self.format,
                    self.color
                );
                ret.map_err(|e| e.to_string())
            }
            PubSubSubcommands::NewTipBlock(args) => {
                let tcp: SocketAddr = SocketParser.parse(&args.tcp)?;
                let ret = block_on!(
                    tcp,
                    ["new_tip_block"].iter(),
                    BlockView,
                    self.format,
                    self.color
                );
                ret.map_err(|e| e.to_string())
            }
            PubSubSubcommands::NewTransaction(args) => {
                let tcp: SocketAddr = SocketParser.parse(&args.tcp)?;
                let ret = block_on!(
                    tcp,
                    ["new_transaction"].iter(),
                    PoolTransactionEntry,
                    self.format,
                    self.color
                );
                ret.map_err(|e| e.to_string())
            }
            PubSubSubcommands::ProposedTransaction(args) => {
                let tcp: SocketAddr = SocketParser.parse(&args.tcp)?;
                let ret = block_on!(
                    tcp,
                    ["proposed_transaction"].iter(),
                    PoolTransactionEntry,
                    self.format,
                    self.color
                );
                ret.map_err(|e| e.to_string())
            }
            PubSubSubcommands::RejectedTransaction(args) => {
                let tcp: SocketAddr = SocketParser.parse(&args.tcp)?;
                let ret = block_on!(
                    tcp,
                    ["rejected_transaction"].iter(),
                    (PoolTransactionEntry, PoolTransactionReject),
                    self.format,
                    self.color
                );
                ret.map_err(|e| e.to_string())
            }
            PubSubSubcommands::List(args) => {
                let tcp: SocketAddr = SocketParser.parse(&args.tcp)?;
                let ret = block_on!(
                    tcp,
                    args.topics.iter().map(String::as_str),
                    ListOutput,
                    self.format,
                    self.color
                );
                ret.map_err(|e| e.to_string())
            }
        }
    }
}

pub async fn new_tcp_client(addr: SocketAddr) -> io::Result<Client<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    Ok(Client::new(tcp))
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
enum ListOutput {
    Header(HeaderView),
    Block(BlockView),
    Tx(PoolTransactionEntry),
    Reject((PoolTransactionEntry, PoolTransactionReject)),
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SubOutputFormat<T> {
    topic: String,
    data: T,
}

impl<T> SubOutputFormat<T> {
    fn new(topic: String, data: T) -> Self {
        Self { topic, data }
    }
}
