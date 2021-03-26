use ckb_jsonrpc_types::{BlockView, HeaderView, PoolTransactionEntry, PoolTransactionReject};
use ckb_sdk::pubsub::Client;
use clap::{App, Arg, ArgMatches};
use futures::StreamExt;
use std::io;
use std::net::SocketAddr;
use tokio::net::TcpStream;

use super::{CliSubCommand, Output};
use crate::utils::arg_parser::{ArgParser, SocketParser};
use crate::OutputFormat;

macro_rules! block_on {
    ($addr:ident, $topic:expr, $output:ty, $format:expr, $color:expr) => {{
        let rt = tokio::runtime::Runtime::new().unwrap();
        let ret: io::Result<Output> = rt.block_on(async {
            let c = new_tcp_client($addr).await?;
            let mut h = c.subscribe::<$output>($topic).await.map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not a subcribe port, please set ckb `tcp_listen_address` to use subcribe rpc feature"))?;
            while let Some(Ok(r)) = h.next().await {
                Output::new_output(r).print($format, $color);
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

    pub fn subcommand() -> App<'static> {
        let arg = Arg::with_name("tcp")
            .long("tcp")
            .takes_value(true)
            .required(true)
            .validator(|input| SocketParser.validate(input))
            .about("RPC pubsub server socket, like \"127.0.0.1:18114\"");

        App::new("subscribe")
            .about("Subscribe to TCP interface of node")
            .subcommands(vec![
                App::new("new_tip_header")
                    .arg(arg.clone())
                    .about("Subscribe to new block header notification"),
                App::new("new_tip_block")
                    .arg(arg.clone())
                    .about("Subscribe to new block notification"),
                App::new("new_transaction")
                    .arg(arg.clone())
                    .about("Subscribe to new transaction notification"),
                App::new("proposed_transaction")
                    .arg(arg.clone())
                    .about("Subscribe to new proposed transaction notification"),
                App::new("rejected_transaction")
                    .arg(arg)
                    .about("Subscribe to rejected transaction notification"),
            ])
    }
}

impl CliSubCommand for PubSubCommand {
    fn process(&mut self, matches: &ArgMatches, _debug: bool) -> Result<Output, String> {
        match matches.subcommand() {
            ("new_tip_header", Some(m)) => {
                let tcp: SocketAddr = SocketParser.from_matches(m, "tcp")?;
                let ret = block_on!(tcp, "new_tip_header", HeaderView, self.format, self.color);
                ret.map_err(|e| e.to_string())
            }
            ("new_tip_block", Some(m)) => {
                let tcp: SocketAddr = SocketParser.from_matches(m, "tcp")?;
                let ret = block_on!(tcp, "new_tip_block", BlockView, self.format, self.color);
                ret.map_err(|e| e.to_string())
            }
            ("new_transaction", Some(m)) => {
                let tcp: SocketAddr = SocketParser.from_matches(m, "tcp")?;
                let ret = block_on!(
                    tcp,
                    "new_transaction",
                    PoolTransactionEntry,
                    self.format,
                    self.color
                );
                ret.map_err(|e| e.to_string())
            }
            ("rejected_transaction", Some(m)) => {
                let tcp: SocketAddr = SocketParser.from_matches(m, "tcp")?;
                let ret = block_on!(
                    tcp,
                    "rejected_transaction",
                    (PoolTransactionEntry, PoolTransactionReject),
                    self.format,
                    self.color
                );
                ret.map_err(|e| e.to_string())
            }
            _ => Err(Self::subcommand().generate_usage()),
        }
    }
}

pub async fn new_tcp_client(addr: SocketAddr) -> io::Result<Client<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    Ok(Client::new(tcp))
}
