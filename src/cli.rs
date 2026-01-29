use clap::Parser;

use crate::utils::arg_parser::{ArgParser, UrlParser};

fn parse_url(input: &str) -> Result<String, String> {
    UrlParser.validate(input).map(|_| input.to_string())
}

#[derive(Parser, Debug)]
#[command(name = "ckb-cli")]
pub struct CliArgs {
    /// CKB RPC server url.
    /// The default value is http://127.0.0.1:8114
    /// You may also use some public available nodes, check the list of public nodes:
    /// https://github.com/nervosnetwork/ckb/wiki/Public-JSON-RPC-nodes
    #[arg(long, value_parser = parse_url)]
    pub url: Option<String>,

    /// Select output format
    #[arg(long = "output-format", id = "output-format", value_parser = ["yaml", "json"], default_value = "yaml", global = true)]
    pub output_format: String,

    /// Do not highlight(color) output json
    #[arg(long = "no-color", id = "no-color", global = true)]
    pub no_color: bool,

    /// Display request parameters
    #[arg(long, global = true)]
    pub debug: bool,

    /// This is a local only subcommand, do not check alerts and get network type
    #[arg(long = "local-only", id = "local-only", global = true)]
    pub local_only: bool,
}
