pub mod rpc;
pub mod wallet;

pub use rpc::RpcSubCommand;
pub use wallet::WalletSubCommand;

use serde::de::{DeserializeOwned};
use clap::{ArgMatches};

use crate::utils::printer::Printable;

pub trait CliSubCommand {
    fn process(&mut self, matches: &ArgMatches) -> Result<Box<dyn Printable>, String>;
}


fn from_string<T: DeserializeOwned>(source: String) -> T {
    let value = serde_json::Value::String(source);
    serde_json::from_value(value).unwrap()
}

fn from_matches<T>(matches: &ArgMatches, name: &str) -> T
where
    T: DeserializeOwned,
{
    from_string(matches.value_of(name).unwrap().to_string())
}

fn from_matches_opt<T>(matches: &ArgMatches, name: &str) -> Option<T>
where
    T: DeserializeOwned,
{
    matches.value_of(name).map(|hash_str| {
        from_string(hash_str.to_string())
    }).unwrap_or(None)
}
