use std::collections::HashMap;

use ckb_jsonrpc_types as json_types;
use ckb_jsonrpc_types::JsonBytes;
use ckb_types::H160;
use serde_derive::{Deserialize, Serialize};

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct ReprMultisigConfig {
    pub sighash_addresses: Vec<String>,
    pub require_first_n: u8,
    pub threshold: u8,
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct ReprTxHelper {
    pub transaction: json_types::Transaction,
    pub multisig_configs: HashMap<H160, ReprMultisigConfig>,
    pub signatures: HashMap<JsonBytes, Vec<JsonBytes>>,
}
