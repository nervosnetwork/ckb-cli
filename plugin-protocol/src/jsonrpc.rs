use ckb_types::{
    packed::{CellInput, OutPoint},
    prelude::Pack,
    H256,
};
use serde_derive::{Deserialize, Serialize};

pub const JSONRPC_VERSION: &str = "2.0";

/// A JSONRPC error object
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JsonrpcError {
    /// The integer identifier of the error
    pub code: i32,
    /// A string describing the error
    pub message: String,
    /// Additional data specific to the error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// A JSONRPC request object
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct JsonrpcRequest {
    /// jsonrpc field, MUST be "2.0"
    pub jsonrpc: String,
    /// Identifier for this Request, which should appear in the response
    pub id: serde_json::Value,
    /// The name of the RPC call
    pub method: String,
    /// Parameters to the RPC call
    pub params: Vec<serde_json::Value>,
}

/// A JSONRPC response object
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct JsonrpcResponse {
    /// jsonrpc field, MUST be "2.0"
    pub jsonrpc: String,
    /// Identifier for this Request, which should match that of the request
    pub id: serde_json::Value,
    /// A result if there is one, or null
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// An error if there is one, or null
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonrpcError>,
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct LiveCellInfo {
    pub tx_hash: H256,
    pub output_index: u32,
    pub data_bytes: u64,
    pub lock_hash: H256,
    // Type script's code_hash and script_hash
    pub type_hashes: Option<(H256, H256)>,
    // Capacity
    pub capacity: u64,
    // Block number
    pub number: u64,
    // Location in the block
    pub index: CellIndex,
}

impl LiveCellInfo {
    pub fn out_point(&self) -> OutPoint {
        OutPoint::new(self.tx_hash.pack(), self.output_index)
    }
    pub fn input(&self) -> CellInput {
        CellInput::new(self.out_point(), 0)
    }
}

// LiveCell index in a block
#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub struct CellIndex {
    // The transaction index in the block
    pub tx_index: u32,
    // The output index in the transaction
    pub output_index: u32,
}
