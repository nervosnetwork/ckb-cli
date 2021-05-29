use super::tx_helper::ReprMultisigConfig;
use ckb_jsonrpc_types as json_types;
use ckb_types::H256;
use serde_derive::{Deserialize, Serialize};

// Deployment
#[derive(Clone, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Deployment {
    pub lock: json_types::Script,
    pub cells: Vec<Cell>,
    #[serde(default)]
    pub dep_groups: Vec<DepGroup>,
    #[serde(default)]
    pub multisig_config: ReprMultisigConfig,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CellLocation {
    OutPoint { tx_hash: H256, index: u32 },
    File { file: String },
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Cell {
    pub name: String,
    pub location: CellLocation,
    pub enable_type_id: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DepGroup {
    pub name: String,
    pub cells: Vec<String>,
}

// Recipe
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CellRecipe {
    pub name: String,
    pub tx_hash: H256,
    pub index: u32,
    pub occupied_capacity: u64,
    pub data_hash: H256,
    pub type_id: Option<H256>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepGroupRecipe {
    pub name: String,
    pub tx_hash: H256,
    pub index: u32,
    #[serde(default)]
    pub data_hash: H256,
    pub occupied_capacity: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DeploymentRecipe {
    pub cell_recipes: Vec<CellRecipe>,
    pub dep_group_recipes: Vec<DepGroupRecipe>,
}
