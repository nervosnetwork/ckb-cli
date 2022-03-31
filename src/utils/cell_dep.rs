use serde::{Deserialize, Serialize};

use ckb_jsonrpc_types as rpc_types;
use ckb_sdk::traits::DefaultCellDepResolver;
use ckb_types::H256;

#[derive(Clone, Hash, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct ScriptId {
    pub code_hash: H256,
    pub hash_type: rpc_types::ScriptHashType,
}

impl From<ScriptId> for ckb_sdk::types::ScriptId {
    fn from(json: ScriptId) -> ckb_sdk::types::ScriptId {
        ckb_sdk::types::ScriptId::new(json.code_hash, json.hash_type.into())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CellDepItem {
    pub script_id: ScriptId,
    pub cell_dep: rpc_types::CellDep,
    pub name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CellDeps {
    pub items: Vec<CellDepItem>,
}

impl CellDeps {
    pub fn apply_to_resolver(&self, resolver: &mut DefaultCellDepResolver) {
        for item in self.items.clone() {
            resolver.insert(
                item.script_id.into(),
                item.cell_dep.into(),
                item.name.unwrap_or_else(|| "none".to_string()),
            );
        }
    }
}
