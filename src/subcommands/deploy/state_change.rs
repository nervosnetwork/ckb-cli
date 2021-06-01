use crate::utils::other::calculate_type_id;
use ckb_chain_spec::consensus::TYPE_ID_CODE_HASH;
use ckb_sdk::constants::ONE_CKB;
use ckb_sdk_types::deployment::{Cell, CellRecipe, DepGroup, DepGroupRecipe};
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, ScriptHashType},
    packed,
    prelude::*,
    H256,
};
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum StateChange<C, R> {
    Changed {
        // New data
        data: Bytes,
        data_hash: H256,
        config: C,
        old_recipe: R,
        output_index: u64,
    },
    NewAdded {
        data: Bytes,
        data_hash: H256,
        config: C,
        output_index: u64,
    },
    Unchanged {
        data: Bytes,
        data_hash: H256,
        config: C,
        old_recipe: R,
    },
    Removed {
        old_recipe: R,
    },
}

impl<C, R> StateChange<C, R> {
    fn has_new_output(&self) -> bool {
        match self {
            StateChange::Changed { .. } => true,
            StateChange::NewAdded { .. } => true,
            StateChange::Removed { .. } => false,
            StateChange::Unchanged { .. } => false,
        }
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct ReprStateChange {
    pub name: String,
    pub kind: String,
    pub old_capacity: u64,
    pub new_capacity: u64,
}

pub type CellChange = StateChange<Cell, CellRecipe>;
pub type DepGroupChange = StateChange<DepGroup, DepGroupRecipe>;

pub trait ChangeInfo {
    fn name(&self) -> &String;
    fn to_repr(&self, lock_script: &packed::Script) -> ReprStateChange;
    fn has_new_output(&self) -> bool;
    fn has_new_recipe(&self) -> bool;
    fn occupied_capacity(&self, lock_script: &packed::Script) -> u64;
    fn build_input(&self) -> Option<(packed::CellInput, u64)>;
    fn build_cell_output(
        &self,
        lock_script: &packed::Script,
        first_cell_input: &packed::CellInput,
    ) -> Option<(packed::CellOutput, Bytes)>;
}

impl ChangeInfo for CellChange {
    fn name(&self) -> &String {
        match self {
            StateChange::Changed { config, .. } => &config.name,
            StateChange::NewAdded { config, .. } => &config.name,
            StateChange::Unchanged { config, .. } => &config.name,
            StateChange::Removed { old_recipe } => &old_recipe.name,
        }
    }

    fn to_repr(&self, lock_script: &packed::Script) -> ReprStateChange {
        let new_capacity = self.occupied_capacity(lock_script);
        let (kind, old_capacity) = match self {
            StateChange::Changed { old_recipe, .. } => ("Changed", old_recipe.occupied_capacity),
            StateChange::NewAdded { .. } => ("NewAdded", 0),
            StateChange::Unchanged { .. } => ("Unchanged", new_capacity),
            StateChange::Removed { old_recipe } => ("Removed", old_recipe.occupied_capacity),
        };
        ReprStateChange {
            name: self.name().clone(),
            kind: kind.to_string(),
            old_capacity,
            new_capacity,
        }
    }

    fn has_new_output(&self) -> bool {
        StateChange::has_new_output(self)
    }

    fn has_new_recipe(&self) -> bool {
        match self {
            StateChange::Removed { .. } => false,
            _ => true,
        }
    }

    fn occupied_capacity(&self, lock_script: &packed::Script) -> u64 {
        let (data, config) = match self {
            StateChange::Removed { .. } => return 0,
            StateChange::Changed { data, config, .. } => (data, config),
            StateChange::Unchanged { data, config, .. } => (data, config),
            StateChange::NewAdded { data, config, .. } => (data, config),
        };
        let data_size = data.len() as u64;
        let type_script_size: u64 = if config.enable_type_id {
            32 + 1 + 32
        } else {
            0
        };
        lock_script.occupied_capacity().expect("capacity").as_u64()
            + (type_script_size + data_size + 8) * ONE_CKB
    }

    fn build_input(&self) -> Option<(packed::CellInput, u64)> {
        match self {
            StateChange::Changed { old_recipe, .. } => {
                let out_point = packed::OutPoint::new(old_recipe.tx_hash.pack(), old_recipe.index);
                let input = packed::CellInput::new(out_point, 0);
                Some((input, old_recipe.occupied_capacity))
            }
            _ => None,
        }
    }

    fn build_cell_output(
        &self,
        lock_script: &packed::Script,
        first_cell_input: &packed::CellInput,
    ) -> Option<(packed::CellOutput, Bytes)> {
        let (data, config, output_index, old_type_id) = match self {
            StateChange::Removed { .. } => {
                return None;
            }
            StateChange::Unchanged { .. } => {
                return None;
            }
            StateChange::Changed {
                data,
                config,
                old_recipe,
                output_index,
                ..
            } => (data, config, *output_index, old_recipe.type_id.clone()),
            StateChange::NewAdded {
                data,
                config,
                output_index,
                ..
            } => (data, config, *output_index, None),
        };
        let type_id = if config.enable_type_id {
            old_type_id.or_else(|| {
                Some(H256::from(calculate_type_id(
                    first_cell_input,
                    output_index,
                )))
            })
        } else {
            None
        };
        let occupied_capacity = self.occupied_capacity(lock_script);
        let type_script_opt = type_id.map(|type_id_args| {
            packed::Script::new_builder()
                .code_hash(TYPE_ID_CODE_HASH.pack())
                .hash_type(ScriptHashType::Type.into())
                .args(Bytes::from(type_id_args.as_bytes().to_vec()).pack())
                .build()
        });
        let output = packed::CellOutput::new_builder()
            .capacity(Capacity::shannons(occupied_capacity).pack())
            .lock(lock_script.clone())
            .type_(
                packed::ScriptOpt::new_builder()
                    .set(type_script_opt)
                    .build(),
            )
            .build();
        Some((output, data.clone()))
    }
}

impl CellChange {
    pub fn build_new_recipe(
        &self,
        lock_script: &packed::Script,
        first_cell_input: &packed::CellInput,
        new_tx_hash: &H256,
    ) -> Option<CellRecipe> {
        let (tx_hash, index, data_hash, config, old_type_id) = match self {
            StateChange::Removed { .. } => {
                return None;
            }
            StateChange::Changed {
                data_hash,
                config,
                old_recipe,
                output_index,
                ..
            } => (
                new_tx_hash.clone(),
                *output_index as u32,
                data_hash.clone(),
                config,
                old_recipe.type_id.clone(),
            ),
            StateChange::Unchanged {
                data_hash,
                config,
                old_recipe,
                ..
            } => (
                old_recipe.tx_hash.clone(),
                old_recipe.index,
                data_hash.clone(),
                config,
                old_recipe.type_id.clone(),
            ),
            StateChange::NewAdded {
                data_hash,
                config,
                output_index,
                ..
            } => (
                new_tx_hash.clone(),
                *output_index as u32,
                data_hash.clone(),
                config,
                None,
            ),
        };
        let type_id = if config.enable_type_id {
            old_type_id.or_else(|| {
                Some(H256::from(calculate_type_id(
                    first_cell_input,
                    index as u64,
                )))
            })
        } else {
            None
        };
        Some(CellRecipe {
            name: self.name().clone(),
            // To be replaced with final transaction hash
            tx_hash,
            index,
            occupied_capacity: self.occupied_capacity(lock_script),
            data_hash,
            type_id,
        })
    }
}

impl ChangeInfo for DepGroupChange {
    fn name(&self) -> &String {
        match self {
            StateChange::Changed { config, .. } => &config.name,
            StateChange::NewAdded { config, .. } => &config.name,
            StateChange::Unchanged { config, .. } => &config.name,
            StateChange::Removed { old_recipe } => &old_recipe.name,
        }
    }

    fn to_repr(&self, lock_script: &packed::Script) -> ReprStateChange {
        let new_capacity = self.occupied_capacity(lock_script);
        let (kind, old_capacity) = match self {
            StateChange::Changed { old_recipe, .. } => ("Changed", old_recipe.occupied_capacity),
            StateChange::NewAdded { .. } => ("NewAdded", 0),
            StateChange::Unchanged { .. } => ("Unchanged", new_capacity),
            StateChange::Removed { old_recipe } => ("Removed", old_recipe.occupied_capacity),
        };
        ReprStateChange {
            name: self.name().clone(),
            kind: kind.to_string(),
            old_capacity,
            new_capacity,
        }
    }

    fn has_new_output(&self) -> bool {
        StateChange::has_new_output(self)
    }

    fn has_new_recipe(&self) -> bool {
        match self {
            StateChange::Removed { .. } => false,
            _ => true,
        }
    }

    fn occupied_capacity(&self, lock_script: &packed::Script) -> u64 {
        let data = match self {
            StateChange::Removed { .. } => return 0,
            StateChange::Changed { data, .. } => data,
            StateChange::Unchanged { data, .. } => data,
            StateChange::NewAdded { data, .. } => data,
        };
        let data_size = data.len() as u64;
        lock_script.occupied_capacity().expect("capacity").as_u64() + (data_size + 8) * ONE_CKB
    }

    fn build_input(&self) -> Option<(packed::CellInput, u64)> {
        match self {
            StateChange::Changed { old_recipe, .. } => {
                let out_point = packed::OutPoint::new(old_recipe.tx_hash.pack(), old_recipe.index);
                let input = packed::CellInput::new(out_point, 0);
                Some((input, old_recipe.occupied_capacity))
            }
            _ => None,
        }
    }

    fn build_cell_output(
        &self,
        lock_script: &packed::Script,
        _first_cell_input: &packed::CellInput,
    ) -> Option<(packed::CellOutput, Bytes)> {
        let data = match self {
            StateChange::Removed { .. } => {
                return None;
            }
            StateChange::Unchanged { .. } => {
                return None;
            }
            StateChange::Changed { data, .. } => data,
            StateChange::NewAdded { data, .. } => data,
        };
        let occupied_capacity = self.occupied_capacity(lock_script);
        let output = packed::CellOutput::new_builder()
            .capacity(Capacity::shannons(occupied_capacity).pack())
            .lock(lock_script.clone())
            .build();
        Some((output, data.clone()))
    }
}

impl DepGroupChange {
    pub fn build_new_recipe(
        &self,
        lock_script: &packed::Script,
        new_tx_hash: H256,
    ) -> Option<DepGroupRecipe> {
        let (tx_hash, index, data_hash) = match self {
            StateChange::Removed { .. } => {
                return None;
            }
            StateChange::Changed {
                data_hash,
                output_index,
                ..
            } => (new_tx_hash, *output_index as u32, data_hash.clone()),
            StateChange::Unchanged {
                data_hash,
                old_recipe,
                ..
            } => (
                old_recipe.tx_hash.clone(),
                old_recipe.index,
                data_hash.clone(),
            ),
            StateChange::NewAdded {
                data_hash,
                output_index,
                ..
            } => (new_tx_hash, *output_index as u32, data_hash.clone()),
        };
        Some(DepGroupRecipe {
            name: self.name().clone(),
            // To be replaced with final transaction hash
            tx_hash,
            index,
            data_hash,
            occupied_capacity: self.occupied_capacity(lock_script),
        })
    }
}
