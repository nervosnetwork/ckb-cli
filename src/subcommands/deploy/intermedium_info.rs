use std::collections::HashMap;
use std::convert::TryFrom;

use anyhow::{Error, Result};
use ckb_jsonrpc_types as json_types;
use ckb_jsonrpc_types::JsonBytes;
use ckb_sdk::{MultisigConfig, NetworkType, TxHelper};
use ckb_sdk_types::{
    deployment::{Deployment, DeploymentRecipe},
    tx_helper::{ReprMultisigConfig, ReprTxHelper},
};
use ckb_types::{H160, H256};
use serde_derive::{Deserialize, Serialize};

use super::state_change::ReprStateChange;

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct IntermediumInfo {
    pub deployment: Deployment,
    pub last_recipe: Option<DeploymentRecipe>,
    pub new_recipe: DeploymentRecipe,
    // For offline sign (should verify the tx hash)
    pub used_input_txs: HashMap<H256, json_types::Transaction>,
    pub cell_tx: Option<json_types::Transaction>,
    pub cell_tx_signatures: HashMap<JsonBytes, Vec<JsonBytes>>,
    pub cell_changes: Vec<ReprStateChange>,
    pub dep_group_tx: Option<json_types::Transaction>,
    pub dep_group_tx_signatures: HashMap<JsonBytes, Vec<JsonBytes>>,
    pub dep_group_changes: Vec<ReprStateChange>,
}

impl IntermediumInfo {
    pub fn multisig_configs(&self) -> Result<HashMap<H160, ReprMultisigConfig>> {
        // NOTE: we don't care the NetworkType here.
        let network = NetworkType::Testnet;
        let mut multisig_configs = HashMap::default();
        if !self.deployment.multisig_config.sighash_addresses.is_empty() {
            let config = MultisigConfig::try_from(self.deployment.multisig_config.clone())
                .map_err(Error::msg)?;
            multisig_configs.insert(config.hash160(), config.into_repr(network));
        }
        Ok(multisig_configs)
    }

    pub fn cell_tx_helper(&self) -> Result<Option<TxHelper>> {
        if let Some(cell_tx) = self.cell_tx.as_ref() {
            let repr = ReprTxHelper {
                transaction: cell_tx.clone(),
                multisig_configs: self.multisig_configs()?,
                signatures: self.cell_tx_signatures.clone(),
            };
            let helper = TxHelper::try_from(repr).map_err(Error::msg)?;
            Ok(Some(helper))
        } else {
            Ok(None)
        }
    }

    pub fn dep_group_tx_helper(&self) -> Result<Option<TxHelper>> {
        if let Some(dep_group_tx) = self.dep_group_tx.as_ref() {
            let repr = ReprTxHelper {
                transaction: dep_group_tx.clone(),
                multisig_configs: self.multisig_configs()?,
                signatures: self.dep_group_tx_signatures.clone(),
            };
            let helper = TxHelper::try_from(repr).map_err(Error::msg)?;
            Ok(Some(helper))
        } else {
            Ok(None)
        }
    }
}
