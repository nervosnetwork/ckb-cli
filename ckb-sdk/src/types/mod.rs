///! Basic ckb sdk types
mod address;
mod human_capacity;
mod since;

use serde_derive::{Deserialize, Serialize};
use std::fmt;

pub use address::{
    Address, AddressPayload, AddressType, CodeHashIndex, OldAddress, OldAddressFormat,
};
pub use human_capacity::HumanCapacity;
pub use since::{Since, SinceType};

use crate::constants::{
    NETWORK_DEV, NETWORK_MAINNET, NETWORK_TESTNET, PREFIX_MAINNET, PREFIX_TESTNET,
};

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NetworkType {
    Mainnet,
    // Aggron
    Testnet,
    Dev,
}

impl NetworkType {
    pub fn from_prefix(value: &str) -> Option<NetworkType> {
        match value {
            PREFIX_MAINNET => Some(NetworkType::Mainnet),
            PREFIX_TESTNET => Some(NetworkType::Testnet),
            _ => None,
        }
    }

    pub fn to_prefix(self) -> &'static str {
        match self {
            NetworkType::Mainnet => PREFIX_MAINNET,
            _ => PREFIX_TESTNET,
        }
    }

    pub fn from_raw_str(value: &str) -> Option<NetworkType> {
        match value {
            NETWORK_MAINNET => Some(NetworkType::Mainnet),
            NETWORK_TESTNET => Some(NetworkType::Testnet),
            NETWORK_DEV => Some(NetworkType::Dev),
            _ => None,
        }
    }

    pub fn to_str(self) -> &'static str {
        match self {
            NetworkType::Mainnet => NETWORK_MAINNET,
            NetworkType::Testnet => NETWORK_TESTNET,
            NetworkType::Dev => NETWORK_DEV,
        }
    }
}

impl fmt::Display for NetworkType {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.to_str())
    }
}
