use ckb_jsonrpc_types::{Deployment, EpochNumber, HardForkFeature};
use serde::{Deserialize, Serialize};

/// SoftFork information
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum SoftFork {
    /// buried - the activation epoch is hard-coded into the client implementation
    Buried(Buried),
    /// rfc0043 - the activation is controlled by rfc0043 signaling
    Rfc0043(Rfc0043),
}

/// Represent soft fork deployments where the activation epoch is
/// hard-coded into the client implementation
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Buried {
    /// SoftFork status
    pub status: SoftForkStatus,
    /// Whether the rules are active
    pub active: bool,
    /// The first epoch  which the rules will be enforced
    pub epoch: EpochNumber,
}

/// Represent soft fork deployments
/// where activation is controlled by rfc0043 signaling
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Rfc0043 {
    /// SoftFork status
    pub status: SoftForkStatus,
    /// RFC0043 deployment params
    pub rfc0043: Deployment,
}

/// SoftForkStatus which is either `buried` (for soft fork deployments where the activation epoch is
/// hard-coded into the client implementation), or `rfc0043` (for soft fork deployments
/// where activation is controlled by rfc0043 signaling).
#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SoftForkStatus {
    /// the activation epoch is hard-coded into the client implementation
    Buried,
    /// the activation is controlled by rfc0043 signaling
    Rfc0043,
}

/// Hardfork information
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(transparent)]
pub struct HardForks {
    pub inner: Vec<HardForkFeature>,
}
