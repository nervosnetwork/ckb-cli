mod dao;
mod plugin;
mod rpc;
mod util;
mod wallet;

pub use dao::*;
pub use plugin::*;
pub use rpc::*;
pub use util::*;
pub use wallet::*;

use crate::setup::Setup;
use ckb_app_config::CKBAppConfig;
use ckb_chain_spec::ChainSpec;

pub trait Spec {
    fn modify_ckb_toml(&self, _ckb_toml: &mut CKBAppConfig) {}

    fn modify_spec_toml(&self, _spec_toml: &mut ChainSpec) {}

    fn run(&self, setup: &mut Setup);
}
