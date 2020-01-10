use crate::setup::Setup;
use crate::spec::Spec;

pub struct RpcGetTipBlockNumber;

impl Spec for RpcGetTipBlockNumber {
    fn run(&self, setup: &mut Setup) {
        setup.miner().generate_block();
        let output = setup.cli("rpc get_tip_block_number");
        assert_eq!("1".to_string(), output);
    }
}
