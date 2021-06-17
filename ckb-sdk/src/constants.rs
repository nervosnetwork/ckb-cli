use ckb_types::{
    core::{DepType, EpochNumberWithFraction, ScriptHashType},
    h256, H256,
};

pub const PREFIX_MAINNET: &str = "ckb";
pub const PREFIX_TESTNET: &str = "ckt";

pub const NETWORK_MAINNET: &str = "ckb";
pub const NETWORK_TESTNET: &str = "ckb_testnet";
pub const NETWORK_DEV: &str = "ckb_dev";

pub const SECP_SIGNATURE_SIZE: usize = 65;

// Since relative mask
pub const LOCK_TYPE_FLAG: u64 = 1 << 63;
pub const METRIC_TYPE_FLAG_MASK: u64 = 0x6000_0000_0000_0000;
pub const VALUE_MASK: u64 = 0x00ff_ffff_ffff_ffff;
pub const REMAIN_FLAGS_BITS: u64 = 0x1f00_0000_0000_0000;

// Special cells in genesis transactions: (transaction-index, output-index)
pub const SIGHASH_OUTPUT_LOC: (usize, usize) = (0, 1);
pub const MULTISIG_OUTPUT_LOC: (usize, usize) = (0, 4);
pub const DAO_OUTPUT_LOC: (usize, usize) = (0, 2);
pub const SIGHASH_GROUP_OUTPUT_LOC: (usize, usize) = (1, 0);
pub const MULTISIG_GROUP_OUTPUT_LOC: (usize, usize) = (1, 1);

pub const ONE_CKB: u64 = 100_000_000;
pub const MIN_SECP_CELL_CAPACITY: u64 = 61 * ONE_CKB;
// mainnet,testnet cellbase maturity
pub const CELLBASE_MATURITY: EpochNumberWithFraction =
    EpochNumberWithFraction::new_unchecked(4, 0, 1);

// https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0024-ckb-system-script-list/0024-ckb-system-script-list.md

// They are identical in mainnet and aggron testnet
pub const SIGHASH_TYPE_HASH: H256 =
    h256!("0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8");
pub const MULTISIG_TYPE_HASH: H256 =
    h256!("0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8");
pub const DAO_TYPE_HASH: H256 =
    h256!("0x82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e");

pub const LINA_ACP_CODE_HASH: H256 =
    h256!("0xd369597ff47f29fbc0d47d2e3775370d1250b85140c670e4718af712983a2354");
pub const LINA_ACP_HASH_TYPE: ScriptHashType = ScriptHashType::Type;
pub const LINA_ACP_TX_HASH: H256 =
    h256!("0x4153a2014952d7cac45f285ce9a7c5c0c0e1b21f2d378b82ac1433cb11c25c4d");
pub const LINA_ACP_INDEX: u32 = 0;
pub const LINA_ACP_DEP_TYPE: DepType = DepType::DepGroup;

pub const AGGRON_ACP_CODE_HASH: H256 =
    h256!("0x3419a1c09eb2567f6552ee7a8ecffd64155cffe0f1796e6e61ec088d740c1356");
pub const AGGRON_ACP_HASH_TYPE: ScriptHashType = ScriptHashType::Type;
pub const AGGRON_ACP_TX_HASH: H256 =
    h256!("0xec26b0f85ed839ece5f11c4c4e837ec359f5adc4420410f6453b1f6b60fb96a6");
pub const AGGRON_ACP_INDEX: u32 = 0;
pub const AGGRON_ACP_DEP_TYPE: DepType = DepType::DepGroup;

#[cfg(test)]
mod test {
    use super::*;
    use ckb_types::{
        core::Capacity,
        packed::{CellOutput, Script},
        prelude::*,
        H160,
    };

    #[test]
    fn test_min_capacity() {
        let min_secp_cell_capacity = CellOutput::new_builder()
            .lock(
                Script::new_builder()
                    .args(H160::default().as_bytes().pack())
                    .build(),
            )
            .build()
            .occupied_capacity(Capacity::zero())
            .unwrap()
            .as_u64();

        assert_eq!(min_secp_cell_capacity, MIN_SECP_CELL_CAPACITY);
    }
}
