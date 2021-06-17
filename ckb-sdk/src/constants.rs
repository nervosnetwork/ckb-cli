use ckb_types::{core::EpochNumberWithFraction, h256, H256};

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

pub const SIGHASH_TYPE_HASH: H256 =
    h256!("0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8");
pub const MULTISIG_TYPE_HASH: H256 =
    h256!("0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8");
pub const DAO_TYPE_HASH: H256 =
    h256!("0x82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e");

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
