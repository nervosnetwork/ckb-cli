use ckb_resource::{
    CODE_HASH_DAO, CODE_HASH_SECP256K1_BLAKE160_MULTISIG_ALL,
    CODE_HASH_SECP256K1_BLAKE160_SIGHASH_ALL,
};
use ckb_types::{
    core::{BlockView, DepType, EpochNumberWithFraction, HeaderView},
    packed::{Byte32, CellDep, CellOutput, OutPoint},
    prelude::*,
    U256,
};

use crate::constants::{
    DAO_OUTPUT_LOC, MULTISIG_GROUP_OUTPUT_LOC, MULTISIG_OUTPUT_LOC, SIGHASH_GROUP_OUTPUT_LOC,
    SIGHASH_OUTPUT_LOC,
};

#[derive(Debug, Clone)]
pub struct GenesisInfo {
    header: HeaderView,
    out_points: Vec<Vec<OutPoint>>,
    sighash_data_hash: Byte32,
    sighash_type_hash: Byte32,
    multisig_data_hash: Byte32,
    multisig_type_hash: Byte32,
    dao_data_hash: Byte32,
    dao_type_hash: Byte32,
}

impl GenesisInfo {
    pub fn from_block(genesis_block: &BlockView) -> Result<GenesisInfo, String> {
        let header = genesis_block.header();
        if header.number() != 0 {
            return Err(format!(
                "Convert to GenesisInfo failed, block number {} > 0",
                header.number()
            ));
        }

        let mut sighash_data_hash = None;
        let mut sighash_type_hash = None;
        let mut multisig_data_hash = None;
        let mut multisig_type_hash = None;
        let mut dao_data_hash = None;
        let mut dao_type_hash = None;
        let out_points = genesis_block
            .transactions()
            .iter()
            .enumerate()
            .map(|(tx_index, tx)| {
                tx.outputs()
                    .into_iter()
                    .zip(tx.outputs_data().into_iter())
                    .enumerate()
                    .map(|(index, (output, data))| {
                        if tx_index == SIGHASH_OUTPUT_LOC.0 && index == SIGHASH_OUTPUT_LOC.1 {
                            sighash_type_hash = output
                                .type_()
                                .to_opt()
                                .map(|script| script.calc_script_hash());
                            let data_hash = CellOutput::calc_data_hash(&data.raw_data());
                            if data_hash != CODE_HASH_SECP256K1_BLAKE160_SIGHASH_ALL.pack() {
                                log::error!(
                                    "System sighash script code hash error! found: {}, expected: {}",
                                    data_hash,
                                    CODE_HASH_SECP256K1_BLAKE160_SIGHASH_ALL,
                                );
                            }
                            sighash_data_hash = Some(data_hash);
                        }
                        if tx_index == MULTISIG_OUTPUT_LOC.0 && index == MULTISIG_OUTPUT_LOC.1 {
                            multisig_type_hash = output
                                .type_()
                                .to_opt()
                                .map(|script| script.calc_script_hash());
                            let data_hash = CellOutput::calc_data_hash(&data.raw_data());
                            if data_hash != CODE_HASH_SECP256K1_BLAKE160_MULTISIG_ALL.pack() {
                                log::error!(
                                    "System multisig script code hash error! found: {}, expected: {}",
                                    data_hash,
                                    CODE_HASH_SECP256K1_BLAKE160_MULTISIG_ALL,
                                );
                            }
                            multisig_data_hash = Some(data_hash);
                        }
                        if tx_index == DAO_OUTPUT_LOC.0 && index == DAO_OUTPUT_LOC.1 {
                            dao_type_hash = output
                                .type_()
                                .to_opt()
                                .map(|script| script.calc_script_hash());
                            let data_hash = CellOutput::calc_data_hash(&data.raw_data());
                            if data_hash != CODE_HASH_DAO.pack() {
                                log::error!(
                                    "System dao script code hash error! found: {}, expected: {}",
                                    data_hash,
                                    CODE_HASH_DAO,
                                );
                            }
                            dao_data_hash = Some(data_hash);
                        }
                        OutPoint::new(tx.hash(), index as u32)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let sighash_data_hash = sighash_data_hash
            .ok_or_else(|| "No data hash(sighash) found in txs[0][1]".to_owned())?;
        let sighash_type_hash = sighash_type_hash
            .ok_or_else(|| "No type hash(sighash) found in txs[0][1]".to_owned())?;
        let multisig_data_hash = multisig_data_hash
            .ok_or_else(|| "No data hash(multisig) found in txs[0][4]".to_owned())?;
        let multisig_type_hash = multisig_type_hash
            .ok_or_else(|| "No type hash(multisig) found in txs[0][4]".to_owned())?;
        let dao_data_hash =
            dao_data_hash.ok_or_else(|| "No data hash(dao) found in txs[0][2]".to_owned())?;
        let dao_type_hash =
            dao_type_hash.ok_or_else(|| "No type hash(dao) found in txs[0][2]".to_owned())?;
        Ok(GenesisInfo {
            header,
            out_points,
            sighash_data_hash,
            sighash_type_hash,
            multisig_data_hash,
            multisig_type_hash,
            dao_data_hash,
            dao_type_hash,
        })
    }

    pub fn header(&self) -> &HeaderView {
        &self.header
    }

    pub fn sighash_data_hash(&self) -> &Byte32 {
        &self.sighash_data_hash
    }

    pub fn sighash_type_hash(&self) -> &Byte32 {
        &self.sighash_type_hash
    }

    pub fn multisig_data_hash(&self) -> &Byte32 {
        &self.multisig_data_hash
    }

    pub fn multisig_type_hash(&self) -> &Byte32 {
        &self.multisig_type_hash
    }

    pub fn dao_data_hash(&self) -> &Byte32 {
        &self.dao_data_hash
    }

    pub fn dao_type_hash(&self) -> &Byte32 {
        &self.dao_type_hash
    }

    pub fn sighash_dep(&self) -> CellDep {
        CellDep::new_builder()
            .out_point(
                self.out_points[SIGHASH_GROUP_OUTPUT_LOC.0][SIGHASH_GROUP_OUTPUT_LOC.1].clone(),
            )
            .dep_type(DepType::DepGroup.into())
            .build()
    }

    pub fn multisig_dep(&self) -> CellDep {
        CellDep::new_builder()
            .out_point(
                self.out_points[MULTISIG_GROUP_OUTPUT_LOC.0][MULTISIG_GROUP_OUTPUT_LOC.1].clone(),
            )
            .dep_type(DepType::DepGroup.into())
            .build()
    }

    pub fn dao_dep(&self) -> CellDep {
        CellDep::new_builder()
            .out_point(self.out_points[DAO_OUTPUT_LOC.0][DAO_OUTPUT_LOC.1].clone())
            .build()
    }
}

// Calculate max mature block number
pub fn calc_max_mature_number(
    tip_epoch: EpochNumberWithFraction,
    max_mature_epoch: Option<(u64, u64)>,
    cellbase_maturity: EpochNumberWithFraction,
) -> u64 {
    if tip_epoch.to_rational() < cellbase_maturity.to_rational() {
        0
    } else if let Some((start_number, length)) = max_mature_epoch {
        let epoch_delta = tip_epoch.to_rational() - cellbase_maturity.to_rational();
        let index_bytes: [u8; 32] = ((epoch_delta.clone() - epoch_delta.into_u256())
            * U256::from(length))
        .into_u256()
        .to_le_bytes();
        let mut index_bytes_u64 = [0u8; 8];
        index_bytes_u64.copy_from_slice(&index_bytes[0..8]);
        u64::from_le_bytes(index_bytes_u64) + start_number
    } else {
        0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::CELLBASE_MATURITY;

    #[test]
    fn test_calc_max_mature_number() {
        assert_eq!(
            calc_max_mature_number(
                EpochNumberWithFraction::new(3, 86, 1800),
                Some((0, 3)),
                CELLBASE_MATURITY,
            ),
            0
        );
        assert_eq!(
            calc_max_mature_number(
                EpochNumberWithFraction::new(4, 86, 1800),
                Some((0, 1000)),
                CELLBASE_MATURITY,
            ),
            47
        );
        assert_eq!(
            calc_max_mature_number(
                EpochNumberWithFraction::new(4, 0, 1800),
                Some((0, 1000)),
                CELLBASE_MATURITY,
            ),
            0
        );
        assert_eq!(
            calc_max_mature_number(
                EpochNumberWithFraction::new(5, 900, 1800),
                Some((2000, 1000)),
                CELLBASE_MATURITY,
            ),
            2500
        );
    }
}
