use ckb_types::core::EpochNumberWithFraction;

use crate::constants::LOCK_TYPE_FLAG;

#[derive(Clone, Copy, Debug)]
pub enum SinceType {
    BlockNumber,
    EpochNumberWithFraction,
    Timestamp,
}

#[derive(Clone, Copy, Debug)]
pub struct Since(u64);

impl Since {
    pub fn new(ty: SinceType, value: u64, is_relative: bool) -> Since {
        let value = match ty {
            SinceType::BlockNumber => value,
            SinceType::EpochNumberWithFraction => 0x2000_0000_0000_0000 | value,
            SinceType::Timestamp => 0x4000_0000_0000_0000 | value,
        };
        if is_relative {
            Since(LOCK_TYPE_FLAG | value)
        } else {
            Since(value)
        }
    }

    pub fn new_absolute_epoch(epoch_number: u64) -> Since {
        let epoch = EpochNumberWithFraction::new(epoch_number, 0, 1);
        Self::new(
            SinceType::EpochNumberWithFraction,
            epoch.full_value(),
            false,
        )
    }

    pub fn value(self) -> u64 {
        self.0
    }
}
