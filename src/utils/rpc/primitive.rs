use std::fmt;

use chrono::{Local, TimeZone};
use ckb_jsonrpc_types as rpc_types;
use ckb_types::core;
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use ckb_sdk::{HumanCapacity, SinceType};

macro_rules! impl_serde {
    ($struct:ident, $visitor:ident, $from_str_ty:ty, $gen_string:path) => {
        struct $visitor;

        impl<'a> Visitor<'a> for $visitor {
            type Value = $struct;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a uint64")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                value
                    .parse::<$from_str_ty>()
                    .map($struct)
                    .map_err(|err| Error::custom(format!("parse uint64 error: {}", err)))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: Error,
            {
                self.visit_str(&value)
            }
        }

        impl Serialize for $struct {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let string = $gen_string(self.0);
                serializer.collect_str(&string)
            }
        }
        impl<'a> Deserialize<'a> for $struct {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'a>,
            {
                deserializer.deserialize_any($visitor)
            }
        }
    };
}

macro_rules! impl_u64_serde {
    ($struct:ident, $visitor:ident, $from:ty, $gen_string:path) => {
        #[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Debug)]
        pub struct $struct(pub u64);

        impl From<u64> for $struct {
            fn from(v: u64) -> $struct {
                $struct(v)
            }
        }
        impl From<$from> for $struct {
            fn from(v: $from) -> $struct {
                $struct(v.into())
            }
        }
        impl From<$struct> for $from {
            fn from(v: $struct) -> $from {
                From::from(v.0)
            }
        }

        impl_serde!($struct, $visitor, u64, $gen_string);
    };
}

fn capacity_to_string(value: u64) -> String {
    HumanCapacity(value).to_string()
}
fn epoch_to_string(value: u64) -> String {
    let epoch = core::EpochNumberWithFraction::from_full_value(value);
    format!(
        "0x{:x} {{number: {}, index: {}, length: {}}}",
        value,
        epoch.number(),
        epoch.index(),
        epoch.length(),
    )
}
// The value comes from the RPC server, so it may be out of the range chrono can represent
fn timestamp_to_string(value: u64) -> String {
    match i64::try_from(value)
        .ok()
        .and_then(|millis| Local.timestamp_millis_opt(millis).single())
    {
        Some(dt) => format!("{} ({})", value, dt),
        None => format!("{} (invalid timestamp)", value),
    }
}
fn since_to_string(value: u64) -> String {
    let since = ckb_sdk::Since::from_raw_value(value);
    let Some((ty, inner_value)) = since.extract_metric() else {
        return format!("0x{:x} (invalid since)", value);
    };
    let prefix = if since.is_absolute() {
        "absolute"
    } else {
        "relative"
    };
    let value_string = match ty {
        SinceType::BlockNumber => format!("block({})", inner_value),
        SinceType::EpochNumberWithFraction => {
            let epoch = core::EpochNumberWithFraction::from_full_value(inner_value);
            format!(
                "epoch{{number: {}, index: {}, length: {}}}",
                epoch.number(),
                epoch.index(),
                epoch.length()
            )
        }
        SinceType::Timestamp => match i64::try_from(inner_value)
            .ok()
            .and_then(|secs| Local.timestamp_opt(secs, 0).single())
        {
            Some(dt) => format!("timestamp({})", dt),
            None => format!("timestamp({}, invalid)", inner_value),
        },
    };
    format!("0x{:x} ({} {})", value, prefix, value_string)
}

impl_u64_serde!(
    Capacity,
    CapacityVisitor,
    rpc_types::Capacity,
    capacity_to_string
);
impl_u64_serde!(
    Timestamp,
    TimestampVisitor,
    rpc_types::Timestamp,
    timestamp_to_string
);
impl_u64_serde!(
    EpochNumberWithFraction,
    EpochNumberWithFractionVisitor,
    rpc_types::EpochNumberWithFraction,
    epoch_to_string
);
impl_u64_serde!(Since, SinceVisitor, rpc_types::Uint64, since_to_string);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_out_of_range_timestamp_does_not_panic() {
        // 2025-06-15 15:06:40 UTC, still June 2025 in any time zone
        assert!(timestamp_to_string(1_750_000_000_000).starts_with("1750000000000 (2025-06-"));
        assert_eq!(
            timestamp_to_string(9_000_000_000_000_000),
            "9000000000000000 (invalid timestamp)"
        );
        assert_eq!(
            timestamp_to_string(u64::MAX),
            format!("{} (invalid timestamp)", u64::MAX)
        );
    }

    #[test]
    fn test_invalid_since_does_not_panic() {
        // absolute timestamp since with the largest value
        let since = 0x40ff_ffff_ffff_ffffu64;
        assert_eq!(
            since_to_string(since),
            format!(
                "0x{:x} (absolute timestamp({}, invalid))",
                since, 0x00ff_ffff_ffff_ffffu64
            )
        );
        // metric flag 0b11 is not a valid since type
        let since = 0x6000_0000_0000_0000u64;
        assert_eq!(
            since_to_string(since),
            format!("0x{:x} (invalid since)", since)
        );
        // a valid block number since is still rendered
        assert_eq!(since_to_string(100), "0x64 (absolute block(100))");
    }
}
