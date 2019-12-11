use std::fmt;

use chrono::{Local, TimeZone};
use ckb_jsonrpc_types as rpc_types;
use ckb_types::core;
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{HumanCapacity, SinceType};

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
fn timestamp_to_string(value: u64) -> String {
    let dt = Local.timestamp_millis(value as i64);
    format!("{} ({})", value, dt)
}
fn since_to_string(value: u64) -> String {
    let since = crate::Since::from_raw_value(value);
    let (ty, inner_value) = since.extract_metric().unwrap();
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
        SinceType::Timestamp => format!("timestamp({})", Local.timestamp(inner_value as i64, 0)),
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
