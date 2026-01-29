#![allow(dead_code)]

use crate::utils::arg_parser::{
    AddressParser, ArgParser, CapacityParser, FilePathParser, FixedHashParser, FromStrParser,
    HexParser, OutPointParser, PrivkeyPathParser, PubkeyHexParser,
};
use ckb_types::H160;
use clap::builder::ValueParser;
use clap::Arg;

pub trait ArgValidatorExt {
    fn validator<F>(self, validator: F) -> Self
    where
        F: Fn(&str) -> Result<(), String> + Clone + Send + Sync + 'static;
}

impl ArgValidatorExt for Arg {
    fn validator<F>(self, validator: F) -> Self
    where
        F: Fn(&str) -> Result<(), String> + Clone + Send + Sync + 'static,
    {
        self.value_parser(ValueParser::new(move |input: &str| {
            validator(input).map(|_| input.to_string())
        }))
    }
}

pub fn privkey_path() -> Arg {
    Arg::new("privkey-path")
        .long("privkey-path")
        .num_args(1)
        .validator(|input| PrivkeyPathParser.validate(input))
        .help("Private key file path (only read first line)")
}

pub fn pubkey() -> Arg {
    Arg::new("pubkey")
        .long("pubkey")
        .num_args(1)
        .validator(|input| PubkeyHexParser.validate(input))
        .help("Public key (hex string, compressed format)")
}

pub fn address() -> Arg {
    Arg::new("address")
        .long("address")
        .num_args(1)
        .validator(|input| AddressParser::default().validate(input))
        .help(
            "Target address (see: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0021-ckb-address-format/0021-ckb-address-format.md)",
        )
}

pub fn derive_receiving_address_length() -> Arg {
    Arg::new("derive-receiving-address-length")
        .long("derive-receiving-address-length")
        .num_args(1)
        .default_value("1000")
        .validator(|input| FromStrParser::<u32>::default().validate(input))
        .help("Search derived receiving address length")
}

pub fn derive_change_address_length() -> Arg {
    Arg::new("derive-change-address-length")
        .long("derive-change-address-length")
        .num_args(1)
        .default_value("1000")
        .validator(|input| FromStrParser::<u32>::default().validate(input))
        .help("Search derived change address length")
}

pub fn derive_change_address() -> Arg {
    Arg::new("derive-change-address")
        .long("derive-change-address")
        .num_args(1)
        .validator(|input| AddressParser::default().validate(input))
        .help("Manually specify the last change address (search 10000 addresses max, required keystore password, see: BIP-44)")
}

pub fn derived() -> Arg {
    Arg::new("derived")
        .long("derived")
        .help("Search derived address space (search 10000 addresses(change/receiving) max, required keystore password, see: BIP-44)")
}

pub fn lock_arg() -> Arg {
    Arg::new("lock-arg")
        .long("lock-arg")
        .num_args(1)
        .validator(|input| FixedHashParser::<H160>::default().validate(input))
        .help("Lock argument (account identifier, blake2b(pubkey)[0..20])")
}

pub fn from_account() -> Arg {
    Arg::new("from-account")
        .long("from-account")
        .num_args(1)
        .validator(|input| {
            FixedHashParser::<H160>::default()
                .validate(input)
                .or_else(|err| {
                    AddressParser::default()
                        .validate(input)
                        .and_then(|()| AddressParser::new_sighash().validate(input))
                        .map_err(|_| err)
                })
        })
        .help("The account's lock-arg or sighash address (transfer from this account)")
}

pub fn from_locked_address() -> Arg {
    Arg::new("from-locked-address")
        .long("from-locked-address")
        .num_args(1)
        .validator(|input| AddressParser::default().validate(input))
        .help("The time locked multisig address to search live cells (which S=0,R=0,M=1,N=1 and have since value)")
}

pub fn to_address() -> Arg {
    Arg::new("to-address")
        .long("to-address")
        .num_args(1)
        .validator(|input| AddressParser::default().validate(input))
        .help("Target address")
}

pub fn to_data() -> Arg {
    Arg::new("to-data")
        .long("to-data")
        .num_args(1)
        .validator(|input| HexParser.validate(input))
        .help("Hex data store in target cell (optional)")
}

pub fn to_data_path() -> Arg {
    Arg::new("to-data-path")
        .long("to-data-path")
        .num_args(1)
        .validator(|input| FilePathParser::new(true).validate(input))
        .help("Data binary file path store in target cell (optional)")
}

pub fn capacity() -> Arg {
    Arg::new("capacity")
        .long("capacity")
        .num_args(1)
        .validator(|input| CapacityParser.validate(input))
        .help("The capacity (unit: CKB, format: 123.335)")
}

pub fn fee_rate() -> Arg {
    Arg::new("fee-rate")
        .long("fee-rate")
        .num_args(1)
        .validator(|input| FromStrParser::<u64>::default().validate(input))
        .default_value("1000")
        .help("The transaction fee rate (unit: shannons/KB)")
}

/// create an Arg object to receive value of force_small_change_as_fee for CapacityBalancer
pub fn max_tx_fee() -> Arg {
    Arg::new("max-tx-fee")
        .long("max-tx-fee")
        .num_args(1)
        .value_name("capacity")
        .validator(|input| CapacityParser.validate(input))
        .help("When there is no more inputs for create a change cell to balance the transaction capacity, force the addition capacity as fee, the value is actual maximum transaction fee(unit CKB, example:0.001)")
}

pub fn live_cells_limit() -> Arg {
    Arg::new("limit")
        .long("limit")
        .num_args(1)
        .validator(|input| FromStrParser::<usize>::default().validate(input))
        .default_value("15")
        .help("Get live cells <= limit")
}

pub fn from_block_number() -> Arg {
    Arg::new("from")
        .long("from")
        .num_args(1)
        .validator(|input| FromStrParser::<u64>::default().validate(input))
        .help("From block number (inclusive)")
}

pub fn to_block_number() -> Arg {
    Arg::new("to")
        .long("to")
        .num_args(1)
        .validator(|input| FromStrParser::<u64>::default().validate(input))
        .help("To block number (exclusive)")
}

pub fn out_point() -> Arg {
    Arg::new("out-point")
        .long("out-point")
        .num_args(1)
        .validator(|input| { OutPointParser.validate(input) })
        .help("out-point to specify a cell. Example: 0xd56ed5d4e8984701714de9744a533413f79604b3b91461e2265614829d2005d1-1")
}
