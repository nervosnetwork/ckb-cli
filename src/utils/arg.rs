use crate::utils::arg_parser::{
    AddressParser, ArgParser, CapacityParser, FilePathParser, FixedHashParser, FromStrParser,
    HexParser, PrivkeyPathParser, PubkeyHexParser,
};
use ckb_types::{H160, H256};
use clap::Arg;

pub fn privkey_path<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("privkey-path")
        .long("privkey-path")
        .takes_value(true)
        .validator(|input| PrivkeyPathParser.validate(input))
        .help("Private key file path (only read first line)")
}

pub fn pubkey<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("pubkey")
        .long("pubkey")
        .takes_value(true)
        .validator(|input| PubkeyHexParser.validate(input))
        .help("Public key (hex string, compressed format)")
}

pub fn address<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("address")
        .long("address")
        .takes_value(true)
        .validator(|input| AddressParser.validate(input))
        .help(
            "Target address (see: https://github.com/nervosnetwork/ckb/wiki/Common-Address-Format)",
        )
}

pub fn lock_hash<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("lock-hash")
        .long("lock-hash")
        .takes_value(true)
        .validator(|input| FixedHashParser::<H256>::default().validate(input))
        .help("Lock hash")
}

pub fn lock_arg<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("lock-arg")
        .long("lock-arg")
        .takes_value(true)
        .validator(|input| FixedHashParser::<H160>::default().validate(input))
        .help("Lock argument (account identifier, blake2b(pubkey)[0..20])")
}

pub fn from_account<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("from-account")
        .long("from-account")
        .takes_value(true)
        .validator(|input| FixedHashParser::<H160>::default().validate(input))
        .help("The account's lock-arg (transfer from this account)")
}

pub fn to_address<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("to-address")
        .long("to-address")
        .takes_value(true)
        .validator(|input| AddressParser.validate(input))
        .help("Target address")
}

pub fn to_data<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("to-data")
        .long("to-data")
        .takes_value(true)
        .validator(|input| HexParser.validate(input))
        .help("Hex data store in target cell (optional)")
}

pub fn to_data_path<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("to-data-path")
        .long("to-data-path")
        .takes_value(true)
        .validator(|input| FilePathParser::new(true).validate(input))
        .help("Data binary file path store in target cell (optional)")
}

pub fn capacity<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("capacity")
        .long("capacity")
        .takes_value(true)
        .validator(|input| CapacityParser.validate(input))
        .help("The capacity (unit: CKB, format: 123.335)")
}

pub fn with_password<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("with-password")
        .long("with-password")
        .help("Input password to unlock keystore account just for current transfer transaction")
}

pub fn type_hash<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("type-hash")
        .long("type-hash")
        .takes_value(true)
        .validator(|input| FixedHashParser::<H256>::default().validate(input))
        .help("The type script hash")
}

pub fn code_hash<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("code-hash")
        .long("code-hash")
        .takes_value(true)
        .validator(|input| FixedHashParser::<H256>::default().validate(input))
        .help("The type script's code hash")
}

pub fn live_cells_limit<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("limit")
        .long("limit")
        .takes_value(true)
        .validator(|input| FromStrParser::<usize>::default().validate(input))
        .default_value("15")
        .help("Get live cells <= limit")
}

pub fn from_block_number<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("from")
        .long("from")
        .takes_value(true)
        .validator(|input| FromStrParser::<u64>::default().validate(input))
        .help("From block number")
}

pub fn to_block_number<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("to")
        .long("to")
        .takes_value(true)
        .validator(|input| FromStrParser::<u64>::default().validate(input))
        .help("To block number")
}

pub fn top_n<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("number")
        .short("n")
        .long("number")
        .takes_value(true)
        .validator(|input| FromStrParser::<u32>::default().validate(input))
        .default_value("10")
        .help("Get top n capacity addresses")
}
