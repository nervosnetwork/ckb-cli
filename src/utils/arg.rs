use crate::utils::arg_parser::{
    AddressParser, ArgParser, CapacityParser, FilePathParser, FixedHashParser, FromStrParser,
    HexParser, OutPointParser, PrivkeyPathParser, PubkeyHexParser,
};
use ckb_types::H160;
use clap::Arg;

pub fn privkey_path<'a>() -> Arg<'a> {
    Arg::with_name("privkey-path")
        .long("privkey-path")
        .takes_value(true)
        .validator(|input| PrivkeyPathParser.validate(input))
        .about("Private key file path (only read first line)")
}

pub fn pubkey<'a>() -> Arg<'a> {
    Arg::with_name("pubkey")
        .long("pubkey")
        .takes_value(true)
        .validator(|input| PubkeyHexParser.validate(input))
        .about("Public key (hex string, compressed format)")
}

pub fn address<'a>() -> Arg<'a> {
    Arg::with_name("address")
        .long("address")
        .takes_value(true)
        .validator(|input| AddressParser::default().validate(input))
        .about(
            "Target address (see: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0021-ckb-address-format/0021-ckb-address-format.md)",
        )
}

pub fn derive_receiving_address_length<'a>() -> Arg<'a> {
    Arg::with_name("derive-receiving-address-length")
        .long("derive-receiving-address-length")
        .takes_value(true)
        .default_value("1000")
        .validator(|input| FromStrParser::<u32>::default().validate(input))
        .about("Search derived receiving address length")
}

pub fn derive_change_address_length<'a>() -> Arg<'a> {
    Arg::with_name("derive-change-address-length")
        .long("derive-change-address-length")
        .takes_value(true)
        .default_value("1000")
        .validator(|input| FromStrParser::<u32>::default().validate(input))
        .about("Search derived change address length")
}

pub fn derive_change_address<'a>() -> Arg<'a> {
    Arg::with_name("derive-change-address")
        .long("derive-change-address")
        .takes_value(true)
        .validator(|input| AddressParser::default().validate(input))
        .about("Manually specify the last change address (search 10000 addresses max, required keystore password, see: BIP-44)")
}

pub fn derived<'a>() -> Arg<'a> {
    Arg::with_name("derived")
        .long("derived")
        .about("Search derived address space (search 10000 addresses(change/receiving) max, required keystore password, see: BIP-44)")
}

pub fn lock_arg<'a>() -> Arg<'a> {
    Arg::with_name("lock-arg")
        .long("lock-arg")
        .takes_value(true)
        .validator(|input| FixedHashParser::<H160>::default().validate(input))
        .about("Lock argument (account identifier, blake2b(pubkey)[0..20])")
}

pub fn from_account<'a>() -> Arg<'a> {
    Arg::with_name("from-account")
        .long("from-account")
        .takes_value(true)
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
        .about("The account's lock-arg or sighash address (transfer from this account)")
}

pub fn from_locked_address<'a>() -> Arg<'a> {
    Arg::with_name("from-locked-address")
        .long("from-locked-address")
        .takes_value(true)
        .validator(|input| AddressParser::default().validate(input))
        .about("The time locked multisig address to search live cells (which S=0,R=0,M=1,N=1 and have since value)")
}

pub fn to_address<'a>() -> Arg<'a> {
    Arg::with_name("to-address")
        .long("to-address")
        .takes_value(true)
        .validator(|input| AddressParser::default().validate(input))
        .about("Target address")
}

pub fn to_data<'a>() -> Arg<'a> {
    Arg::with_name("to-data")
        .long("to-data")
        .takes_value(true)
        .validator(|input| HexParser.validate(input))
        .about("Hex data store in target cell (optional)")
}

pub fn to_data_path<'a>() -> Arg<'a> {
    Arg::with_name("to-data-path")
        .long("to-data-path")
        .takes_value(true)
        .validator(|input| FilePathParser::new(true).validate(input))
        .about("Data binary file path store in target cell (optional)")
}

pub fn capacity<'a>() -> Arg<'a> {
    Arg::with_name("capacity")
        .long("capacity")
        .takes_value(true)
        .validator(|input| CapacityParser.validate(input))
        .about("The capacity (unit: CKB, format: 123.335)")
}

pub fn fee_rate<'a>() -> Arg<'a> {
    Arg::with_name("fee-rate")
        .long("fee-rate")
        .takes_value(true)
        .validator(|input| FromStrParser::<u64>::default().validate(input))
        .default_value("1000")
        .about("The transaction fee rate (unit: shannons/KB)")
}

/// create an Arg object to receive value of force_small_change_as_fee for CapacityBalancer
pub fn max_tx_fee<'a>() -> Arg<'a> {
    Arg::with_name("max-tx-fee")
        .long("max-tx-fee")
        .takes_value(true)
        .value_name("capacity")
        .validator(|input|CapacityParser.validate(input))
        .about("When there is no more inputs for create a change cell to balance the transaction capacity, force the addition capacity as fee, the value is actual maximum transaction fee(unit CKB, example:0.001)")
}

pub fn live_cells_limit<'a>() -> Arg<'a> {
    Arg::with_name("limit")
        .long("limit")
        .takes_value(true)
        .validator(|input| FromStrParser::<usize>::default().validate(input))
        .default_value("15")
        .about("Get live cells <= limit")
}

pub fn from_block_number<'a>() -> Arg<'a> {
    Arg::with_name("from")
        .long("from")
        .takes_value(true)
        .validator(|input| FromStrParser::<u64>::default().validate(input))
        .about("From block number (inclusive)")
}

pub fn to_block_number<'a>() -> Arg<'a> {
    Arg::with_name("to")
        .long("to")
        .takes_value(true)
        .validator(|input| FromStrParser::<u64>::default().validate(input))
        .about("To block number (exclusive)")
}

pub fn out_point<'a>() -> Arg<'a> {
    Arg::with_name("out-point")
        .long("out-point")
        .takes_value(true)
        .validator(|input| { OutPointParser.validate(input) })
        .about("out-point to specify a cell. Example: 0xd56ed5d4e8984701714de9744a533413f79604b3b91461e2265614829d2005d1-1")
}
