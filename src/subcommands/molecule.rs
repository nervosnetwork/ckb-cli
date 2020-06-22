use std::fmt::Display;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::{self as json_types, JsonBytes};
use ckb_types::{bytes::Bytes, packed, prelude::*, H256};
use clap::{App, Arg, ArgMatches};
use serde_derive::{Deserialize, Serialize};

use super::{CliSubCommand, Output};
use crate::utils::arg_parser::{ArgParser, FilePathParser, HexParser};

pub struct MoleculeSubCommand {}

impl MoleculeSubCommand {
    pub fn new() -> MoleculeSubCommand {
        MoleculeSubCommand {}
    }

    pub fn subcommand(name: &'static str) -> App<'static> {
        let arg_type = Arg::with_name("type")
            .long("type")
            .takes_value(true)
            .required(true)
            .about("The molecule type name defined in blockchain.mol (and extra OutPointVec)");
        let arg_binary_hex = Arg::with_name("binary-hex")
            .long("binary-hex")
            .takes_value(true)
            .required(true)
            .validator(|input| HexParser.validate(input))
            .about("Binary data hex format");

        let arg_json_path = Arg::with_name("json-path")
            .long("json-path")
            .takes_value(true)
            .required(true)
            .validator(|input| FilePathParser::new(true).validate(input));
        let arg_serialize_output_type = Arg::with_name("output-type")
            .long("output-type")
            .takes_value(true)
            .default_value("binary")
            .possible_values(&["binary", "hash"])
            .about("Serialize output type");

        App::new(name)
            .about("Molecule encode/decode utilities")
            .subcommands(vec![
                App::new("decode")
                    .about("Decode molecule type from binary")
                    .arg(arg_type.clone())
                    .arg(arg_binary_hex.clone()),
                App::new("encode")
                    .about("Encode molecule type from json to binary")
                    .arg(arg_type.clone())
                    .arg(arg_json_path.clone())
                    .arg(arg_serialize_output_type),
                App::new("default")
                    .about("Print default json structure of certain molecule type")
                    .arg(arg_type.clone())
                    .arg(
                        arg_json_path
                            .clone()
                            .required(false)
                            .validator(|input| FilePathParser::new(false).validate(input)),
                    ),
            ])
    }
}

impl CliSubCommand for MoleculeSubCommand {
    fn process(&mut self, matches: &ArgMatches, _debug: bool) -> Result<Output, String> {
        match matches.subcommand() {
            ("decode", Some(m)) => {
                let type_name = m.value_of("type").unwrap();
                let binary: Vec<u8> = HexParser.from_matches(m, "binary-hex")?;
                match type_name {
                    "Uint32" => packed::Uint32::from_slice(&binary)
                        .map(|s| Unpack::<u32>::unpack(&s).to_string())
                        .map(|s| Output::new_output(serde_json::json!(s)))
                        .map_err(|err| format!("Invalid data, error: {}", err)),
                    "Uint64" => packed::Uint64::from_slice(&binary)
                        .map(|s| Unpack::<u64>::unpack(&s).to_string())
                        .map(|s| Output::new_output(serde_json::json!(s)))
                        .map_err(|err| format!("Invalid data, error: {}", err)),
                    "Uint128" => packed::Uint128::from_slice(&binary)
                        .map(|s| Unpack::<u128>::unpack(&s).to_string())
                        .map(|s| Output::new_output(serde_json::json!(s)))
                        .map_err(|err| format!("Invalid data, error: {}", err)),
                    "Bytes" => decode_simple::<packed::Bytes>(&binary),
                    "BytesVec" => decode_simple::<packed::BytesVec>(&binary),
                    "Byte32Vec" => decode_simple::<packed::Byte32Vec>(&binary),

                    "UncleBlockVec" => decode_simple::<packed::UncleBlockVec>(&binary),
                    "TransactionVec" => decode_simple::<packed::TransactionVec>(&binary),
                    "ProposalShortIdVec" => decode_simple::<packed::ProposalShortIdVec>(&binary),
                    "CellDepVec" => decode_simple::<packed::CellDepVec>(&binary),
                    "CellInputVec" => decode_simple::<packed::CellInputVec>(&binary),
                    "CellOutputVec" => decode_simple::<packed::CellOutputVec>(&binary),
                    "Script" => decode_to_json::<packed::Script, json_types::Script>(&binary),
                    "OutPoint" => decode_to_json::<packed::OutPoint, json_types::OutPoint>(&binary),
                    "CellInput" => {
                        decode_to_json::<packed::CellInput, json_types::CellInput>(&binary)
                    }
                    "CellOutput" => {
                        decode_to_json::<packed::CellOutput, json_types::CellOutput>(&binary)
                    }
                    "CellDep" => decode_to_json::<packed::CellDep, json_types::CellDep>(&binary),
                    "RawTransaction" => {
                        decode_to_json::<packed::RawTransaction, RawTransaction>(&binary)
                    }
                    "Transaction" => {
                        decode_to_json::<packed::Transaction, json_types::Transaction>(&binary)
                    }
                    "RawHeader" => decode_to_json::<packed::RawHeader, RawHeader>(&binary),
                    "Header" => decode_to_json::<packed::Header, json_types::Header>(&binary),
                    "UncleBlock" => {
                        decode_to_json::<packed::UncleBlock, json_types::UncleBlock>(&binary)
                    }
                    "Block" => decode_to_json::<packed::Block, json_types::Block>(&binary),
                    "CellbaseWitness" => {
                        decode_to_json::<packed::CellbaseWitness, CellbaseWitness>(&binary)
                    }
                    "WitnessArgs" => decode_to_json::<packed::WitnessArgs, WitnessArgs>(&binary),
                    // In extensions.mol
                    "OutPointVec" => decode_to_json::<packed::OutPointVec, OutPoints>(&binary),

                    _ => Err(format!("Unsupported molecule type name: {}", type_name)),
                }
            }
            ("encode", Some(m)) => {
                let type_name = m.value_of("type").unwrap();
                let output_type = m.value_of("output-type").unwrap();
                let json_path: PathBuf = FilePathParser::new(true).from_matches(m, "json-path")?;
                let content = fs::read_to_string(json_path).map_err(|err| err.to_string())?;

                let binary_result = match type_name {
                    "Script" => {
                        encode_from_json::<packed::Script, json_types::Script>(content.as_str())
                    }
                    "OutPoint" => {
                        encode_from_json::<packed::OutPoint, json_types::OutPoint>(content.as_str())
                    }
                    "CellInput" => encode_from_json::<packed::CellInput, json_types::CellInput>(
                        content.as_str(),
                    ),
                    "CellOutput" => encode_from_json::<packed::CellOutput, json_types::CellOutput>(
                        content.as_str(),
                    ),
                    "CellDep" => {
                        encode_from_json::<packed::CellDep, json_types::CellDep>(content.as_str())
                    }
                    "RawTransaction" => {
                        encode_from_json::<packed::RawTransaction, RawTransaction>(content.as_str())
                    }
                    "Transaction" => {
                        encode_from_json::<packed::Transaction, json_types::Transaction>(
                            content.as_str(),
                        )
                    }
                    "RawHeader" => {
                        encode_from_json::<packed::RawHeader, RawHeader>(content.as_str())
                    }
                    "Header" => {
                        encode_from_json::<packed::Header, json_types::Header>(content.as_str())
                    }
                    "UncleBlock" => encode_from_json::<packed::UncleBlock, json_types::UncleBlock>(
                        content.as_str(),
                    ),
                    "Block" => {
                        encode_from_json::<packed::Block, json_types::Block>(content.as_str())
                    }
                    "CellbaseWitness" => {
                        encode_from_json::<packed::CellbaseWitness, CellbaseWitness>(
                            content.as_str(),
                        )
                    }
                    "WitnessArgs" => {
                        encode_from_json::<packed::WitnessArgs, WitnessArgs>(content.as_str())
                    }
                    // In extensions.mol
                    "OutPointVec" => {
                        encode_from_json::<packed::OutPointVec, OutPoints>(content.as_str())
                    }
                    _ => Err(format!("Unsupported molecule type name: {}", type_name)),
                };

                let binary = binary_result?;
                let output = match output_type {
                    "binary" => format!("0x{}", hex_string(&binary)),
                    "hash" => format!("0x{}", hex_string(&blake2b_256(&binary))),
                    _ => panic!("Invalid output type"),
                };
                Ok(Output::new_output(serde_json::Value::String(output)))
            }
            ("default", Some(m)) => {
                let type_name = m.value_of("type").unwrap();
                let json_path: Option<PathBuf> =
                    FilePathParser::new(false).from_matches_opt(m, "json-path", false)?;
                if let Some(path) = json_path.as_ref() {
                    if path.exists() {
                        return Err(format!("File exists: {:?}", path));
                    }
                }

                let value = match type_name {
                    "Script" => serde_json::to_value(json_types::Script::default()).unwrap(),
                    "OutPoint" => serde_json::to_value(json_types::OutPoint::default()).unwrap(),
                    "CellInput" => serde_json::to_value(json_types::CellInput::default()).unwrap(),
                    "CellOutput" => {
                        serde_json::to_value(json_types::CellOutput::default()).unwrap()
                    }
                    "CellDep" => serde_json::to_value(json_types::CellDep::default()).unwrap(),
                    "RawTransaction" => serde_json::to_value(RawTransaction::default()).unwrap(),
                    "Transaction" => {
                        serde_json::to_value(json_types::Transaction::default()).unwrap()
                    }
                    "RawHeader" => serde_json::to_value(RawHeader::default()).unwrap(),
                    "Header" => serde_json::to_value(json_types::Header::default()).unwrap(),
                    "UncleBlock" => {
                        serde_json::to_value(json_types::UncleBlock::default()).unwrap()
                    }
                    "Block" => serde_json::to_value(json_types::Block::default()).unwrap(),
                    "CellbaseWitness" => serde_json::to_value(CellbaseWitness::default()).unwrap(),
                    "WitnessArgs" => serde_json::to_value(WitnessArgs::default()).unwrap(),
                    // In extensions.mol
                    "OutPointVec" => serde_json::to_value(OutPoints::default()).unwrap(),
                    _ => {
                        return Err(format!("Unsupported molecule type name: {}", type_name));
                    }
                };
                if let Some(path) = json_path {
                    fs::File::create(path)
                        .map_err(|err| err.to_string())?
                        .write_all(serde_json::to_string_pretty(&value).unwrap().as_bytes())
                        .map_err(|err| err.to_string())?;
                    Ok(Output::new_success())
                } else {
                    Ok(Output::new_output(value))
                }
            }
            _ => Err(Self::subcommand("molecule").generate_usage()),
        }
    }
}

fn decode_simple<T: Entity + Display>(binary: &[u8]) -> Result<Output, String> {
    T::from_slice(binary)
        .map(|s| s.to_string())
        .map(|s| Output::new_output(serde_json::json!(s)))
        .map_err(|err| err.to_string())
}

fn decode_to_json<T, J>(binary: &[u8]) -> Result<Output, String>
where
    T: Entity + Into<J>,
    J: serde::Serialize,
{
    let json: J = T::from_slice(&binary)
        .map(Into::into)
        .map_err(|err| err.to_string())?;
    Ok(Output::new_output(json))
}

fn encode_from_json<'a, T, J>(content: &'a str) -> Result<Bytes, String>
where
    T: Entity + From<J>,
    J: serde::Deserialize<'a>,
{
    let json: J = serde_json::from_str(content).map_err(|err| err.to_string())?;
    Ok(T::from(json).as_bytes())
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
#[serde(deny_unknown_fields)]
struct WitnessArgs {
    pub lock: Option<JsonBytes>,
    pub input_type: Option<JsonBytes>,
    pub output_type: Option<JsonBytes>,
}

impl From<packed::WitnessArgs> for WitnessArgs {
    fn from(input: packed::WitnessArgs) -> Self {
        WitnessArgs {
            lock: input
                .lock()
                .to_opt()
                .map(|data| JsonBytes::from_bytes(data.unpack())),
            input_type: input
                .input_type()
                .to_opt()
                .map(|data| JsonBytes::from_bytes(data.unpack())),
            output_type: input
                .output_type()
                .to_opt()
                .map(|data| JsonBytes::from_bytes(data.unpack())),
        }
    }
}

impl From<WitnessArgs> for packed::WitnessArgs {
    fn from(json: WitnessArgs) -> Self {
        packed::WitnessArgs::new_builder()
            .lock(
                packed::BytesOpt::new_builder()
                    .set(json.lock.map(Into::into))
                    .build(),
            )
            .input_type(
                packed::BytesOpt::new_builder()
                    .set(json.input_type.map(Into::into))
                    .build(),
            )
            .output_type(
                packed::BytesOpt::new_builder()
                    .set(json.output_type.map(Into::into))
                    .build(),
            )
            .build()
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
#[serde(deny_unknown_fields)]
struct CellbaseWitness {
    pub lock: json_types::Script,
    pub message: JsonBytes,
}

impl From<packed::CellbaseWitness> for CellbaseWitness {
    fn from(input: packed::CellbaseWitness) -> CellbaseWitness {
        CellbaseWitness {
            lock: input.lock().into(),
            message: JsonBytes::from_bytes(input.message().unpack()),
        }
    }
}

impl From<CellbaseWitness> for packed::CellbaseWitness {
    fn from(json: CellbaseWitness) -> Self {
        packed::CellbaseWitness::new_builder()
            .lock(json.lock.into())
            .message(json.message.into())
            .build()
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
#[serde(deny_unknown_fields)]
struct RawTransaction {
    pub version: json_types::Version,
    pub cell_deps: Vec<json_types::CellDep>,
    pub header_deps: Vec<H256>,
    pub inputs: Vec<json_types::CellInput>,
    pub outputs: Vec<json_types::CellOutput>,
    pub outputs_data: Vec<JsonBytes>,
}

impl From<packed::RawTransaction> for RawTransaction {
    fn from(input: packed::RawTransaction) -> Self {
        RawTransaction {
            version: input.version().unpack(),
            cell_deps: input.cell_deps().into_iter().map(Into::into).collect(),
            header_deps: input
                .header_deps()
                .into_iter()
                .map(|d| Unpack::<H256>::unpack(&d))
                .collect(),
            inputs: input.inputs().into_iter().map(Into::into).collect(),
            outputs: input.outputs().into_iter().map(Into::into).collect(),
            outputs_data: input.outputs_data().into_iter().map(Into::into).collect(),
        }
    }
}

impl From<RawTransaction> for packed::RawTransaction {
    fn from(json: RawTransaction) -> Self {
        packed::RawTransaction::new_builder()
            .version(json.version.pack())
            .cell_deps(json.cell_deps.into_iter().map(Into::into).pack())
            .header_deps(json.header_deps.iter().map(Pack::pack).pack())
            .inputs(json.inputs.into_iter().map(Into::into).pack())
            .outputs(json.outputs.into_iter().map(Into::into).pack())
            .outputs_data(json.outputs_data.into_iter().map(Into::into).pack())
            .build()
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
#[serde(deny_unknown_fields)]
struct RawHeader {
    pub version: json_types::Version,
    pub compact_target: json_types::Uint32,
    pub parent_hash: H256,
    pub timestamp: json_types::Timestamp,
    pub number: json_types::BlockNumber,
    pub epoch: json_types::EpochNumberWithFraction,
    pub transactions_root: H256,
    pub proposals_hash: H256,
    pub uncles_hash: H256,
    pub dao: json_types::Byte32,
}

impl From<packed::RawHeader> for RawHeader {
    fn from(input: packed::RawHeader) -> Self {
        RawHeader {
            version: input.version().unpack(),
            parent_hash: input.parent_hash().unpack(),
            timestamp: input.timestamp().unpack(),
            number: input.number().unpack(),
            epoch: input.epoch().unpack(),
            transactions_root: input.transactions_root().unpack(),
            proposals_hash: input.proposals_hash().unpack(),
            compact_target: input.compact_target().unpack(),
            uncles_hash: input.uncles_hash().unpack(),
            dao: input.dao().into(),
        }
    }
}

impl From<RawHeader> for packed::RawHeader {
    fn from(json: RawHeader) -> Self {
        packed::RawHeader::new_builder()
            .version(json.version.pack())
            .parent_hash(json.parent_hash.pack())
            .timestamp(json.timestamp.pack())
            .number(json.number.pack())
            .epoch(json.epoch.pack())
            .transactions_root(json.transactions_root.pack())
            .proposals_hash(json.proposals_hash.pack())
            .compact_target(json.compact_target.pack())
            .uncles_hash(json.uncles_hash.pack())
            .dao(json.dao.into())
            .build()
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
#[serde(deny_unknown_fields)]
struct OutPoints {
    pub items: Vec<json_types::OutPoint>,
}

impl From<packed::OutPointVec> for OutPoints {
    fn from(input: packed::OutPointVec) -> Self {
        OutPoints {
            items: input.into_iter().map(json_types::OutPoint::from).collect(),
        }
    }
}

impl From<OutPoints> for packed::OutPointVec {
    fn from(json: OutPoints) -> Self {
        json.items.into_iter().map(packed::OutPoint::from).pack()
    }
}
