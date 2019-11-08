use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use ckb_hash::{blake2b_256, new_blake2b};
use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    serialize_signature, wallet::KeyStore, Address, AddressType, CodeHashIndex, GenesisInfo,
    HttpRpcClient, NetworkType, Since, SECP256K1,
};
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, ScriptHashType, TransactionBuilder, TransactionView},
    packed::{self, CellOutput, WitnessArgs},
    prelude::*,
    H160, H256,
};
use clap::{App, Arg, ArgMatches, SubCommand};
use faster_hex::hex_string;
use serde_derive::{Deserialize, Serialize};

use super::CliSubCommand;
use crate::utils::{
    arg,
    arg_parser::{
        AddressParser, ArgParser, CapacityParser, FilePathParser, FixedHashParser, FromStrParser,
        HexParser, PrivkeyPathParser, PrivkeyWrapper,
    },
    other::{check_capacity, get_genesis_info, get_to_data, read_password},
    printer::{OutputFormat, Printable},
};

const SIGNATURE_SIZE: usize = 65;

pub struct MultisigSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    key_store: &'a mut KeyStore,
    genesis_info: Option<GenesisInfo>,
}

impl<'a> MultisigSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        key_store: &'a mut KeyStore,
        genesis_info: Option<GenesisInfo>,
    ) -> MultisigSubCommand<'a> {
        MultisigSubCommand {
            rpc_client,
            key_store,
            genesis_info,
        }
    }

    pub fn subcommand(name: &'static str) -> App<'static, 'static> {
        let arg_tx_file = Arg::with_name("tx-file")
            .long("tx-file")
            .takes_value(true)
            .validator(|input| FilePathParser::new(false).validate(input))
            .required(true)
            .help("Multisig transaction data file (format: json)");
        let arg_signature = Arg::with_name("signature")
            .long("signature")
            .takes_value(true)
            .multiple(true)
            .required(true)
            .validator(|input| HexParser.validate(input))
            .help("The signature by one account of current transaction (NOTE: order may matters)");
        // let arg_since_value = Arg::with_name("since-value")
        //     .long("since-value")
        //     .takes_value(true)
        //     .required(true)
        //     .validator(|input| FromStrParser::<u64>::default().validate(input))
        //     .help("Since value (use rfc3339 format for timestamp value)");
        // let arg_since_type = Arg::with_name("since-type")
        //     .long("since-type")
        //     .takes_value(true)
        //     .required(true)
        //     .required(true)
        //     .possible_values(&["timestamp", "block-number", "epoch-number"])
        //     .help("Since type");
        // let arg_since_relative = Arg::with_name("since-relative")
        //     .long("since-relative")
        //     .help("Build a relative since");
        let arg_sighash_address = Arg::with_name("sighash-address")
            .long("sighash-address")
            .takes_value(true)
            .multiple(true)
            .required(true)
            .validator(|input| AddressParser::new_sighash().validate(input))
            .help("Normal sighash address");
        let arg_require_first_n = Arg::with_name("require-first-n")
            .long("require-first-n")
            .takes_value(true)
            .default_value("0")
            .validator(|input| FromStrParser::<u8>::default().validate(input))
            .help("Require first n signatures of corresponding pubkey");
        let arg_threshold = Arg::with_name("threshold")
            .long("threshold")
            .takes_value(true)
            .default_value("1")
            .validator(|input| FromStrParser::<u8>::default().validate(input))
            .help("Multisig threshold");

        SubCommand::with_name(name)
            .about("Handle multisig transaction")
            .subcommands(vec![
                SubCommand::with_name("tx-template")
                    .about("Multisig transaction template")
                    .arg(arg_sighash_address.clone())
                    .arg(arg_require_first_n.clone())
                    .arg(arg_threshold.clone())
                    .arg(arg_tx_file.clone()),
                SubCommand::with_name("add-input")
                    .about("Add cell input")
                    .arg(
                        Arg::with_name("tx-hash")
                            .long("tx-hash")
                            .takes_value(true)
                            .validator(|input| FixedHashParser::<H256>::default().validate(input))
                            .required(true)
                            .help("Transaction hash"),
                    )
                    .arg(
                        Arg::with_name("index")
                            .long("index")
                            .takes_value(true)
                            .validator(|input| FromStrParser::<u32>::default().validate(input))
                            .required(true)
                            .help("Transaction output index"),
                    )
                    // .arg(arg_since_value.clone())
                    // .arg(arg_since_type.clone())
                    // .arg(arg_since_relative.clone())
                    .arg(arg_tx_file.clone()),
                SubCommand::with_name("add-output")
                    .about("Add cell output")
                    .arg(
                        Arg::with_name("to-sighash-address")
                            .long("to-sighash-address")
                            .takes_value(true)
                            .validator(|input| AddressParser::new_sighash().validate(input))
                            .help("To normal sighash address"),
                    )
                    .arg(
                        Arg::with_name("to-short-multisig-address")
                            .long("to-short-multisig-address")
                            .takes_value(true)
                            .validator(|input| AddressParser::new_multisig().validate(input))
                            .help("To short multisig address"),
                    )
                    // .arg(
                    //     Arg::with_name("to-long-multisig-address")
                    //         .long("to-long-multisig-address")
                    //         .takes_value(true)
                    //         .validator(|input| AddressParser::new_multisig().validate(input))
                    //         .help("To long multisig address (special case, include since)"),
                    // )
                    .arg(arg::capacity().required(true))
                    .arg(arg::to_data())
                    .arg(arg::to_data_path())
                    .arg(arg_tx_file.clone()),
                SubCommand::with_name("add-signature")
                    .about("Add signature")
                    .arg(
                        Arg::with_name("lock-arg")
                            .long("lock-arg")
                            .takes_value(true)
                            .required(true)
                            .validator(|input| match HexParser.parse(&input) {
                                Ok(ref data) if data.len() == 20 || data.len() == 28 => Ok(()),
                                Ok(ref data) => Err(format!("invalid data length: {}", data.len())),
                                Err(err) => Err(err.to_string()),
                            })
                            .help("The lock_arg of input lock script (20 bytes or 28 bytes)"),
                    )
                    .arg(
                        Arg::with_name("signature")
                            .long("signature")
                            .takes_value(true)
                            .required(true)
                            .validator(|input| match HexParser.parse(&input) {
                                Ok(ref data) if data.len() == SIGNATURE_SIZE => Ok(()),
                                Ok(ref data) => Err(format!("invalid data length: {}", data.len())),
                                Err(err) => Err(err.to_string()),
                            })
                            .help("The signature"),
                    )
                    .arg(arg_tx_file.clone()),
                SubCommand::with_name("tx-info")
                    .about("Show detail of this multisig transaction (capacity, tx-fee, etc.)")
                    .arg(arg_tx_file.clone()),
                SubCommand::with_name("sign-tx")
                    .about("Sign a mutisig transaction")
                    .arg(arg::privkey_path().required_unless(arg::from_account().b.name))
                    .arg(arg::from_account().required_unless(arg::privkey_path().b.name))
                    .arg(arg_tx_file.clone()),
                SubCommand::with_name("send-tx")
                    .about("Send multisig transaction")
                    .arg(arg_signature.clone())
                    .arg(arg_tx_file.clone()),
                SubCommand::with_name("build-multisig-address")
                    .about("Build multisig address (only support short version, without since)")
                    .arg(arg_sighash_address.clone())
                    .arg(arg_require_first_n.clone())
                    .arg(arg_threshold.clone()),
            ])
    }
}

impl<'a> CliSubCommand for MultisigSubCommand<'a> {
    fn process(
        &mut self,
        matches: &ArgMatches,
        format: OutputFormat,
        color: bool,
        _debug: bool,
    ) -> Result<String, String> {
        let genesis_info = get_genesis_info(&mut self.genesis_info, self.rpc_client)?;
        fn modify_tx_file<F: FnOnce(&mut MultisigTx) -> Result<(), String>>(
            path: &PathBuf,
            func: F,
        ) -> Result<(), String> {
            let mut multisig_tx: MultisigTx = {
                let file = fs::File::open(path).map_err(|err| err.to_string())?;
                serde_json::from_reader(&file).map_err(|err| err.to_string())?
            };
            func(&mut multisig_tx)?;
            let mut file = fs::File::create(path).map_err(|err| err.to_string())?;
            let content =
                serde_json::to_string_pretty(&multisig_tx).map_err(|err| err.to_string())?;
            file.write_all(content.as_bytes())
                .map_err(|err| err.to_string())?;
            Ok(())
        }

        match matches.subcommand() {
            ("tx-template", Some(m)) => {
                let tx_file: PathBuf = FilePathParser::new(false).from_matches(m, "tx-file")?;
                let sighash_addresses: Vec<Address> =
                    AddressParser::new_sighash().from_matches_vec(m, "sighash-address")?;
                let require_first_n: u8 =
                    FromStrParser::<u8>::default().from_matches(m, "require-first-n")?;
                let threshold: u8 = FromStrParser::<u8>::default().from_matches(m, "threshold")?;

                let rpc_tx: json_types::Transaction = TransactionBuilder::default()
                    .cell_dep(genesis_info.multisig_dep())
                    .build()
                    .data()
                    .into();
                let multisig_args = MultisigArgs {
                    sighash_addresses,
                    require_first_n,
                    threshold,
                };
                let multisig_tx = MultisigTx {
                    transaction: rpc_tx,
                    multisig_args,
                    all_signatures: Vec::new(),
                };
                let mut file = fs::File::create(&tx_file).map_err(|err| err.to_string())?;
                let content =
                    serde_json::to_string_pretty(&multisig_tx).map_err(|err| err.to_string())?;
                file.write_all(content.as_bytes())
                    .map_err(|err| err.to_string())?;
                Ok(format!(
                    ">> Success wrote multisig transaction to file: {:?}",
                    tx_file
                ))
            }
            ("add-input", Some(m)) => {
                let tx_file: PathBuf = FilePathParser::new(true).from_matches(m, "tx-file")?;
                let tx_hash: H256 =
                    FixedHashParser::<H256>::default().from_matches(m, "tx-hash")?;
                let index: u32 = FromStrParser::<u32>::default().from_matches(m, "index")?;

                modify_tx_file(&tx_file, |multisig_tx| {
                    let cell_input = json_types::CellInput {
                        previous_output: json_types::OutPoint {
                            tx_hash,
                            index: index.into(),
                        },
                        since: 0u64.into(),
                    };
                    multisig_tx.transaction.inputs.push(cell_input);
                    Ok(())
                })?;
                Ok("ok".to_string())
            }
            ("add-output", Some(m)) => {
                let tx_file: PathBuf = FilePathParser::new(true).from_matches(m, "tx-file")?;
                let capacity: u64 = CapacityParser.from_matches(m, "capacity")?;
                let to_sighash_address_opt: Option<Address> = AddressParser::new_sighash()
                    .from_matches_opt(m, "to-sighash-address", false)?;
                let to_multisig_address_opt: Option<Address> = AddressParser::new_multisig()
                    .from_matches_opt(m, "to-short-multisig-address", false)?;

                let to_data = get_to_data(m)?;
                check_capacity(capacity, to_data.len())?;
                let genesis_info = get_genesis_info(&mut self.genesis_info, self.rpc_client)?;
                let lock_script = to_sighash_address_opt
                    .map(|address| {
                        address
                            .lock_script(genesis_info.secp_type_hash().clone())
                            .unwrap()
                    })
                    .or_else(|| {
                        to_multisig_address_opt.map(|address| {
                            address
                                .lock_script(genesis_info.multisig_type_hash().clone())
                                .unwrap()
                        })
                    })
                    .ok_or_else(|| "missing target address".to_string())?;
                let output = CellOutput::new_builder()
                    .capacity(Capacity::shannons(capacity).pack())
                    .lock(lock_script)
                    .build();
                modify_tx_file(&tx_file, |multisig_tx| {
                    multisig_tx.transaction.outputs.push(output.into());
                    multisig_tx
                        .transaction
                        .outputs_data
                        .push(json_types::JsonBytes::from_bytes(to_data));
                    Ok(())
                })?;
                Ok("ok".to_string())
            }
            ("add-signature", Some(m)) => {
                let tx_file: PathBuf = FilePathParser::new(true).from_matches(m, "tx-file")?;
                let lock_arg: Vec<u8> = HexParser.from_matches(m, "lock-arg")?;
                let signature: Vec<u8> = HexParser.from_matches(m, "signature")?;

                modify_tx_file(&tx_file, |multisig_tx| {
                    let mut all_signatures = multisig_tx.all_signatures();
                    all_signatures
                        .entry(lock_arg)
                        .or_default()
                        .insert(signature);
                    multisig_tx.set_all_signatures(all_signatures);
                    Ok(())
                })?;
                Ok("ok".to_string())
            }
            ("tx-info", Some(m)) => {
                let tx_file: PathBuf = FilePathParser::new(false).from_matches(m, "tx-file")?;
                Ok("TODO".to_string())
            }
            ("sign-tx", Some(m)) => {
                let tx_file: PathBuf = FilePathParser::new(false).from_matches(m, "tx-file")?;
                let privkey: Option<PrivkeyWrapper> =
                    PrivkeyPathParser.from_matches_opt(m, "privkey-path", false)?;
                let account: Option<H160> =
                    FixedHashParser::<H160>::default().from_matches_opt(m, "account", false)?;

                let file = fs::File::open(&tx_file).map_err(|err| err.to_string())?;
                let multisig_tx: MultisigTx =
                    serde_json::from_reader(&file).map_err(|err| err.to_string())?;

                let signer_lock_arg = if let Some(privkey) = privkey.as_ref() {
                    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, privkey);
                    let pubkey_hash = blake2b_256(&pubkey.serialize()[..]);
                    H160::from_slice(&pubkey_hash[0..20]).unwrap()
                } else {
                    account
                        .ok_or_else(|| "privkey-path or account argument is missing".to_string())?
                };

                let genesis_info = get_genesis_info(&mut self.genesis_info, self.rpc_client)?;
                // For cache password
                let mut password_opt: Option<String> = None;
                let mut signer = |message: &H256, key_store: &mut KeyStore| {
                    if let Some(privkey) = privkey.as_ref() {
                        let message = secp256k1::Message::from_slice(message.as_bytes())
                            .expect("Convert to secp256k1 message failed");
                        Ok(serialize_signature(
                            &SECP256K1.sign_recoverable(&message, privkey),
                        ))
                    } else {
                        if password_opt.is_none() {
                            password_opt = Some(read_password(false, None)?);
                        }
                        let password = password_opt.as_ref().unwrap();
                        key_store
                            .sign_recoverable_with_password(
                                &signer_lock_arg,
                                message,
                                password.as_bytes(),
                            )
                            .map(|sig| serialize_signature(&sig))
                            .map_err(|err| err.to_string())
                    }
                };
                multisig_tx.check(self.rpc_client, &genesis_info, Some(&signer_lock_arg))?;

                let tx = multisig_tx.tx_view();
                let witness_base_data = multisig_tx.multisig_args.to_witness_data()?;
                let params_hash = blake2b_256(&witness_base_data);
                let params_hash160 = &params_hash[0..20];
                let mut input_group: HashMap<Bytes, Vec<usize>> = HashMap::default();
                let mut witnesses: Vec<_> = tx.witnesses().into_iter().collect();
                while witnesses.len() < tx.inputs().len() {
                    witnesses.push(Bytes::new().pack());
                }
                for (idx, input) in tx.inputs().into_iter().enumerate() {
                    let out_point: json_types::OutPoint = input.previous_output().into();
                    let cell = self
                        .rpc_client
                        .get_live_cell(out_point, false)
                        .call()
                        .map_err(|err| err.to_string())?;
                    let lock: packed::Script = cell
                        .cell
                        .ok_or_else(|| format!("Invalid input(no.{}) cell", idx + 1))?
                        .output
                        .lock
                        .into();
                    let lock_arg = lock.args().raw_data();
                    if &lock.code_hash() == genesis_info.multisig_type_hash()
                        && lock.hash_type() == ScriptHashType::Type.into()
                        && &lock_arg[..20] == params_hash160
                        && (lock_arg.len() == 20 || lock_arg.len() == 28)
                    {
                        input_group.entry(lock_arg).or_default().push(idx);
                    } else {
                        return Err(format!("Invalid input(no.{}) lock script", idx + 1));
                    }
                }

                for (lock_arg, idxs) in input_group.into_iter() {
                    let lock_without_sig = {
                        let sig_len =
                            (multisig_tx.multisig_args.threshold as usize) * SIGNATURE_SIZE;
                        let mut data = witness_base_data.clone();
                        data.extend_from_slice(vec![0u8; sig_len].as_slice());
                        data
                    };
                    let init_witness = WitnessArgs::new_builder()
                        .lock(Some(lock_without_sig).pack())
                        .build();
                    let mut blake2b = new_blake2b();
                    blake2b.update(tx.hash().as_slice());
                    blake2b.update(&(init_witness.as_bytes().len() as u64).to_le_bytes());
                    blake2b.update(&init_witness.as_bytes());
                    for idx in idxs.iter().skip(1).cloned() {
                        let other_witness = &witnesses[idx];
                        blake2b.update(&(other_witness.len() as u64).to_le_bytes());
                        blake2b.update(other_witness.as_slice());
                    }
                    let mut message = [0u8; 32];
                    blake2b.finalize(&mut message);
                    let message = H256::from(message);
                    let signature = signer(&message, self.key_store)?;
                    println!(
                        "lock-arg: 0x{}, signature: 0x{}",
                        hex_string(&lock_arg).unwrap(),
                        hex_string(&signature).unwrap(),
                    );
                }
                Ok(String::default())
            }
            ("send-tx", Some(m)) => {
                let tx_file: PathBuf = FilePathParser::new(false).from_matches(m, "tx-file")?;
                let file = fs::File::open(&tx_file).map_err(|err| err.to_string())?;
                let multisig_tx: MultisigTx =
                    serde_json::from_reader(&file).map_err(|err| err.to_string())?;

                multisig_tx.check(self.rpc_client, &genesis_info, None)?;

                let tx = multisig_tx.tx_view();
                let witness_base_data = multisig_tx.multisig_args.to_witness_data()?;
                let params_hash = blake2b_256(&witness_base_data);
                let params_hash160 = &params_hash[0..20];
                let mut input_group: HashMap<Bytes, Vec<usize>> = HashMap::default();
                let mut witnesses: Vec<_> = tx.witnesses().into_iter().collect();
                while witnesses.len() < tx.inputs().len() {
                    witnesses.push(Bytes::new().pack());
                }
                for (idx, input) in tx.inputs().into_iter().enumerate() {
                    let out_point: json_types::OutPoint = input.previous_output().into();
                    let cell = self
                        .rpc_client
                        .get_live_cell(out_point, false)
                        .call()
                        .map_err(|err| err.to_string())?;
                    let lock: packed::Script = cell
                        .cell
                        .ok_or_else(|| format!("Invalid input(no.{}) cell", idx + 1))?
                        .output
                        .lock
                        .into();
                    let lock_arg = lock.args().raw_data();
                    if &lock.code_hash() == genesis_info.multisig_type_hash()
                        && lock.hash_type() == ScriptHashType::Type.into()
                        && &lock_arg[..20] == params_hash160
                        && (lock_arg.len() == 20 || lock_arg.len() == 28)
                    {
                        input_group.entry(lock_arg).or_default().push(idx);
                    } else {
                        return Err(format!("Invalid input(no.{}) lock script", idx + 1));
                    }
                }
                let threshold = multisig_tx.multisig_args.threshold as usize;
                let all_signatures = multisig_tx.all_signatures();
                for (lock_arg, idxs) in input_group.into_iter() {
                    let mut data = witness_base_data.clone();
                    let signatures = all_signatures.get(&lock_arg.to_vec()).ok_or_else(|| {
                        format!(
                            "missing signatures for lock_arg: 0x{}",
                            hex_string(&lock_arg).unwrap()
                        )
                    })?;
                    if signatures.len() != threshold {
                        return Err(format!(
                            "Invalid signature length for lock_arg: 0x{}, got: {}, expected: {}",
                            hex_string(&lock_arg).unwrap(),
                            signatures.len(),
                            threshold,
                        ));
                    }
                    for signature in signatures {
                        data.extend_from_slice(&signature);
                    }
                    witnesses[idxs[0]] = data.pack();
                }

                let rpc_tx: json_types::Transaction = tx
                    .as_advanced_builder()
                    .set_witnesses(witnesses)
                    .build()
                    .data()
                    .into();
                let resp = self
                    .rpc_client
                    .send_transaction(rpc_tx)
                    .call()
                    .map_err(|err| format!("Send transaction error: {}", err))?;
                Ok(resp.render(format, color))
            }
            ("build-multisig-address", Some(m)) => {
                let sighash_addresses: Vec<Address> =
                    AddressParser::new_sighash().from_matches_vec(m, "sighash-address")?;
                let require_first_n: u8 =
                    FromStrParser::<u8>::default().from_matches(m, "require-first-n")?;
                let threshold: u8 = FromStrParser::<u8>::default().from_matches(m, "threshold")?;

                let genesis_info = get_genesis_info(&mut self.genesis_info, self.rpc_client)?;
                let multisig_args = MultisigArgs {
                    sighash_addresses,
                    require_first_n,
                    threshold,
                };
                multisig_args.check(None)?;
                let address = multisig_args.to_address(None, &genesis_info)?;
                let resp = serde_json::json!({
                    "mainnet": address.display_with_prefix(NetworkType::MainNet),
                    "testnet": address.display_with_prefix(NetworkType::TestNet),
                });
                Ok(resp.render(format, color))
            }
            _ => Err(matches.usage().to_owned()),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct MultisigTx {
    transaction: json_types::Transaction,
    multisig_args: MultisigArgs,
    all_signatures: Vec<MultisigSignatures>,
}

impl MultisigTx {
    fn check(
        &self,
        client: &mut HttpRpcClient,
        genesis_info: &GenesisInfo,
        signer_lock_arg: Option<&H160>,
    ) -> Result<(), String> {
        self.multisig_args.check(signer_lock_arg)?;
        let tx: packed::Transaction = self.transaction.clone().into();
        let tx = tx.into_view();
        for (i, input) in tx.inputs().into_iter().enumerate() {
            let out_point: json_types::OutPoint = input.previous_output().into();
            let cell = client
                .get_live_cell(out_point, false)
                .call()
                .map_err(|err| err.to_string())?;
            if cell.status != "live" || cell.cell.is_none() {
                return Err(format!(
                    "Invalid input(no.{}) cell status: {}",
                    i + 1,
                    cell.status
                ));
            }
            let lock_script = cell.cell.unwrap().output.lock;
            if &lock_script.code_hash.pack() != genesis_info.multisig_type_hash()
                || lock_script.hash_type != ScriptHashType::Type.into()
            {
                return Err(format!(
                    "Invalid input(no.{}) lock script: ({:#x}, {}), expected: ({:#x}, {:?})",
                    i + 1,
                    lock_script.code_hash,
                    lock_script.hash_type,
                    genesis_info.multisig_type_hash(),
                    json_types::ScriptHashType::Type,
                ));
            }
        }
        Ok(())
    }

    fn tx_view(&self) -> TransactionView {
        let tx: packed::Transaction = self.transaction.clone().into();
        tx.into_view()
    }

    fn all_signatures(&self) -> HashMap<Vec<u8>, HashSet<Vec<u8>>> {
        self.all_signatures
            .iter()
            .map(|item| {
                (
                    item.lock_arg.clone(),
                    item.signatures.iter().cloned().collect(),
                )
            })
            .collect()
    }

    fn set_all_signatures(&mut self, map: HashMap<Vec<u8>, HashSet<Vec<u8>>>) {
        self.all_signatures.clear();
        for (lock_arg, sigs) in map.into_iter() {
            let signatures = sigs.into_iter().collect();
            self.all_signatures.push(MultisigSignatures {
                lock_arg,
                signatures,
            });
        }
    }
}

#[derive(Serialize, Deserialize)]
struct MultisigSignatures {
    lock_arg: Vec<u8>,
    signatures: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct MultisigArgs {
    sighash_addresses: Vec<Address>,
    require_first_n: u8,
    threshold: u8,
}

impl MultisigArgs {
    fn check(&self, signer_lock_arg: Option<&H160>) -> Result<(), String> {
        if let Some(lock_arg) = signer_lock_arg {
            if !self
                .sighash_addresses
                .iter()
                .any(|addr| addr.payload().as_ref() == lock_arg.as_bytes())
            {
                return Err(format!(
                    "signer lock arg ({:#x}) is not in pubkey list",
                    lock_arg
                ));
            }
        }

        if self.threshold as usize > self.sighash_addresses.len() {
            return Err(format!(
                "Invalid threshold {} > {}",
                self.threshold,
                self.sighash_addresses.len()
            ));
        }
        if self.require_first_n > self.threshold {
            return Err(format!(
                "Invalid require-first-n {} > {}",
                self.require_first_n, self.threshold
            ));
        }

        for sighash_address in &self.sighash_addresses {
            if sighash_address.ty() != AddressType::Default
                || sighash_address.index() != Some(CodeHashIndex::Default)
            {
                return Err(format!(
                    "Invalid address in MultisigArgs, mainet-address: {}, type: {}, index: {:?}",
                    sighash_address.display_with_prefix(NetworkType::MainNet),
                    sighash_address.ty() as u8,
                    sighash_address.index(),
                ));
            }
        }
        Ok(())
    }

    fn to_address(
        &self,
        since_absolute_epoch: Option<u64>,
        genesis_info: &GenesisInfo,
    ) -> Result<Address, String> {
        let witness_data = self.to_witness_data()?;
        let params_hash = blake2b_256(&witness_data);
        let hash160 = &params_hash[0..20];
        if let Some(absolute_epoch_number) = since_absolute_epoch {
            let since_value = Since::new_absolute_epoch(absolute_epoch_number).value();
            let mut payload = genesis_info.multisig_type_hash().raw_data();
            payload.extend_from_slice(hash160);
            payload.extend_from_slice(&since_value.to_le_bytes()[..]);
            Ok(Address::new_full_type(payload))
        } else {
            let hash = H160::from_slice(hash160).unwrap();
            Ok(Address::new_multisig(hash))
        }
    }

    fn to_witness_data(&self) -> Result<Bytes, String> {
        let reserved_byte = 0u8;
        let mut witness_data = vec![
            reserved_byte,
            self.require_first_n,
            self.threshold,
            self.sighash_addresses.len() as u8,
        ];
        for sighash_address in &self.sighash_addresses {
            if sighash_address.ty() != AddressType::Default
                || sighash_address.index() != Some(CodeHashIndex::Default)
            {
                return Err(format!(
                    "Invalid address in MultisigArgs, mainet-address: {}, type: {}, index: {:?}",
                    sighash_address.display_with_prefix(NetworkType::MainNet),
                    sighash_address.ty() as u8,
                    sighash_address.index(),
                ));
            }
            witness_data.extend_from_slice(sighash_address.payload().as_ref());
        }
        Ok(Bytes::from(witness_data))
    }
}
