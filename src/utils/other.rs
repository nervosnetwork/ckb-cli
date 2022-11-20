use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ckb_hash::{blake2b_256, new_blake2b};
use ckb_jsonrpc_types as rpc_types;
use ckb_sdk::{
    constants::{MIN_SECP_CELL_CAPACITY, ONE_CKB},
    traits::LiveCell,
    tx_builder::{BalanceTxCapacityError, TxBuilderError},
    util::serialize_signature,
    Address, AddressPayload, NetworkType, SECP256K1,
};
use ckb_signer::{KeyStore, ScryptType};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, Capacity, TransactionView},
    h256,
    packed::{CellInput, CellOutput, OutPoint},
    prelude::*,
    H160, H256,
};
use clap::ArgMatches;
use colored::Colorize;
use plugin_protocol::{CellIndex, LiveCellInfo};
use rpassword::prompt_password_stdout;

use super::arg_parser::{
    AddressParser, ArgParser, FixedHashParser, HexParser, PrivkeyWrapper, PubkeyHexParser,
};
use super::rpc::{AlertMessage, HttpRpcClient};
use super::tx_helper::SignerFn;
use crate::plugin::{KeyStoreHandler, SignTarget};
use crate::utils::genesis_info::GenesisInfo;

pub fn read_password(repeat: bool, prompt: Option<&str>) -> Result<String, String> {
    let prompt = prompt.unwrap_or("Password");
    let pass =
        prompt_password_stdout(format!("{}: ", prompt).as_str()).map_err(|err| err.to_string())?;
    if repeat {
        let repeat_pass =
            prompt_password_stdout("Repeat password: ").map_err(|err| err.to_string())?;
        if pass != repeat_pass {
            return Err("Passwords do not match".to_owned());
        }
    }
    Ok(pass)
}

pub fn get_key_store(ckb_cli_dir: PathBuf) -> Result<KeyStore, String> {
    let mut keystore_dir = ckb_cli_dir;
    keystore_dir.push("keystore");
    fs::create_dir_all(&keystore_dir)
        .map_err(|err| err.to_string())
        .and_then(|_| {
            KeyStore::from_dir(keystore_dir, ScryptType::default()).map_err(|err| err.to_string())
        })
}

pub fn get_address(network: Option<NetworkType>, m: &ArgMatches) -> Result<AddressPayload, String> {
    let address_opt: Option<Address> = AddressParser::new_sighash()
        .set_network_opt(network)
        .from_matches_opt(m, "address")?;
    let pubkey: Option<secp256k1::PublicKey> = PubkeyHexParser.from_matches_opt(m, "pubkey")?;
    let lock_arg: Option<H160> =
        FixedHashParser::<H160>::default().from_matches_opt(m, "lock-arg")?;
    let address = address_opt
        .map(|address| address.payload().clone())
        .or_else(|| pubkey.map(|pubkey| AddressPayload::from_pubkey(&pubkey)))
        .or_else(|| lock_arg.map(AddressPayload::from_pubkey_hash))
        .ok_or_else(|| "Please give one argument".to_owned())?;
    Ok(address)
}

pub fn get_signer(
    keystore: KeyStoreHandler,
    require_password: bool,
) -> impl Fn(&H160, &H256, &rpc_types::Transaction) -> Result<[u8; 65], String> + 'static {
    move |lock_arg: &H160, message: &H256, _tx: &rpc_types::Transaction| {
        let password = if require_password {
            let prompt = format!("Password for [{:x}]", lock_arg);
            Some(read_password(false, Some(prompt.as_str()))?)
        } else {
            None
        };
        let path = keystore.root_key_path(lock_arg.clone())?;
        let data = keystore.sign(
            lock_arg.clone(),
            &path,
            message.clone(),
            SignTarget::AnyMessage(message.clone()),
            password,
            true,
        )?;
        if data.len() != 65 {
            Err(format!(
                "Invalid signature data lenght: {}, data: {:?}",
                data.len(),
                data
            ))
        } else {
            let mut data_bytes = [0u8; 65];
            data_bytes.copy_from_slice(&data[..]);
            Ok(data_bytes)
        }
    }
}

pub fn check_alerts(rpc_client: &mut HttpRpcClient) {
    log::debug!("checking alerts...");
    if let Some(alerts) = rpc_client
        .get_blockchain_info()
        .ok()
        .map(|info| info.alerts)
    {
        for AlertMessage {
            id,
            priority,
            notice_until,
            message,
        } in alerts
        {
            if notice_until.0
                >= SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs()
                    * 1000
            {
                eprintln!(
                    "[{}]: id={}, priority={}, message={}",
                    "alert".yellow().bold(),
                    id.to_string().blue().bold(),
                    priority.to_string().blue().bold(),
                    message.yellow().bold(),
                )
            }
        }
    }
}

pub fn get_genesis_info(
    genesis_info: &Option<GenesisInfo>,
    rpc_client: &mut HttpRpcClient,
) -> Result<GenesisInfo, String> {
    if let Some(genesis_info) = genesis_info {
        Ok(genesis_info.clone())
    } else {
        let genesis_block: BlockView = rpc_client
            .get_block_by_number(0)?
            .ok_or_else(|| String::from("Can not get genesis block"))?
            .into();
        GenesisInfo::from_block(&genesis_block)
    }
}

pub fn get_live_cell_with_cache(
    cache: &mut HashMap<(OutPoint, bool), (CellOutput, Bytes)>,
    client: &mut HttpRpcClient,
    out_point: OutPoint,
    with_data: bool,
) -> Result<(CellOutput, Bytes), String> {
    if let Some(output) = cache.get(&(out_point.clone(), with_data)).cloned() {
        Ok(output)
    } else {
        let output = get_live_cell(client, out_point.clone(), with_data)?;
        cache.insert((out_point, with_data), output.clone());
        Ok(output)
    }
}

pub fn get_live_cell(
    client: &mut HttpRpcClient,
    out_point: OutPoint,
    with_data: bool,
) -> Result<(CellOutput, Bytes), String> {
    let cell = client.get_live_cell(out_point.clone(), with_data)?;
    if cell.status != "live" {
        return Err(format!(
            "Invalid cell status: {}, out_point: {}",
            cell.status, out_point
        ));
    }
    let cell_status = cell.status.clone();
    cell.cell
        .map(|cell| {
            (
                cell.output.into(),
                cell.data
                    .map(|data| data.content.into_bytes())
                    .unwrap_or_default(),
            )
        })
        .ok_or_else(|| {
            format!(
                "Invalid input cell, status: {}, out_point: {}",
                cell_status, out_point
            )
        })
}

pub fn get_network_type(rpc_client: &mut HttpRpcClient) -> Result<NetworkType, String> {
    log::debug!("getting network type...");
    let chain_info = rpc_client.get_blockchain_info()?;
    NetworkType::from_raw_str(chain_info.chain.as_str())
        .ok_or_else(|| format!("Unexpected network type: {}", chain_info.chain))
}

pub fn check_capacity(capacity: u64, to_data_len: usize) -> Result<(), String> {
    if capacity < MIN_SECP_CELL_CAPACITY {
        return Err(format!(
            "Capacity can not less than {} shannons",
            MIN_SECP_CELL_CAPACITY
        ));
    }
    if capacity < MIN_SECP_CELL_CAPACITY + (to_data_len as u64 * ONE_CKB) {
        return Err(format!(
            "Capacity can not hold {} bytes of data",
            to_data_len
        ));
    }
    Ok(())
}

pub fn check_lack_of_capacity(transaction: &TransactionView) -> Result<(), String> {
    for (output, output_data) in transaction.outputs_with_data_iter() {
        let exact = output
            .clone()
            .as_builder()
            .build_exact_capacity(Capacity::bytes(output_data.len()).unwrap())
            .unwrap();
        let output_capacity: u64 = output.capacity().unpack();
        let exact_capacity: u64 = exact.capacity().unpack();
        if output_capacity < exact_capacity {
            return Err(format!(
                "Insufficient Cell Capacity, output_capacity({}) < exact_capacity({}), output: {}, output_data_size: {}",
                output_capacity,
                exact_capacity,
                output,
                output_data.len(),
            ));
        }
    }
    Ok(())
}

pub fn get_to_data(m: &ArgMatches) -> Result<Bytes, String> {
    let to_data_opt: Option<Bytes> = HexParser.from_matches_opt(m, "to-data")?;
    match to_data_opt {
        Some(data) => Ok(data),
        None => {
            if let Some(path) = m.value_of("to-data-path") {
                let mut content = Vec::new();
                let mut file = fs::File::open(path).map_err(|err| err.to_string())?;
                file.read_to_end(&mut content)
                    .map_err(|err| err.to_string())?;
                Ok(Bytes::from(content))
            } else {
                Ok(Bytes::new())
            }
        }
    }
}

pub fn get_privkey_signer(privkey: PrivkeyWrapper) -> SignerFn {
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &privkey);
    let lock_arg = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
        .expect("Generate hash(H160) from pubkey failed");
    Box::new(
        move |lock_args: &HashSet<H160>, message: &H256, _tx: &rpc_types::Transaction| {
            if lock_args.contains(&lock_arg) {
                if message == &h256!("0x0") {
                    Ok(Some([0u8; 65]))
                } else {
                    let message = secp256k1::Message::from_slice(message.as_bytes())
                        .expect("Convert to secp256k1 message failed");
                    let signature = SECP256K1.sign_ecdsa_recoverable(&message, &privkey);
                    Ok(Some(serialize_signature(&signature)))
                }
            } else {
                Ok(None)
            }
        },
    )
}

pub fn get_arg_value(matches: &ArgMatches, name: &str) -> Result<String, String> {
    matches
        .value_of(name)
        .map(|s| s.to_string())
        .ok_or_else(|| format!("<{}> is required", name))
}

pub fn to_live_cell_info(cell: &LiveCell) -> LiveCellInfo {
    let output_index: u32 = cell.out_point.index().unpack();
    LiveCellInfo {
        tx_hash: cell.out_point.tx_hash().unpack(),
        output_index,
        data_bytes: cell.output_data.len() as u64,
        lock_hash: cell.output.lock().calc_script_hash().unpack(),
        type_hashes: cell.output.type_().to_opt().map(|type_script| {
            (
                type_script.code_hash().unpack(),
                type_script.calc_script_hash().unpack(),
            )
        }),
        capacity: cell.output.capacity().unpack(),
        number: cell.block_number,
        index: CellIndex {
            tx_index: cell.tx_index,
            output_index,
        },
    }
}

pub fn address_json(payload: AddressPayload, is_new: bool) -> serde_json::Value {
    serde_json::json!({
        "mainnet": Address::new(NetworkType::Mainnet, payload.clone(), is_new).to_string(),
        "testnet": Address::new(NetworkType::Testnet, payload, is_new).to_string(),
    })
}

pub fn calculate_type_id(first_cell_input: &CellInput, output_index: u64) -> [u8; 32] {
    let mut blake2b = new_blake2b();
    blake2b.update(first_cell_input.as_slice());
    blake2b.update(&output_index.to_le_bytes());
    let mut ret = [0u8; 32];
    blake2b.finalize(&mut ret);
    ret
}

pub(crate) fn map_tx_builder_error_2_str(no_max_tx_fee: bool, err: TxBuilderError) -> String {
    if no_max_tx_fee {
        if let TxBuilderError::BalanceCapacity(BalanceTxCapacityError::CapacityNotEnough(ref msg)) =
            err
        {
            if msg.contains("can not create change cell") {
                return format!("{}, {}.", err, "try to calculate capacity again or try parameter `--max-tx-fee` to make small left capacity as transaction fee");
            }
        }
    }
    err.to_string()
}
