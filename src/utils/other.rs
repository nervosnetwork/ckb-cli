use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::ArgMatches;
use colored::Colorize;
use either::Either;
use rpassword::prompt_password_stdout;

use ckb_hash::blake2b_256;
use ckb_index::{LiveCellInfo, VERSION};
use ckb_ledger::LedgerKeyStore;
use ckb_sdk::{
    calc_max_mature_number,
    constants::{CELLBASE_MATURITY, MIN_SECP_CELL_CAPACITY, ONE_CKB},
    rpc::{AlertMessage, Transaction},
    wallet::{
        AbstractKeyStore, AbstractMasterPrivKey, AbstractPrivKey, DerivationPath,
        FullyBoxedAbstractMasterPrivkey, KeyStore, ScryptType,
    },
    Address, AddressPayload, CodeHashIndex, GenesisInfo, HttpRpcClient, NetworkType,
    SignerClosureHelper, SignerFnTrait, SECP256K1,
};
use ckb_types::{
    bytes::Bytes,
    core::{service::Request, BlockView, Capacity, EpochNumberWithFraction, TransactionView},
    packed::{CellOutput, OutPoint},
    prelude::*,
    H160, H256,
};

use super::arg_parser::{
    AddressParser, ArgParser, FixedHashParser, FromAccountParser, HexParser, PrivkeyPathParser,
    PrivkeyWrapper, PubkeyHexParser,
};
use super::index::{IndexController, IndexRequest, IndexThreadState};
use super::key_adapter::KeyAdapter;
use crate::subcommands::account::AccountId;

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

fn get_some_dir(dir: &str, ckb_cli_dir: &PathBuf) -> Result<PathBuf, String> {
    let mut keystore_dir = ckb_cli_dir.clone();
    keystore_dir.push(dir);
    fs::create_dir_all(&keystore_dir).map_err(|err| err.to_string())?;
    Ok(keystore_dir)
}

pub fn get_key_store(ckb_cli_dir: &PathBuf) -> Result<KeyStore, String> {
    let keystore_dir = get_some_dir("keystore", ckb_cli_dir)?;
    KeyStore::from_dir(keystore_dir, ScryptType::default()).map_err(|err| err.to_string())
}

pub fn get_ledger_key_store(ckb_cli_dir: &PathBuf) -> Result<LedgerKeyStore, String> {
    let keystore_dir = get_some_dir("ledger-keystore", ckb_cli_dir)?;
    LedgerKeyStore::from_dir(keystore_dir, ScryptType::default()).map_err(|err| err.to_string())
}

pub fn get_all_key_stores(ckb_cli_dir: &PathBuf) -> Result<(KeyStore, LedgerKeyStore), String> {
    Ok((
        get_key_store(ckb_cli_dir)?,
        get_ledger_key_store(ckb_cli_dir)?,
    ))
}

pub fn get_address(network: Option<NetworkType>, m: &ArgMatches) -> Result<AddressPayload, String> {
    let address_opt: Option<Address> = AddressParser::default()
        .set_network_opt(network)
        .set_short(CodeHashIndex::Sighash)
        .from_matches_opt(m, "address", false)?;
    let pubkey: Option<secp256k1::PublicKey> =
        PubkeyHexParser.from_matches_opt(m, "pubkey", false)?;
    let lock_arg: Option<H160> =
        FixedHashParser::<H160>::default().from_matches_opt(m, "lock-arg", false)?;
    let address = address_opt
        .map(|address| address.payload().clone())
        .or_else(|| pubkey.map(|pubkey| AddressPayload::from_pubkey(&pubkey)))
        .or_else(|| lock_arg.map(AddressPayload::from_pubkey_hash))
        .ok_or_else(|| "Please give one argument".to_owned())?;
    Ok(address)
}

pub fn get_singer(
    key_store: KeyStore,
) -> impl Fn(&H160, &H256) -> Result<[u8; 65], String> + 'static {
    move |lock_arg: &H160, tx_hash_hash: &H256| {
        let prompt = format!("Password for [{:x}]", lock_arg);
        let password = read_password(false, Some(prompt.as_str()))?;
        let signature = key_store
            .sign_recoverable_with_password(lock_arg, &[], tx_hash_hash, password.as_bytes())
            .map_err(|err| err.to_string())?;
        let (recov_id, data) = signature.serialize_compact();
        let mut signature_bytes = [0u8; 65];
        signature_bytes[0..64].copy_from_slice(&data[0..64]);
        signature_bytes[64] = recov_id.to_i32() as u8;
        Ok(signature_bytes)
    }
}

pub fn check_alerts(rpc_client: &mut HttpRpcClient) {
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
    cache: &mut HashMap<(OutPoint, bool), ((CellOutput, Transaction), Bytes)>,
    client: &mut HttpRpcClient,
    out_point: OutPoint,
    with_data: bool,
) -> Result<((CellOutput, Transaction), Bytes), String> {
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
) -> Result<((CellOutput, Transaction), Bytes), String> {
    let cell = client.get_live_cell(out_point.clone(), with_data)?;
    if cell.status != "live" {
        return Err(format!(
            "Invalid cell status: {}, out_point: {}",
            cell.status, out_point
        ));
    }
    let cell_status = cell.status.clone();
    let cell = cell.cell.ok_or_else(|| {
        format!(
            "Invalid input cell, status: {}, out_point: {}",
            cell_status, out_point
        )
    })?;
    let tx_hash = H256::from_slice(out_point.tx_hash().as_slice()).expect("should be 32 bytes");
    Ok((
        (
            cell.output.into(),
            client
                .get_transaction(tx_hash.clone())?
                .ok_or_else(|| format!("transaction with given hash {} should exist.", &tx_hash))?
                .transaction
                .inner,
        ),
        cell.data
            .map(|data| data.content.into_bytes())
            .unwrap_or_default(),
    ))
}

// Get max mature block number
pub fn get_max_mature_number(rpc_client: &mut HttpRpcClient) -> Result<u64, String> {
    let tip_epoch = rpc_client
        .get_tip_header()
        .map(|header| EpochNumberWithFraction::from_full_value(header.inner.epoch.0))?;
    let tip_epoch_number = tip_epoch.number();
    if tip_epoch_number < 4 {
        // No cellbase live cell is mature
        Ok(0)
    } else {
        let max_mature_epoch = rpc_client
            .get_epoch_by_number(tip_epoch_number - 4)?
            .ok_or_else(|| "Can not get epoch less than current epoch number".to_string())?;
        let start_number = max_mature_epoch.start_number;
        let length = max_mature_epoch.length;
        Ok(calc_max_mature_number(
            tip_epoch,
            Some((start_number, length)),
            CELLBASE_MATURITY,
        ))
    }
}

pub fn get_network_type(rpc_client: &mut HttpRpcClient) -> Result<NetworkType, String> {
    let chain_info = rpc_client.get_blockchain_info()?;
    NetworkType::from_raw_str(chain_info.chain.as_str())
        .ok_or_else(|| format!("Unexpected network type: {}", chain_info.chain))
}

pub fn index_dirname() -> String {
    format!("index-v{}", VERSION)
}

pub fn sync_to_tip(index_controller: &IndexController) -> Result<(), String> {
    // Kick index thread to start
    Request::call(index_controller.sender(), IndexRequest::Kick);
    loop {
        let state = IndexThreadState::clone(&index_controller.state().read());
        if state.is_synced() {
            break;
        } else if state.is_error() {
            return Err(state.get_error().unwrap());
        } else {
            thread::sleep(Duration::from_millis(200));
        }
    }
    Ok(())
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
    let to_data_opt: Option<Bytes> = HexParser.from_matches_opt(m, "to-data", false)?;
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

pub fn get_keystore_signer(
    key_store: KeyStore,
    account: H160,
    password: String,
) -> Result<impl SignerFnTrait + 'static, String> {
    let key = key_store
        .get_key(&account, password.as_bytes())
        .map_err(|err| err.to_string())?
        .clone();
    get_master_key_signer_raw(key, DerivationPath::empty())
}

pub fn get_master_key_signer_raw<'a, K>(
    key: K,
    path: DerivationPath,
) -> Result<impl SignerFnTrait + Sized, String>
where
    K: AbstractMasterPrivKey + Clone,
    K::Privkey: Clone,
    <K as AbstractMasterPrivKey>::Err: ToString,
    <K::Privkey as AbstractPrivKey>::Err: ToString,
{
    let derived_key = key
        .extended_privkey(path.as_ref())
        .map_err(|err| err.to_string())?;
    get_privkey_signer(derived_key)
}

pub fn get_privkey_signer<'a, K>(privkey: K) -> Result<impl SignerFnTrait, String>
where
    K: AbstractPrivKey + Clone,
    K::Err: ToString,
{
    let pubkey = privkey.public_key().map_err(|err| err.to_string())?;
    let lock_arg = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
        .expect("Generate hash(H160) from pubkey failed");
    Ok(SignerClosureHelper(move |lock_args: &HashSet<H160>| {
        Ok(if !lock_args.contains(&lock_arg) {
            None
        } else {
            Some(KeyAdapter(privkey.begin_sign_recoverable()))
        })
    }))
}

pub fn serialize_signature(signature: &secp256k1::recovery::RecoverableSignature) -> [u8; 65] {
    let (recov_id, data) = signature.serialize_compact();
    let mut signature_bytes = [0u8; 65];
    signature_bytes[0..64].copy_from_slice(&data[0..64]);
    signature_bytes[64] = recov_id.to_i32() as u8;
    signature_bytes
}

pub fn serialize_signature_bytes(signature: &secp256k1::recovery::RecoverableSignature) -> Bytes {
    Bytes::from(&serialize_signature(signature)[..])
}

pub fn is_mature(info: &LiveCellInfo, max_mature_number: u64) -> bool {
    // Not cellbase cell
    info.index.tx_index > 0
    // Live cells in genesis are all mature
        || info.number == 0
        || info.number <= max_mature_number
}

pub fn privkey_or_from_account(
    m: &ArgMatches,
) -> Result<Either<PrivkeyWrapper, AccountId>, String> {
    let from_privkey_opt = PrivkeyPathParser.from_matches_opt(m, "privkey-path", false)?;
    let from_account_opt = FromAccountParser.from_matches_opt(m, "from-account", false)?;
    Ok(match (from_privkey_opt, from_account_opt) {
        (Some(pk), None) => Either::Left(pk),
        (None, Some(aid)) => Either::Right(aid),
        _ => unreachable!("arg parser should prevent both or neithers of --privkey-path and --from--account specified")
    })
}

pub fn make_address_payload_and_master_key_cap<'a>(
    from_account: &'a Either<PrivkeyWrapper, AccountId>,
    key_store: &'a mut KeyStore,
    ledger_key_store: &'a mut LedgerKeyStore,
) -> Result<
    (
        Option<AddressPayload>,
        Option<FullyBoxedAbstractMasterPrivkey<'static>>,
    ),
    String,
> {
    Ok(match from_account {
        Either::Left(ref from_privkey) => {
            let from_pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, from_privkey);
            (
                Some(AddressPayload::from_pubkey(&from_pubkey)),
                None,
                //Some(Box::new(KeyAdapter(PrivkeyWrapper(from_pubkey.clone())))),
            )
        }
        Either::Right(AccountId::SoftwareMasterKey(ref hash160)) => {
            let password = read_password(false, None)?;
            (
                Some(AddressPayload::from_pubkey_hash(hash160.clone())),
                Some(Box::new(KeyAdapter(
                    key_store
                        .get_key(&hash160, password.as_bytes())
                        .map_err(|e| e.to_string())?,
                ))),
            )
        }
        Either::Right(AccountId::LedgerId(ref ledger_id)) => (
            None,
            Some(Box::new(KeyAdapter(
                ledger_key_store
                    .borrow_account(ledger_id)
                    .map_err(|e| e.to_string())?
                    .clone(),
            ))),
        ),
    })
}
