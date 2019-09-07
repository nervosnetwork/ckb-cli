use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ckb_jsonrpc_types::{AlertMessage, BlockNumber};
use ckb_sdk::{
    wallet::{KeyStore, ScryptType},
    Address, GenesisInfo, HttpRpcClient,
};
use ckb_types::{core::BlockView, H160, H256};
use clap::ArgMatches;
use colored::Colorize;
use rpassword::prompt_password_stdout;

use super::arg_parser::{AddressParser, ArgParser, FixedHashParser, PubkeyHexParser};

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

pub fn get_key_store(ckb_cli_dir: &PathBuf) -> Result<KeyStore, String> {
    let mut keystore_dir = ckb_cli_dir.clone();
    keystore_dir.push("keystore");
    fs::create_dir_all(&keystore_dir)
        .map_err(|err| err.to_string())
        .and_then(|_| {
            KeyStore::from_dir(keystore_dir, ScryptType::default()).map_err(|err| err.to_string())
        })
}

pub fn get_address(m: &ArgMatches) -> Result<Address, String> {
    let address: Option<Address> = AddressParser.from_matches_opt(m, "address", false)?;
    let pubkey: Option<secp256k1::PublicKey> =
        PubkeyHexParser.from_matches_opt(m, "pubkey", false)?;
    let lock_arg: Option<H160> =
        FixedHashParser::<H160>::default().from_matches_opt(m, "lock-arg", false)?;
    let address = address
        .or_else(|| pubkey.map(|pubkey| Address::from_pubkey(&pubkey).unwrap()))
        .or_else(|| lock_arg.map(|lock_arg| Address::from_lock_arg(lock_arg.as_bytes()).unwrap()))
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
            .sign_recoverable_with_password(lock_arg, tx_hash_hash, password.as_bytes())
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
        .call()
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
                    id.0.to_string().blue().bold(),
                    priority.0.to_string().blue().bold(),
                    message.yellow().bold(),
                )
            }
        }
    }
}

pub fn get_genesis_info(
    genesis_info: &mut Option<GenesisInfo>,
    rpc_client: &mut HttpRpcClient,
) -> Result<GenesisInfo, String> {
    if genesis_info.is_none() {
        let genesis_block: BlockView = rpc_client
            .get_block_by_number(BlockNumber(0))
            .call()
            .map_err(|err| err.to_string())?
            .0
            .ok_or_else(|| String::from("Can not get genesis block"))?
            .into();
        *genesis_info = Some(GenesisInfo::from_block(&genesis_block)?);
    }
    genesis_info
        .clone()
        .ok_or_else(|| String::from("Can not get genesis info"))
}
