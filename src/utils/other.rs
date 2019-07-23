use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ckb_core::block::Block;
use ckb_jsonrpc_types::{AlertMessage, BlockNumber};
use ckb_sdk::{
    wallet::{KeyStore, ScryptType},
    GenesisInfo, HttpRpcClient,
};
use colored::Colorize;
use rpassword::prompt_password_stdout;

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
        let genesis_block: Block = rpc_client
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
