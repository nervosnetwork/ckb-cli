use ckb_crypto::secp::SECP256K1;
use ckb_hash::blake2b_256;
use ckb_sdk::{Address, GenesisInfo, HttpRpcClient, NetworkType, OldAddress};
use clap::{App, Arg, ArgMatches, SubCommand};
use faster_hex::hex_string;
use numext_fixed_hash::H160;

use super::CliSubCommand;
use crate::utils::{
    arg_parser::{AddressParser, ArgParser, FixedHashParser, PrivkeyPathParser, PubkeyHexParser},
    other::{get_address, get_genesis_info},
    printer::{OutputFormat, Printable},
};

pub struct UtilSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    genesis_info: Option<GenesisInfo>,
}

impl<'a> UtilSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        genesis_info: Option<GenesisInfo>,
    ) -> UtilSubCommand<'a> {
        UtilSubCommand {
            rpc_client,
            genesis_info,
        }
    }

    pub fn subcommand(name: &'static str) -> App<'static, 'static> {
        let arg_privkey = Arg::with_name("privkey-path")
            .long("privkey-path")
            .takes_value(true)
            .validator(|input| PrivkeyPathParser.validate(input))
            .help("Private key file path (only read first line)");
        let arg_pubkey = Arg::with_name("pubkey")
            .long("pubkey")
            .takes_value(true)
            .validator(|input| PubkeyHexParser.validate(input))
            .help("Public key (hex string, compressed format)");
        let arg_address = Arg::with_name("address")
            .long("address")
            .takes_value(true)
            .validator(|input| AddressParser.validate(input))
            .required(true)
            .help("Target address (see: https://github.com/nervosnetwork/ckb/wiki/Common-Address-Format)");
        let arg_lock_arg = Arg::with_name("lock-arg")
            .long("lock-arg")
            .takes_value(true)
            .validator(|input| FixedHashParser::<H160>::default().validate(input))
            .help("Lock argument (account identifier, blake2b(pubkey)[0..20])");
        SubCommand::with_name(name)
            .about("Utilities")
            .subcommands(vec![SubCommand::with_name("key-info")
                .about(
                    "Show public information of a secp256k1 private key (from file) or public key",
                )
                .arg(arg_privkey.clone().conflicts_with("pubkey"))
                .arg(arg_pubkey.clone().required(false))
                .arg(arg_address.clone().required(false))
                .arg(arg_lock_arg.clone())])
    }
}

impl<'a> CliSubCommand for UtilSubCommand<'a> {
    fn process(
        &mut self,
        matches: &ArgMatches,
        format: OutputFormat,
        color: bool,
    ) -> Result<String, String> {
        match matches.subcommand() {
            ("key-info", Some(m)) => {
                let privkey_opt: Option<secp256k1::SecretKey> =
                    PrivkeyPathParser.from_matches_opt(m, "privkey-path", false)?;
                let pubkey_opt: Option<secp256k1::PublicKey> =
                    PubkeyHexParser.from_matches_opt(m, "pubkey", false)?;
                let pubkey_opt = privkey_opt
                    .map(|privkey| secp256k1::PublicKey::from_secret_key(&SECP256K1, &privkey))
                    .or_else(|| pubkey_opt);
                let pubkey_string_opt = pubkey_opt.as_ref().map(|pubkey| {
                    hex_string(&pubkey.serialize()[..]).expect("encode pubkey failed")
                });
                let address = match pubkey_opt {
                    Some(pubkey) => {
                        let pubkey_hash = blake2b_256(&pubkey.serialize()[..]);
                        Address::from_lock_arg(&pubkey_hash[0..20])?
                    }
                    None => get_address(m)?,
                };
                let old_address = OldAddress::new_default(address.hash().clone());

                let genesis_info = get_genesis_info(&mut self.genesis_info, self.rpc_client)?;
                let secp_code_hash = genesis_info.secp_code_hash();
                println!(
                    r#"Put this config in < ckb.toml >:

[block_assembler]
code_hash = "{:#x}"
args = ["{:#x}"]
"#,
                    secp_code_hash,
                    address.hash()
                );

                let resp = serde_json::json!({
                    "pubkey": pubkey_string_opt,
                    "address": {
                        "testnet": address.to_string(NetworkType::TestNet),
                        "mainnet": address.to_string(NetworkType::MainNet),
                    },
                    // NOTE: remove this later (after all testnet race reward received)
                    "old-testnet-address": old_address.to_string(NetworkType::TestNet),
                    "lock_arg": format!("{:x}", address.hash()),
                    "lock_hash": address.lock_script(secp_code_hash.clone()).hash(),
                });
                Ok(resp.render(format, color))
            }
            _ => Err(matches.usage().to_owned()),
        }
    }
}
