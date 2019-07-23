use std::fs;
use std::io::Read;
use std::path::PathBuf;

use bytes::Bytes;
use ckb_core::{
    capacity_bytes,
    header::Header,
    script::{Script, ScriptHashType},
    transaction::{CellInput, CellOutput, OutPoint},
    Capacity,
};
use ckb_sdk::{
    wallet::KeyStore, GenesisInfo, HttpRpcClient, MockDep, MockInput, MockResourceLoader,
    MockTransaction, MockTransactionHelper, ReprMockTransaction,
};
use clap::{App, Arg, ArgMatches, SubCommand};
use numext_fixed_hash::{h256, H160, H256};

use super::CliSubCommand;
use crate::utils::{
    arg_parser::{ArgParser, FilePathParser, FixedHashParser},
    other::{get_genesis_info, read_password},
    printer::{OutputFormat, Printable},
};

pub struct MockTxSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    key_store: &'a mut KeyStore,
    genesis_info: Option<GenesisInfo>,
}

impl<'a> MockTxSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        key_store: &'a mut KeyStore,
        genesis_info: Option<GenesisInfo>,
    ) -> MockTxSubCommand<'a> {
        MockTxSubCommand {
            rpc_client,
            key_store,
            genesis_info,
        }
    }

    pub fn subcommand(name: &'static str) -> App<'static, 'static> {
        let arg_tx_file = Arg::with_name("tx-file")
            .long("tx-file")
            .takes_value(true)
            .required(true)
            .validator(|input| FilePathParser::new(true).validate(input))
            .help("Mock transaction data file (format: json,yaml)");
        let arg_lock_arg = Arg::with_name("lock-arg")
            .long("lock-arg")
            .takes_value(true)
            .validator(|input| FixedHashParser::<H160>::default().validate(input))
            .required(true)
            .help("The lock_arg (identifier) of the account");
        SubCommand::with_name(name)
            .about("Handle mock transactions (verify/send)")
            .subcommands(vec![
                SubCommand::with_name("template")
                    .about("Print mock transaction template")
                    .arg(arg_lock_arg.clone().required(false)),
                SubCommand::with_name("verify")
                    .about("Verify a mock transaction in local")
                    .arg(arg_tx_file.clone()),
                SubCommand::with_name("send")
                    .about("Send a transaction if there is no mock data")
                    .arg(arg_tx_file.clone()),
            ])
    }
}

impl<'a> CliSubCommand for MockTxSubCommand<'a> {
    fn process(
        &mut self,
        matches: &ArgMatches,
        format: OutputFormat,
        color: bool,
    ) -> Result<String, String> {
        let genesis_info = get_genesis_info(&mut self.genesis_info, self.rpc_client)?;
        match matches.subcommand() {
            ("template", Some(m)) => {
                let lock_arg_opt: Option<H160> =
                    FixedHashParser::<H160>::default().from_matches_opt(m, "lock-arg", false)?;
                let lock_arg = lock_arg_opt.unwrap_or_else(H160::zero);
                let secp_code_hash = genesis_info.secp_code_hash();
                let sample_script = || {
                    Script::new(
                        vec![Bytes::from(lock_arg.as_ref())],
                        secp_code_hash.clone(),
                        ScriptHashType::Data,
                    )
                };
                let mock_dep = MockDep {
                    out_point: OutPoint::new_cell(h256!("0xff01"), 0),
                    cell: CellOutput {
                        capacity: capacity_bytes!(600),
                        data: Bytes::default(),
                        lock: sample_script(),
                        type_: None,
                    },
                };
                let input = CellInput::new(OutPoint::new_cell(h256!("0xff02"), 0), 0);
                let mock_input = MockInput {
                    input: input.clone(),
                    cell: CellOutput {
                        capacity: capacity_bytes!(300),
                        data: Bytes::default(),
                        lock: sample_script(),
                        type_: None,
                    },
                };
                let output = CellOutput {
                    capacity: capacity_bytes!(120),
                    data: Bytes::default(),
                    lock: sample_script(),
                    type_: Some(sample_script()),
                };

                let mut mock_tx = MockTransaction::default();
                mock_tx.mock_deps = vec![mock_dep];
                mock_tx.mock_inputs = vec![mock_input];
                mock_tx.inputs = vec![input];
                mock_tx.outputs = vec![output];
                mock_tx.witnesses = vec![vec![Bytes::from("abc")]];
                {
                    let mut helper = MockTransactionHelper::new(&mut mock_tx);
                    helper.fill_deps(&genesis_info, |_| unreachable!())?;
                }
                let repr_tx: ReprMockTransaction = mock_tx.into();

                Ok(serde_json::to_value(&repr_tx)
                    .unwrap()
                    .render(format, color))
            }
            ("verify", Some(m)) => {
                let path: PathBuf = FilePathParser::new(true).from_matches(m, "tx-file")?;
                let mut content = String::new();
                let mut file = fs::File::open(path).map_err(|err| err.to_string())?;
                file.read_to_string(&mut content)
                    .map_err(|err| err.to_string())?;
                let repr_tx: ReprMockTransaction = serde_yaml::from_str(content.as_str())
                    .map_err(|err| err.to_string())
                    .or_else(|_| {
                        serde_json::from_str(content.as_str()).map_err(|err| err.to_string())
                    })?;
                let mut mock_tx: MockTransaction = repr_tx.into();

                let key_store = self.key_store.clone();
                let signer = |lock_arg: &H160, tx_hash_hash: &H256| {
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
                };
                let mut loader = Loader {
                    rpc_client: self.rpc_client,
                };
                let mut helper = MockTransactionHelper::new(&mut mock_tx);
                helper.complete_tx(None, &genesis_info, &signer, |out_point| {
                    loader.get_live_cell(out_point)
                })?;
                println!(
                    "{}",
                    ReprMockTransaction::from((*helper.tx).clone()).render(format, color)
                );
                println!("[tx-hash]: {:x}", helper.tx.core_transaction().hash());

                let cycle = helper.verify(u64::max_value(), loader)?;
                Ok(format!("cycle: {}", cycle))
            }
            ("send", Some(_m)) => Ok(String::from("null")),
            _ => Err(matches.usage().to_owned()),
        }
    }
}

struct Loader<'a> {
    rpc_client: &'a mut HttpRpcClient,
}

impl<'a> MockResourceLoader for Loader<'a> {
    fn get_header(&mut self, hash: H256) -> Result<Option<Header>, String> {
        self.rpc_client
            .get_header(hash)
            .call()
            .map(|header_opt| header_opt.0.map(Into::into))
            .map_err(|err| err.to_string())
    }
    fn get_live_cell(&mut self, out_point: OutPoint) -> Result<Option<CellOutput>, String> {
        self.rpc_client
            .get_live_cell(out_point.into())
            .call()
            .map(|resp| resp.cell.map(Into::into))
            .map_err(|err| err.to_string())
    }
}
