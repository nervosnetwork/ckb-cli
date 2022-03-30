use std::collections::HashMap;
use std::path::PathBuf;

use clap::{App, Arg, ArgMatches};

use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
    rpc::CkbRpcClient,
    traits::{
        default_impls::{
            DefaultCellDepResolver, DefaultHeaderDepResolver, DefaultTransactionDependencyProvider,
        },
        CellCollector, CellQueryOptions, Signer, ValueRangeOption,
    },
    tx_builder::{
        udt::{UdtIssueBuilder, UdtIssueReceiver, UdtIssueType, UdtTransferReceiver},
        CapacityBalancer, CapacityProvider, TransferAction, TxBuilder,
    },
    types::ScriptId,
    unlock::{ScriptUnlocker, SecpSighashScriptSigner, SecpSighashUnlocker},
    Address, AddressPayload, GenesisInfo, NetworkType,
};
use ckb_types::{
    bytes::Bytes,
    core::{FeeRate, ScriptHashType, TransactionView},
    packed::{CellInput, OutPoint, Script, WitnessArgs},
    prelude::*,
    H160, H256,
};

use crate::plugin::PluginManager;
use crate::subcommands::{CliSubCommand, Output};
use crate::utils::{
    arg,
    arg_parser::{
        AddressParser, ArgParser, CellDepsParser, FromStrParser, OutPointParser, ScriptIdParser,
        UdtTargetParser,
    },
    cell_collector::LocalCellCollector,
    cell_dep::CellDeps,
    index::IndexController,
    other::{get_network_type, read_password, to_live_cell_info},
    rpc::HttpRpcClient,
    signer::KeyStoreHandlerSigner,
};

pub struct SudtSubCommand<'a> {
    plugin_mgr: &'a mut PluginManager,
    rpc_client: &'a mut HttpRpcClient,
    cell_collector: LocalCellCollector,
    cell_dep_resolver: DefaultCellDepResolver,
    header_dep_resolver: DefaultHeaderDepResolver,
    tx_dep_provider: DefaultTransactionDependencyProvider,
}

impl<'a> SudtSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        plugin_mgr: &'a mut PluginManager,
        genesis_info: GenesisInfo,
        index_dir: PathBuf,
        index_controller: IndexController,
        wait_for_sync: bool,
    ) -> Self {
        let tx_dep_provider = DefaultTransactionDependencyProvider::new(rpc_client.url(), 10);
        let cell_collector = LocalCellCollector::new(
            index_dir,
            index_controller,
            HttpRpcClient::new(rpc_client.url().to_string()),
            Some(genesis_info.header().clone()),
            wait_for_sync,
        );
        let cell_dep_resolver = DefaultCellDepResolver::new(&genesis_info);
        let header_dep_resolver = DefaultHeaderDepResolver::new(rpc_client.url());
        Self {
            plugin_mgr,
            rpc_client,
            cell_collector,
            cell_dep_resolver,
            header_dep_resolver,
            tx_dep_provider,
        }
    }

    fn issue(
        &mut self,
        owner: Address,
        udt_script_id: ScriptId,
        udt_to_vec: Vec<(Address, u128)>,
        cheque_script_id: Option<ScriptId>,
        cell_deps: CellDeps,
        fee_rate: u64,
        network: NetworkType,
        debug: bool,
    ) -> Result<Output, String> {
        let owner_account = H160::from_slice(owner.payload().args().as_ref()).unwrap();
        let owner_script = Script::from(&owner);
        let owner_script_hash = owner_script.calc_script_hash();
        let signer: Box<dyn Signer> = {
            let handler = self.plugin_mgr.keystore_handler();
            let change_path = handler.root_key_path(owner_account.clone())?;
            let mut signer = KeyStoreHandlerSigner::new(
                handler,
                Box::new(DefaultTransactionDependencyProvider::new(
                    self.rpc_client.url(),
                    0,
                )),
            );
            if self.plugin_mgr.keystore_require_password() {
                signer.set_password(
                    owner_account.clone(),
                    read_password(false, Some("owner Password"))?,
                );
            }
            signer.set_change_path(owner_account, change_path.to_string());
            Box::new(signer)
        };
        let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
        let sighash_unlocker = SecpSighashUnlocker::new(SecpSighashScriptSigner::new(signer));
        let mut unlockers: HashMap<_, Box<dyn ScriptUnlocker>> = HashMap::new();
        unlockers.insert(sighash_script_id, Box::new(sighash_unlocker));

        let receivers = udt_to_vec
            .into_iter()
            .map(|(addr, amount)| {
                let receiver_script = Script::from(&addr);
                let lock_script = if let Some(script_id) = cheque_script_id.as_ref() {
                    let receiver_script_hash = receiver_script.calc_script_hash();
                    let mut script_args = vec![0u8; 40];
                    script_args[0..20].copy_from_slice(&receiver_script_hash.as_slice()[0..20]);
                    script_args[20..40].copy_from_slice(&owner_script_hash.as_slice()[0..20]);
                    Script::new_builder()
                        .code_hash(script_id.code_hash.pack())
                        .hash_type(script_id.hash_type.into())
                        .args(Bytes::from(script_args).pack())
                        .build()
                } else {
                    receiver_script
                };
                UdtIssueReceiver {
                    lock_script,
                    capacity: None,
                    amount,
                    extra_data: None,
                }
            })
            .collect::<Vec<_>>();
        let builder = UdtIssueBuilder {
            udt_type: UdtIssueType::Sudt,
            script_id: udt_script_id,
            owner: owner_script.clone(),
            receivers,
        };
        let balancer = CapacityBalancer {
            fee_rate: FeeRate::from_u64(fee_rate),
            change_lock_script: None,
            capacity_provider: CapacityProvider {
                lock_scripts: vec![(
                    owner_script,
                    WitnessArgs::new_builder()
                        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
                        .build(),
                )],
            },
            force_small_change_as_fee: None,
        };
        cell_deps.apply_to_resolver(&mut self.cell_dep_resolver);

        let (tx, still_locked_groups) = builder
            .build_unlocked(
                &mut self.cell_collector,
                &self.cell_dep_resolver,
                &self.header_dep_resolver,
                &self.tx_dep_provider,
                &balancer,
                &unlockers,
            )
            .map_err(|err| err.to_string())?;
        assert!(still_locked_groups.is_empty());
        let outputs_validator = Some(json_types::OutputsValidator::Passthrough);
        let tx_hash = self
            .rpc_client
            .send_transaction(tx.data(), outputs_validator)
            .map_err(|err| format!("Send transaction error: {}", err))?;
        assert_eq!(tx.hash(), tx_hash.pack());

        if debug {
            let rpc_tx_view = json_types::TransactionView::from(tx);
            Ok(Output::new_output(rpc_tx_view))
        } else {
            let tx_hash: H256 = tx.hash().unpack();
            Ok(Output::new_output(tx_hash))
        }
    }

    pub fn subcommand(name: &'static str) -> App<'static> {
        let arg_owner = Arg::with_name("owner")
            .long("owner")
            .takes_value(true)
            .required(true)
            .validator(|input| AddressParser::default().validate(input))
            .about("The owner of the sudt cell (the admin's lock script)");
        let arg_script_id = Arg::with_name("udt-script-id")
            .long("udt-script-id")
            .takes_value(true)
            .required(true)
            .validator(|input| ScriptIdParser.validate(input))
            .about("The script id of this SUDT, format: {code_hash}-{hash_type}, `hash_type` can be: [type, data, data1]");
        let arg_udt_to = Arg::with_name("udt-to")
            .long("udt-to")
            .takes_value(true)
            .multiple(true)
            .validator(|input| UdtTargetParser::new(AddressParser::default()).validate(input))
            .about("The issue target, format: {address}:{amount}, the address typically is an cheque address");
        let arg_capacity_provider = Arg::with_name("capacity-provider")
            .long("capacity-provider")
            .takes_value(true)
            .validator(|input| AddressParser::new_sighash().validate(input))
            .about("Capacity provider address");
        let arg_sender = Arg::with_name("sender")
            .long("sender")
            .takes_value(true)
            .validator(|input| AddressParser::default().validate(input))
            .about("Sender's address");
        let arg_cell_deps = Arg::with_name("cell-deps")
            .long("cell-deps")
            .takes_value(true)
            .required(true)
            .validator(|input| CellDepsParser.validate(input))
            .about("The cell deps information (for resolve cell_dep by script id)");
        App::new(name)
            .about("SUDT issue/transfer/.. operations")
            .subcommands(vec![
                App::new("issue")
                    .about("Issue SUDT")
                    .arg(arg_owner.clone())
                    .arg(arg_script_id.clone())
                    .arg(arg_udt_to.clone())
                    .arg(arg_cell_deps.clone())
                    .arg(
                        Arg::with_name("cheque-script-id")
                            .long("cheque-script-id")
                            .takes_value(true)
                            .validator(|input| ScriptIdParser.validate(input))
                            .about("The script id of cheque lock, format: {code_hash}-{hash_type}")
                    )
                    .arg(
                        Arg::with_name("to-cheque-address")
                            .long("to-cheque-address")
                            .about("If this flag is presented the address in <udt-to> will be used as cheque lock's receiver script hash (and the owner is the sender), otherwise the address will be used as the lock script of the SUDT cell. When this flag is presented <cheque-script-id> argument must be given")
                    )
                    .arg(arg::fee_rate()),
                App::new("transfer")
                    .about("Transfer SUDT to an address")
                    .arg(arg_owner.clone())
                    .arg(arg_script_id.clone())
                    .arg(arg_udt_to)
                    .arg(arg_sender.clone())
                    .arg(arg_cell_deps.clone())
                    .arg(
                        Arg::with_name("to-is-acp")
                            .long("to-is-acp")
                            .about("If the to address is anyone-can-pay address"),
                    ),
                App::new("new-empty-acp")
                    .about("Create a SUDT cell with 0 amount and an acp lock script")
                    .arg(arg_owner.clone())
                    .arg(arg_script_id.clone())
                    .arg(arg_capacity_provider)
                    .arg(arg_cell_deps.clone())
                    .arg(
                        Arg::with_name("to")
                            .long("to")
                            .takes_value(true)
                            .validator(|input| AddressParser::default().validate(input))
                            .about("The target address"),
                    ),
                App::new("cheque-claim")
                    .about("Claim all cheque cells identify by given lock script and type script")
                    .arg(arg_owner.clone())
                    .arg(arg_script_id.clone())
                    .arg(arg_sender.clone())
                    .arg(arg_cell_deps.clone())
                    .arg(
                        Arg::with_name("cheque-address")
                            .long("cheque-address")
                            .takes_value(true)
                            .validator(|input| AddressParser::default().validate(input))
                            .about("The cheque cell's address")
                    )
                    .arg(
                        Arg::with_name("receiver-address")
                            .takes_value(true)
                            .validator(|input| AddressParser::default().validate(input))
                            .about("The claim receiver's address, for searching an input to save the claimed amount (hint: this address should be an anyone-can-pay address)")
                    ),
                App::new("cheque-withdraw")
                    .about("Withdraw cheque cells")
                    .arg(arg_owner)
                    .arg(arg_script_id)
                    .arg(arg_sender)
                    .arg(arg_cell_deps.clone())
            ])
    }
}
impl<'a> CliSubCommand for SudtSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches, debug: bool) -> Result<Output, String> {
        let network = get_network_type(self.rpc_client)?;
        match matches.subcommand() {
            ("issue", Some(m)) => {
                let owner: Address = AddressParser::new_sighash()
                    .set_network(network)
                    .from_matches(m, "owner")?;
                let udt_script_id: ScriptId = ScriptIdParser.from_matches(m, "udt-script-id")?;
                let udt_to_vec: Vec<(Address, u128)> = {
                    let mut address_parser = AddressParser::default();
                    address_parser.set_network(network);
                    UdtTargetParser::new(address_parser).from_matches_vec(m, "udt-to")?
                };
                let cell_deps: CellDeps = CellDepsParser.from_matches(m, "cell-deps")?;
                let fee_rate: u64 = FromStrParser::<u64>::default().from_matches(m, "fee-rate")?;
                let cheque_script_id: Option<ScriptId> = if m.is_present("to-cheque-address") {
                    Some(ScriptIdParser.from_matches(m, "cheque-script-id")?)
                } else {
                    None
                };

                if udt_to_vec.is_empty() {
                    return Err("missing <udt-to> argument".to_string());
                }
                self.issue(
                    owner,
                    udt_script_id,
                    udt_to_vec,
                    cheque_script_id,
                    cell_deps,
                    fee_rate,
                    network,
                    debug,
                )
            }
            _ => Err(Self::subcommand("sudt").generate_usage()),
        }
    }
}
