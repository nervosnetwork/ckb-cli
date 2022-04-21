use std::path::PathBuf;

use clap::{App, Arg, ArgMatches};

use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    traits::{
        default_impls::{
            DefaultCellDepResolver, DefaultHeaderDepResolver, DefaultTransactionDependencyProvider,
        },
        CellCollector, CellQueryOptions,
    },
    tx_builder::cheque::{ChequeClaimBuilder, ChequeWithdrawBuilder},
    unlock::ChequeAction,
    Address, AddressPayload, GenesisInfo,
};
use ckb_types::{
    bytes::Bytes,
    packed::{CellInput, Script},
    prelude::*,
    H160, H256,
};

use super::{get_script_id, UdtTxBuilder};
use crate::plugin::PluginManager;
use crate::subcommands::{CliSubCommand, Output};
use crate::utils::{
    arg,
    arg_parser::{
        AddressParser, ArgParser, CellDepsParser, FromStrParser, PrivkeyPathParser, PrivkeyWrapper,
    },
    cell_collector::LocalCellCollector,
    cell_dep::{CellDepName, CellDeps},
    index::IndexController,
    other::get_network_type,
    rpc::HttpRpcClient,
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

    pub fn subcommand(name: &'static str) -> App<'static> {
        let arg_receiver = Arg::with_name("receiver")
            .long("receiver")
            .takes_value(true)
            .required(true)
            .validator(|input| AddressParser::new_sighash().validate(input));
        App::new(name)
            .about("Other sudt operations (cheque claim/withdraw/build address)")
            .subcommands(vec![
                App::new("cheque-claim")
                    .about("Claim all cheque cells identified by given lock script and type script")
                    .arg(super::arg_owner())
                    .arg(super::arg_sender().about("The cheque sender address (sighash)"))
                    .arg(
                        arg_receiver
                            .clone()
                            .about("The cheque receiver address (sighash), for searching an input to save the claimed amount, this address will be used to build anyone-can-pay address, if <capacity-provider> not given <receiver> will also be used as capacity provider")
                    )
                    .arg(super::arg_capacity_provider())
                    .arg(super::arg_cell_deps())
                    .arg(arg::privkey_path().multiple(true))
                    .arg(arg::fee_rate()),
                App::new("cheque-withdraw")
                    .about("Withdraw all cheque cells identified by given lock script and type script")
                    .arg(super::arg_owner())
                    .arg(super::arg_sender().about("The cheque sender address (sighash), if <capacity-provider> not given <sender> will use as capacity provider"))
                    .arg(arg_receiver.clone().about("The cheque receiver address (sighash)"))
                    .arg(super::arg_capacity_provider())
                    .arg(super::arg_to_acp_address().about("Withdraw to anyone-can-pay address, will use <sender> to build the anyone-can-pay address, the cell must be already exists"))
                    .arg(super::arg_cell_deps())
                    .arg(arg::privkey_path().multiple(true))
                    .arg(arg::fee_rate()),
                // TODO: move this subcommand to `util`
                App::new("build-acp-address")
                    .about("Build an anyone-can-pay address by sighash address and anyone-can-pay script id.")
                    .arg(super::arg_cell_deps())
                    .arg(
                        Arg::with_name("sighash-address")
                            .long("sighash-address")
                            .takes_value(true)
                            .required(true)
                            .validator(|input| AddressParser::new_sighash().validate(input))
                            .about("The sighash address")
                    ),
                App::new("build-cheque-address")
                    .about("Build a cheque address by cheque script id and receiver+sender address")
                    .arg(super::arg_cell_deps())
                    .arg(arg_receiver.about("The receiver address"))
                    .arg(super::arg_sender()),
            ])
    }

    fn cheque_claim(
        &mut self,
        args: ClaimArgs,
        privkeys: Vec<PrivkeyWrapper>,
        cell_deps: CellDeps,
        fee_rate: u64,
        debug: bool,
    ) -> Result<Output, String> {
        let ClaimArgs {
            owner,
            sender,
            receiver,
            capacity_provider,
        } = args;
        let udt_script_id = get_script_id(&cell_deps, CellDepName::Sudt)?;
        let cheque_script_id = get_script_id(&cell_deps, CellDepName::Cheque)?;
        let acp_script_id = get_script_id(&cell_deps, CellDepName::Acp)?;
        let owner_script = Script::from(&owner);
        let sender_script = Script::from(&sender);
        let receiver_script = Script::from(&receiver);
        let cheque_script = {
            let mut script_args = vec![0u8; 40];
            script_args[0..20]
                .copy_from_slice(&receiver_script.calc_script_hash().as_slice()[0..20]);
            script_args[20..40]
                .copy_from_slice(&sender_script.calc_script_hash().as_slice()[0..20]);
            Script::new_builder()
                .code_hash(cheque_script_id.code_hash.pack())
                .hash_type(cheque_script_id.hash_type.into())
                .args(Bytes::from(script_args).pack())
                .build()
        };
        let receiver_acp_script = Script::new_builder()
            .code_hash(acp_script_id.code_hash.pack())
            .hash_type(acp_script_id.hash_type.into())
            .args(receiver_script.args())
            .build();
        let type_script = Script::new_builder()
            .code_hash(udt_script_id.code_hash.pack())
            .hash_type(udt_script_id.hash_type.into())
            .args(owner_script.calc_script_hash().as_bytes().pack())
            .build();

        let mut cheque_query = CellQueryOptions::new_lock(cheque_script);
        cheque_query.secondary_script = Some(type_script.clone());
        cheque_query.min_total_capacity = u64::max_value();
        let (cheque_cells, _) = self
            .cell_collector
            .collect_live_cells(&cheque_query, false)
            .map_err(|err| err.to_string())?;
        if cheque_cells.is_empty() {
            return Err("no cheque cell found".to_string());
        }

        let mut udt_acp_query = CellQueryOptions::new_lock(receiver_acp_script);
        udt_acp_query.secondary_script = Some(type_script);
        let (udt_acp_cells, _) = self
            .cell_collector
            .collect_live_cells(&udt_acp_query, false)
            .map_err(|err| err.to_string())?;
        if udt_acp_cells.is_empty() {
            return Err(format!(
                "no SUDT cell found from receiver address: {}",
                receiver
            ));
        }

        let cheque_inputs = cheque_cells
            .into_iter()
            .map(|cell| CellInput::new(cell.out_point, 0))
            .collect::<Vec<_>>();
        let receiver_input = CellInput::new(udt_acp_cells[0].out_point.clone(), 0);
        let builder = ChequeClaimBuilder {
            inputs: cheque_inputs,
            receiver_input,
            sender_lock_script: sender_script,
        };

        let receiver_account =
            H160::from_slice(&receiver.payload().args().as_ref()[0..20]).unwrap();
        let mut accounts = vec![("receiver".to_string(), receiver_account)];
        if let Some(addr) = capacity_provider.as_ref() {
            if *addr != receiver {
                let account = H160::from_slice(addr.payload().args().as_ref()).unwrap();
                accounts.push(("capacity provider".to_string(), account));
            }
        }
        let capacity_provider = Script::from(capacity_provider.as_ref().unwrap_or(&receiver));
        let mut udt_builder = UdtTxBuilder {
            plugin_mgr: self.plugin_mgr,
            rpc_client: self.rpc_client,
            cell_collector: &mut self.cell_collector,
            cell_dep_resolver: &mut self.cell_dep_resolver,
            header_dep_resolver: &self.header_dep_resolver,
            tx_dep_provider: &self.tx_dep_provider,
            builder: &builder,
        };
        let tx = udt_builder.build(
            accounts,
            privkeys,
            &cell_deps,
            capacity_provider,
            Some(acp_script_id),
            Some((cheque_script_id, ChequeAction::Claim)),
            fee_rate,
        )?;

        let outputs_validator = Some(json_types::OutputsValidator::Passthrough);
        let tx_hash = self
            .rpc_client
            .send_transaction(tx.data(), outputs_validator)
            .map_err(|err| format!("Send transaction error: {}", err))?;
        assert_eq!(tx.hash(), tx_hash.pack());

        if debug {
            let rpc_tx_view = json_types::TransactionView::from(tx);
            let resp = serde_json::json!({ "transaction": rpc_tx_view });
            Ok(Output::new_output(resp))
        } else {
            let tx_hash: H256 = tx.hash().unpack();
            let resp = serde_json::json!({ "transaction-hash": tx_hash });
            Ok(Output::new_output(resp))
        }
    }

    fn cheque_withdraw(
        &mut self,
        args: WithdrawArgs,
        privkeys: Vec<PrivkeyWrapper>,
        cell_deps: CellDeps,
        fee_rate: u64,
        debug: bool,
    ) -> Result<Output, String> {
        let WithdrawArgs {
            owner,
            sender,
            receiver,
            capacity_provider,
            to_acp_address,
        } = args;
        let udt_script_id = get_script_id(&cell_deps, CellDepName::Sudt)?;
        let cheque_script_id = get_script_id(&cell_deps, CellDepName::Cheque)?;
        let acp_script_id = if to_acp_address {
            Some(get_script_id(&cell_deps, CellDepName::Acp)?)
        } else {
            None
        };
        let owner_script = Script::from(&owner);
        let sender_script = Script::from(&sender);
        let receiver_script = Script::from(&receiver);
        let cheque_script = {
            let mut script_args = vec![0u8; 40];
            script_args[0..20]
                .copy_from_slice(&receiver_script.calc_script_hash().as_slice()[0..20]);
            script_args[20..40]
                .copy_from_slice(&sender_script.calc_script_hash().as_slice()[0..20]);
            Script::new_builder()
                .code_hash(cheque_script_id.code_hash.pack())
                .hash_type(cheque_script_id.hash_type.into())
                .args(Bytes::from(script_args).pack())
                .build()
        };
        let type_script = Script::new_builder()
            .code_hash(udt_script_id.code_hash.pack())
            .hash_type(udt_script_id.hash_type.into())
            .args(owner_script.calc_script_hash().as_bytes().pack())
            .build();

        let mut cheque_query = CellQueryOptions::new_lock(cheque_script);
        cheque_query.secondary_script = Some(type_script);
        cheque_query.min_total_capacity = u64::max_value();
        let (cheque_cells, _) = self
            .cell_collector
            .collect_live_cells(&cheque_query, false)
            .map_err(|err| err.to_string())?;
        if cheque_cells.is_empty() {
            return Err("no cheque cell found".to_string());
        }

        let cheque_out_points = cheque_cells
            .into_iter()
            .map(|cell| cell.out_point)
            .collect::<Vec<_>>();
        let builder = ChequeWithdrawBuilder {
            out_points: cheque_out_points,
            sender_lock_script: sender_script,
            acp_script_id: acp_script_id.clone(),
        };

        let sender_account = H160::from_slice(&sender.payload().args().as_ref()[0..20]).unwrap();
        let mut accounts = vec![("sender".to_string(), sender_account)];
        if let Some(addr) = capacity_provider.as_ref() {
            if *addr != receiver {
                let account = H160::from_slice(addr.payload().args().as_ref()).unwrap();
                accounts.push(("capacity provider".to_string(), account));
            }
        }
        let capacity_provider = Script::from(capacity_provider.as_ref().unwrap_or(&sender));
        let mut udt_builder = UdtTxBuilder {
            plugin_mgr: self.plugin_mgr,
            rpc_client: self.rpc_client,
            cell_collector: &mut self.cell_collector,
            cell_dep_resolver: &mut self.cell_dep_resolver,
            header_dep_resolver: &self.header_dep_resolver,
            tx_dep_provider: &self.tx_dep_provider,
            builder: &builder,
        };
        let tx = udt_builder.build(
            accounts,
            privkeys,
            &cell_deps,
            capacity_provider,
            acp_script_id,
            Some((cheque_script_id, ChequeAction::Withdraw)),
            fee_rate,
        )?;

        let outputs_validator = Some(json_types::OutputsValidator::Passthrough);
        let tx_hash = self
            .rpc_client
            .send_transaction(tx.data(), outputs_validator)
            .map_err(|err| format!("Send transaction error: {}", err))?;
        assert_eq!(tx.hash(), tx_hash.pack());

        if debug {
            let rpc_tx_view = json_types::TransactionView::from(tx);
            let resp = serde_json::json!({ "transaction": rpc_tx_view });
            Ok(Output::new_output(resp))
        } else {
            let tx_hash: H256 = tx.hash().unpack();
            let resp = serde_json::json!({ "transaction-hash": tx_hash });
            Ok(Output::new_output(resp))
        }
    }
}

impl<'a> CliSubCommand for SudtSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches, debug: bool) -> Result<Output, String> {
        let network = get_network_type(self.rpc_client)?;
        match matches.subcommand() {
            ("cheque-claim", Some(m)) => {
                let owner: Address = AddressParser::new_sighash()
                    .set_network(network)
                    .from_matches(m, "owner")?;
                let sender: Address = AddressParser::new_sighash()
                    .set_network(network)
                    .from_matches(m, "sender")?;
                let receiver: Address = AddressParser::new_sighash()
                    .set_network(network)
                    .from_matches(m, "receiver")?;
                let capacity_provider: Option<Address> = AddressParser::new_sighash()
                    .set_network(network)
                    .from_matches_opt(m, "capacity-provider")?;
                let privkeys: Vec<PrivkeyWrapper> =
                    PrivkeyPathParser.from_matches_vec(m, "privkey-path")?;
                let cell_deps: CellDeps = CellDepsParser.from_matches(m, "cell-deps")?;
                let fee_rate: u64 = FromStrParser::<u64>::default().from_matches(m, "fee-rate")?;

                if capacity_provider.as_ref() == Some(&sender) {
                    return Err("<capacity-provider> can't be the same with <sender>".to_string());
                }
                self.cheque_claim(
                    ClaimArgs {
                        owner,
                        sender,
                        receiver,
                        capacity_provider,
                    },
                    privkeys,
                    cell_deps,
                    fee_rate,
                    debug,
                )
            }
            ("cheque-withdraw", Some(m)) => {
                let owner: Address = AddressParser::new_sighash()
                    .set_network(network)
                    .from_matches(m, "owner")?;
                let sender: Address = AddressParser::new_sighash()
                    .set_network(network)
                    .from_matches(m, "sender")?;
                let receiver: Address = AddressParser::new_sighash()
                    .set_network(network)
                    .from_matches(m, "receiver")?;
                let capacity_provider: Option<Address> = AddressParser::new_sighash()
                    .set_network(network)
                    .from_matches_opt(m, "capacity-provider")?;
                let to_acp_address = m.is_present("to-acp-address");
                let privkeys: Vec<PrivkeyWrapper> =
                    PrivkeyPathParser.from_matches_vec(m, "privkey-path")?;
                let cell_deps: CellDeps = CellDepsParser.from_matches(m, "cell-deps")?;
                let fee_rate: u64 = FromStrParser::<u64>::default().from_matches(m, "fee-rate")?;
                self.cheque_withdraw(
                    WithdrawArgs {
                        owner,
                        sender,
                        receiver,
                        capacity_provider,
                        to_acp_address,
                    },
                    privkeys,
                    cell_deps,
                    fee_rate,
                    debug,
                )
            }
            ("build-acp-address", Some(m)) => {
                let sighash_addr: Address = AddressParser::new_sighash()
                    .set_network(network)
                    .from_matches(m, "sighash-address")?;
                let cell_deps: CellDeps = CellDepsParser.from_matches(m, "cell-deps")?;
                let acp_script_id = get_script_id(&cell_deps, CellDepName::Acp)?;
                let acp_script = Script::new_builder()
                    .code_hash(acp_script_id.code_hash.pack())
                    .hash_type(acp_script_id.hash_type.into())
                    .args(sighash_addr.payload().args().pack())
                    .build();
                let acp_payload = AddressPayload::from(acp_script);
                let acp_addr = Address::new(network, acp_payload, true);
                Ok(Output::new_output(acp_addr.to_string()))
            }
            ("build-cheque-address", Some(m)) => {
                let sender: Address = AddressParser::new_sighash()
                    .set_network(network)
                    .from_matches(m, "sender")?;
                let receiver: Address = AddressParser::new_sighash()
                    .set_network(network)
                    .from_matches(m, "receiver")?;
                let cell_deps: CellDeps = CellDepsParser.from_matches(m, "cell-deps")?;

                let cheque_script_id = get_script_id(&cell_deps, CellDepName::Cheque)?;
                let sender_script_hash = Script::from(&sender).calc_script_hash();
                let receiver_script_hash = Script::from(&receiver).calc_script_hash();
                let mut script_args = vec![0u8; 40];
                script_args[0..20].copy_from_slice(&receiver_script_hash.as_slice()[0..20]);
                script_args[20..40].copy_from_slice(&sender_script_hash.as_slice()[0..20]);
                let cheque_script = Script::new_builder()
                    .code_hash(cheque_script_id.code_hash.pack())
                    .hash_type(cheque_script_id.hash_type.into())
                    .args(Bytes::from(script_args).pack())
                    .build();
                let cheque_payload = AddressPayload::from(cheque_script);
                let cheque_addr = Address::new(network, cheque_payload, true);
                Ok(Output::new_output(cheque_addr.to_string()))
            }
            _ => Err(Self::subcommand("sudt").generate_usage()),
        }
    }
}

struct ClaimArgs {
    owner: Address,
    sender: Address,
    receiver: Address,
    capacity_provider: Option<Address>,
}
struct WithdrawArgs {
    owner: Address,
    sender: Address,
    receiver: Address,
    capacity_provider: Option<Address>,
    to_acp_address: bool,
}
