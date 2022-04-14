mod sudt;
mod xudt;

pub use sudt::SudtSubCommand;
// pub use xudt::XudtSubCommand;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use clap::{App, Arg, ArgMatches};
use sparse_merkle_tree::{
    blake2b::Blake2bHasher, default_store::DefaultStore, SparseMerkleTree, H256 as SmtH256,
};

use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
    rpc::CkbRpcClient,
    traits::{
        default_impls::{
            DefaultCellDepResolver, DefaultHeaderDepResolver, DefaultTransactionDependencyProvider,
        },
        CellCollector, CellQueryOptions, Signer,
    },
    tx_builder::{
        balance_tx_capacity, fill_placeholder_witnesses,
        transfer::CapacityTransferBuilder,
        udt::{
            xudt_rce::{
                ScriptVec, SmtProof, SmtProofEntry, SmtProofEntryVec, XudtData, XudtWitnessInput,
            },
            UdtIssueBuilder, UdtTargetReceiver, UdtTransferBuilder, UdtType,
        },
        unlock_tx, CapacityBalancer, CapacityProvider, TransferAction, TxBuilder,
    },
    types::ScriptId,
    unlock::{
        AcpScriptSigner, AcpUnlocker, ChequeAction, ChequeScriptSigner, ChequeUnlocker,
        ScriptUnlocker, SecpSighashScriptSigner, SecpSighashUnlocker,
    },
    Address, AddressPayload, GenesisInfo, NetworkType,
};
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, FeeRate, ScriptHashType, TransactionView},
    packed::{self, Byte32, CellOutput, Script, WitnessArgs},
    prelude::*,
    H160, H256,
};

use crate::plugin::PluginManager;
use crate::subcommands::{CliSubCommand, Output};
use crate::utils::{
    arg,
    arg_parser::{
        AddressParser, ArgParser, CellDepsParser, FixedHashParser, FromStrParser,
        PrivkeyPathParser, PrivkeyWrapper, UdtTargetParser,
    },
    cell_collector::LocalCellCollector,
    cell_dep::{CellDepName, CellDeps},
    index::IndexController,
    other::{get_network_type, read_password},
    rpc::HttpRpcClient,
    signer::{CommonSigner, KeyStoreHandlerSigner, PrivkeySigner},
};

const RCE_HASH: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

type Smt = SparseMerkleTree<Blake2bHasher, SmtH256, DefaultStore<SmtH256>>;

pub struct UdtSubCommand<'a> {
    plugin_mgr: &'a mut PluginManager,
    rpc_client: &'a mut HttpRpcClient,
    cell_collector: LocalCellCollector,
    cell_dep_resolver: DefaultCellDepResolver,
    header_dep_resolver: DefaultHeaderDepResolver,
    tx_dep_provider: DefaultTransactionDependencyProvider,
}

impl<'a> UdtSubCommand<'a> {
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
        let header_dep_resolver =
            DefaultHeaderDepResolver::new(CkbRpcClient::new(rpc_client.url()));
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
        let arg_xudt_rce_args = Arg::with_name("xudt-rce-args")
            .long("xudt-rce-args")
            .takes_value(true)
            .validator(|input| FixedHashParser::<H256>::default().validate(input))
            .about("The xudt rce script args (rce cell's type script hash), if given will treat all udt cell as xudt cell otherwise will treat all udt cell as sudt cell. Currently, only RCE extension work with one empty blacklist is supported.");
        let arg_udt_to = Arg::with_name("udt-to")
            .long("udt-to")
            .takes_value(true)
            .multiple(true)
            .required(true)
            .validator(|input| UdtTargetParser::new(AddressParser::default()).validate(input));
        let arg_to_cheque_address = Arg::with_name("to-cheque-address").long("to-cheque-address");
        App::new(name)
            .about("UDT (sudt/xudt) issue/transfer operations")
            .subcommands(vec![
                App::new("issue")
                    .about("Issue UDT to multiple addresses")
                    .arg(arg_owner())
                    .arg(
                        arg_udt_to.clone()
                            .about("The issue target, format: {address}:{amount}, the address type can be: [acp, sighash]")
                    )
                    .arg(arg_xudt_rce_args.clone())
                    .arg(arg_cell_deps())
                    .arg(arg_to_acp_address())
                    .arg(
                        arg_to_cheque_address
                            .clone()
                            .about("Treat all addresses in <udt-to> as cheque receiver (sighash address, and the cheque sender is the <owner>), otherwise the address will be used as the lock script of the UDT cell")
                    )
                    .arg(arg::privkey_path().multiple(true))
                    .arg(arg::fee_rate()),
                App::new("transfer")
                    .about("Transfer UDT to multiple addresses (all target addresses must have same lock script id)")
                    .arg(arg_owner())
                    .arg(arg_sender().about("UDT sender address, the address type can be: [acp, sighash], when address type is `acp` this address will be used to build a sighash lock script for build cheque address or provide capacity, if <capacity-provider> is not given <sender> will also use as capacity provider."))
                    .arg(
                        arg_udt_to
                         .about("The transfer target, format: {address}:{amount}, the address type can be: [acp, sighash]")
                    )
                    .arg(arg_xudt_rce_args.clone())
                    .arg(arg_cell_deps())
                    .arg(arg_to_acp_address())
                    .arg(
                        arg_to_cheque_address
                            .clone()
                            .about("Treat all addresses in <udt-to> as cheque receiver (sighash address), otherwise the address will be used as the lock script of the UDT cell. When this flag is presented <cheque> cell_dep must be given")
                    )
                    .arg(arg_capacity_provider())
                    .arg(arg::privkey_path().multiple(true))
                    .arg(arg::fee_rate()),
                App::new("get-amount")
                    .about("Get UDT total amount of an address")
                    .arg(arg_owner())
                    .arg(arg_xudt_rce_args.clone())
                    .arg(arg_cell_deps())
                    .arg(
                        Arg::with_name("address")
                            .long("address")
                            .takes_value(true)
                            .required(true)
                            .validator(|input| AddressParser::default().validate(input))
                            .about("The target address of those SUDT cells"),
                    ),
                App::new("new-empty-acp")
                    .about("Create a UDT cell with 0 amount and an acp lock script")
                    .arg(arg_owner())
                    .arg(arg_capacity_provider())
                    .arg(
                        Arg::with_name("to")
                            .long("to")
                            .takes_value(true)
                            .required(true)
                            .validator(|input| AddressParser::new_sighash().validate(input))
                            .about("The target address (sighash), used to create anyone-can-pay address, if <capacity-provider> is not given <to> will also use as capacity provider"),
                    )
                    .arg(arg_xudt_rce_args)
                    .arg(arg_cell_deps())
                    .arg(arg::privkey_path().multiple(true))
                    .arg(arg::fee_rate()),
            ])
    }

    fn issue(
        &mut self,
        owner: Address,
        xudt_rce_args: Option<H256>,
        udt_to_vec: Vec<(Address, u128)>,
        to_cheque_address: bool,
        to_acp_address: bool,
        privkeys: Vec<PrivkeyWrapper>,
        cell_deps: CellDeps,
        fee_rate: u64,
        network: NetworkType,
        debug: bool,
    ) -> Result<Output, String> {
        let (udt_script_id, udt_type, xudt_data) = udt_info(xudt_rce_args.as_ref(), &cell_deps)?;
        let acp_script_id = if to_acp_address {
            Some(get_script_id(&cell_deps, CellDepName::Acp)?)
        } else {
            None
        };
        let cheque_script_id = if to_cheque_address {
            Some(get_script_id(&cell_deps, CellDepName::Cheque)?)
        } else {
            None
        };
        let owner_account = H160::from_slice(owner.payload().args().as_ref()).unwrap();
        let owner_script = Script::from(&owner);
        let owner_script_hash = owner_script.calc_script_hash();
        let receivers = udt_to_vec
            .into_iter()
            .map(|(addr, amount)| {
                let receiver_script = Script::from(&addr);
                let (action, lock_script) = if let Some(script_id) = cheque_script_id.as_ref() {
                    let receiver_script_hash = receiver_script.calc_script_hash();
                    let mut script_args = vec![0u8; 40];
                    script_args[0..20].copy_from_slice(&receiver_script_hash.as_slice()[0..20]);
                    // owner is also the sender here
                    script_args[20..40].copy_from_slice(&owner_script_hash.as_slice()[0..20]);
                    let script = Script::new_builder()
                        .code_hash(script_id.code_hash.pack())
                        .hash_type(script_id.hash_type.into())
                        .args(Bytes::from(script_args).pack())
                        .build();
                    (TransferAction::Create, script)
                } else if to_acp_address {
                    (TransferAction::Update, receiver_script)
                } else {
                    (TransferAction::Create, receiver_script)
                };
                UdtTargetReceiver {
                    action,
                    lock_script,
                    capacity: None,
                    amount,
                    extra_data: xudt_data.clone(),
                }
            })
            .collect::<Vec<_>>();
        let udt_lock_hashes = receivers
            .iter()
            .map(|receiver| receiver.lock_script.calc_script_hash())
            .collect::<HashSet<_>>();
        let receiver_infos = receivers
            .iter()
            .map(|receiver| {
                let payload = AddressPayload::from(receiver.lock_script.clone());
                serde_json::json!({
                    "address": Address::new(network, payload, true).to_string(),
                    "amount": receiver.amount.to_string(),
                })
            })
            .collect::<Vec<_>>();
        let builder = UdtIssueBuilder {
            udt_type,
            script_id: udt_script_id,
            owner: owner_script.clone(),
            receivers,
        };
        let rce_info = xudt_rce_args
            .map(|rce_cell_hash| (rce_cell_hash, build_rce_witness(udt_lock_hashes, true)));
        let mut udt_builder = UdtTxBuilder {
            plugin_mgr: self.plugin_mgr,
            rpc_client: self.rpc_client,
            cell_collector: &mut self.cell_collector,
            cell_dep_resolver: &mut self.cell_dep_resolver,
            header_dep_resolver: &self.header_dep_resolver,
            tx_dep_provider: &self.tx_dep_provider,
            builder: &builder,
            rce_info,
        };
        let tx = udt_builder.build(
            vec![("owner".to_string(), owner_account)],
            privkeys,
            &cell_deps,
            owner_script,
            acp_script_id,
            None,
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
            let resp = serde_json::json!({
                "transaction": rpc_tx_view,
                "receivers": receiver_infos,
            });
            Ok(Output::new_output(resp))
        } else {
            let tx_hash: H256 = tx.hash().unpack();
            let resp = serde_json::json!({
                "transaction-hash": tx_hash,
                "receivers": receiver_infos,
            });
            Ok(Output::new_output(resp))
        }
    }

    fn transfer(
        &mut self,
        owner: Address,
        xudt_rce_args: Option<H256>,
        sender: Address,
        udt_to_vec: Vec<(Address, u128)>,
        to_cheque_address: bool,
        to_acp_address: bool,
        capacity_provider: Option<Address>,
        privkeys: Vec<PrivkeyWrapper>,
        cell_deps: CellDeps,
        fee_rate: u64,
        network: NetworkType,
        debug: bool,
    ) -> Result<Output, String> {
        let (udt_script_id, udt_type, xudt_data) = udt_info(xudt_rce_args.as_ref(), &cell_deps)?;
        let acp_script_id = get_script_id(&cell_deps, CellDepName::Acp)?;
        let cheque_script_id = if to_cheque_address {
            Some(get_script_id(&cell_deps, CellDepName::Cheque)?)
        } else {
            None
        };

        let owner_script_hash = Script::from(&owner).calc_script_hash();
        let sender_account = H160::from_slice(&sender.payload().args().as_ref()[0..20]).unwrap();
        let sender_script = Script::from(&sender);
        let type_script = udt_type.build_script(&udt_script_id, &owner_script_hash);
        let cheque_sender_script_hash = Script::new_builder()
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(sender_account.as_bytes().to_vec()).pack())
            .build()
            .calc_script_hash();
        let receivers = udt_to_vec
            .into_iter()
            .map(|(addr, amount)| {
                let receiver_script = Script::from(&addr);
                let (action, lock_script) = if let Some(script_id) = cheque_script_id.as_ref() {
                    let receiver_script_hash = receiver_script.calc_script_hash();
                    let mut script_args = vec![0u8; 40];
                    script_args[0..20].copy_from_slice(&receiver_script_hash.as_slice()[0..20]);
                    script_args[20..40]
                        .copy_from_slice(&cheque_sender_script_hash.as_slice()[0..20]);
                    let script = Script::new_builder()
                        .code_hash(script_id.code_hash.pack())
                        .hash_type(script_id.hash_type.into())
                        .args(Bytes::from(script_args).pack())
                        .build();
                    (TransferAction::Create, script)
                } else if to_acp_address {
                    (TransferAction::Update, receiver_script)
                } else {
                    (TransferAction::Create, receiver_script)
                };
                UdtTargetReceiver {
                    action,
                    lock_script,
                    capacity: None,
                    amount,
                    extra_data: xudt_data.clone(),
                }
            })
            .collect::<Vec<_>>();
        let mut udt_lock_hashes = receivers
            .iter()
            .map(|receiver| receiver.lock_script.calc_script_hash())
            .collect::<HashSet<_>>();
        udt_lock_hashes.insert(sender_script.calc_script_hash());

        let receiver_infos = receivers
            .iter()
            .map(|receiver| {
                let payload = AddressPayload::from(receiver.lock_script.clone());
                serde_json::json!({
                    "address": Address::new(network, payload, true).to_string(),
                    "amount": receiver.amount.to_string(),
                })
            })
            .collect::<Vec<_>>();
        let sender_sighash = Address::new(
            network,
            AddressPayload::from_pubkey_hash(sender_account.clone()),
            true,
        );
        let mut accounts = vec![(format!("sender({})", sender_sighash), sender_account)];
        if let Some(addr) = capacity_provider.as_ref() {
            if *addr != sender {
                let account = H160::from_slice(addr.payload().args().as_ref()).unwrap();
                accounts.push((format!("capacity provider({})", addr), account));
            }
        }
        let capacity_provider = Script::from(capacity_provider.as_ref().unwrap_or(&sender_sighash));
        let builder = UdtTransferBuilder {
            type_script,
            sender: sender_script,
            receivers,
        };
        let rce_info = xudt_rce_args
            .map(|rce_cell_hash| (rce_cell_hash, build_rce_witness(udt_lock_hashes, false)));
        let mut udt_builder = UdtTxBuilder {
            plugin_mgr: self.plugin_mgr,
            rpc_client: self.rpc_client,
            cell_collector: &mut self.cell_collector,
            cell_dep_resolver: &mut self.cell_dep_resolver,
            header_dep_resolver: &self.header_dep_resolver,
            tx_dep_provider: &self.tx_dep_provider,
            builder: &builder,
            rce_info,
        };
        let tx = udt_builder.build(
            accounts,
            privkeys,
            &cell_deps,
            capacity_provider,
            Some(acp_script_id),
            None,
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
            let resp = serde_json::json!({
                "transaction": rpc_tx_view,
                "receivers": receiver_infos,
            });
            Ok(Output::new_output(resp))
        } else {
            let tx_hash: H256 = tx.hash().unpack();
            let resp = serde_json::json!({
                "transaction-hash": tx_hash,
                "receivers": receiver_infos,
            });
            Ok(Output::new_output(resp))
        }
    }

    fn get_amount(
        &mut self,
        owner: Address,
        xudt_rce_args: Option<H256>,
        address: Address,
        cell_deps: CellDeps,
    ) -> Result<Output, String> {
        let (udt_script_id, udt_type, _) = udt_info(xudt_rce_args.as_ref(), &cell_deps)?;
        let owner_script_hash = Script::from(&owner).calc_script_hash();
        let type_script = udt_type.build_script(&udt_script_id, &owner_script_hash);

        let mut query = CellQueryOptions::new_lock(Script::from(&address));
        query.secondary_script = Some(type_script);
        query.min_total_capacity = u64::max_value();
        let (cells, _) = self
            .cell_collector
            .collect_live_cells(&query, false)
            .map_err(|err| err.to_string())?;
        let mut total_amount: u128 = 0;
        let mut infos = Vec::new();
        for cell in cells {
            if cell.output_data.len() < 16 {
                return Err(format!(
                    "invalid cell data length: {}, expected: >= 16",
                    cell.output_data.len()
                ));
            }
            let mut amount_bytes = [0u8; 16];
            amount_bytes.copy_from_slice(&cell.output_data.as_ref()[0..16]);
            let amount = u128::from_le_bytes(amount_bytes);
            total_amount += amount;
            infos.push(serde_json::json!({
                "out_point": json_types::OutPoint::from(cell.out_point),
                // u128 is too large for json
                "amount": amount.to_string(),
            }));
        }
        let resp = serde_json::json!({
            "cell_count": infos.len(),
            "cells": infos,
            // u128 is too large for json
            "total_amount": total_amount.to_string(),
        });
        Ok(Output::new_output(resp))
    }

    fn new_empty_acp(
        &mut self,
        owner: Address,
        xudt_rce_args: Option<H256>,
        to: Address,
        capacity_provider: Option<Address>,
        privkeys: Vec<PrivkeyWrapper>,
        cell_deps: CellDeps,
        fee_rate: u64,
        network: NetworkType,
        debug: bool,
    ) -> Result<Output, String> {
        let (udt_script_id, udt_type, xudt_data) = udt_info(xudt_rce_args.as_ref(), &cell_deps)?;
        let acp_script_id = get_script_id(&cell_deps, CellDepName::Acp)?;
        let owner_script_hash = Script::from(&owner).calc_script_hash();
        let capacity_provider = capacity_provider.unwrap_or_else(|| to.clone());
        let capacity_provider_account =
            H160::from_slice(capacity_provider.payload().args().as_ref()).unwrap();
        let acp_lock = Script::new_builder()
            .code_hash(acp_script_id.code_hash.pack())
            .hash_type(acp_script_id.hash_type.into())
            .args(to.payload().args().pack())
            .build();
        let acp_address = {
            let payload = AddressPayload::from(acp_lock.clone());
            Address::new(network, payload, true)
        };
        let mut udt_lock_hashes = HashSet::default();
        udt_lock_hashes.insert(acp_lock.calc_script_hash());

        let type_script = udt_type.build_script(&udt_script_id, &owner_script_hash);
        let base_output = CellOutput::new_builder()
            .lock(acp_lock)
            .type_(Some(type_script).pack())
            .build();
        let occupied_capacity: u64 = base_output
            .occupied_capacity(Capacity::bytes(16).unwrap())
            .unwrap()
            .as_u64();
        let output = base_output
            .as_builder()
            .capacity(occupied_capacity.pack())
            .build();
        let output_data = {
            let mut buf = vec![
                0u8;
                16 + xudt_data
                    .as_ref()
                    .map(|data| data.len())
                    .unwrap_or_default()
            ];
            buf[0..16].copy_from_slice(&0u128.to_le_bytes()[..]);
            if let Some(data) = xudt_data.as_ref() {
                buf[16..].copy_from_slice(data.as_ref());
            }
            Bytes::from(buf)
        };
        let builder = CapacityTransferBuilder::new(vec![(output, output_data)]);
        let rce_info = xudt_rce_args
            .map(|rce_cell_hash| (rce_cell_hash, build_rce_witness(udt_lock_hashes, true)));
        let mut udt_builder = UdtTxBuilder {
            plugin_mgr: self.plugin_mgr,
            rpc_client: self.rpc_client,
            cell_collector: &mut self.cell_collector,
            cell_dep_resolver: &mut self.cell_dep_resolver,
            header_dep_resolver: &self.header_dep_resolver,
            tx_dep_provider: &self.tx_dep_provider,
            builder: &builder,
            rce_info,
        };
        let tx = udt_builder.build(
            vec![("capacity provider".to_string(), capacity_provider_account)],
            privkeys,
            &cell_deps,
            Script::from(&capacity_provider),
            None,
            None,
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
            let resp = serde_json::json!({
                "transaction": rpc_tx_view,
                "acp-address": acp_address.to_string(),
            });
            Ok(Output::new_output(resp))
        } else {
            let tx_hash: H256 = tx.hash().unpack();
            let resp = serde_json::json!({
                "transaction-hash": tx_hash,
                "acp-address": acp_address.to_string(),
            });
            Ok(Output::new_output(resp))
        }
    }
}

impl<'a> CliSubCommand for UdtSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches, debug: bool) -> Result<Output, String> {
        let network = get_network_type(self.rpc_client)?;
        match matches.subcommand() {
            ("issue", Some(m)) => {
                let owner: Address = AddressParser::new_sighash()
                    .set_network(network)
                    .from_matches(m, "owner")?;
                let xudt_rce_args: Option<H256> =
                    FixedHashParser::<H256>::default().from_matches_opt(m, "xudt-rce-args")?;
                let udt_to_vec: Vec<(Address, u128)> = {
                    let mut address_parser = AddressParser::default();
                    address_parser.set_network(network);
                    UdtTargetParser::new(address_parser).from_matches_vec(m, "udt-to")?
                };
                let privkeys: Vec<PrivkeyWrapper> =
                    PrivkeyPathParser.from_matches_vec(m, "privkey-path")?;
                let cell_deps: CellDeps = CellDepsParser.from_matches(m, "cell-deps")?;
                let fee_rate: u64 = FromStrParser::<u64>::default().from_matches(m, "fee-rate")?;
                let to_cheque_address = m.is_present("to-cheque-address");
                let to_acp_address = m.is_present("to-acp-address");

                check_udt_args(
                    &udt_to_vec,
                    to_cheque_address,
                    to_acp_address,
                    &cell_deps,
                    network,
                )?;

                self.issue(
                    owner,
                    xudt_rce_args,
                    udt_to_vec,
                    to_cheque_address,
                    to_acp_address,
                    privkeys,
                    cell_deps,
                    fee_rate,
                    network,
                    debug,
                )
            }
            ("transfer", Some(m)) => {
                let owner: Address = AddressParser::default()
                    .set_network(network)
                    .from_matches(m, "owner")?;
                let xudt_rce_args: Option<H256> =
                    FixedHashParser::<H256>::default().from_matches_opt(m, "xudt-rce-args")?;
                let sender: Address = AddressParser::default()
                    .set_network(network)
                    .from_matches(m, "sender")?;
                let udt_to_vec: Vec<(Address, u128)> = {
                    let mut address_parser = AddressParser::default();
                    address_parser.set_network(network);
                    UdtTargetParser::new(address_parser).from_matches_vec(m, "udt-to")?
                };
                let capacity_provider: Option<Address> = AddressParser::new_sighash()
                    .set_network(network)
                    .from_matches_opt(m, "capacity-provider")?;
                let privkeys: Vec<PrivkeyWrapper> =
                    PrivkeyPathParser.from_matches_vec(m, "privkey-path")?;
                let cell_deps: CellDeps = CellDepsParser.from_matches(m, "cell-deps")?;
                let to_cheque_address = m.is_present("to-cheque-address");
                let to_acp_address = m.is_present("to-acp-address");
                let fee_rate: u64 = FromStrParser::<u64>::default().from_matches(m, "fee-rate")?;

                check_udt_args(
                    &udt_to_vec,
                    to_cheque_address,
                    to_acp_address,
                    &cell_deps,
                    network,
                )?;

                self.transfer(
                    owner,
                    xudt_rce_args,
                    sender,
                    udt_to_vec,
                    to_cheque_address,
                    to_acp_address,
                    capacity_provider,
                    privkeys,
                    cell_deps,
                    fee_rate,
                    network,
                    debug,
                )
            }
            ("get-amount", Some(m)) => {
                let owner: Address = AddressParser::default()
                    .set_network(network)
                    .from_matches(m, "owner")?;
                let xudt_rce_args: Option<H256> =
                    FixedHashParser::<H256>::default().from_matches_opt(m, "xudt-rce-args")?;
                let cell_deps: CellDeps = CellDepsParser.from_matches(m, "cell-deps")?;
                let address: Address = AddressParser::default()
                    .set_network(network)
                    .from_matches(m, "address")?;
                self.get_amount(owner, xudt_rce_args, address, cell_deps)
            }
            ("new-empty-acp", Some(m)) => {
                let owner: Address = AddressParser::default()
                    .set_network(network)
                    .from_matches(m, "owner")?;
                let xudt_rce_args: Option<H256> =
                    FixedHashParser::<H256>::default().from_matches_opt(m, "xudt-rce-args")?;
                let to: Address = AddressParser::new_sighash()
                    .set_network(network)
                    .from_matches(m, "to")?;
                let capacity_provider: Option<Address> = AddressParser::new_sighash()
                    .set_network(network)
                    .from_matches_opt(m, "capacity-provider")?;
                let privkeys: Vec<PrivkeyWrapper> =
                    PrivkeyPathParser.from_matches_vec(m, "privkey-path")?;
                let cell_deps: CellDeps = CellDepsParser.from_matches(m, "cell-deps")?;
                let fee_rate: u64 = FromStrParser::<u64>::default().from_matches(m, "fee-rate")?;
                self.new_empty_acp(
                    owner,
                    xudt_rce_args,
                    to,
                    capacity_provider,
                    privkeys,
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

pub fn get_script_id(cell_deps: &CellDeps, name: CellDepName) -> Result<ScriptId, String> {
    cell_deps
        .get_item(name)
        .map(|item| item.script_id.clone().into())
        .ok_or_else(|| format!("no {} cell_dep item in cell_deps", name))
}

fn udt_info(
    xudt_rce_args: Option<&H256>,
    cell_deps: &CellDeps,
) -> Result<(ScriptId, UdtType, Option<Bytes>), String> {
    if let Some(rce_args) = xudt_rce_args {
        let xudt_data = XudtData::new_builder()
            .lock(Bytes::default().pack())
            .data(vec![Bytes::default().pack()].pack())
            .build()
            .as_bytes();
        let xudt_args = {
            let flags = 1u32.to_le_bytes();
            let rce_script = Script::new_builder()
                .code_hash(RCE_HASH.pack())
                .hash_type(ScriptHashType::Type.into())
                .args(Bytes::from(rce_args.as_bytes().to_vec()).pack())
                .build();
            let script_vec_bytes = ScriptVec::new_builder().push(rce_script).build().as_bytes();
            let mut buf = vec![0u8; 4 + script_vec_bytes.len()];
            buf[0..4].copy_from_slice(&flags[..]);
            buf[4..].copy_from_slice(script_vec_bytes.as_ref());
            Bytes::from(buf)
        };
        Ok((
            get_script_id(cell_deps, CellDepName::Xudt)?,
            UdtType::Xudt(xudt_args),
            Some(xudt_data),
        ))
    } else {
        Ok((
            get_script_id(cell_deps, CellDepName::Sudt)?,
            UdtType::Sudt,
            None,
        ))
    }
}

// NOTE: here we assume rce cell is just one empty blaklist set.
fn build_rce_witness(lock_hashes: HashSet<Byte32>, is_issue: bool) -> WitnessArgs {
    let tree = Smt::default();
    let lock_hashes = lock_hashes
        .into_iter()
        .map(|hash| {
            let hash: H256 = hash.unpack();
            SmtH256::from(hash.0)
        })
        .collect::<Vec<_>>();
    let pairs = lock_hashes
        .iter()
        .map(|hash| (*hash, SmtH256::default()))
        .collect::<Vec<_>>();
    let compiled_proof = tree
        .merkle_proof(lock_hashes)
        .expect("smt proof")
        .compile(pairs)
        .expect("smt compile proof");
    let mask: u8 = 0x3;
    let smt_proof = SmtProof::new_builder()
        .extend(compiled_proof.0.into_iter().map(packed::Byte::new))
        .build();
    let smt_proof_entry = SmtProofEntry::new_builder()
        .mask(packed::Byte::new(mask))
        .proof(smt_proof)
        .build();
    let smt_proof_entry_vec_bytes = SmtProofEntryVec::new_builder()
        .push(smt_proof_entry)
        .build()
        .as_bytes();
    let xudt_witness_input_bytes = XudtWitnessInput::new_builder()
        .extension_data(vec![smt_proof_entry_vec_bytes].pack())
        .build()
        .as_bytes();
    if is_issue {
        WitnessArgs::new_builder()
            .output_type(Some(xudt_witness_input_bytes).pack())
            .build()
    } else {
        WitnessArgs::new_builder()
            .input_type(Some(xudt_witness_input_bytes).pack())
            .build()
    }
}

fn check_udt_args(
    udt_to: &[(Address, u128)],
    to_cheque_address: bool,
    to_acp_address: bool,
    cell_deps: &CellDeps,
    network: NetworkType,
) -> Result<(), String> {
    if to_cheque_address && to_acp_address {
        return Err("to-acp-address and to-cheque-address can not both presented".to_string());
    }

    let acp_script_id = if to_acp_address {
        Some(get_script_id(cell_deps, CellDepName::Acp)?)
    } else {
        None
    };
    for (addr, _) in udt_to {
        let payload = addr.payload();
        let code_hash = payload.code_hash(Some(network));
        let hash_type = payload.hash_type();
        if to_cheque_address
            && (code_hash != SIGHASH_TYPE_HASH.pack() || hash_type != ScriptHashType::Type)
        {
            return Err(format!("when <to-cheque-address> is presented, all addresses in <udt-to> must be sighash address, invalid address: {}", addr));
        }
        if let Some(script_id) = acp_script_id.as_ref() {
            if code_hash != script_id.code_hash.pack() || hash_type != script_id.hash_type {
                return Err(format!("when <to-acp-address> is presented, all addresses in <udt-to> must be acp address, invalid address: {}", addr));
            }
        }
    }
    Ok(())
}

pub fn arg_owner<'a>() -> Arg<'a> {
    Arg::with_name("owner")
        .long("owner")
        .takes_value(true)
        .required(true)
        .validator(|input| AddressParser::new_sighash().validate(input))
        .about("The owner address of the SUDT cell (the admin address, only sighash address is supported)")
}
pub fn arg_sender<'a>() -> Arg<'a> {
    Arg::with_name("sender")
        .long("sender")
        .takes_value(true)
        .required(true)
        .validator(|input| AddressParser::default().validate(input))
        .about("Sender address")
}
pub fn arg_capacity_provider<'a>() -> Arg<'a> {
    Arg::with_name("capacity-provider")
        .long("capacity-provider")
        .takes_value(true)
        .validator(|input| AddressParser::new_sighash().validate(input))
        .about("Capacity provider address (provide transaction fee or needed capacity)")
}
pub fn arg_to_acp_address<'a>() -> Arg<'a> {
    Arg::with_name("to-acp-address")
        .long("to-acp-address")
        .about("Treat all addresses in <udt-to> as anyone-can-pay address")
}
pub fn arg_cell_deps<'a>() -> Arg<'a> {
    Arg::with_name("cell-deps")
        .long("cell-deps")
        .takes_value(true)
        .required(true)
        .validator(|input| CellDepsParser.validate(input))
        .about("The cell deps information (for resolve cell_dep by script id or build lock/type script)")
}

pub struct UdtTxBuilder<'a> {
    pub plugin_mgr: &'a mut PluginManager,
    pub rpc_client: &'a HttpRpcClient,
    pub cell_collector: &'a mut LocalCellCollector,
    pub cell_dep_resolver: &'a mut DefaultCellDepResolver,
    pub header_dep_resolver: &'a DefaultHeaderDepResolver,
    pub tx_dep_provider: &'a DefaultTransactionDependencyProvider,
    pub builder: &'a dyn TxBuilder,
    pub rce_info: Option<(H256, WitnessArgs)>,
}

impl<'a> UdtTxBuilder<'a> {
    pub fn build(
        &mut self,
        accounts: Vec<(String, H160)>,
        privkeys: Vec<PrivkeyWrapper>,
        cell_deps: &CellDeps,
        capacity_provider: Script,
        acp_script_id: Option<ScriptId>,
        cheque_script_id: Option<(ScriptId, ChequeAction)>,
        fee_rate: u64,
    ) -> Result<TransactionView, String> {
        let mut passwords: HashMap<H160, String> = HashMap::with_capacity(accounts.len());
        let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
        let mut get_signer = || -> Result<Box<dyn Signer>, String> {
            let handler = self.plugin_mgr.keystore_handler();
            let mut keystore_signer = KeyStoreHandlerSigner::new(
                handler.clone(),
                Box::new(DefaultTransactionDependencyProvider::new(
                    self.rpc_client.url(),
                    0,
                )),
            );
            let mut privkey_signer = PrivkeySigner::new(privkeys.clone());
            for (name, account) in accounts.clone() {
                if privkey_signer.has_account(&account) {
                    if cheque_script_id.is_some() {
                        let _ = privkey_signer
                            .cache_account_lock_hash160(account.clone(), &sighash_script_id);
                    }
                } else {
                    if !handler.has_account(account.clone()).unwrap_or_default() {
                        return Err(format!("no such account in keystore: {}", name));
                    }
                    let change_path = handler.root_key_path(account.clone())?;
                    if self.plugin_mgr.keystore_require_password() {
                        let password = if let Some(password) = passwords.get(&account) {
                            password.clone()
                        } else {
                            let password =
                                read_password(false, Some(format!("{} Password", name).as_str()))?;
                            passwords.insert(account.clone(), password.clone());
                            password
                        };
                        keystore_signer.set_password(account.clone(), password);
                    }
                    // for matching cheque lock script args
                    if cheque_script_id.is_some() {
                        let _ = keystore_signer
                            .cache_account_lock_hash160(account.clone(), &sighash_script_id);
                    }
                    keystore_signer.set_change_path(account, change_path.to_string());
                }
            }
            Ok(Box::new(CommonSigner::new(vec![
                Box::new(privkey_signer),
                Box::new(keystore_signer),
            ])))
        };

        let mut unlockers: HashMap<_, Box<dyn ScriptUnlocker>> = HashMap::new();
        let sighash_unlocker =
            SecpSighashUnlocker::new(SecpSighashScriptSigner::new(get_signer()?));
        unlockers.insert(sighash_script_id.clone(), Box::new(sighash_unlocker));
        if let Some(script_id) = acp_script_id {
            let acp_unlocker = AcpUnlocker::new(AcpScriptSigner::new(get_signer()?));
            unlockers.insert(script_id, Box::new(acp_unlocker));
        }
        if let Some((script_id, action)) = cheque_script_id.clone() {
            let cheque_unlocker =
                ChequeUnlocker::new(ChequeScriptSigner::new(get_signer()?, action));
            unlockers.insert(script_id, Box::new(cheque_unlocker));
        }

        let balancer = CapacityBalancer {
            fee_rate: FeeRate::from_u64(fee_rate),
            change_lock_script: None,
            capacity_provider: CapacityProvider {
                lock_scripts: vec![(
                    capacity_provider,
                    WitnessArgs::new_builder()
                        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
                        .build()
                        .as_bytes(),
                )],
            },
            force_small_change_as_fee: None,
        };

        cell_deps.apply_to_resolver(self.cell_dep_resolver)?;

        let mut base_tx = self
            .builder
            .build_base(
                self.cell_collector,
                self.cell_dep_resolver,
                self.header_dep_resolver,
                self.tx_dep_provider,
            )
            .map_err(|err| err.to_string())?;
        if let Some((rce_cell_hash, rce_witness)) = self.rce_info.as_ref() {
            let mut tx_cell_deps: Vec<_> = base_tx.cell_deps().into_iter().collect();
            let mut witnesses: Vec<_> = base_tx.witnesses().into_iter().collect();
            let rce_cell_dep = cell_deps.rce_cells.get(rce_cell_hash).ok_or_else(|| {
                format!(
                    "no rce cell_dep found for {:#x}, please check `rce_cells` of cell_deps config",
                    rce_cell_hash
                )
            })?;
            tx_cell_deps.push(rce_cell_dep.clone().into());
            if witnesses.is_empty() {
                witnesses.push(rce_witness.as_bytes().pack());
            } else {
                witnesses[0] = rce_witness.as_bytes().pack();
            }
            base_tx = base_tx
                .as_advanced_builder()
                .set_cell_deps(tx_cell_deps)
                .set_witnesses(witnesses)
                .build();
        }
        let (tx_filled_witnesses, _) =
            fill_placeholder_witnesses(base_tx, self.tx_dep_provider, &unlockers)
                .map_err(|err| err.to_string())?;
        let balanced_tx = balance_tx_capacity(
            &tx_filled_witnesses,
            &balancer,
            self.cell_collector,
            self.tx_dep_provider,
            self.cell_dep_resolver,
            self.header_dep_resolver,
        )
        .map_err(|err| err.to_string())?;

        let (tx, still_locked_groups) = unlock_tx(balanced_tx, self.tx_dep_provider, &unlockers)
            .map_err(|err| err.to_string())?;
        assert!(
            still_locked_groups.is_empty(),
            "script: {:?}, groups.len(): {}",
            still_locked_groups[0].script,
            still_locked_groups.len(),
        );
        Ok(tx)
    }
}
