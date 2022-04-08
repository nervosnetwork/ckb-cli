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
        CellCollector, CellQueryOptions, Signer,
    },
    tx_builder::{
        cheque::{ChequeClaimBuilder, ChequeWithdrawBuilder},
        transfer::CapacityTransferBuilder,
        udt::{UdtIssueBuilder, UdtIssueType, UdtTargetReceiver, UdtTransferBuilder},
        CapacityBalancer, CapacityProvider, TransferAction, TxBuilder,
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
    packed::{CellInput, CellOutput, Script, WitnessArgs},
    prelude::*,
    H160, H256,
};

use crate::plugin::PluginManager;
use crate::subcommands::{CliSubCommand, Output};
use crate::utils::{
    arg,
    arg_parser::{AddressParser, ArgParser, CellDepsParser, FromStrParser, UdtTargetParser},
    cell_collector::LocalCellCollector,
    cell_dep::{CellDepName, CellDeps},
    index::IndexController,
    other::{get_network_type, read_password},
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

    pub fn subcommand(name: &'static str) -> App<'static> {
        let arg_owner = Arg::with_name("owner")
            .long("owner")
            .takes_value(true)
            .required(true)
            .validator(|input| AddressParser::new_sighash().validate(input))
            .about("The owner address of the SUDT cell (the admin address, only sighash address is supported)");
        let arg_udt_to = Arg::with_name("udt-to")
            .long("udt-to")
            .takes_value(true)
            .multiple(true)
            .required(true)
            .validator(|input| UdtTargetParser::new(AddressParser::default()).validate(input));
        let arg_capacity_provider = Arg::with_name("capacity-provider")
            .long("capacity-provider")
            .takes_value(true)
            .validator(|input| AddressParser::new_sighash().validate(input))
            .about("Capacity provider address (provide transaction fee or needed capacity)");
        let arg_sender = Arg::with_name("sender")
            .long("sender")
            .takes_value(true)
            .validator(|input| AddressParser::default().validate(input))
            .about("Sender address");
        let arg_receiver = Arg::with_name("receiver")
            .long("receiver")
            .takes_value(true)
            .validator(|input| AddressParser::new_sighash().validate(input));
        let arg_cell_deps = Arg::with_name("cell-deps")
            .long("cell-deps")
            .takes_value(true)
            .required(true)
            .validator(|input| CellDepsParser.validate(input))
            .about("The cell deps information (for resolve cell_dep by script id or build lock/type script)");
        let arg_to_cheque_address = Arg::with_name("to-cheque-address").long("to-cheque-address");
        let arg_to_acp_address = Arg::with_name("to-acp-address")
            .long("to-acp-address")
            .about("Treat all addresses in <udt-to> as anyone-can-pay address");
        App::new(name)
            .about("SUDT issue/transfer and cheque claim/withdraw operations")
            .subcommands(vec![
                App::new("issue")
                    .about("Issue SUDT to multiple addresses")
                    .arg(arg_owner.clone())
                    .arg(
                        arg_udt_to.clone()
                            .about("The issue target, format: {address}:{amount}, the address type can be: [acp, sighash]")
                    )
                    .arg(arg_cell_deps.clone())
                    .arg(arg_to_acp_address.clone())
                    .arg(
                        arg_to_cheque_address
                            .clone()
                            .about("Treat all addresses in <udt-to> as cheque receiver (sighash address, and the cheque sender is the <owner>), otherwise the address will be used as the lock script of the SUDT cell")
                    )
                    .arg(arg::fee_rate()),
                App::new("transfer")
                    .about("Transfer SUDT to multiple addresses (all target addresses must have same lock script id)")
                    .arg(arg_owner.clone())
                    .arg(arg_sender.clone().required(true).about("SUDT sender address, the address type can be: [acp, sighash], if <capacity-provider> is not given <sender> will also use as capacity provider."))
                    .arg(
                        arg_udt_to
                         .about("The transfer target, format: {address}:{amount}, the address type can be: [acp, sighash]")
                    )
                    .arg(arg_cell_deps.clone())
                    .arg(arg_to_acp_address.clone())
                    .arg(
                        arg_to_cheque_address
                            .clone()
                            .about("Treat all addresses in <udt-to> as cheque receiver (sighash address), otherwise the address will be used as the lock script of the SUDT cell. When this flag is presented <cheque> cell_dep must be given")
                    )
                    .arg(arg_capacity_provider.clone())
                    .arg(arg::fee_rate()),
                App::new("get-amount")
                    .about("Get SUDT total amount of an address")
                    .arg(arg_owner.clone())
                    .arg(arg_cell_deps.clone())
                    .arg(
                        Arg::with_name("address")
                            .long("address")
                            .takes_value(true)
                            .required(true)
                            .validator(|input| AddressParser::default().validate(input))
                            .about("The target address of those SUDT cells"),
                    ),
                App::new("new-empty-acp")
                    .about("Create a SUDT cell with 0 amount and an acp lock script")
                    .arg(arg_owner.clone())
                    .arg(arg_capacity_provider.clone())
                    .arg(
                        Arg::with_name("to")
                            .long("to")
                            .takes_value(true)
                            .required(true)
                            .validator(|input| AddressParser::new_sighash().validate(input))
                            .about("The target address (sighash), used to create anyone-can-pay address, if <capacity-provider> is not given <to> will also use as capacity provider"),
                    )
                    .arg(arg_cell_deps.clone())
                    .arg(arg::fee_rate()),
                App::new("cheque-claim")
                    .about("Claim all cheque cells identified by given lock script and type script")
                    .arg(arg_owner.clone())
                    .arg(arg_sender.clone().required(true).about("The cheque sender address (sighash)"))
                    .arg(
                        arg_receiver
                            .clone()
                            .required(true)
                            .about("The cheque receiver address (sighash), for searching an input to save the claimed amount, this address will be used to build anyone-can-pay address, if <capacity-provider> not given <receiver> will also be used as capacity provider")
                    )
                    .arg(arg_capacity_provider.clone())
                    .arg(arg_cell_deps.clone())
                    .arg(arg::fee_rate()),
                App::new("cheque-withdraw")
                    .about("Withdraw all cheque cells identified by given lock script and type script")
                    .arg(arg_owner)
                    .arg(arg_sender.about("The cheque sender address (sighash), if <capacity-provider> not given <sender> will use as capacity provider"))
                    .arg(arg_receiver.about("The cheque receiver address (sighash)"))
                    .arg(arg_capacity_provider)
                    .arg(arg_to_acp_address.about("Withdraw to anyone-can-pay address, will use <sender> to build the anyone-can-pay address, the cell must be already exists"))
                    .arg(arg_cell_deps.clone())
                    .arg(arg::fee_rate()),
                // TODO: move this subcommand to `util`
                App::new("build-acp-address")
                    .about("Build an anyone-can-pay address by sighash address and anyone-can-pay script id.")
                    .arg(arg_cell_deps.clone())
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
                    .arg(arg_cell_deps.clone())
                    .arg(
                        Arg::with_name("receiver")
                            .long("receiver")
                            .takes_value(true)
                            .required(true)
                            .validator(|input| AddressParser::default().validate(input))
                            .about("The receiver address")
                    )
                    .arg(
                        Arg::with_name("sender")
                            .long("sender")
                            .takes_value(true)
                            .required(true)
                            .validator(|input| AddressParser::default().validate(input))
                            .about("The sender address")
                    ),
            ])
    }

    fn build_tx(
        &mut self,
        builder: &dyn TxBuilder,
        accounts: Vec<(String, H160)>,
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
            let mut signer = KeyStoreHandlerSigner::new(
                handler.clone(),
                Box::new(DefaultTransactionDependencyProvider::new(
                    self.rpc_client.url(),
                    0,
                )),
            );
            for (name, account) in accounts.clone() {
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
                    signer.set_password(account.clone(), password);
                }
                // for matching cheque lock script args
                if cheque_script_id.is_some() {
                    signer.cache_account_lock_hash160(account.clone(), &sighash_script_id);
                }
                signer.set_change_path(account, change_path.to_string());
            }
            Ok(Box::new(signer))
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
                        .build(),
                )],
            },
            force_small_change_as_fee: None,
        };

        cell_deps.apply_to_resolver(&mut self.cell_dep_resolver)?;

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
        assert!(
            still_locked_groups.is_empty(),
            "script: {:?}, groups.len(): {}",
            still_locked_groups[0].script,
            still_locked_groups.len(),
        );
        Ok(tx)
    }

    fn issue(
        &mut self,
        owner: Address,
        udt_to_vec: Vec<(Address, u128)>,
        to_cheque_address: bool,
        to_acp_address: bool,
        cell_deps: CellDeps,
        fee_rate: u64,
        network: NetworkType,
        debug: bool,
    ) -> Result<Output, String> {
        let udt_script_id = get_script_id(&cell_deps, CellDepName::Sudt)?;
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
                    extra_data: None,
                }
            })
            .collect::<Vec<_>>();
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
            udt_type: UdtIssueType::Sudt,
            script_id: udt_script_id,
            owner: owner_script.clone(),
            receivers,
        };
        let tx = self.build_tx(
            &builder,
            vec![("owner".to_string(), owner_account)],
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
        sender: Address,
        udt_to_vec: Vec<(Address, u128)>,
        to_cheque_address: bool,
        to_acp_address: bool,
        capacity_provider: Option<Address>,
        cell_deps: CellDeps,
        fee_rate: u64,
        network: NetworkType,
        debug: bool,
    ) -> Result<Output, String> {
        let udt_script_id = get_script_id(&cell_deps, CellDepName::Sudt)?;
        let acp_script_id = get_script_id(&cell_deps, CellDepName::Acp)?;
        let cheque_script_id = if to_cheque_address {
            Some(get_script_id(&cell_deps, CellDepName::Cheque)?)
        } else {
            None
        };

        let owner_script_hash = Script::from(&owner).calc_script_hash();
        let sender_account = H160::from_slice(&sender.payload().args().as_ref()[0..20]).unwrap();
        let type_script = Script::new_builder()
            .code_hash(udt_script_id.code_hash.pack())
            .hash_type(udt_script_id.hash_type.into())
            .args(owner_script_hash.as_bytes().pack())
            .build();
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
                    extra_data: None,
                }
            })
            .collect::<Vec<_>>();
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
        let sender_script = Script::from(&sender);
        let builder = UdtTransferBuilder {
            type_script,
            sender: sender_script,
            receivers,
        };
        let tx = self.build_tx(
            &builder,
            accounts,
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
        address: Address,
        cell_deps: CellDeps,
    ) -> Result<Output, String> {
        let udt_script_id = get_script_id(&cell_deps, CellDepName::Sudt)?;
        let owner_script_hash = Script::from(&owner).calc_script_hash();
        let type_script = Script::new_builder()
            .code_hash(udt_script_id.code_hash.pack())
            .hash_type(udt_script_id.hash_type.into())
            .args(owner_script_hash.as_bytes().pack())
            .build();
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
        to: Address,
        capacity_provider: Option<Address>,
        cell_deps: CellDeps,
        fee_rate: u64,
        network: NetworkType,
        debug: bool,
    ) -> Result<Output, String> {
        let udt_script_id = get_script_id(&cell_deps, CellDepName::Sudt)?;
        let acp_script_id = get_script_id(&cell_deps, CellDepName::Acp)?;
        let owner_lock_hash = Script::from(&owner).calc_script_hash();
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

        let type_script = Script::new_builder()
            .code_hash(udt_script_id.code_hash.pack())
            .hash_type(udt_script_id.hash_type.into())
            .args(owner_lock_hash.as_bytes().pack())
            .build();
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
        let output_data = Bytes::from(0u128.to_le_bytes().to_vec());
        let builder = CapacityTransferBuilder::new(vec![(output, output_data)]);

        let tx = self.build_tx(
            &builder,
            vec![("capacity provider".to_string(), capacity_provider_account)],
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

    fn cheque_claim(
        &mut self,
        owner: Address,
        sender: Address,
        receiver: Address,
        capacity_provider: Option<Address>,
        cell_deps: CellDeps,
        fee_rate: u64,
        debug: bool,
    ) -> Result<Output, String> {
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
        let tx = self.build_tx(
            &builder,
            accounts,
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
        owner: Address,
        sender: Address,
        receiver: Address,
        capacity_provider: Option<Address>,
        to_acp_address: bool,
        cell_deps: CellDeps,
        fee_rate: u64,
        debug: bool,
    ) -> Result<Output, String> {
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
        let tx = self.build_tx(
            &builder,
            accounts,
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
            ("issue", Some(m)) => {
                let owner: Address = AddressParser::new_sighash()
                    .set_network(network)
                    .from_matches(m, "owner")?;
                let udt_to_vec: Vec<(Address, u128)> = {
                    let mut address_parser = AddressParser::default();
                    address_parser.set_network(network);
                    UdtTargetParser::new(address_parser).from_matches_vec(m, "udt-to")?
                };
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
                    udt_to_vec,
                    to_cheque_address,
                    to_acp_address,
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
                    sender,
                    udt_to_vec,
                    to_cheque_address,
                    to_acp_address,
                    capacity_provider,
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
                let cell_deps: CellDeps = CellDepsParser.from_matches(m, "cell-deps")?;
                let address: Address = AddressParser::default()
                    .set_network(network)
                    .from_matches(m, "address")?;
                self.get_amount(owner, address, cell_deps)
            }
            ("new-empty-acp", Some(m)) => {
                let owner: Address = AddressParser::default()
                    .set_network(network)
                    .from_matches(m, "owner")?;
                let to: Address = AddressParser::new_sighash()
                    .set_network(network)
                    .from_matches(m, "to")?;
                let capacity_provider: Option<Address> = AddressParser::new_sighash()
                    .set_network(network)
                    .from_matches_opt(m, "capacity-provider")?;
                let cell_deps: CellDeps = CellDepsParser.from_matches(m, "cell-deps")?;
                let fee_rate: u64 = FromStrParser::<u64>::default().from_matches(m, "fee-rate")?;
                self.new_empty_acp(
                    owner,
                    to,
                    capacity_provider,
                    cell_deps,
                    fee_rate,
                    network,
                    debug,
                )
            }
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
                let cell_deps: CellDeps = CellDepsParser.from_matches(m, "cell-deps")?;
                let fee_rate: u64 = FromStrParser::<u64>::default().from_matches(m, "fee-rate")?;

                if capacity_provider.as_ref() == Some(&sender) {
                    return Err("<capacity-provider> can't be the same with <sender>".to_string());
                }
                self.cheque_claim(
                    owner,
                    sender,
                    receiver,
                    capacity_provider,
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
                let cell_deps: CellDeps = CellDepsParser.from_matches(m, "cell-deps")?;
                let fee_rate: u64 = FromStrParser::<u64>::default().from_matches(m, "fee-rate")?;
                self.cheque_withdraw(
                    owner,
                    sender,
                    receiver,
                    capacity_provider,
                    to_acp_address,
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

fn get_script_id(cell_deps: &CellDeps, name: CellDepName) -> Result<ScriptId, String> {
    cell_deps
        .get_item(name)
        .map(|item| item.script_id.clone().into())
        .ok_or_else(|| format!("no {} cell_dep item in cell_deps", name))
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
