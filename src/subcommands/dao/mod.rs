use std::collections::HashMap;

use byteorder::{ByteOrder, LittleEndian};

use ckb_sdk::{
    constants::{DAO_TYPE_HASH, SIGHASH_TYPE_HASH},
    traits::{
        default_impls::{
            DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
            DefaultTransactionDependencyProvider,
        },
        CellCollector, CellQueryOptions, Signer, ValueRangeOption,
    },
    tx_builder::{
        dao::{
            DaoDepositBuilder, DaoDepositReceiver, DaoPrepareBuilder, DaoPrepareItem,
            DaoWithdrawBuilder, DaoWithdrawItem, DaoWithdrawReceiver,
        },
        CapacityBalancer, CapacityProvider, TxBuilder,
    },
    types::ScriptId,
    unlock::{ScriptUnlocker, SecpSighashScriptSigner, SecpSighashUnlocker},
};
use ckb_types::{
    bytes::Bytes,
    core::{FeeRate, ScriptHashType, TransactionView},
    packed::{CellInput, OutPoint, Script, WitnessArgs},
    prelude::*,
    H160,
};
use plugin_protocol::LiveCellInfo;

use self::command::TransactArgs;
use crate::{
    plugin::PluginManager,
    utils::{
        genesis_info::GenesisInfo,
        other::{map_tx_builder_error_2_str, read_password, to_live_cell_info},
        rpc::HttpRpcClient,
        signer::KeyStoreHandlerSigner,
    },
};

mod command;
mod util;

// Should CLI handle "immature header problem"?
pub struct DAOSubCommand<'a> {
    plugin_mgr: &'a mut PluginManager,
    rpc_client: &'a mut HttpRpcClient,
    cell_collector: DefaultCellCollector,
    cell_dep_resolver: DefaultCellDepResolver,
    header_dep_resolver: DefaultHeaderDepResolver,
    tx_dep_provider: DefaultTransactionDependencyProvider,
}

impl<'a> DAOSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        plugin_mgr: &'a mut PluginManager,
        genesis_info: GenesisInfo,
    ) -> Self {
        let tx_dep_provider = DefaultTransactionDependencyProvider::new(rpc_client.url(), 10);
        let cell_collector = DefaultCellCollector::new(rpc_client.url());
        let cell_dep_resolver = genesis_info.cell_dep_resolver;
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

    fn build_tx(
        &mut self,
        builder: &dyn TxBuilder,
        args: &TransactArgs,
    ) -> Result<TransactionView, String> {
        let lock_script: Script = args.address.payload().into();
        let balancer = CapacityBalancer {
            fee_rate: FeeRate::from_u64(args.fee_rate),
            change_lock_script: None,
            capacity_provider: CapacityProvider::new_simple(vec![(
                lock_script.clone(),
                WitnessArgs::new_builder()
                    .lock(Some(Bytes::from(vec![0u8; 65])).pack())
                    .build(),
            )]),
            force_small_change_as_fee: args.force_small_change_as_fee,
        };

        let signer: Box<dyn Signer> = if let Some(privkey) = args.privkey.as_ref() {
            Box::new(privkey.clone())
        } else {
            let account =
                H160::from_slice(lock_script.args().raw_data().as_ref()).expect("lock args");
            let handler = self.plugin_mgr.keystore_handler();
            let change_path = handler.root_key_path(account.clone())?;
            let mut signer = KeyStoreHandlerSigner::new(
                handler,
                Box::new(DefaultTransactionDependencyProvider::new(
                    self.rpc_client.url(),
                    0,
                )),
            );
            if self.plugin_mgr.keystore_require_password() {
                signer.set_password(account.clone(), read_password(false, None)?);
            }
            signer.set_change_path(account, change_path.to_string());
            Box::new(signer)
        };

        let script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
        let sighash_unlocker = SecpSighashUnlocker::new(SecpSighashScriptSigner::new(signer));
        let mut unlockers: HashMap<_, Box<dyn ScriptUnlocker>> = HashMap::new();
        unlockers.insert(script_id, Box::new(sighash_unlocker));

        let (tx, still_locked_groups) = builder
            .build_unlocked(
                &mut self.cell_collector,
                &self.cell_dep_resolver,
                &self.header_dep_resolver,
                &self.tx_dep_provider,
                &balancer,
                &unlockers,
            )
            .map_err(|err| {
                map_tx_builder_error_2_str(balancer.force_small_change_as_fee.is_none(), err)
            })?;
        assert!(still_locked_groups.is_empty());
        Ok(tx)
    }

    pub fn deposit(
        &mut self,
        args: &TransactArgs,
        capacity: u64,
    ) -> Result<TransactionView, String> {
        let lock_script: Script = args.address.payload().into();
        let deposit_receiver = DaoDepositReceiver::new(lock_script, capacity);
        let tx_builder = DaoDepositBuilder::new(vec![deposit_receiver]);
        self.build_tx(&tx_builder, args)
    }

    pub fn prepare(
        &mut self,
        args: &TransactArgs,
        out_points: Vec<OutPoint>,
    ) -> Result<TransactionView, String> {
        let items = out_points
            .into_iter()
            .map(|out_point| DaoPrepareItem::from(CellInput::new(out_point, 0)))
            .collect::<Vec<_>>();
        let tx_builder = DaoPrepareBuilder::new(items);
        self.build_tx(&tx_builder, args)
    }

    pub fn withdraw(
        &mut self,
        args: &TransactArgs,
        out_points: Vec<OutPoint>,
    ) -> Result<TransactionView, String> {
        if out_points.is_empty() {
            return Err("missing out poinst".to_string());
        }
        let lock_script: Script = args.address.payload().into();
        let mut items = out_points
            .into_iter()
            .map(|out_point| DaoWithdrawItem::new(out_point, None))
            .collect::<Vec<_>>();
        items[0].init_witness = Some(
            WitnessArgs::new_builder()
                .lock(Some(Bytes::from(vec![0u8; 65])).pack())
                .build(),
        );
        let receiver = DaoWithdrawReceiver::LockScript {
            script: lock_script,
            fee_rate: Some(FeeRate::from_u64(args.fee_rate)),
        };

        let tx_builder = DaoWithdrawBuilder::new(items, receiver);
        self.build_tx(&tx_builder, args)
    }

    fn query_dao_cells(
        &mut self,
        lock: Script,
        is_deposit: bool,
    ) -> Result<Vec<LiveCellInfo>, String> {
        let dao_type_script = Script::new_builder()
            .code_hash(DAO_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .build();
        let mut query = CellQueryOptions::new_lock(lock);
        query.secondary_script = Some(dao_type_script);
        query.data_len_range = Some(ValueRangeOption::new_exact(8));
        query.min_total_capacity = u64::max_value();
        let (cells, _) = self
            .cell_collector
            .collect_live_cells(&query, false)
            .map_err(|err| err.to_string())?;
        let cell_filter = if is_deposit {
            |block_number| block_number == 0
        } else {
            |block_number| block_number != 0
        };
        Ok(cells
            .iter()
            .filter(|cell| cell_filter(LittleEndian::read_u64(&cell.output_data.as_ref()[0..8])))
            .map(to_live_cell_info)
            .collect::<Vec<_>>())
    }

    pub fn query_deposit_cells(&mut self, lock: Script) -> Result<Vec<LiveCellInfo>, String> {
        self.query_dao_cells(lock, true)
    }

    pub fn query_prepare_cells(&mut self, lock: Script) -> Result<Vec<LiveCellInfo>, String> {
        self.query_dao_cells(lock, false)
    }
}
