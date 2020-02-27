use byteorder::{ByteOrder, LittleEndian};
use either::Either;
use itertools::Itertools;
use std::collections::HashSet;
use std::path::PathBuf;

use self::builder::DAOBuilder;
use self::command::TransactArgs;
use crate::subcommands::account::AccountId;
use crate::utils::index::IndexController;
use crate::utils::key_adapter::KeyAdapter;
use crate::utils::other::{
    get_max_mature_number, get_network_type, get_privkey_signer, is_mature, read_password,
};

use ckb_crypto::secp::SECP256K1;
use ckb_hash::new_blake2b;
use ckb_index::{with_index_db, IndexDatabase, LiveCellInfo};
use ckb_jsonrpc_types::JsonBytes;
use ckb_ledger::LedgerKeyStore;
use ckb_sdk::{
    constants::{MIN_SECP_CELL_CAPACITY, SIGHASH_TYPE_HASH},
    wallet::{AbstractKeyStore, AbstractMasterPrivKey, AbstractPrivKey, KeyStore},
    Address, AddressPayload, BoxedSignerFn, GenesisInfo, HttpRpcClient,
};
use ckb_types::{
    bytes::Bytes,
    core::{ScriptHashType, TransactionView},
    packed::{Byte32, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
    {H160, H256},
};

mod builder;
mod command;
mod util;

// Should CLI handle "immature header problem"?
pub struct DAOSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    key_store: &'a mut KeyStore,
    ledger_key_store: &'a mut LedgerKeyStore,
    genesis_info: GenesisInfo,
    index_dir: PathBuf,
    index_controller: IndexController,
}

impl<'a> DAOSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        key_store: &'a mut KeyStore,
        ledger_key_store: &'a mut LedgerKeyStore,
        genesis_info: GenesisInfo,
        index_dir: PathBuf,
        index_controller: IndexController,
    ) -> Self {
        Self {
            rpc_client,
            key_store,
            ledger_key_store,
            genesis_info,
            index_dir,
            index_controller,
        }
    }

    pub fn query_deposit_cells(&mut self, lock_hash: Byte32) -> Result<Vec<LiveCellInfo>, String> {
        let dao_cells = self.collect_dao_cells(lock_hash)?;
        assert!(dao_cells.iter().all(|cell| cell.data_bytes == 8));
        let mut ret = Vec::with_capacity(dao_cells.len());
        for cell in dao_cells {
            if is_deposit_cell(self.rpc_client(), &cell)? {
                ret.push(cell);
            }
        }
        Ok(ret)
    }

    pub fn query_prepare_cells(&mut self, lock_hash: Byte32) -> Result<Vec<LiveCellInfo>, String> {
        let dao_cells = self.collect_dao_cells(lock_hash)?;
        assert!(dao_cells.iter().all(|cell| cell.data_bytes == 8));
        let mut ret = Vec::with_capacity(dao_cells.len());
        for cell in dao_cells {
            if is_prepare_cell(self.rpc_client(), &cell)? {
                ret.push(cell);
            }
        }
        Ok(ret)
    }

    fn collect_dao_cells(&mut self, lock_hash: Byte32) -> Result<Vec<LiveCellInfo>, String> {
        let dao_type_hash = self.dao_type_hash().clone();
        self.with_db(|db, _| {
            let cells_by_lock = db
                .get_live_cells_by_lock(lock_hash, Some(0), |_, _| (false, true))
                .into_iter()
                .collect::<HashSet<_>>();
            let cells_by_code = db
                .get_live_cells_by_code(dao_type_hash.clone(), Some(0), |_, _| (false, true))
                .into_iter()
                .collect::<HashSet<_>>();
            cells_by_lock
                .intersection(&cells_by_code)
                .sorted_by_key(|live| (live.number, live.tx_index, live.index.output_index))
                .cloned()
                .collect::<Vec<_>>()
        })
    }

    fn check_db_ready(&mut self) -> Result<(), String> {
        self.with_db(|_, _| ())
    }

    fn with_db<F, T>(&mut self, func: F) -> Result<T, String>
    where
        F: FnOnce(IndexDatabase, &mut HttpRpcClient) -> T,
    {
        let network_type = get_network_type(self.rpc_client)?;
        let genesis_info = self.genesis_info.clone();
        let genesis_hash: H256 = genesis_info.header().hash().unpack();
        with_index_db(&self.index_dir.clone(), genesis_hash, |backend, cf| {
            let db = IndexDatabase::from_db(backend, cf, network_type, genesis_info, false)?;
            Ok(func(db, self.rpc_client()))
        })
        .map_err(|_err| {
            format!(
                "Index database may not ready, sync process: {}",
                self.index_controller.state().read().to_string()
            )
        })
    }

    fn dao_type_hash(&self) -> &Byte32 {
        self.genesis_info.dao_type_hash()
    }

    pub(crate) fn rpc_client(&mut self) -> &mut HttpRpcClient {
        &mut self.rpc_client
    }

    fn with_transact_args<'b>(
        &'b mut self,
        transact_args: TransactArgs,
    ) -> Result<WithTransactArgs<'a, 'b>, String> {
        WithTransactArgs::from_subcommand(self, transact_args)
    }
}

struct WithTransactArgs<'a, 'b> {
    dao: &'b mut DAOSubCommand<'a>,
    transact_args: TransactArgs,
    address_payload: AddressPayload,
    key_cap: Box<dyn AbstractPrivKey<Err = String>>,
}

impl<'a, 'b> WithTransactArgs<'a, 'b> {
    fn from_subcommand(
        dao: &'b mut DAOSubCommand<'a>,
        transact_args: TransactArgs,
    ) -> Result<Self, String> {
        let (address_payload, key_cap): (AddressPayload, Box<dyn AbstractPrivKey<Err = String>>) =
            match transact_args.account {
                Either::Left(ref from_privkey) => {
                    let from_pubkey =
                        secp256k1::PublicKey::from_secret_key(&SECP256K1, from_privkey);
                    (
                        AddressPayload::from_pubkey(&from_pubkey),
                        Box::new(KeyAdapter(from_privkey.clone())),
                    )
                }
                Either::Right(AccountId::SoftwareMasterKey(ref hash160)) => {
                    let password = read_password(false, None)?;
                    (
                        AddressPayload::from_pubkey_hash(hash160.clone()),
                        KeyAdapter(
                            dao.key_store
                                .get_key(&hash160, password.as_bytes())
                                .map_err(|e| e.to_string())?,
                        )
                        .extended_privkey(transact_args.path.as_ref())?,
                    )
                }
                Either::Right(AccountId::LedgerId(ref ledger_id)) => {
                    let master = dao
                        .ledger_key_store
                        .borrow_account(&ledger_id)
                        .map_err(|e| e.to_string())?
                        .clone();
                    let derived_priv = master
                        .extended_privkey(transact_args.path.as_ref())
                        .map_err(|e| e.to_string())?;
                    let derived_pub = master
                        .extended_pubkey(transact_args.path.as_ref())
                        .map_err(|e| e.to_string())?;
                    (
                        AddressPayload::from_pubkey(&derived_pub.public_key),
                        Box::new(KeyAdapter(derived_priv)),
                    )
                }
            };
        assert_eq!(address_payload.code_hash(), SIGHASH_TYPE_HASH.pack());
        Ok(Self {
            dao,
            transact_args,
            address_payload,
            key_cap,
        })
    }

    pub(crate) fn sighash_args(&self) -> H160 {
        H160::from_slice(self.address_payload.args().as_ref()).unwrap()
    }

    pub(crate) fn lock_hash(&self) -> Byte32 {
        Script::from(&self.address_payload).calc_script_hash()
    }

    pub fn deposit(&mut self, capacity: u64) -> Result<TransactionView, String> {
        self.dao.check_db_ready()?;
        let target_capacity = capacity + self.transact_args.tx_fee;
        let cells = self.collect_sighash_cells(target_capacity)?;
        let raw_transaction = self.build(cells).deposit(capacity)?;
        self.sign(raw_transaction)
    }

    pub fn prepare(&mut self, out_points: Vec<OutPoint>) -> Result<TransactionView, String> {
        self.dao.check_db_ready()?;
        let tx_fee = self.transact_args.tx_fee;
        let lock_hash = self.lock_hash();
        let cells = {
            let mut to_pay_fee = self.collect_sighash_cells(tx_fee)?;
            let mut to_prepare = {
                let deposit_cells = self.dao.query_deposit_cells(lock_hash)?;
                take_by_out_points(deposit_cells, &out_points)?
            };
            to_prepare.append(&mut to_pay_fee);
            to_prepare
        };
        let raw_transaction = self.build(cells).prepare(self.dao.rpc_client())?;
        self.sign(raw_transaction)
    }

    pub fn withdraw(&mut self, out_points: Vec<OutPoint>) -> Result<TransactionView, String> {
        self.dao.check_db_ready()?;
        let lock_hash = self.lock_hash();
        let cells = {
            let prepare_cells = self.dao.query_prepare_cells(lock_hash)?;
            take_by_out_points(prepare_cells, &out_points)?
        };
        let raw_transaction = self.build(cells).withdraw(self.dao.rpc_client())?;
        self.sign(raw_transaction)
    }

    fn collect_sighash_cells(&mut self, target_capacity: u64) -> Result<Vec<LiveCellInfo>, String> {
        let mut enough = false;
        let mut take_capacity = 0;
        let max_mature_number = get_max_mature_number(self.dao.rpc_client())?;
        let terminator = |_, cell: &LiveCellInfo| {
            if !(cell.type_hashes.is_none() && cell.data_bytes == 0)
                && is_mature(cell, max_mature_number)
            {
                return (false, false);
            }

            take_capacity += cell.capacity;
            if take_capacity == target_capacity
                || take_capacity >= target_capacity + MIN_SECP_CELL_CAPACITY
            {
                enough = true;
            }
            (enough, true)
        };

        let cells: Vec<LiveCellInfo> = {
            let lock_hash = self.lock_hash();
            self.dao
                .with_db(|db, _| db.get_live_cells_by_lock(lock_hash, None, terminator))?
        };

        if !enough {
            return Err(format!(
                "Capacity not enough: {} => {}",
                Address::new(
                    self.transact_args.network_type,
                    self.address_payload.clone()
                ),
                take_capacity,
            ));
        }
        Ok(cells)
    }

    fn build(&self, cells: Vec<LiveCellInfo>) -> DAOBuilder {
        let tx_fee = self.transact_args.tx_fee;
        DAOBuilder::new(self.dao.genesis_info.clone(), tx_fee, cells)
    }

    fn sign(&mut self, transaction: TransactionView) -> Result<TransactionView, String> {
        // 1. Install sighash lock script
        let transaction = self.install_sighash_lock(transaction);

        // 2. Install signed sighash witnesses
        let transaction = self.install_sighash_witness(transaction)?;

        Ok(transaction)
    }

    fn install_sighash_lock(&self, transaction: TransactionView) -> TransactionView {
        let sighash_args = self.sighash_args();
        let genesis_info = &self.dao.genesis_info;
        let sighash_dep = genesis_info.sighash_dep();
        let sighash_type_hash = genesis_info.sighash_type_hash();
        let lock_script = Script::new_builder()
            .hash_type(ScriptHashType::Type.into())
            .code_hash(sighash_type_hash.clone())
            .args(Bytes::from(sighash_args.as_bytes()).pack())
            .build();
        let outputs = transaction
            .outputs()
            .into_iter()
            .map(|output: CellOutput| output.as_builder().lock(lock_script.clone()).build())
            .collect::<Vec<_>>();
        transaction
            .as_advanced_builder()
            .set_outputs(outputs)
            .cell_dep(sighash_dep)
            .build()
    }

    fn install_sighash_witness(
        &self,
        transaction: TransactionView,
    ) -> Result<TransactionView, String> {
        for output in transaction.outputs() {
            assert_eq!(output.lock().hash_type(), ScriptHashType::Type.into());
            assert_eq!(output.lock().args().len(), 20);
            assert_eq!(output.lock().code_hash(), SIGHASH_TYPE_HASH.pack());
        }
        for witness in transaction.witnesses() {
            if let Ok(w) = WitnessArgs::from_slice(witness.as_slice()) {
                assert!(w.lock().is_none());
            }
        }

        let mut witnesses = transaction
            .witnesses()
            .into_iter()
            .map(|w| w.unpack())
            .collect::<Vec<Bytes>>();
        let init_witness = {
            let init_witness = if witnesses[0].is_empty() {
                WitnessArgs::default()
            } else {
                WitnessArgs::from_slice(&witnesses[0]).map_err(|err| err.to_string())?
            };
            init_witness
                .as_builder()
                .lock(Some(Bytes::from(&[0u8; 65][..])).pack())
                .build()
        };
        let digest = {
            let mut blake2b = new_blake2b();
            blake2b.update(&transaction.hash().raw_data());
            blake2b.update(&(init_witness.as_bytes().len() as u64).to_le_bytes());
            blake2b.update(&init_witness.as_bytes());
            for other_witness in witnesses.iter().skip(1) {
                blake2b.update(&(other_witness.len() as u64).to_le_bytes());
                blake2b.update(&other_witness);
            }
            let mut message = [0u8; 32];
            blake2b.finalize(&mut message);
            H256::from(message)
        };
        let signature = {
            let account = self.sighash_args();
            let mut signer: BoxedSignerFn = Box::new(get_privkey_signer(&self.key_cap)?);
            let accounts = vec![account].into_iter().collect::<HashSet<H160>>();
            signer(&accounts, &digest)?.expect("signer missed")
        };

        witnesses[0] = init_witness
            .as_builder()
            .lock(Some(Bytes::from(&signature[..])).pack())
            .build()
            .as_bytes();

        Ok(transaction
            .as_advanced_builder()
            .set_witnesses(witnesses.into_iter().map(|w| w.pack()).collect::<Vec<_>>())
            .build())
    }
}

fn take_by_out_points(
    cells: Vec<LiveCellInfo>,
    out_points: &[OutPoint],
) -> Result<Vec<LiveCellInfo>, String> {
    let mut set = out_points.iter().collect::<HashSet<_>>();
    let takes = cells
        .into_iter()
        .filter(|cell| set.remove(&cell.out_point()))
        .collect::<Vec<_>>();
    if !set.is_empty() {
        return Err(format!("cells are not found: {:?}", set));
    }
    Ok(takes)
}

fn is_deposit_cell(
    rpc_client: &mut HttpRpcClient,
    dao_cell: &LiveCellInfo,
) -> Result<bool, String> {
    get_cell_data(rpc_client, dao_cell)
        .map(|content| LittleEndian::read_u64(&content.as_bytes()[0..8]) == 0)
}

fn is_prepare_cell(
    rpc_client: &mut HttpRpcClient,
    dao_cell: &LiveCellInfo,
) -> Result<bool, String> {
    get_cell_data(rpc_client, dao_cell)
        .map(|content| LittleEndian::read_u64(&content.as_bytes()[0..8]) != 0)
}

fn get_cell_data(
    rpc_client: &mut HttpRpcClient,
    dao_cell: &LiveCellInfo,
) -> Result<JsonBytes, String> {
    let cell_info = rpc_client
        .get_live_cell(dao_cell.out_point(), true)?
        .cell
        .ok_or_else(|| format!("cell is not found: {:?}", dao_cell.out_point()))?;
    Ok(cell_info.data.unwrap().content)
}
