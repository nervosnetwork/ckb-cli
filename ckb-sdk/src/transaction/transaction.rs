
use rocksdb::{DB, ColumnFamily, Options, IteratorMode};
use numext_fixed_hash::H256;
use ckb_core::{
    Cycle,
    transaction::{
        Witness,
        Transaction as CoreTransaction,
        TransactionBuilder as CoreTransactionBuilder,
    },
};

use crate::{ROCKSDB_COL_TX};

pub struct TransactionManager<'a> {
    cf: ColumnFamily<'a>,
    db: &'a DB,
}

impl<'a> TransactionManager<'a> {
    pub fn new(db: &'a DB) -> TransactionManager {
        let cf =
            db.cf_handle(ROCKSDB_COL_TX)
            .unwrap_or_else(||{
                db.create_cf(ROCKSDB_COL_TX, &Options::default())
                    .expect(&format!("Create ColumnFamily {} failed", ROCKSDB_COL_TX))
            });
        TransactionManager { cf, db }
    }

    pub fn add(&self, tx: &CoreTransaction) -> Result<(), String> {
        if tx.inputs().len() != tx.witnesses().len() {
            return Err(format!(
                "Invalid witnesses length: {}, expected: {}",
                tx.witnesses().len(),
                tx.inputs().len(),
            ));
        }
        // TODO: check all deps can be found
        // TODO: check all inputs can be found
        // TODO: check all output can be found
        let key_bytes = tx.hash().to_vec();
        let value_bytes = bincode::serialize(tx).unwrap();
        self.db.put_cf(self.cf, key_bytes, value_bytes)?;
        Ok(())
    }

    pub fn set_witness(
        &self,
        hash: &H256,
        input_index: usize,
        witness: Witness,
    ) -> Result<CoreTransaction, String> {
        let tx = self.get(hash)?;
        if input_index >= tx.inputs().len() {
            return Err(format!("input index out of bound"));
        }
        let mut witnesses = tx.witnesses().to_vec();
        witnesses[input_index] = witness;
        let tx_new = CoreTransactionBuilder::from_transaction(tx)
            .witnesses(witnesses)
            .build();
        assert_eq!(hash, tx_new.hash(), "Transaction hash must not changed just update witness");
        self.add(&tx_new)?;
        Ok(tx_new)
    }

    // TODO: set witnesses by saved secp256k1 private keys
    pub fn set_witnesses_by_keys(&self, hash: &H256) -> Result<CoreTransaction, String> {
        let tx = self.get(hash)?;
        Ok(tx)
    }

    pub fn remove(&self, hash: &H256) -> Result<(), String> {
        if self.db.get_cf(self.cf, hash.as_bytes())?.is_some() {
            self.db.delete_cf(self.cf, hash.as_bytes())?;
            Ok(())
        } else {
            Err("key not exists".to_owned())
        }
    }

    pub fn get(&self, hash: &H256) -> Result<CoreTransaction, String> {
        match self.db.get_cf(self.cf, hash.as_bytes())? {
            Some(db_vec) => Ok(bincode::deserialize(&db_vec).unwrap()),
            None => Err("key not found".to_owned())
        }
    }

    pub fn list(&self) -> Result<Vec<CoreTransaction>, String> {
        let mut txs = Vec::new();
        for (key_bytes, value_bytes) in self.db.iterator_cf(self.cf, IteratorMode::Start)? {
            let key = H256::from_slice(&key_bytes).unwrap();
            let tx: CoreTransaction = bincode::deserialize(&value_bytes).unwrap();
            assert_eq!(&key, tx.hash(), "Transaction hash not match the transaction");
            txs.push(tx);
        }
        Ok(txs)
    }

    pub fn verify(&self, hash: &H256, max_cycle: Cycle) -> Result<VerifyResult, String> {
        Ok(VerifyResult { cycle: 0, debug_logs: Vec::new() })
    }
}

pub struct VerifyResult {
    cycle: Cycle,
    debug_logs: Vec<String>,
}
