use crate::Address;
use ckb_crypto::secp::SECP256K1;
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::Transaction as RpcTransaction;
use ckb_resource::{CODE_HASH_SECP256K1_BLAKE160_SIGHASH_ALL};
use ckb_types::{
    bytes::Bytes,
    core::{ScriptHashType, BlockView, Capacity, DepType, HeaderView, TransactionBuilder, TransactionView},
    packed::{CellDep, CellInput, CellOutput, OutPoint, Witness, Script},
    prelude::*,
    H256, h256,
};
use secp256k1::recovery::RecoverableSignature;
use std::collections::VecDeque;

pub const ONE_CKB: u64 = 100_000_000;
// H256(secp code hash) + H160 (secp pubkey hash) + 1 (ScriptHashType) + u64(capacity) = 32 + 20 + 1 + 8 = 61
pub const MIN_SECP_CELL_CAPACITY: u64 = (32 + 20 + 1 + 8) * ONE_CKB;

#[derive(Debug, Clone)]
pub struct GenesisInfo {
    header: HeaderView,
    out_points: Vec<Vec<OutPoint>>,
    secp_data_hash: H256,
    secp_type_hash: H256,
    dao_data_hash: H256,
    dao_type_hash: H256,
}

impl GenesisInfo {
    pub fn from_block(genesis_block: &BlockView) -> Result<GenesisInfo, String> {
        let header = genesis_block.header();
        if header.number() != 0 {
            return Err(format!(
                "Convert to GenesisInfo failed, block number {} > 0",
                header.number()
            ));
        }

        let mut secp_data_hash = None;
        let mut secp_type_hash = None;
        let mut dao_data_hash = None;
        let mut dao_type_hash = None;
        let out_points = genesis_block
            .transactions()
            .iter()
            .enumerate()
            .map(|(tx_index, tx)| {
                tx.outputs()
                    .into_iter()
                    .zip(tx.outputs_data().into_iter())
                    .enumerate()
                    .map(|(index, (output, data))| {
                        if tx_index == 0 && index == 1 {
                            secp_type_hash = output
                                .type_()
                                .to_opt()
                                .map(|script| script.calc_script_hash());
                            let data_hash = CellOutput::calc_data_hash(&data.raw_data());
                            if data_hash != CODE_HASH_SECP256K1_BLAKE160_SIGHASH_ALL {
                                log::error!(
                                    "System secp script code hash error! found: {}, expected: {}",
                                    data_hash,
                                    CODE_HASH_SECP256K1_BLAKE160_SIGHASH_ALL,
                                );
                            }
                            secp_data_hash = Some(data_hash);
                        }
                        OutPoint::new(tx.hash().unpack(), index as u32)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let secp_data_hash =
            secp_data_hash.ok_or_else(|| "No data hash(secp) found in txs[0][1]".to_owned())?;
        let secp_type_hash =
            secp_type_hash.ok_or_else(|| "No type hash(secp) found in txs[0][1]".to_owned())?;
        Ok(GenesisInfo {
            header,
            out_points,
            secp_data_hash,
            secp_type_hash,
        })
    }

    pub fn header(&self) -> &HeaderView {
        &self.header
    }

    pub fn secp_data_hash(&self) -> &H256 {
        &self.secp_data_hash
    }

    pub fn secp_type_hash(&self) -> &H256 {
        &self.secp_type_hash
    }

    pub fn secp_dep(&self) -> CellDep {
        CellDep::new_builder()
            .out_point(self.out_points[1][0].clone())
            .dep_type(DepType::DepGroup.pack())
            .build()
    }

    pub fn dao_dep(&self) -> OutPoint {
        OutPoint {
            cell: Some(self.out_points[0][2].clone()),
            block_hash: None,
        }
    }
}

#[derive(Debug)]
pub struct TransferTransactionBuilder<'a> {
    from_address: &'a Address,
    from_capacity: u64,
    to_data: &'a Bytes,
    to_address: &'a Address,
    to_capacity: u64,

    inputs: Vec<CellInput>,
    outputs: Vec<CellOutput>,
    exchanges: Vec<CellOutput>,
    deps: Vec<OutPoint>,
    witnesses: Vec<VecDeque<Bytes>>,
}

impl<'a> TransferTransactionBuilder<'a> {
    pub fn new(
        from_address: &'a Address,
        from_capacity: u64,
        to_data: &'a Bytes,
        to_address: &'a Address,
        to_capacity: u64,
        inputs: Vec<CellInput>,
    ) -> Self {
        assert!(from_capacity >= to_capacity);

        let mut witnesses = Vec::with_capacity(inputs.len());
        inputs.iter().for_each(|_| witnesses.push(VecDeque::new()));

        Self {
            from_address,
            from_capacity,
            to_data,
            to_address,
            to_capacity,
            inputs,
            witnesses,

            outputs: Vec::new(),
            exchanges: Vec::new(),
            deps: Vec::new(),
        }
    }

    pub fn transfer<F>(
        &mut self,
        genesis_info: &GenesisInfo,
        build_witness: F,
    ) -> Result<Transaction, String>
    where
        F: FnOnce(&Vec<&[u8]>) -> Result<Bytes, String>,
    {
        self.deps.extend(vec![genesis_info.secp_dep()]);
        self.build_outputs(genesis_info);
        self.build_exchanges(genesis_info);
        self.build_secp_witnesses(build_witness)?;
        Ok(self.build_transaction())
    }

    pub fn deposit_dao<F>(
        &mut self,
        genesis_info: &GenesisInfo,
        build_witness: F,
    ) -> Result<Transaction, String>
    where
        F: FnOnce(&Vec<&[u8]>) -> Result<Bytes, String>,
    {
        self.deps
            .extend(vec![genesis_info.secp_dep(), genesis_info.dao_dep()]);
        self.build_outputs(genesis_info);
        self.build_exchanges(genesis_info);
        self.build_dao_type(genesis_info);
        self.build_secp_witnesses(build_witness)?;
        Ok(self.build_transaction())
    }

    pub fn withdraw_dao<F>(
        &mut self,
        withdraw_header_hash: H256,
        genesis_info: &GenesisInfo,
        build_witness: F,
    ) -> Result<Transaction, String>
    where
        F: FnOnce(&Vec<&[u8]>) -> Result<Bytes, String>,
    {
        self.deps.extend(vec![
            genesis_info.secp_dep(),
            genesis_info.dao_dep(),
            OutPoint::new_block_hash(withdraw_header_hash),
        ]);
        self.build_outputs(genesis_info);
        self.build_exchanges(genesis_info);
        self.build_dao_witnesses();
        self.build_secp_witnesses(build_witness)?;
        Ok(self.build_transaction())
    }

    fn build_secp_witnesses<F>(&mut self, build_witness: F) -> Result<(), String>
    where
        F: FnOnce(&Vec<&[u8]>) -> Result<Bytes, String>,
    {
        // The finalized witness is blake2b([tx_hash, witnesses[1], witnesses[2], ...)
        let transaction = self.build_transaction();
        let mut secp_witness_args: Vec<&[u8]> = Vec::new();
        secp_witness_args.push(transaction.hash().as_ref());
        let witness = &self.witnesses[0];
        for wit in witness.iter() {
            secp_witness_args.push(wit.as_ref());
        }
        let secp_witness = build_witness(&secp_witness_args)?;

        // Clone the secp witness and put in the first witness for every inputs
        for witness in self.witnesses.iter_mut() {
            witness.push_front(secp_witness.clone());
        }

        Ok(())
    }

    fn build_dao_witnesses(&mut self) {
        // NOTE: We assume all the inputs are deposited-dao cells
        for witness in self.witnesses.iter_mut() {
            let dao_i = 2u64; // point to a header-only withdraw out point
            let dao_witness = Bytes::from(dao_i.to_le_bytes().to_vec());
            witness.push_back(dao_witness);
        }
    }

    fn build_outputs(&mut self, genesis_info: &GenesisInfo) {
        self.outputs.push(CellOutput {
            capacity: Capacity::shannons(self.to_capacity),
            data: self.to_data.clone(),
            lock: self
                .to_address
                .lock_script(genesis_info.secp_code_hash().to_owned()),
            type_: None,
        });
    }

    // Exchange back to sender if the rest is enough to pay for a cell
    fn build_exchanges(&mut self, genesis_info: &GenesisInfo) {
        let rest_capacity = self.from_capacity - self.to_capacity;
        if rest_capacity >= MIN_SECP_CELL_CAPACITY {
            // The rest send back to sender
            self.exchanges.push(CellOutput {
                capacity: Capacity::shannons(rest_capacity),
                data: Bytes::default(),
                lock: self
                    .from_address
                    .lock_script(genesis_info.secp_code_hash().to_owned()),
                type_: None,
            });
        }
    }

    fn build_dao_type(&mut self, genesis_info: &GenesisInfo) {
        for output in self.outputs.iter_mut() {
            output.type_ = Some(Script {
                args: Vec::new(),
                hash_type: ScriptHashType::Data,
                code_hash: genesis_info.dao_code_hash().to_owned(),
            });
        }
    }

    fn build_transaction(&self) -> Transaction {
        TransactionBuilder::default()
            .inputs(self.inputs.clone())
            .outputs(self.outputs.clone())
            .outputs(self.exchanges.clone())
            .deps(self.deps.clone())
            .witnesses(self.witnesses.clone())
            .build()
    }
}

pub fn build_witness_with_key(privkey: &secp256k1::SecretKey, args: &[&[u8]]) -> Bytes {
    let message = secp256k1::Message::from_slice(&blake2b_args(args))
        .expect("Convert to secp256k1 message failed");
    serialize_signature(&SECP256K1.sign_recoverable(&message, privkey))
}

pub fn serialize_signature(signature: &secp256k1::RecoverableSignature) -> Bytes {
    let (recov_id, data) = signature.serialize_compact();
    let mut signature_bytes = [0u8; 65];
    signature_bytes[0..64].copy_from_slice(&data[0..64]);
    signature_bytes[64] = recov_id.to_i32() as u8;
    Bytes::from(signature_bytes.to_vec())
}

pub fn blake2b_args(args: &[&[u8]]) -> [u8; 32] {
    let mut blake2b = new_blake2b();
    for arg in args.iter() {
        blake2b.update(arg);
    }
    let mut digest = [0u8; 32];
    blake2b.finalize(&mut digest);
    digest
}
