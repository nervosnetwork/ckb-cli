use crate::Address;
use ckb_crypto::secp::SECP256K1;
use ckb_hash::new_blake2b;
use ckb_resource::{CODE_HASH_DAO, CODE_HASH_SECP256K1_BLAKE160_SIGHASH_ALL};
use ckb_types::{
    bytes::Bytes,
    core::{
        BlockView, Capacity, DepType, HeaderView, ScriptHashType, TransactionBuilder,
        TransactionView,
    },
    packed::{Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, ScriptOpt},
    prelude::*,
    H160, H256,
};
use secp256k1::recovery::RecoverableSignature;
use std::collections::VecDeque;

pub const ONE_CKB: u64 = 100_000_000;

lazy_static::lazy_static! {
    pub static ref MIN_SECP_CELL_CAPACITY: u64 = {
        CellOutput::new_builder()
            .lock(
                Script::new_builder()
                    .args(H160::default().as_bytes().pack())
                    .build()
            )
            .build()
            .occupied_capacity(Capacity::zero())
            .unwrap()
            .as_u64()
    };
}

const SECP_TRANSACTION_INDEX: usize = 0;
const SECP_OUTPUT_INDEX: usize = 1;
const SECP_GROUP_TRANSACTION_INDEX: usize = 1;
const SECP_GROUP_OUTPUT_INDEX: usize = 0;
const DAO_TRANSACTION_INDEX: usize = 0;
const DAO_OUTPUT_INDEX: usize = 2;

#[derive(Debug, Clone)]
pub struct GenesisInfo {
    header: HeaderView,
    out_points: Vec<Vec<OutPoint>>,
    secp_data_hash: Byte32,
    secp_type_hash: Byte32,
    dao_data_hash: Byte32,
    dao_type_hash: Byte32,
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
                        if tx_index == SECP_TRANSACTION_INDEX && index == SECP_OUTPUT_INDEX {
                            secp_type_hash = output
                                .type_()
                                .to_opt()
                                .map(|script| script.calc_script_hash());
                            let data_hash = CellOutput::calc_data_hash(&data.raw_data());
                            if data_hash != CODE_HASH_SECP256K1_BLAKE160_SIGHASH_ALL.pack() {
                                log::error!(
                                    "System secp script code hash error! found: {}, expected: {}",
                                    data_hash,
                                    CODE_HASH_SECP256K1_BLAKE160_SIGHASH_ALL,
                                );
                            }
                            secp_data_hash = Some(data_hash);
                        }
                        if tx_index == DAO_TRANSACTION_INDEX && index == DAO_OUTPUT_INDEX {
                            dao_type_hash = output
                                .type_()
                                .to_opt()
                                .map(|script| script.calc_script_hash());
                            let data_hash = CellOutput::calc_data_hash(&data.raw_data());
                            if data_hash != CODE_HASH_DAO.pack() {
                                log::error!(
                                    "System dao script code hash error! found: {}, expected: {}",
                                    data_hash,
                                    CODE_HASH_DAO,
                                );
                            }
                            dao_data_hash = Some(data_hash);
                        }
                        OutPoint::new(tx.hash(), index as u32)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let secp_data_hash =
            secp_data_hash.ok_or_else(|| "No data hash(secp) found in txs[0][1]".to_owned())?;
        let secp_type_hash =
            secp_type_hash.ok_or_else(|| "No type hash(secp) found in txs[0][1]".to_owned())?;
        let dao_data_hash =
            dao_data_hash.ok_or_else(|| "No data hash(dao) found in txs[0][2]".to_owned())?;
        let dao_type_hash =
            dao_type_hash.ok_or_else(|| "No type hash(dao) found in txs[0][2]".to_owned())?;
        Ok(GenesisInfo {
            header,
            out_points,
            secp_data_hash,
            secp_type_hash,
            dao_data_hash,
            dao_type_hash,
        })
    }

    pub fn header(&self) -> &HeaderView {
        &self.header
    }

    pub fn secp_data_hash(&self) -> &Byte32 {
        &self.secp_data_hash
    }

    pub fn secp_type_hash(&self) -> &Byte32 {
        &self.secp_type_hash
    }

    pub fn dao_data_hash(&self) -> &Byte32 {
        &self.dao_data_hash
    }

    pub fn dao_type_hash(&self) -> &Byte32 {
        &self.dao_type_hash
    }

    pub fn secp_dep(&self) -> CellDep {
        CellDep::new_builder()
            .out_point(
                self.out_points[SECP_GROUP_TRANSACTION_INDEX][SECP_GROUP_OUTPUT_INDEX].clone(),
            )
            .dep_type(DepType::DepGroup.pack())
            .build()
    }

    pub fn dao_dep(&self) -> CellDep {
        CellDep::new_builder()
            .out_point(self.out_points[DAO_TRANSACTION_INDEX][DAO_OUTPUT_INDEX].clone())
            .build()
    }
}

#[derive(Debug)]
pub struct TransferTransactionBuilder<'a> {
    from_address: &'a Address,
    from_capacity: u64,
    to_data: &'a Bytes,
    to_address: &'a Address,
    to_capacity: u64,
    tx_fee: Option<u64>,
    fee_rate: Option<u64>,

    inputs: Vec<CellInput>,
    outputs: Vec<(CellOutput, Bytes)>,
    changes: Vec<(CellOutput, Bytes)>,
    cell_deps: Vec<CellDep>,
    header_deps: Vec<Byte32>,
    witnesses: Vec<VecDeque<Bytes>>,
}

impl<'a> TransferTransactionBuilder<'a> {
    pub fn new(
        from_address: &'a Address,
        from_capacity: u64,
        to_data: &'a Bytes,
        to_address: &'a Address,
        to_capacity: u64,
        fee: (Option<u64>, Option<u64>),
        inputs: Vec<CellInput>,
    ) -> Self {
        let (tx_fee, fee_rate) = fee;
        let mut witnesses = Vec::with_capacity(inputs.len());
        inputs.iter().for_each(|_| witnesses.push(VecDeque::new()));

        Self {
            from_address,
            from_capacity,
            to_data,
            to_address,
            to_capacity,
            tx_fee,
            fee_rate,
            inputs,
            witnesses,

            outputs: Vec::new(),
            changes: Vec::new(),
            cell_deps: Vec::new(),
            header_deps: Vec::new(),
        }
    }

    pub fn transfer<F>(
        &mut self,
        genesis_info: &GenesisInfo,
        build_witness: F,
    ) -> Result<TransactionView, String>
    where
        F: FnMut(&Vec<&[u8]>) -> Result<Bytes, String>,
    {
        self.cell_deps.extend(vec![genesis_info.secp_dep()]);
        self.build_outputs(genesis_info);
        self.build_changes(genesis_info, false);
        self.build_secp_witnesses(build_witness)?;
        Ok(self.build_transaction())
    }

    pub fn deposit_dao<F>(
        &mut self,
        genesis_info: &GenesisInfo,
        build_witness: F,
    ) -> Result<TransactionView, String>
    where
        F: FnMut(&Vec<&[u8]>) -> Result<Bytes, String>,
    {
        self.cell_deps
            .extend(vec![genesis_info.secp_dep(), genesis_info.dao_dep()]);
        self.build_outputs(genesis_info);
        self.build_changes(genesis_info, true);
        self.build_dao_type(genesis_info);
        self.build_secp_witnesses(build_witness)?;
        Ok(self.build_transaction())
    }

    pub fn withdraw_dao<F>(
        &mut self,
        withdraw_header_hash: H256,
        input_header_hashes: Vec<H256>,
        genesis_info: &GenesisInfo,
        build_witness: F,
    ) -> Result<TransactionView, String>
    where
        F: FnMut(&Vec<&[u8]>) -> Result<Bytes, String>,
    {
        self.cell_deps
            .extend(vec![genesis_info.secp_dep(), genesis_info.dao_dep()]);
        self.header_deps.push(withdraw_header_hash.pack());
        self.header_deps
            .extend(input_header_hashes.into_iter().map(|h| h.pack()));
        self.build_outputs(genesis_info);
        self.build_changes(genesis_info, true);
        self.build_dao_witnesses();
        self.build_secp_witnesses(build_witness)?;
        Ok(self.build_transaction())
    }

    pub fn estimate_tx_fee(&self, is_dao: bool) -> u64 {
        self.tx_fee.unwrap_or_else(|| {
            let (outputs, outputs_data): (Vec<_>, Vec<_>) = self.outputs.iter().cloned().unzip();
            let change_cell = CellOutput::new_builder()
                .capacity(Capacity::bytes(100).unwrap().pack())
                .lock(self.from_address.lock_script(Default::default()))
                .build();
            let change_data = Bytes::default();
            let witnesses: Vec<Bytes> = self
                .witnesses
                .iter()
                .map(|_| {
                    // secp signature
                    let mut data = vec![0u8; 65];
                    if is_dao {
                        // dao position argument
                        data.extend_from_slice(&0u64.to_le_bytes()[..]);
                    }
                    Bytes::from(data)
                })
                .collect();
            TransactionBuilder::default()
                .inputs(self.inputs.clone())
                .outputs(outputs)
                .output(change_cell)
                .outputs_data(outputs_data.iter().map(Pack::pack))
                .output_data(change_data.pack())
                .cell_deps(self.cell_deps.clone())
                .header_deps(self.header_deps.clone())
                .witnesses(witnesses.pack())
                .build()
                .data()
                .serialized_size_in_block() as u64
                * self.fee_rate.unwrap()
        })
    }

    fn build_secp_witnesses<F>(&mut self, mut build_witness: F) -> Result<(), String>
    where
        F: FnMut(&Vec<&[u8]>) -> Result<Bytes, String>,
    {
        let transaction = self.build_transaction();

        // The finalized witness is blake2b([tx_hash, witness[1], witness[2], ...)
        for witness in self.witnesses.iter_mut() {
            let first_w = transaction.hash().as_bytes();
            let mut secp_witness_args = vec![&first_w];
            secp_witness_args.extend(witness.iter().map(|wit| wit));

            let secp_witness =
                build_witness(&secp_witness_args.into_iter().map(|w| w.as_ref()).collect())?;
            witness.push_front(secp_witness);
        }

        Ok(())
    }

    fn build_dao_witnesses(&mut self) {
        // NOTE: We assume all the inputs are deposited-dao cells
        for witness in self.witnesses.iter_mut() {
            let dao_i = 0u64; // point to a header-only withdraw out point
            let dao_witness = Bytes::from(dao_i.to_le_bytes().to_vec());
            witness.push_back(dao_witness);
        }
    }

    fn build_outputs(&mut self, genesis_info: &GenesisInfo) {
        let output = CellOutput::new_builder()
            .capacity(Capacity::shannons(self.to_capacity).pack())
            .lock(
                self.to_address
                    .lock_script(genesis_info.secp_type_hash.clone())
                    .to_owned(),
            )
            .build();
        self.outputs.push((output, self.to_data.clone()));
    }

    // Exchange back to sender if the rest is enough to pay for a cell
    fn build_changes(&mut self, genesis_info: &GenesisInfo, is_dao: bool) {
        let rest_capacity = self.from_capacity - self.to_capacity - self.estimate_tx_fee(is_dao);
        if rest_capacity >= *MIN_SECP_CELL_CAPACITY {
            // The rest send back to sender
            let change = CellOutput::new_builder()
                .capacity(Capacity::shannons(rest_capacity).pack())
                .lock(
                    self.from_address
                        .lock_script(genesis_info.secp_type_hash.to_owned()),
                )
                .build();
            let change_data = Bytes::default();
            self.changes.push((change, change_data));
        }
    }

    fn build_dao_type(&mut self, genesis_info: &GenesisInfo) {
        self.outputs = self
            .outputs
            .iter()
            .cloned()
            .map(|(output, output_data)| {
                let type_ = Script::new_builder()
                    .hash_type(ScriptHashType::Type.pack())
                    .code_hash(genesis_info.dao_type_hash().clone())
                    .build();
                let type_opt = ScriptOpt::new_builder().set(Some(type_)).build();
                let new_output = output.as_builder().type_(type_opt).build();
                (new_output, output_data)
            })
            .collect();
    }

    fn build_transaction(&self) -> TransactionView {
        let (outputs, outputs_data): (Vec<_>, Vec<_>) = self.outputs.iter().cloned().unzip();
        let (changes, changes_data): (Vec<_>, Vec<_>) = self.changes.iter().cloned().unzip();
        let witnesses: Vec<Bytes> = self
            .witnesses
            .iter()
            .cloned()
            .map(|witness| {
                witness
                    .into_iter()
                    .fold(Vec::new(), |mut data, part| {
                        data.extend_from_slice(&part);
                        data
                    })
                    .into()
            })
            .collect();
        TransactionBuilder::default()
            .inputs(self.inputs.clone())
            .outputs(outputs)
            .outputs(changes)
            .outputs_data(outputs_data.iter().map(Pack::pack))
            .outputs_data(changes_data.iter().map(Pack::pack))
            .cell_deps(self.cell_deps.clone())
            .header_deps(self.header_deps.clone())
            .witnesses(witnesses.pack())
            .build()
    }
}

pub fn build_witness_with_key(privkey: &secp256k1::SecretKey, args: &[&[u8]]) -> Bytes {
    let message = secp256k1::Message::from_slice(&blake2b_args(args))
        .expect("Convert to secp256k1 message failed");
    serialize_signature(&SECP256K1.sign_recoverable(&message, privkey))
}

pub fn serialize_signature(signature: &RecoverableSignature) -> Bytes {
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
