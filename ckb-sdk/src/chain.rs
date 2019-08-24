use crate::Address;
use ckb_crypto::secp::SECP256K1;
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::Transaction as RpcTransaction;
use ckb_resource::CODE_HASH_SECP256K1_BLAKE160_SIGHASH_ALL;
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, Capacity, DepType, HeaderView, TransactionBuilder},
    packed::{CellDep, CellInput, CellOutput, OutPoint, Witness},
    prelude::*,
    H256,
};
use secp256k1::recovery::RecoverableSignature;

pub const ONE_CKB: u64 = 100_000_000;
// H256(secp code hash) + H160 (secp pubkey hash) + 1 (ScriptHashType) + u64(capacity) = 32 + 20 + 1 + 8 = 61
pub const MIN_SECP_CELL_CAPACITY: u64 = (32 + 20 + 1 + 8) * ONE_CKB;

#[derive(Debug, Clone)]
pub struct GenesisInfo {
    header: HeaderView,
    out_points: Vec<Vec<OutPoint>>,
    secp_data_hash: H256,
    secp_type_hash: H256,
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
}

#[derive(Debug)]
pub struct TransferTransactionBuilder<'a> {
    pub from_address: &'a Address,
    pub from_capacity: u64,
    pub to_data: &'a Bytes,
    pub to_address: &'a Address,
    pub to_capacity: u64,
}

impl<'a> TransferTransactionBuilder<'a> {
    pub fn build<F>(
        &self,
        inputs: Vec<CellInput>,
        genesis_info: &GenesisInfo,
        build_witness: F,
    ) -> Result<RpcTransaction, String>
    where
        F: FnOnce(&H256) -> Result<Bytes, String>,
    {
        assert!(self.from_capacity >= self.to_capacity);
        let secp_dep = genesis_info.secp_dep();
        let secp_type_hash = genesis_info.secp_type_hash();

        // TODO: calculate transaction fee
        // Send to user
        let mut from_capacity = self.from_capacity;
        let mut outputs = vec![CellOutput::new_builder()
            .capacity(Capacity::shannons(self.to_capacity).pack())
            .lock(self.to_address.lock_script(secp_type_hash.clone()))
            .build()];
        let mut outputs_data = vec![self.to_data.clone().pack()];
        from_capacity -= self.to_capacity;

        if from_capacity > MIN_SECP_CELL_CAPACITY {
            // The rest send back to sender
            outputs.push(
                CellOutput::new_builder()
                    .capacity(Capacity::shannons(from_capacity).pack())
                    .lock(self.from_address.lock_script(secp_type_hash.clone()))
                    .build(),
            );
            outputs_data.push(Default::default());
        }

        let core_tx = TransactionBuilder::default()
            .inputs(inputs.clone())
            .outputs(outputs.clone())
            .outputs_data(outputs_data.clone())
            .cell_dep(secp_dep.clone())
            .build();

        let witness: Witness = vec![build_witness(&core_tx.hash().unpack())?.pack()].pack();
        let witnesses = inputs
            .iter()
            .map(|_| witness.clone().pack())
            .collect::<Vec<_>>();
        Ok(TransactionBuilder::default()
            .inputs(inputs)
            .outputs(outputs)
            .outputs_data(outputs_data)
            .cell_dep(secp_dep)
            .witnesses(witnesses)
            .build()
            .data()
            .into())
    }
}

pub fn build_witness_with_key(privkey: &secp256k1::SecretKey, tx_hash: &H256) -> Bytes {
    let message = secp256k1::Message::from_slice(&blake2b_256(tx_hash))
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
