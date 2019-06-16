use crate::{Address, LiveCellInfo, SECP_CODE_HASH};
use bytes::Bytes;
use ckb_core::{
    block::Block,
    header::Header,
    transaction::{CellOutPoint, CellOutput, OutPoint, TransactionBuilder},
    Capacity,
};
use crypto::secp::Privkey;
use hash::blake2b_256;
use jsonrpc_types::Transaction as RpcTransaction;
use numext_fixed_hash::H256;

pub const ONE_CKB: u64 = 10000_0000;
// H256(secp code hash) + H160 (secp pubkey hash) + u64(capacity) = 32 + 20 + 8 = 60
pub const MIN_SECP_CELL_CAPACITY: u64 = 60 * ONE_CKB;

#[derive(Debug, Clone)]
pub struct GenesisInfo {
    header: Header,
    out_points: Vec<Vec<CellOutPoint>>,
}

impl GenesisInfo {
    pub fn from_block(genesis_block: &Block) -> Result<GenesisInfo, String> {
        let header = genesis_block.header().clone();
        if header.number() != 0 {
            return Err(format!(
                "Convert to GenesisInfo failed, block number {} > 0",
                header.number()
            ));
        }

        let mut error = None;
        let out_points = genesis_block
            .transactions()
            .iter()
            .enumerate()
            .map(|(tx_index, tx)| {
                tx.outputs()
                    .iter()
                    .enumerate()
                    .map(|(index, output)| {
                        if tx_index == 0 && index == 1 {
                            let code_hash = H256::from_slice(&blake2b_256(&output.data))
                                .expect("Convert to H256 error");
                            if code_hash != SECP_CODE_HASH {
                                error = Some(format!(
                                    "System secp script code hash error! found: {}, expected: {}",
                                    code_hash, SECP_CODE_HASH,
                                ));
                            }
                        }
                        CellOutPoint {
                            tx_hash: tx.hash().clone(),
                            index: index as u32,
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        if let Some(err) = error {
            Err(err)
        } else {
            Ok(GenesisInfo { header, out_points })
        }
    }
    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn secp_dep(&self) -> OutPoint {
        OutPoint {
            cell: Some(self.out_points[0][1].clone().into()),
            block_hash: None,
        }
    }
}

#[derive(Debug)]
pub struct TransferTransactionBuilder<'a> {
    pub from_privkey: &'a Privkey,
    pub from_address: &'a Address,
    pub from_capacity: u64,
    pub to_data: &'a Bytes,
    pub to_address: &'a Address,
    pub to_capacity: u64,
}

impl<'a> TransferTransactionBuilder<'a> {
    pub fn build(&self, input_infos: Vec<LiveCellInfo>, secp_dep: OutPoint) -> RpcTransaction {
        assert!(self.from_capacity >= self.to_capacity);

        let inputs = input_infos
            .iter()
            .map(|info| info.core_input())
            .collect::<Vec<_>>();

        // TODO: calculate transaction fee
        // Send to user
        let mut from_capacity = self.from_capacity;
        let mut outputs = vec![CellOutput {
            capacity: Capacity::shannons(self.to_capacity),
            data: self.to_data.clone(),
            lock: self.to_address.lock_script(),
            type_: None,
        }];
        from_capacity -= self.to_capacity;

        if from_capacity > MIN_SECP_CELL_CAPACITY {
            // The rest send back to sender
            outputs.push(CellOutput {
                capacity: Capacity::shannons(from_capacity),
                data: Bytes::default(),
                lock: self.from_address.lock_script(),
                type_: None,
            });
        }

        let core_tx = TransactionBuilder::default()
            .inputs(inputs.clone())
            .outputs(outputs.clone())
            .dep(secp_dep.clone())
            .build();

        let witness = build_witness(&self.from_privkey, core_tx.hash());
        let witnesses = inputs.iter().map(|_| witness.clone()).collect::<Vec<_>>();
        (&TransactionBuilder::default()
            .inputs(inputs)
            .outputs(outputs)
            .dep(secp_dep)
            .witnesses(witnesses)
            .build())
            .into()
    }
}

pub fn build_witness(privkey: &Privkey, tx_hash: &H256) -> Vec<Bytes> {
    let message = H256::from(blake2b_256(tx_hash));
    let pubkey_bytes = privkey.pubkey().unwrap().serialize();
    let signature = privkey.sign_recoverable(&message).unwrap();
    let signature_der = signature.serialize_der();
    vec![Bytes::from(pubkey_bytes), Bytes::from(signature_der)]
}
