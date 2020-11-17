use ckb_hash::new_blake2b;
use ckb_jsonrpc_types as rpc_types;
use ckb_script::TransactionScriptsVerifier;
use ckb_types::{
    bytes::Bytes,
    core::{cell::resolve_transaction, Capacity, Cycle, ScriptHashType},
    packed::{Byte32, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
    H160, H256,
};
use failure::Error as FailureError;
use fnv::FnvHashSet;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;

use crate::constants::MIN_SECP_CELL_CAPACITY;
use crate::GenesisInfo;

pub use ckb_sdk_types::transaction::{
    MockCellDep, MockInfo, MockInput, MockResourceLoader, MockTransaction, ReprMockCellDep,
    ReprMockInfo, ReprMockInput, ReprMockTransaction, Resource,
};

pub struct MockTransactionHelper<'a> {
    pub mock_tx: &'a mut MockTransaction,
    live_cell_cache: HashMap<OutPoint, (CellOutput, Bytes, H256)>,
}

impl<'a> MockTransactionHelper<'a> {
    pub fn new(mock_tx: &'a mut MockTransaction) -> MockTransactionHelper<'a> {
        MockTransactionHelper {
            mock_tx,
            live_cell_cache: HashMap::default(),
        }
    }

    fn get_input_cell<C>(
        &mut self,
        input: &CellInput,
        live_cell_getter: C,
    ) -> Result<(CellOutput, Bytes, H256), String>
    where
        C: FnMut(OutPoint) -> Result<Option<(CellOutput, Bytes, H256)>, String>,
    {
        let cell = match self.live_cell_cache.get(&input.previous_output()) {
            Some(cell) => cell.clone(),
            None => {
                let cell = self
                    .mock_tx
                    .get_input_cell(input, live_cell_getter)?
                    .ok_or_else(|| format!("input cell not found: {:?}", input))?;
                self.live_cell_cache
                    .insert(input.previous_output(), cell.clone());
                cell
            }
        };
        Ok(cell)
    }

    /// Add a change cell output use `target_lock` as output lock script, default the same as first input
    pub fn add_change_output<C>(
        &mut self,
        target_lock: Option<Script>,
        mut live_cell_getter: C,
    ) -> Result<u64, String>
    where
        C: FnMut(OutPoint) -> Result<Option<(CellOutput, Bytes, H256)>, String>,
    {
        let mut input_total: u64 = 0;
        let mut first_input_cell = None;
        for input in self.mock_tx.core_transaction().inputs().into_iter() {
            let (output, _, _) = self.get_input_cell(&input, &mut live_cell_getter)?;
            if first_input_cell.is_none() {
                first_input_cell = Some(output.clone());
            }
            input_total += Unpack::<u64>::unpack(&output.capacity());
        }
        if first_input_cell.is_none() {
            return Err(String::from("Must have at least one input"));
        }

        let output_total: u64 = self
            .mock_tx
            .core_transaction()
            .outputs()
            .into_iter()
            .map(|output| Unpack::<u64>::unpack(&output.capacity()))
            .sum();
        let delta = input_total.saturating_sub(output_total);
        if input_total < output_total {
            Err(format!(
                "input total({}) < output total({})",
                input_total, output_total
            ))
        } else if delta < MIN_SECP_CELL_CAPACITY {
            Ok(0)
        } else {
            let output_lock = target_lock.unwrap_or_else(|| {
                first_input_cell
                    .expect("Must have at least one input")
                    .lock()
            });
            let output = CellOutput::new_builder()
                .capacity(Capacity::shannons(delta).pack())
                .lock(output_lock)
                .build();
            self.mock_tx.tx = self
                .mock_tx
                .tx
                .as_advanced_builder()
                .output(output)
                .output_data(Bytes::default().pack())
                .build()
                .data();
            Ok(delta)
        }
    }

    /// Fill deps by code hash or type hash (from mock_deps or system secp256k1 cell)
    pub fn fill_deps<C>(
        &mut self,
        genesis_info: &GenesisInfo,
        mut live_cell_getter: C,
    ) -> Result<(), String>
    where
        C: FnMut(OutPoint) -> Result<Option<(CellOutput, Bytes, H256)>, String>,
    {
        let tx = self.mock_tx.core_transaction();
        let mut cell_deps = tx.cell_deps().into_iter().collect::<HashSet<_>>();
        let data_deps = self
            .mock_tx
            .mock_info
            .cell_deps
            .iter()
            .filter(|mock| !mock.data.is_empty())
            .map(|mock| {
                (
                    CellOutput::calc_data_hash(&mock.data),
                    mock.cell_dep.clone(),
                )
            })
            .collect::<HashMap<_, _>>();
        let type_deps = self
            .mock_tx
            .mock_info
            .cell_deps
            .iter()
            .filter(|mock| !mock.data.is_empty())
            .filter_map(|mock| {
                mock.output
                    .type_()
                    .to_opt()
                    .as_ref()
                    .map(|script| (script.calc_script_hash(), mock.cell_dep.clone()))
            })
            .collect::<HashMap<_, _>>();
        let sighash_type_hash = genesis_info.sighash_type_hash();
        let mut insert_dep = |hash_type, code_hash: &Byte32| -> Result<(), String> {
            match (hash_type, code_hash) {
                (ScriptHashType::Data, data_hash) => {
                    let dep = data_deps.get(data_hash).cloned().ok_or_else(|| {
                        format!("Can not find data hash in mock deps: {}", data_hash)
                    })?;
                    cell_deps.insert(dep);
                }
                (ScriptHashType::Type, code_hash) if code_hash == sighash_type_hash => {
                    cell_deps.insert(genesis_info.sighash_dep());
                }
                (ScriptHashType::Type, type_hash) => {
                    let dep = type_deps.get(type_hash).cloned().ok_or_else(|| {
                        format!("Can not find type hash in mock deps: {}", type_hash)
                    })?;
                    cell_deps.insert(dep);
                }
            }
            Ok(())
        };
        for input in tx.inputs().into_iter() {
            let lock = self.get_input_cell(&input, &mut live_cell_getter)?.0.lock();
            let hash_type = lock
                .hash_type()
                .try_into()
                .map_err(|err: FailureError| err.to_string())?;
            insert_dep(hash_type, &lock.code_hash())?;
        }
        for output in tx.outputs().into_iter() {
            if let Some(script) = output.type_().to_opt() {
                let hash_type = script
                    .hash_type()
                    .try_into()
                    .map_err(|err: FailureError| err.to_string())?;
                insert_dep(hash_type, &script.code_hash())?;
            }
        }
        let new_cell_deps = tx
            .cell_deps()
            .into_iter()
            .chain(
                cell_deps
                    .difference(&tx.cell_deps().into_iter().collect())
                    .cloned(),
            )
            .collect::<Vec<_>>();
        self.mock_tx.tx = self
            .mock_tx
            .tx
            .as_advanced_builder()
            .set_cell_deps(new_cell_deps)
            .build()
            .data();
        Ok(())
    }

    /// Compute transaction hash and set witnesses for inputs (search by lock scripts)
    pub fn fill_witnesses<S, C>(
        &mut self,
        genesis_info: &GenesisInfo,
        signer: S,
        mut live_cell_getter: C,
    ) -> Result<(), String>
    where
        S: Fn(&H160, &H256, &rpc_types::Transaction) -> Result<[u8; 65], String>,
        C: FnMut(OutPoint) -> Result<Option<(CellOutput, Bytes, H256)>, String>,
    {
        let tx = self.mock_tx.core_transaction();
        let mut witnesses: Vec<_> = tx.witnesses().into_iter().collect();
        while witnesses.len() < tx.inputs().len() {
            witnesses.push(Bytes::new().pack());
        }
        let mut input_group: HashMap<H160, Vec<usize>> = HashMap::default();
        for (idx, input) in tx.inputs().into_iter().enumerate() {
            let lock = self.get_input_cell(&input, &mut live_cell_getter)?.0.lock();
            if &lock.code_hash() == genesis_info.sighash_type_hash()
                && lock.hash_type() == ScriptHashType::Type.into()
                && lock.args().raw_data().len() == 20
            {
                let lock_arg =
                    H160::from_slice(&lock.args().raw_data()).expect("Convert to H160 failed");
                input_group
                    .entry(lock_arg)
                    .or_insert_with(Vec::new)
                    .push(idx);
            }
        }

        let mut rpc_tx: rpc_types::Transaction = self.mock_tx.tx.clone().into();
        for (lock_arg, idxs) in input_group.into_iter() {
            let init_witness_idx = idxs[0];
            let init_witness = if witnesses[init_witness_idx].raw_data().is_empty() {
                WitnessArgs::default()
            } else {
                WitnessArgs::from_slice(witnesses[init_witness_idx].raw_data().as_ref())
                    .map_err(|err| err.to_string())?
            };
            let init_witness = init_witness
                .as_builder()
                .lock(Some(Bytes::from(vec![0u8; 65])).pack())
                .build();
            let mut blake2b = new_blake2b();
            blake2b.update(tx.hash().as_slice());
            blake2b.update(&(init_witness.as_bytes().len() as u64).to_le_bytes());
            blake2b.update(&init_witness.as_bytes());
            for idx in idxs.iter().skip(1).cloned() {
                let other_witness = &witnesses[idx];
                blake2b.update(&(other_witness.len() as u64).to_le_bytes());
                blake2b.update(&other_witness.raw_data());
            }
            let mut message = [0u8; 32];
            blake2b.finalize(&mut message);
            let message = H256::from(message);

            witnesses[init_witness_idx] = init_witness.as_bytes().pack();
            rpc_tx.witnesses = witnesses
                .iter()
                .cloned()
                .map(|witness| rpc_types::JsonBytes::from_bytes(witness.raw_data()))
                .collect();
            let sig =
                signer(&lock_arg, &message, &rpc_tx).map(|data| Bytes::from(data.to_vec()))?;
            witnesses[init_witness_idx] = init_witness
                .as_builder()
                .lock(Some(sig).pack())
                .build()
                .as_bytes()
                .pack();
        }

        self.mock_tx.tx = self
            .mock_tx
            .tx
            .as_advanced_builder()
            .set_witnesses(witnesses)
            .build()
            .data();
        Ok(())
    }

    pub fn complete_tx<S, C>(
        &mut self,
        target_lock: Option<Script>,
        genesis_info: &GenesisInfo,
        signer: S,
        mut live_cell_getter: C,
    ) -> Result<(), String>
    where
        S: Fn(&H160, &H256, &rpc_types::Transaction) -> Result<[u8; 65], String>,
        C: FnMut(OutPoint) -> Result<Option<(CellOutput, Bytes, H256)>, String>,
    {
        self.add_change_output(target_lock, &mut live_cell_getter)?;
        self.fill_deps(genesis_info, &mut live_cell_getter)?;
        self.fill_witnesses(genesis_info, signer, &mut live_cell_getter)
    }

    /// Verify the transaction by local ScriptVerifier
    pub fn verify<L: MockResourceLoader>(
        &mut self,
        max_cycle: Cycle,
        loader: L,
    ) -> Result<Cycle, String> {
        let resource = Resource::from_both(self.mock_tx, loader)?;
        let tx = self.mock_tx.core_transaction();
        let rtx = {
            let mut seen_inputs = FnvHashSet::default();
            resolve_transaction(tx, &mut seen_inputs, &resource, &resource)
                .map_err(|err| format!("Resolve transaction error: {:?}", err))?
        };

        let mut verifier = TransactionScriptsVerifier::new(&rtx, &resource);
        verifier.set_debug_printer(|script_hash, message| {
            println!("script: {:x}, debug: {}", script_hash, message);
        });
        verifier
            .verify(max_cycle)
            .map_err(|err| format!("Verify script error: {:?}", err))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ckb_crypto::secp::SECP256K1;
    use ckb_hash::blake2b_256;
    use ckb_jsonrpc_types as json_types;
    use ckb_types::{
        core::{capacity_bytes, BlockView, Capacity, HeaderView},
        h256,
        packed::CellDep,
    };
    use rand::Rng;

    // NOTE: Should update when block structure changed
    const GENESIS_JSON: &str = include_str!("test-data/genesis_block.json");

    fn random_privkey() -> secp256k1::SecretKey {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let privkey_bytes: [u8; 32] = rng.gen();
            if let Ok(privkey) = secp256k1::SecretKey::from_slice(&privkey_bytes) {
                return privkey;
            }
        }
        panic!("Can not find a random private key in 1000 times");
    }

    #[test]
    fn test_verify() {
        let genesis_block: json_types::BlockView = serde_json::from_str(GENESIS_JSON).unwrap();
        let genesis_block: BlockView = genesis_block.into();
        let genesis_info = GenesisInfo::from_block(&genesis_block).unwrap();

        let privkey = random_privkey();
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &privkey);
        let lock_arg = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
            .expect("Generate hash(H160) from pubkey failed");
        let lock_script = Script::new_builder()
            .code_hash(genesis_info.sighash_type_hash().clone())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(lock_arg.as_bytes().to_vec()).pack())
            .build();

        let mut mock_tx = MockTransaction::default();
        let genesis_cellbase = genesis_block.transactions()[0].clone();
        let (dep_group_output, dep_group_data) = genesis_block.transactions()[1]
            .clone()
            .output_with_data(0)
            .unwrap();
        let (secp_output, secp_data) = genesis_cellbase.output_with_data(1).unwrap();
        let (secp_data_output, secp_data_data) = genesis_cellbase.output_with_data(3).unwrap();
        mock_tx.mock_info.cell_deps.extend(vec![
            MockCellDep {
                cell_dep: genesis_info.sighash_dep(),
                output: dep_group_output,
                data: dep_group_data,
                block_hash: H256::default(),
            },
            MockCellDep {
                cell_dep: CellDep::new_builder()
                    .out_point(OutPoint::new(genesis_cellbase.hash(), 1))
                    .build(),
                output: secp_output,
                data: secp_data,
                block_hash: H256::default(),
            },
            MockCellDep {
                cell_dep: CellDep::new_builder()
                    .out_point(OutPoint::new(genesis_cellbase.hash(), 3))
                    .build(),
                output: secp_data_output,
                data: secp_data_data,
                block_hash: H256::default(),
            },
        ]);

        let out_point = OutPoint::new(h256!("0xff01").pack(), 0);
        let input = CellInput::new(out_point, 0);
        mock_tx.mock_info.inputs.push({
            let output = CellOutput::new_builder()
                .capacity(capacity_bytes!(200).pack())
                .lock(lock_script.clone())
                .build();
            MockInput {
                input: input.clone(),
                output,
                data: Bytes::default(),
                block_hash: H256::default(),
            }
        });
        let output = CellOutput::new_builder()
            .capacity(capacity_bytes!(120).pack())
            .lock(lock_script)
            .build();
        mock_tx.tx = mock_tx
            .tx
            .as_advanced_builder()
            .input(input)
            .output(output)
            .output_data(Default::default())
            .build()
            .data();

        let signer = |target_lock_arg: &H160, tx_hash_hash: &H256, _tx: &rpc_types::Transaction| {
            if &lock_arg != target_lock_arg {
                return Err(String::from("lock arg not match"));
            }
            let message = secp256k1::Message::from_slice(tx_hash_hash.as_bytes())
                .expect("Convert to secp256k1 message failed");
            let signature = SECP256K1.sign_recoverable(&message, &privkey);
            let (recov_id, data) = signature.serialize_compact();
            let mut signature_bytes = [0u8; 65];
            signature_bytes[0..64].copy_from_slice(&data[0..64]);
            signature_bytes[64] = recov_id.to_i32() as u8;
            Ok(signature_bytes)
        };

        struct Loader;
        impl MockResourceLoader for Loader {
            fn get_header(&mut self, hash: H256) -> Result<Option<HeaderView>, String> {
                Err(format!("Can not call header getter, hash={:?}", hash))
            }
            fn get_live_cell(
                &mut self,
                out_point: OutPoint,
            ) -> Result<Option<(CellOutput, Bytes, H256)>, String> {
                Err(format!(
                    "Can not call live cell getter, out_point={:?}",
                    out_point
                ))
            }
        }
        let mut helper = MockTransactionHelper::new(&mut mock_tx);
        helper
            .complete_tx(None, &genesis_info, signer, |out_point| {
                Loader.get_live_cell(out_point)
            })
            .expect("Complete mock tx failed");
        let tx = helper.mock_tx.core_transaction();
        assert_eq!(tx.cell_deps().len(), 1, "Deps not set");
        assert_eq!(tx.outputs().len(), 2, "Output change not set");
        assert_eq!(
            Unpack::<u64>::unpack(&tx.outputs().get(1).unwrap().capacity()),
            capacity_bytes!(80).as_u64(),
            "Output change wrong capacity",
        );
        assert_eq!(
            tx.inputs().len(),
            tx.witnesses().len(),
            "Witnesses not match inputs"
        );
        helper
            .verify(u64::max_value(), Loader)
            .expect("Verify mock tx failed");
    }
}
