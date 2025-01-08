use ckb_hash::new_blake2b;
use ckb_jsonrpc_types as rpc_types;
use ckb_types::{
    bytes::{Bytes, BytesMut},
    core::{ScriptHashType, TransactionBuilder, TransactionView},
    h256,
    packed::{
        self, Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, Transaction, WitnessArgs,
    },
    prelude::*,
    H160, H256,
};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;

use ckb_sdk::constants::{MULTISIG_TYPE_HASH, SECP_SIGNATURE_SIZE, SIGHASH_TYPE_HASH};
use ckb_sdk::{unlock::MultisigConfig, Since};

use crate::utils::genesis_info::GenesisInfo;

// TODO: Add dao support

/// A transaction helper handle input/output with secp256k1(sighash/multisg) lock
///  1. Sign transaction
///  2. Inspect transaction information
#[derive(Clone)]
pub struct TxHelper {
    transaction: TransactionView,
    multisig_configs: HashMap<H160, MultisigConfig>,
    // Only support sighash/multisig signatures
    signatures: HashMap<Bytes, HashSet<Bytes>>,
}

impl Default for TxHelper {
    fn default() -> TxHelper {
        TxHelper {
            transaction: TransactionBuilder::default().build(),
            multisig_configs: HashMap::default(),
            signatures: HashMap::default(),
        }
    }
}

type SignFn =
    dyn FnMut(&HashSet<H160>, &H256, &rpc_types::Transaction) -> Result<Option<[u8; 65]>, String>;

impl TxHelper {
    pub fn new(transaction: TransactionView) -> TxHelper {
        TxHelper {
            transaction,
            multisig_configs: HashMap::default(),
            signatures: HashMap::default(),
        }
    }

    pub fn transaction(&self) -> &TransactionView {
        &self.transaction
    }
    pub fn multisig_configs(&self) -> &HashMap<H160, MultisigConfig> {
        &self.multisig_configs
    }
    pub fn signatures(&self) -> &HashMap<Bytes, HashSet<Bytes>> {
        &self.signatures
    }

    pub fn clear_inputs(&mut self) {
        self.transaction = self
            .transaction
            .as_advanced_builder()
            .set_inputs(Vec::new())
            .build();
    }
    pub fn clear_outputs(&mut self) {
        self.transaction = self
            .transaction
            .as_advanced_builder()
            .set_outputs(Vec::new())
            .set_outputs_data(Vec::new())
            .build();
    }
    pub fn clear_signatures(&mut self) {
        self.signatures.clear();
    }

    pub fn add_input<F: FnMut(OutPoint, bool) -> Result<CellOutput, String>>(
        &mut self,
        out_point: OutPoint,
        since_absolute_epoch_opt: Option<u64>,
        mut get_live_cell: F,
        genesis_info: &GenesisInfo,
        skip_check: bool,
    ) -> Result<(), String> {
        let lock = get_live_cell(out_point.clone(), false)?.lock();
        check_lock_script(&lock, skip_check)?;

        let since = if let Some(number) = since_absolute_epoch_opt {
            Since::new_absolute_epoch(number).value()
        } else {
            let lock_arg = lock.args().raw_data();
            if lock.code_hash() == MULTISIG_TYPE_HASH.pack() && lock_arg.len() == 28 {
                let mut since_bytes = [0u8; 8];
                since_bytes.copy_from_slice(&lock_arg[20..]);
                u64::from_le_bytes(since_bytes)
            } else {
                0
            }
        };

        let input = CellInput::new_builder()
            .previous_output(out_point)
            .since(since.pack())
            .build();

        self.transaction = self.transaction.as_advanced_builder().input(input).build();
        let mut cell_deps: HashSet<CellDep> = HashSet::default();
        for ((code_hash, _), _) in self.input_group(get_live_cell, skip_check)?.into_iter() {
            let code_hash: H256 = code_hash.unpack();
            if code_hash == SIGHASH_TYPE_HASH {
                cell_deps.insert(genesis_info.sighash_dep());
            } else if code_hash == MULTISIG_TYPE_HASH {
                cell_deps.insert(genesis_info.multisig_dep());
            } else if !skip_check {
                panic!("Unexpected input code_hash: {:#x}", code_hash);
            }
        }
        self.transaction = self
            .transaction
            .as_advanced_builder()
            .set_cell_deps(cell_deps.into_iter().collect())
            .build();
        Ok(())
    }

    pub fn add_output(&mut self, output: CellOutput, data: Bytes) {
        // TODO: Check output(lock-script/type-script)
        self.transaction = self
            .transaction
            .as_advanced_builder()
            .output(output)
            .output_data(data.pack())
            .build()
    }

    pub fn add_signature(&mut self, lock_arg: Bytes, signature: Bytes) -> Result<bool, String> {
        if lock_arg.len() != 20 && lock_arg.len() != 28 {
            return Err(format!(
                "Invalid lock_arg(0x{}) length({}) with signature(0x{})",
                hex_string(lock_arg.as_ref()),
                lock_arg.len(),
                hex_string(signature.as_ref()),
            ));
        }
        if signature.len() != SECP_SIGNATURE_SIZE {
            return Err(format!(
                "Invalid signature length({}) for lock_arg(0x{})",
                signature.len(),
                hex_string(lock_arg.as_ref()),
            ));
        }

        Ok(self
            .signatures
            .entry(lock_arg)
            .or_default()
            .insert(signature))
    }
    pub fn add_multisig_config(&mut self, config: MultisigConfig) {
        self.multisig_configs.insert(config.hash160(), config);
    }

    pub fn input_group<F: FnMut(OutPoint, bool) -> Result<CellOutput, String>>(
        &self,
        mut get_live_cell: F,
        skip_check: bool,
    ) -> Result<HashMap<(Byte32, Bytes), Vec<usize>>, String> {
        let mut input_group: HashMap<(Byte32, Bytes), Vec<usize>> = HashMap::default();
        for (idx, input) in self.transaction.inputs().into_iter().enumerate() {
            let lock = get_live_cell(input.previous_output(), false)?.lock();
            check_lock_script(&lock, skip_check)
                .map_err(|err| format!("Input(no.{}) {}", idx + 1, err))?;

            let lock_arg = lock.args().raw_data();
            let code_hash = lock.code_hash();
            if code_hash == MULTISIG_TYPE_HASH.pack() {
                let hash160 = H160::from_slice(&lock_arg[..20]).unwrap();
                if !self.multisig_configs.contains_key(&hash160) {
                    return Err(format!(
                        "No mutisig config found for input(no.{}) lock_arg prefix: {:#x}",
                        idx + 1,
                        hash160,
                    ));
                }
            }
            input_group
                .entry((code_hash, lock_arg))
                .or_default()
                .push(idx);
        }
        Ok(input_group)
    }

    pub fn init_witnesses(&self) -> Vec<packed::Bytes> {
        let mut witnesses: Vec<packed::Bytes> = self.transaction.witnesses().into_iter().collect();
        while witnesses.len() < self.transaction.inputs().len() {
            witnesses.push(Bytes::new().pack());
        }
        witnesses
    }

    pub fn sign_inputs<C>(
        &self,
        signer: &mut SignFn,
        get_live_cell: C,
        skip_check: bool,
    ) -> Result<HashMap<Bytes, Bytes>, String>
    where
        C: FnMut(OutPoint, bool) -> Result<CellOutput, String>,
    {
        let all_sighash_lock_args = self
            .multisig_configs
            .iter()
            .map(|(hash160, config)| {
                (
                    hash160.clone(),
                    config
                        .sighash_addresses()
                        .iter()
                        .cloned()
                        .collect::<HashSet<H160>>(),
                )
            })
            .collect::<HashMap<_, _>>();

        let witnesses = self.init_witnesses();
        let input_size = self.transaction.inputs().len();
        let mut signatures: HashMap<Bytes, Bytes> = Default::default();
        for ((code_hash, lock_arg), idxs) in
            self.input_group(get_live_cell, skip_check)?.into_iter()
        {
            if code_hash != SIGHASH_TYPE_HASH.pack() && code_hash != MULTISIG_TYPE_HASH.pack() {
                continue;
            }

            let multisig_hash160 = H160::from_slice(&lock_arg[..20]).unwrap();
            let lock_args = if code_hash == MULTISIG_TYPE_HASH.pack() {
                all_sighash_lock_args
                    .get(&multisig_hash160)
                    .unwrap()
                    .clone()
            } else {
                let mut lock_args = HashSet::default();
                lock_args.insert(H160::from_slice(lock_arg.as_ref()).unwrap());
                lock_args
            };
            if signer(&lock_args, &h256!("0x0"), &Transaction::default().into())?.is_some() {
                let signature = build_signature(
                    &self.transaction,
                    input_size,
                    &idxs,
                    &witnesses,
                    self.multisig_configs.get(&multisig_hash160),
                    |message: &H256, tx: &rpc_types::Transaction| {
                        signer(&lock_args, message, tx).map(|sig| sig.unwrap())
                    },
                )?;
                signatures.insert(lock_arg, signature);
            }
        }
        Ok(signatures)
    }

    pub fn build_tx<F: FnMut(OutPoint, bool) -> Result<CellOutput, String>>(
        &self,
        get_live_cell: F,
        skip_check: bool,
    ) -> Result<TransactionView, String> {
        let mut witnesses = self.init_witnesses();
        for ((code_hash, lock_arg), idxs) in
            self.input_group(get_live_cell, skip_check)?.into_iter()
        {
            if skip_check && !self.signatures.contains_key(&lock_arg) {
                continue;
            }
            let signatures = self.signatures.get(&lock_arg).ok_or_else(|| {
                let lock_script = rpc_types::Script::from(
                    Script::new_builder()
                        .hash_type(ScriptHashType::Type.into())
                        .code_hash(code_hash.clone())
                        .args(lock_arg.pack())
                        .build(),
                );
                format!(
                    "Missing signatures for lock_script: {}",
                    serde_json::to_string_pretty(&lock_script).unwrap()
                )
            })?;
            let lock_field = if code_hash == MULTISIG_TYPE_HASH.pack() {
                let hash160 = H160::from_slice(&lock_arg[..20]).unwrap();
                let multisig_config = self.multisig_configs.get(&hash160).unwrap();
                let threshold = multisig_config.threshold() as usize;
                let mut data = BytesMut::from(&multisig_config.to_witness_data()[..]);
                if signatures.len() != threshold {
                    return Err(format!(
                        "Invalid multisig signature length for lock_arg: 0x{}, got: {}, expected: {}",
                        hex_string(&lock_arg),
                        signatures.len(),
                        threshold,
                    ));
                }
                for signature in signatures {
                    data.extend_from_slice(signature.as_ref());
                }
                data.freeze()
            } else {
                if signatures.len() != 1 {
                    return Err(format!(
                        "Invalid secp signature length for lock_arg: 0x{}, got: {}, expected: 1",
                        hex_string(&lock_arg),
                        signatures.len(),
                    ));
                }
                signatures.iter().last().unwrap().clone()
            };

            let init_witness = if witnesses[idxs[0]].raw_data().is_empty() {
                WitnessArgs::default()
            } else {
                WitnessArgs::from_slice(witnesses[idxs[0]].raw_data().as_ref())
                    .map_err(|err| err.to_string())?
            };
            witnesses[idxs[0]] = init_witness
                .as_builder()
                .lock(Some(lock_field).pack())
                .build()
                .as_bytes()
                .pack();
        }
        Ok(self
            .transaction
            .as_advanced_builder()
            .set_witnesses(witnesses)
            .build())
    }

    pub fn check_tx<F: FnMut(OutPoint, bool) -> Result<CellOutput, String>>(
        &self,
        mut get_live_cell: F,
    ) -> Result<(u64, u64), String> {
        // Check inputs
        let mut previous_outputs: HashSet<OutPoint> = HashSet::default();
        let mut input_total: u64 = 0;
        for (i, input) in self.transaction.inputs().into_iter().enumerate() {
            let out_point = input.previous_output();
            if previous_outputs.contains(&out_point) {
                return Err(format!("Already have input: {}", out_point));
            } else {
                previous_outputs.insert(out_point.clone());
            }
            let output = get_live_cell(out_point, false)?;
            let capacity: u64 = output.capacity().unpack();
            input_total += capacity;

            check_lock_script(&output.lock(), false)
                .map_err(|err| format!("Input(no.{}) {}", i + 1, err))?;
        }

        // Check output
        let mut output_total: u64 = 0;
        for (i, output) in self.transaction.outputs().into_iter().enumerate() {
            let capacity: u64 = output.capacity().unpack();
            output_total += capacity;

            check_lock_script(&output.lock(), false)
                .map_err(|err| format!("Output(no.{}) {}", i + 1, err))?;
        }

        Ok((input_total, output_total))
    }
}

pub type SignerFn = Box<
    dyn FnMut(&HashSet<H160>, &H256, &rpc_types::Transaction) -> Result<Option<[u8; 65]>, String>,
>;

pub fn check_lock_script(lock: &Script, skip_check: bool) -> Result<(), String> {
    #[derive(Eq, PartialEq)]
    enum CodeHashCategory {
        Sighash,
        Multisig,
        Other,
    }

    let code_hash: H256 = lock.code_hash().unpack();
    let hash_type: ScriptHashType = lock.hash_type().try_into().expect("hash_type");
    let lock_args = lock.args().raw_data();

    let code_hash_category = if code_hash == SIGHASH_TYPE_HASH {
        CodeHashCategory::Sighash
    } else if code_hash == MULTISIG_TYPE_HASH {
        CodeHashCategory::Multisig
    } else {
        CodeHashCategory::Other
    };
    let hash_type_str = match hash_type {
        ScriptHashType::Type => "type",
        ScriptHashType::Data => "data",
        ScriptHashType::Data1 => "data1",
        ScriptHashType::Data2 => "data2",
    };

    match (code_hash_category, hash_type, lock_args.len()) {
        (CodeHashCategory::Sighash, ScriptHashType::Type, 20) => Ok(()),
        (CodeHashCategory::Multisig, ScriptHashType::Type, 20) => Ok(()),
        (CodeHashCategory::Multisig, ScriptHashType::Type, 28) => Ok(()),
        (CodeHashCategory::Sighash, _, _) => Err(format!(
            "Invalid sighash lock script, hash_type: {}, args.length: {}",
            hash_type_str,
            lock_args.len()
        )),
        (CodeHashCategory::Multisig, _, _) => Err(format!(
            "Invalid multisig lock script, hash_type: {}, args.length: {}",
            hash_type_str,
            lock_args.len()
        )),
        (CodeHashCategory::Other, _, _) if skip_check => Ok(()),
        (CodeHashCategory::Other, _, _) => Err(format!(
            "invalid lock script code_hash: {:#x}, hash_type: {}, args.length: {}",
            code_hash,
            hash_type_str,
            lock_args.len(),
        )),
    }
}

pub fn build_signature<
    S: FnMut(&H256, &rpc_types::Transaction) -> Result<[u8; SECP_SIGNATURE_SIZE], String>,
>(
    tx: &TransactionView,
    input_size: usize,
    input_group_idxs: &[usize],
    witnesses: &[packed::Bytes],
    multisig_config_opt: Option<&MultisigConfig>,
    mut signer: S,
) -> Result<Bytes, String> {
    let init_witness_idx = input_group_idxs[0];
    let init_witness = if witnesses[init_witness_idx].raw_data().is_empty() {
        WitnessArgs::default()
    } else {
        WitnessArgs::from_slice(witnesses[init_witness_idx].raw_data().as_ref())
            .map_err(|err| err.to_string())?
    };

    let init_witness = if let Some(multisig_config) = multisig_config_opt {
        let lock_without_sig = {
            let sig_len = (multisig_config.threshold() as usize) * SECP_SIGNATURE_SIZE;
            let mut data = BytesMut::from(&multisig_config.to_witness_data()[..]);
            data.extend_from_slice(vec![0u8; sig_len].as_slice());
            data.freeze()
        };
        init_witness
            .as_builder()
            .lock(Some(lock_without_sig).pack())
            .build()
    } else {
        init_witness
            .as_builder()
            .lock(Some(Bytes::from(vec![0u8; SECP_SIGNATURE_SIZE])).pack())
            .build()
    };

    let mut blake2b = new_blake2b();
    blake2b.update(tx.hash().as_slice());
    blake2b.update(&(init_witness.as_bytes().len() as u64).to_le_bytes());
    blake2b.update(&init_witness.as_bytes());
    for idx in input_group_idxs.iter().skip(1).cloned() {
        let other_witness: &packed::Bytes = &witnesses[idx];
        blake2b.update(&(other_witness.len() as u64).to_le_bytes());
        blake2b.update(&other_witness.raw_data());
    }
    for outter_witness in &witnesses[input_size..witnesses.len()] {
        blake2b.update(&(outter_witness.len() as u64).to_le_bytes());
        blake2b.update(&outter_witness.raw_data());
    }
    let mut message = [0u8; 32];
    blake2b.finalize(&mut message);
    let message = H256::from(message);
    let mut new_witnesses = witnesses.to_vec();
    new_witnesses[init_witness_idx] = init_witness.as_bytes().pack();
    let new_tx = tx
        .as_advanced_builder()
        .set_witnesses(new_witnesses)
        .build();
    signer(&message, &new_tx.data().into()).map(|data| Bytes::from(data.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ckb_types::{h160, h256};

    #[test]
    fn test_check_lock_script() {
        let lock_sighash_ok = packed::Script::new_builder()
            .args(Bytes::from(h160!("0x33").as_bytes().to_vec()).pack())
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .build();
        let lock_sighash_bad_hash_type = lock_sighash_ok
            .clone()
            .as_builder()
            .hash_type(ScriptHashType::Data.into())
            .build();
        let lock_sighash_bad_args_1 = lock_sighash_ok
            .clone()
            .as_builder()
            .args(Bytes::from(h256!("0x33").as_bytes().to_vec()).pack())
            .build();
        let lock_sighash_bad_args_2 = lock_sighash_ok
            .clone()
            .as_builder()
            .args(Bytes::from(h256!("0x33").as_bytes()[0..12].to_vec()).pack())
            .build();

        let lock_multisig_ok = packed::Script::new_builder()
            .args(Bytes::from(h160!("0x33").as_bytes().to_vec()).pack())
            .code_hash(MULTISIG_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .build();
        let lock_multisig_ok_args_28 = lock_multisig_ok
            .clone()
            .as_builder()
            .args(Bytes::from(h256!("0x33").as_bytes()[0..28].to_vec()).pack())
            .build();
        let lock_multisig_bad_hash_type = lock_multisig_ok
            .clone()
            .as_builder()
            .hash_type(ScriptHashType::Data.into())
            .build();
        let lock_multisig_bad_args_1 = lock_multisig_ok
            .clone()
            .as_builder()
            .args(Bytes::from(h256!("0x33").as_bytes().to_vec()).pack())
            .build();
        let lock_multisig_bad_args_2 = lock_multisig_ok
            .clone()
            .as_builder()
            .args(Bytes::from(h256!("0x33").as_bytes()[0..12].to_vec()).pack())
            .build();

        let lock_other_type = packed::Script::new_builder()
            .args(Bytes::from(h160!("0x33").as_bytes().to_vec()).pack())
            .code_hash(h256!("0xdeadbeef").pack())
            .hash_type(ScriptHashType::Type.into())
            .build();
        let lock_other_data = packed::Script::new_builder()
            .args(Bytes::from(h256!("0x33").as_bytes().to_vec()).pack())
            .code_hash(h256!("0xdeadbeef").pack())
            .hash_type(ScriptHashType::Data.into())
            .build();

        for (script, is_ok, skip_check) in &[
            (&lock_sighash_ok, true, false),
            (&lock_sighash_ok, true, true),
            (&lock_sighash_bad_hash_type, false, false),
            (&lock_sighash_bad_hash_type, false, true),
            (&lock_sighash_bad_args_1, false, false),
            (&lock_sighash_bad_args_1, false, true),
            (&lock_sighash_bad_args_2, false, false),
            (&lock_sighash_bad_args_2, false, true),
            (&lock_multisig_ok, true, false),
            (&lock_multisig_ok, true, true),
            (&lock_multisig_ok_args_28, true, false),
            (&lock_multisig_ok_args_28, true, true),
            (&lock_multisig_bad_hash_type, false, false),
            (&lock_multisig_bad_hash_type, false, true),
            (&lock_multisig_bad_args_1, false, false),
            (&lock_multisig_bad_args_1, false, true),
            (&lock_multisig_bad_args_2, false, false),
            (&lock_multisig_bad_args_2, false, true),
            (&lock_other_type, true, true),
            (&lock_other_type, false, false),
            (&lock_other_data, true, true),
            (&lock_other_data, false, false),
        ] {
            assert_eq!(check_lock_script(script, *skip_check).is_ok(), *is_ok);
        }
    }
}
