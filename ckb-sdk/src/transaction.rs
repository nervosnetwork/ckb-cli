use bytes::Bytes;
use ckb_core::{
    cell::{
        resolve_transaction, BlockInfo, CellMeta, CellMetaBuilder, CellProvider, CellStatus,
        HeaderProvider, HeaderStatus,
    },
    extras::BlockExt,
    header::Header,
    script::{Script, ScriptHashType},
    transaction::{
        CellInput, CellOutPoint, CellOutput, OutPoint, Transaction, TransactionBuilder, Witness,
    },
    Capacity, Cycle, Version,
};
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_script::{DataLoader, ScriptConfig, TransactionScriptsVerifier};
use fnv::FnvHashSet;
use numext_fixed_hash::{H160, H256};
use serde_derive::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::{GenesisInfo, MIN_SECP_CELL_CAPACITY};

#[derive(Clone, Serialize, Deserialize)]
pub struct MockDep {
    pub out_point: OutPoint,
    pub cell: CellOutput,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MockInput {
    pub input: CellInput,
    pub cell: CellOutput,
}

/// A wrapper transaction with mock inputs and deps
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct MockTransaction {
    pub mock_inputs: Vec<MockInput>,
    pub mock_deps: Vec<MockDep>,

    pub version: Option<Version>,
    // Load live cell as dependency from mock_deps or chain
    pub deps: Vec<OutPoint>,
    // Load live cell as input cell from mock_inputs or chain
    pub inputs: Vec<CellInput>,
    pub outputs: Vec<CellOutput>,
    pub witnesses: Vec<Witness>,
}

impl MockTransaction {
    pub fn get_input_cell<F: FnMut(OutPoint) -> Result<Option<CellOutput>, String>>(
        &self,
        input: &CellInput,
        mut live_cell_getter: F,
    ) -> Result<Option<CellOutput>, String> {
        for mock_input in &self.mock_inputs {
            if input == &mock_input.input {
                return Ok(Some(mock_input.cell.clone()));
            }
        }
        live_cell_getter(input.previous_output.clone())
    }

    pub fn get_dep_cell<F: FnMut(OutPoint) -> Result<Option<CellOutput>, String>>(
        &self,
        out_point: &OutPoint,
        mut live_cell_getter: F,
    ) -> Result<Option<CellOutput>, String> {
        for mock_dep in &self.mock_deps {
            if out_point == &mock_dep.out_point {
                return Ok(Some(mock_dep.cell.clone()));
            }
        }
        live_cell_getter(out_point.clone())
    }

    /// Generate the core transaction
    pub fn core_transaction(&self) -> Transaction {
        TransactionBuilder::default()
            .version(self.version.unwrap_or_default())
            .inputs(self.inputs.clone())
            .outputs(self.outputs.clone())
            .deps(self.deps.clone())
            .witnesses(self.witnesses.clone())
            .build()
    }
}

pub struct MockTransactionHelper<'a> {
    pub tx: &'a mut MockTransaction,
    live_cell_cache: HashMap<OutPoint, CellOutput>,
}

impl<'a> MockTransactionHelper<'a> {
    pub fn new(tx: &'a mut MockTransaction) -> MockTransactionHelper<'a> {
        MockTransactionHelper {
            tx,
            live_cell_cache: HashMap::default(),
        }
    }

    fn get_input_cell<C>(
        &mut self,
        input: &CellInput,
        live_cell_getter: C,
    ) -> Result<CellOutput, String>
    where
        C: FnMut(OutPoint) -> Result<Option<CellOutput>, String>,
    {
        let cell = match self.live_cell_cache.get(&input.previous_output) {
            Some(cell) => cell.clone(),
            None => {
                let cell = self
                    .tx
                    .get_input_cell(input, live_cell_getter)?
                    .ok_or_else(|| format!("input cell not found: {:?}", input))?;
                self.live_cell_cache
                    .insert(input.previous_output.clone(), cell.clone());
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
        C: FnMut(OutPoint) -> Result<Option<CellOutput>, String>,
    {
        let mut input_total: u64 = 0;
        let mut first_input_cell = None;
        for input in self.tx.inputs.clone() {
            let cell = self.get_input_cell(&input, &mut live_cell_getter)?;
            if first_input_cell.is_none() {
                first_input_cell = Some(cell.clone());
            }
            input_total += cell.capacity.as_u64();
        }

        let output_total: u64 = self
            .tx
            .outputs
            .iter()
            .map(|cell| cell.capacity.as_u64())
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
            let output_lock = target_lock
                .unwrap_or_else(|| first_input_cell.expect("Must have at least one input").lock);
            self.tx.outputs.push(CellOutput {
                capacity: Capacity::shannons(delta),
                data: Bytes::default(),
                lock: output_lock,
                type_: None,
            });
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
        C: FnMut(OutPoint) -> Result<Option<CellOutput>, String>,
    {
        let mut deps = self.tx.deps.iter().cloned().collect::<HashSet<_>>();
        let data_deps = self
            .tx
            .mock_deps
            .iter()
            .filter(|mock| !mock.cell.data.is_empty())
            .map(|mock| (mock.cell.data_hash(), mock.out_point.clone()))
            .collect::<HashMap<_, _>>();
        let type_deps = self
            .tx
            .mock_deps
            .iter()
            .filter(|mock| !mock.cell.data.is_empty() && mock.cell.type_.is_some())
            .map(|mock| {
                (
                    mock.cell
                        .type_
                        .as_ref()
                        .map(|script| script.hash())
                        .unwrap(),
                    mock.out_point.clone(),
                )
            })
            .collect::<HashMap<_, _>>();
        let secp_code_hash = genesis_info.secp_code_hash();
        let mut insert_dep = |hash_type, code_hash: &H256| -> Result<(), String> {
            match (hash_type, code_hash) {
                (ScriptHashType::Data, code_hash) if code_hash == secp_code_hash => {
                    deps.insert(genesis_info.secp_dep());
                }
                (ScriptHashType::Data, data_hash) => {
                    let dep = data_deps.get(data_hash).cloned().ok_or_else(|| {
                        format!("Can not find data hash in mock deps: {}", data_hash)
                    })?;
                    deps.insert(dep);
                }
                (ScriptHashType::Type, type_hash) => {
                    let dep = type_deps.get(type_hash).cloned().ok_or_else(|| {
                        format!("Can not find type hash in mock deps: {}", type_hash)
                    })?;
                    deps.insert(dep);
                }
            }
            Ok(())
        };
        for input in self.tx.inputs.clone() {
            let lock = self.get_input_cell(&input, &mut live_cell_getter)?.lock;
            insert_dep(lock.hash_type, &lock.code_hash)?;
        }
        for output in &self.tx.outputs {
            if let Some(ref script) = output.type_ {
                insert_dep(script.hash_type.clone(), &script.code_hash)?;
            }
        }
        self.tx.deps = deps.into_iter().collect::<Vec<_>>();
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
        S: Fn(&H160, &H256) -> Result<[u8; 65], String>,
        C: FnMut(OutPoint) -> Result<Option<CellOutput>, String>,
    {
        let mut witnesses = self.tx.witnesses.clone();
        while witnesses.len() < self.tx.inputs.len() {
            witnesses.push(Vec::new());
        }
        let tx_hash_hash = H256::from_slice(&blake2b_256(self.tx.core_transaction().hash()))
            .expect("Convert to H256 failed");
        let mut witness_cache: HashMap<H160, Bytes> = HashMap::default();
        for (idx, input) in self.tx.inputs.clone().into_iter().enumerate() {
            let lock = self.get_input_cell(&input, &mut live_cell_getter)?.lock;
            if &lock.code_hash == genesis_info.secp_code_hash()
                && lock.args.len() == 1
                && lock.args[0].len() == 20
            {
                let lock_arg =
                    H160::from_slice(lock.args[0].as_ref()).expect("Convert to H160 failed");
                let witness = if let Some(witness) = witness_cache.get(&lock_arg) {
                    witness.clone()
                } else {
                    let witness =
                        signer(&lock_arg, &tx_hash_hash).map(|data| Bytes::from(data.as_ref()))?;
                    witness_cache.insert(lock_arg, witness.clone());
                    witness
                };
                witnesses[idx] = vec![witness];
            }
        }
        self.tx.witnesses = witnesses;
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
        S: Fn(&H160, &H256) -> Result<[u8; 65], String>,
        C: FnMut(OutPoint) -> Result<Option<CellOutput>, String>,
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
        let tx = self.tx.core_transaction();
        let resource = Resource::from_both(&tx, self.tx, loader)?;
        let rtx = {
            let mut seen_inputs = FnvHashSet::default();
            resolve_transaction(&tx, &mut seen_inputs, &resource, &resource)
                .map_err(|err| format!("Resolve transaction error: {:?}", err))?
        };

        let script_config = ScriptConfig::default();
        let mut verifier = TransactionScriptsVerifier::new(&rtx, &resource, &script_config);
        verifier.set_debug_printer(|script_hash, message| {
            println!("script: {:x}, debug: {}", script_hash, message);
        });
        verifier
            .verify(max_cycle)
            .map_err(|err| format!("Verify script error: {:?}", err))
    }
}

fn cell_output_to_meta(
    cell_out_point: CellOutPoint,
    cell_output: CellOutput,
    block_info: Option<BlockInfo>,
) -> CellMeta {
    let data_hash = cell_output.data_hash();
    let mut cell_meta_builder = CellMetaBuilder::from_cell_output(cell_output)
        .out_point(cell_out_point.clone())
        .data_hash(data_hash);
    if let Some(block_info) = block_info {
        cell_meta_builder = cell_meta_builder.block_info(block_info);
    }
    cell_meta_builder.build()
}

pub trait MockResourceLoader {
    fn get_header(&mut self, hash: H256) -> Result<Option<Header>, String>;
    fn get_live_cell(&mut self, out_point: OutPoint) -> Result<Option<CellOutput>, String>;
}

struct Resource {
    out_point_blocks: HashMap<CellOutPoint, H256>,
    required_cells: HashMap<CellOutPoint, CellMeta>,
    required_headers: HashMap<H256, Header>,
}

impl Resource {
    fn from_both<L: MockResourceLoader>(
        tx: &Transaction,
        mock_tx: &MockTransaction,
        mut loader: L,
    ) -> Result<Resource, String> {
        let mut out_point_blocks = HashMap::default();
        let mut required_headers = HashMap::default();
        let mut required_cells = HashMap::default();
        for (input, is_dep) in tx
            .inputs()
            .iter()
            .cloned()
            .map(|input| (input, false))
            .chain(
                tx.deps()
                    .iter()
                    .map(|out_point| (CellInput::new(out_point.clone(), 0), true)),
            )
        {
            let out_point = &input.previous_output;
            let cell_out_point = out_point.cell.clone().unwrap();
            let mut block_info = None;
            if let Some(ref hash) = out_point.block_hash {
                let header = loader
                    .get_header(hash.clone())?
                    .ok_or_else(|| format!("Can not get header: {:x}", hash))?;
                block_info = Some(BlockInfo {
                    number: header.number(),
                    epoch: header.epoch(),
                    hash: header.hash().clone(),
                });
                required_headers.insert(hash.clone(), header);
                out_point_blocks.insert(cell_out_point.clone(), hash.clone());
            }

            let cell_output = if is_dep {
                mock_tx
                    .get_dep_cell(&input.previous_output, |out_point| {
                        loader.get_live_cell(out_point)
                    })?
                    .ok_or_else(|| format!("Can not get CellOutput by dep={:?}", input))?
            } else {
                mock_tx
                    .get_input_cell(&input, |out_point| loader.get_live_cell(out_point))?
                    .ok_or_else(|| format!("Can not get CellOutput by input={:?}", input))?
            };
            let cell_meta = cell_output_to_meta(cell_out_point.clone(), cell_output, block_info);
            required_cells.insert(cell_out_point, cell_meta);
        }
        Ok(Resource {
            out_point_blocks,
            required_cells,
            required_headers,
        })
    }
}

impl<'a> HeaderProvider for Resource {
    fn header(&self, out_point: &OutPoint) -> HeaderStatus {
        out_point
            .block_hash
            .as_ref()
            .map(|block_hash| {
                if let Some(block_hash) = out_point.block_hash.as_ref() {
                    let cell_out_point = out_point.cell.as_ref().unwrap();
                    if let Some(saved_block_hash) = self.out_point_blocks.get(cell_out_point) {
                        if block_hash != saved_block_hash {
                            return HeaderStatus::InclusionFaliure;
                        }
                    }
                }
                self.required_headers
                    .get(block_hash)
                    .cloned()
                    .map(|header| {
                        // TODO: query index db ensure cell_out_point match the block_hash
                        HeaderStatus::live_header(header)
                    })
                    .unwrap_or(HeaderStatus::Unknown)
            })
            .unwrap_or(HeaderStatus::Unspecified)
    }
}

impl CellProvider for Resource {
    fn cell(&self, out_point: &OutPoint) -> CellStatus {
        self.required_cells
            .get(out_point.cell.as_ref().unwrap())
            .cloned()
            .map(CellStatus::live_cell)
            .unwrap_or(CellStatus::Unknown)
    }
}

impl DataLoader for Resource {
    // load CellOutput
    fn lazy_load_cell_output(&self, cell: &CellMeta) -> CellOutput {
        cell.cell_output.clone().unwrap_or_else(|| {
            self.required_cells
                .get(&cell.out_point)
                .and_then(|cell_meta| cell_meta.cell_output.clone())
                .unwrap()
        })
    }
    // load BlockExt
    fn get_block_ext(&self, _block_hash: &H256) -> Option<BlockExt> {
        // TODO: visit this later
        None
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ReprMockDep {
    pub out_point: json_types::OutPoint,
    pub cell: json_types::CellOutput,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ReprMockInput {
    pub input: json_types::CellInput,
    pub cell: json_types::CellOutput,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ReprMockTransaction {
    pub mock_inputs: Vec<ReprMockInput>,
    pub mock_deps: Vec<ReprMockDep>,

    pub version: Option<json_types::Version>,
    pub deps: Vec<json_types::OutPoint>,
    pub inputs: Vec<json_types::CellInput>,
    pub outputs: Vec<json_types::CellOutput>,
    pub witnesses: Vec<json_types::Witness>,
}

impl From<MockDep> for ReprMockDep {
    fn from(dep: MockDep) -> ReprMockDep {
        ReprMockDep {
            out_point: dep.out_point.into(),
            cell: dep.cell.into(),
        }
    }
}
impl From<ReprMockDep> for MockDep {
    fn from(dep: ReprMockDep) -> MockDep {
        MockDep {
            out_point: dep.out_point.into(),
            cell: dep.cell.into(),
        }
    }
}

impl From<MockInput> for ReprMockInput {
    fn from(input: MockInput) -> ReprMockInput {
        ReprMockInput {
            input: input.input.into(),
            cell: input.cell.into(),
        }
    }
}
impl From<ReprMockInput> for MockInput {
    fn from(input: ReprMockInput) -> MockInput {
        MockInput {
            input: input.input.into(),
            cell: input.cell.into(),
        }
    }
}

impl From<MockTransaction> for ReprMockTransaction {
    fn from(tx: MockTransaction) -> ReprMockTransaction {
        ReprMockTransaction {
            mock_inputs: tx.mock_inputs.into_iter().map(Into::into).collect(),
            mock_deps: tx.mock_deps.into_iter().map(Into::into).collect(),
            version: tx.version.map(json_types::Version),
            deps: tx.deps.into_iter().map(Into::into).collect(),
            inputs: tx.inputs.into_iter().map(Into::into).collect(),
            outputs: tx.outputs.into_iter().map(Into::into).collect(),
            witnesses: tx.witnesses.iter().map(Into::into).collect(),
        }
    }
}
impl From<ReprMockTransaction> for MockTransaction {
    fn from(tx: ReprMockTransaction) -> MockTransaction {
        MockTransaction {
            mock_inputs: tx.mock_inputs.into_iter().map(Into::into).collect(),
            mock_deps: tx.mock_deps.into_iter().map(Into::into).collect(),
            version: tx.version.map(|v| v.0),
            deps: tx.deps.into_iter().map(Into::into).collect(),
            inputs: tx.inputs.into_iter().map(Into::into).collect(),
            outputs: tx.outputs.into_iter().map(Into::into).collect(),
            witnesses: tx.witnesses.into_iter().map(Into::into).collect(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ckb_core::{block::Block, capacity_bytes};
    use ckb_crypto::secp::SECP256K1;
    use ckb_jsonrpc_types::BlockView;
    use numext_fixed_hash::h256;
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
        let genesis_block: BlockView = serde_json::from_str(GENESIS_JSON).unwrap();
        let genesis_block: Block = genesis_block.into();
        let genesis_info = GenesisInfo::from_block(&genesis_block).unwrap();

        let privkey = random_privkey();
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &privkey);
        let lock_arg = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
            .expect("Generate hash(H160) from pubkey failed");
        let lock_script = Script::new(
            vec![Bytes::from(lock_arg.as_bytes())],
            genesis_info.secp_code_hash().clone(),
            ScriptHashType::Data,
        );

        let mut mock_tx = MockTransaction::default();
        mock_tx.mock_deps.push(MockDep {
            out_point: genesis_info.secp_dep(),
            cell: genesis_block.transactions()[0].outputs()[1].clone(),
        });

        let out_point = OutPoint::new_cell(h256!("0xff01"), 0);
        let input = CellInput::new(out_point, 0);
        mock_tx.mock_inputs.push({
            let cell = CellOutput {
                capacity: capacity_bytes!(200),
                data: Bytes::default(),
                lock: lock_script.clone(),
                type_: None,
            };
            MockInput {
                input: input.clone(),
                cell,
            }
        });
        mock_tx.inputs.push(input);
        mock_tx.outputs.push(CellOutput {
            capacity: capacity_bytes!(120),
            data: Bytes::default(),
            lock: lock_script,
            type_: None,
        });

        let signer = |target_lock_arg: &H160, tx_hash_hash: &H256| {
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
            fn get_header(&mut self, hash: H256) -> Result<Option<Header>, String> {
                Err(format!("Can not call header getter, hash={:?}", hash))
            }
            fn get_live_cell(&mut self, out_point: OutPoint) -> Result<Option<CellOutput>, String> {
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
        assert_eq!(helper.tx.deps.len(), 1, "Deps not set");
        assert_eq!(helper.tx.outputs.len(), 2, "Output change not set");
        assert_eq!(
            helper.tx.outputs[1].capacity,
            capacity_bytes!(80),
            "Output change wrong capacity",
        );
        assert_eq!(
            helper.tx.inputs.len(),
            helper.tx.witnesses.len(),
            "Witnesses not match inputs"
        );
        helper
            .verify(u64::max_value(), Loader)
            .expect("Verify mock tx failed");
    }
}
