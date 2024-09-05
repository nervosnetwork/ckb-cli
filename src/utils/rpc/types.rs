use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;

pub use ckb_jsonrpc_types::{
    self as rpc_types, Byte32, DepType, JsonBytes, ProposalShortId, ScriptHashType, TxPoolIds,
    TxStatus, Uint128,
};
use ckb_types::{core, packed, prelude::*, H256, U256};

use super::primitive::{Capacity, EpochNumberWithFraction, Since, Timestamp};
use crate::utils::rpc::json_rpc;
use ckb_sdk::constants::{DAO_TYPE_HASH, MULTISIG_TYPE_HASH, SIGHASH_TYPE_HASH};
use ckb_sdk::rpc::ckb_indexer::{self, CellType, Order};

type Version = u32;
type BlockNumber = u64;
type EpochNumber = u64;
type Cycle = u64;
type AlertId = u32;
type AlertPriority = u32;
type Uint32 = u32;
type Uint64 = u64;

/// Represents the ratio `numerator / denominator`, where `numerator` and `denominator` are both
/// unsigned 64-bit integers.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Ratio {
    /// Numerator.
    pub numer: Uint64,
    /// Denominator.
    pub denom: Uint64,
}

impl From<rpc_types::Ratio> for Ratio {
    fn from(value: ckb_jsonrpc_types::Ratio) -> Self {
        Self {
            numer: value.numer.value(),
            denom: value.denom.value(),
        }
    }
}

// ===============
//  blockchain.rs
// ===============
#[derive(Clone, Default, Deserialize, PartialEq, Eq, Hash, Debug)]
#[serde(deny_unknown_fields)]
pub struct Script {
    pub code_hash: H256,
    pub hash_type: ScriptHashType,
    pub args: JsonBytes,
}
impl From<rpc_types::Script> for Script {
    fn from(json: rpc_types::Script) -> Script {
        Script {
            code_hash: json.code_hash,
            hash_type: json.hash_type,
            args: json.args,
        }
    }
}
impl From<Script> for packed::Script {
    fn from(json: Script) -> Self {
        let Script {
            args,
            code_hash,
            hash_type,
        } = json;
        let hash_type: core::ScriptHashType = hash_type.into();
        packed::Script::new_builder()
            .args(args.into_bytes().pack())
            .code_hash(code_hash.pack())
            .hash_type(hash_type.into())
            .build()
    }
}
impl From<packed::Script> for Script {
    fn from(input: packed::Script) -> Script {
        Script {
            code_hash: input.code_hash().unpack(),
            args: JsonBytes::from_bytes(input.args().unpack()),
            hash_type: core::ScriptHashType::try_from(input.hash_type())
                .expect("checked data")
                .into(),
        }
    }
}
impl Serialize for Script {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut rgb = serializer.serialize_struct("Script", 3)?;
        let code_hash_suffix = if self.hash_type == ScriptHashType::Type {
            if self.code_hash == SIGHASH_TYPE_HASH {
                String::from(" (sighash)")
            } else if self.code_hash == MULTISIG_TYPE_HASH {
                String::from(" (multisig)")
            } else if self.code_hash == DAO_TYPE_HASH {
                String::from(" (dao)")
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        let code_hash_string = format!("{:#x}{}", self.code_hash, code_hash_suffix);
        rgb.serialize_field("code_hash", &code_hash_string)?;
        rgb.serialize_field("args", &self.args)?;
        rgb.serialize_field("hash_type", &self.hash_type)?;
        rgb.end()
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
#[serde(deny_unknown_fields)]
pub struct CellOutput {
    pub capacity: Capacity,
    pub lock: Script,
    #[serde(rename = "type")]
    pub type_: Option<Script>,
}
impl From<rpc_types::CellOutput> for CellOutput {
    fn from(json: rpc_types::CellOutput) -> CellOutput {
        CellOutput {
            capacity: json.capacity.into(),
            lock: json.lock.into(),
            type_: json.type_.map(Into::into),
        }
    }
}
impl From<CellOutput> for packed::CellOutput {
    fn from(json: CellOutput) -> packed::CellOutput {
        let CellOutput {
            capacity,
            lock,
            type_,
        } = json;
        let type_builder = packed::ScriptOpt::new_builder();
        let type_ = match type_ {
            Some(type_) => type_builder.set(Some(type_.into())),
            None => type_builder,
        }
        .build();
        packed::CellOutput::new_builder()
            .capacity(capacity.0.pack())
            .lock(lock.into())
            .type_(type_)
            .build()
    }
}
impl From<packed::CellOutput> for CellOutput {
    fn from(input: packed::CellOutput) -> CellOutput {
        let capacity: u64 = input.capacity().unpack();
        CellOutput {
            capacity: capacity.into(),
            lock: input.lock().into(),
            type_: input.type_().to_opt().map(Into::into),
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
#[serde(deny_unknown_fields)]
pub struct OutPoint {
    pub tx_hash: H256,
    pub index: Uint32,
}
impl From<rpc_types::OutPoint> for OutPoint {
    fn from(json: rpc_types::OutPoint) -> OutPoint {
        OutPoint {
            tx_hash: json.tx_hash,
            index: json.index.into(),
        }
    }
}
impl From<OutPoint> for packed::OutPoint {
    fn from(json: OutPoint) -> Self {
        let OutPoint { tx_hash, index } = json;
        packed::OutPoint::new_builder()
            .tx_hash(tx_hash.pack())
            .index(index.pack())
            .build()
    }
}
impl From<packed::OutPoint> for OutPoint {
    fn from(input: packed::OutPoint) -> OutPoint {
        let index: u32 = input.index().unpack();
        OutPoint {
            tx_hash: input.tx_hash().unpack(),
            index,
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
#[serde(deny_unknown_fields)]
pub struct CellInput {
    pub since: Since,
    pub previous_output: OutPoint,
}
impl From<rpc_types::CellInput> for CellInput {
    fn from(json: rpc_types::CellInput) -> CellInput {
        CellInput {
            since: json.since.into(),
            previous_output: json.previous_output.into(),
        }
    }
}
impl From<CellInput> for packed::CellInput {
    fn from(json: CellInput) -> Self {
        let CellInput {
            previous_output,
            since,
        } = json;
        packed::CellInput::new_builder()
            .previous_output(previous_output.into())
            .since(since.0.pack())
            .build()
    }
}
impl From<packed::CellInput> for CellInput {
    fn from(input: packed::CellInput) -> CellInput {
        let since: u64 = input.since().unpack();
        CellInput {
            previous_output: input.previous_output().into(),
            since: since.into(),
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
#[serde(deny_unknown_fields)]
pub struct CellDep {
    pub out_point: OutPoint,
    pub dep_type: DepType,
}
impl From<rpc_types::CellDep> for CellDep {
    fn from(json: rpc_types::CellDep) -> CellDep {
        CellDep {
            out_point: json.out_point.into(),
            dep_type: json.dep_type,
        }
    }
}
impl From<CellDep> for packed::CellDep {
    fn from(json: CellDep) -> Self {
        let CellDep {
            out_point,
            dep_type,
        } = json;
        let dep_type: core::DepType = dep_type.into();
        packed::CellDep::new_builder()
            .out_point(out_point.into())
            .dep_type(dep_type.into())
            .build()
    }
}
impl From<packed::CellDep> for CellDep {
    fn from(input: packed::CellDep) -> Self {
        CellDep {
            out_point: input.out_point().into(),
            dep_type: core::DepType::try_from(input.dep_type())
                .expect("checked data")
                .into(),
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    pub version: Version,
    pub cell_deps: Vec<CellDep>,
    pub header_deps: Vec<H256>,
    pub inputs: Vec<CellInput>,
    pub outputs: Vec<CellOutput>,
    pub outputs_data: Vec<JsonBytes>,
    pub witnesses: Vec<JsonBytes>,
}
impl From<rpc_types::Transaction> for Transaction {
    fn from(json: rpc_types::Transaction) -> Transaction {
        Transaction {
            version: json.version.into(),
            cell_deps: json.cell_deps.into_iter().map(Into::into).collect(),
            header_deps: json.header_deps,
            inputs: json.inputs.into_iter().map(Into::into).collect(),
            outputs: json.outputs.into_iter().map(Into::into).collect(),
            outputs_data: json.outputs_data,
            witnesses: json.witnesses,
        }
    }
}
impl From<Transaction> for packed::Transaction {
    fn from(json: Transaction) -> Self {
        let Transaction {
            version,
            cell_deps,
            header_deps,
            inputs,
            outputs,
            witnesses,
            outputs_data,
        } = json;
        let raw = packed::RawTransaction::new_builder()
            .version(version.pack())
            .cell_deps(cell_deps.into_iter().map(Into::into).pack())
            .header_deps(header_deps.iter().map(Pack::pack).pack())
            .inputs(inputs.into_iter().map(Into::into).pack())
            .outputs(outputs.into_iter().map(Into::into).pack())
            .outputs_data(outputs_data.into_iter().map(Into::into).pack())
            .build();
        packed::Transaction::new_builder()
            .raw(raw)
            .witnesses(witnesses.into_iter().map(Into::into).pack())
            .build()
    }
}
impl From<packed::Transaction> for Transaction {
    fn from(input: packed::Transaction) -> Self {
        let raw = input.raw();
        Self {
            version: raw.version().unpack(),
            cell_deps: raw.cell_deps().into_iter().map(Into::into).collect(),
            header_deps: raw
                .header_deps()
                .into_iter()
                .map(|d| Unpack::<H256>::unpack(&d))
                .collect(),
            inputs: raw.inputs().into_iter().map(Into::into).collect(),
            outputs: raw.outputs().into_iter().map(Into::into).collect(),
            outputs_data: raw.outputs_data().into_iter().map(Into::into).collect(),
            witnesses: input.witnesses().into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct TransactionView {
    #[serde(flatten)]
    pub inner: Transaction,
    pub hash: H256,
}
impl From<rpc_types::TransactionView> for TransactionView {
    fn from(json: rpc_types::TransactionView) -> TransactionView {
        TransactionView {
            inner: json.inner.into(),
            hash: json.hash,
        }
    }
}

/// The enum `Either` with variants `Left` and `Right` is a general purpose
/// sum type with two cases.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
#[serde(untagged)]
pub enum Either<L, R> {
    /// A value of type `L`.
    Left(L),
    /// A value of type `R`.
    Right(R),
}

/// This is a wrapper for JSON serialization to select the format between Json and Hex.
///
/// ## Examples
///
/// `ResponseFormat<BlockView>` returns the block in its Json format or molecule serialized
/// Hex format.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
#[serde(transparent)]
pub struct ResponseFormat<V> {
    /// The inner value.
    pub inner: Either<V, JsonBytes>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct TransactionWithStatus {
    /// The transaction.
    pub transaction: Option<TransactionView>,
    /// The transaction consumed cycles.
    pub cycles: Option<Cycle>,
    /// The Transaction status.
    pub tx_status: TxStatus,
}
impl TryFrom<rpc_types::TransactionWithStatusResponse> for TransactionWithStatus {
    type Error = String;
    fn try_from(
        json: rpc_types::TransactionWithStatusResponse,
    ) -> Result<TransactionWithStatus, Self::Error> {
        Ok(TransactionWithStatus {
            transaction: json
                .transaction
                .map(|tx| match tx.inner {
                    rpc_types::Either::Left(v) => Ok(TransactionView::from(v)),
                    rpc_types::Either::Right(bytes) => {
                        packed::TransactionReader::from_slice(bytes.as_bytes())
                            .map(|reader| {
                                rpc_types::TransactionView::from(reader.to_entity().into_view())
                                    .into()
                            })
                            .map_err(|err| {
                                format!("invalid molecule encoded TransactionView: {}", err)
                            })
                    }
                })
                .transpose()?,
            cycles: json.cycles.map(|c| c.into()),
            tx_status: json.tx_status,
        })
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct PackedTransactionWithStatus {
    /// The transaction.
    pub transaction: Option<JsonBytes>,
    /// The transaction consumed cycles.
    pub cycles: Option<Cycle>,
    /// The Transaction status.
    pub tx_status: TxStatus,
}
impl TryFrom<rpc_types::TransactionWithStatusResponse> for PackedTransactionWithStatus {
    type Error = String;
    fn try_from(
        json: rpc_types::TransactionWithStatusResponse,
    ) -> Result<PackedTransactionWithStatus, Self::Error> {
        Ok(PackedTransactionWithStatus {
            transaction: json
                .transaction
                .map(|tx| match tx.inner {
                    rpc_types::Either::Left(_v) => Err("does not get packed result".to_string()),
                    rpc_types::Either::Right(bytes) => Ok(bytes),
                })
                .transpose()?,
            cycles: json.cycles.map(|c| c.into()),
            tx_status: json.tx_status,
        })
    }
}

/// The JSON view of a transaction as well as its status.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct TransactionWithStatusResponse {
    /// The transaction.
    pub transaction: Option<ResponseFormat<TransactionView>>,
    /// The Transaction status.
    pub tx_status: TxStatus,
}
impl From<rpc_types::TransactionWithStatusResponse> for TransactionWithStatusResponse {
    fn from(json: rpc_types::TransactionWithStatusResponse) -> TransactionWithStatusResponse {
        TransactionWithStatusResponse {
            transaction: json.transaction.map(|tx| match tx.inner {
                rpc_types::Either::Left(v) => ResponseFormat {
                    inner: Either::Left(v.into()),
                },
                rpc_types::Either::Right(bytes) => ResponseFormat {
                    inner: Either::Right(bytes),
                },
            }),
            tx_status: json.tx_status,
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub version: Version,
    pub compact_target: rpc_types::Uint32,
    pub timestamp: Timestamp,
    pub number: BlockNumber,
    pub epoch: EpochNumberWithFraction,
    pub parent_hash: H256,
    pub transactions_root: H256,
    pub proposals_hash: H256,
    pub extra_hash: H256,
    pub dao: Byte32,
    pub nonce: Uint128,
}
impl From<rpc_types::Header> for Header {
    fn from(json: rpc_types::Header) -> Header {
        Header {
            version: json.version.into(),
            compact_target: json.compact_target,
            timestamp: json.timestamp.into(),
            number: json.number.into(),
            epoch: json.epoch.into(),
            parent_hash: json.parent_hash,
            transactions_root: json.transactions_root,
            proposals_hash: json.proposals_hash,
            extra_hash: json.extra_hash,
            dao: json.dao,
            nonce: json.nonce,
        }
    }
}
impl From<Header> for packed::Header {
    fn from(json: Header) -> Self {
        let Header {
            version,
            parent_hash,
            timestamp,
            number,
            epoch,
            transactions_root,
            proposals_hash,
            compact_target,
            extra_hash,
            dao,
            nonce,
        } = json;
        let raw = packed::RawHeader::new_builder()
            .version(version.pack())
            .parent_hash(parent_hash.pack())
            .timestamp(timestamp.0.pack())
            .number(number.pack())
            .epoch(epoch.0.pack())
            .transactions_root(transactions_root.pack())
            .proposals_hash(proposals_hash.pack())
            .compact_target(compact_target.pack())
            .extra_hash(extra_hash.pack())
            .dao(dao.into())
            .build();
        packed::Header::new_builder()
            .raw(raw)
            .nonce(nonce.pack())
            .build()
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct HeaderView {
    #[serde(flatten)]
    pub inner: Header,
    pub hash: H256,
}
impl From<rpc_types::HeaderView> for HeaderView {
    fn from(json: rpc_types::HeaderView) -> HeaderView {
        HeaderView {
            inner: json.inner.into(),
            hash: json.hash,
        }
    }
}
impl From<HeaderView> for core::HeaderView {
    fn from(input: HeaderView) -> Self {
        let header: packed::Header = input.inner.into();
        header.into_view()
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
#[serde(deny_unknown_fields)]
pub struct UncleBlock {
    pub header: Header,
    pub proposals: Vec<ProposalShortId>,
}
impl From<rpc_types::UncleBlock> for UncleBlock {
    fn from(json: rpc_types::UncleBlock) -> UncleBlock {
        UncleBlock {
            header: json.header.into(),
            proposals: json.proposals,
        }
    }
}
impl From<UncleBlock> for packed::UncleBlock {
    fn from(json: UncleBlock) -> Self {
        let UncleBlock { header, proposals } = json;
        packed::UncleBlock::new_builder()
            .header(header.into())
            .proposals(proposals.into_iter().map(Into::into).pack())
            .build()
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct UncleBlockView {
    pub header: HeaderView,
    pub proposals: Vec<ProposalShortId>,
}
impl From<rpc_types::UncleBlockView> for UncleBlockView {
    fn from(json: rpc_types::UncleBlockView) -> UncleBlockView {
        UncleBlockView {
            header: json.header.into(),
            proposals: json.proposals,
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub header: Header,
    pub uncles: Vec<UncleBlock>,
    pub transactions: Vec<Transaction>,
    pub proposals: Vec<ProposalShortId>,
}
impl From<rpc_types::Block> for Block {
    fn from(json: rpc_types::Block) -> Block {
        Block {
            header: json.header.into(),
            uncles: json.uncles.into_iter().map(Into::into).collect(),
            transactions: json.transactions.into_iter().map(Into::into).collect(),
            proposals: json.proposals,
        }
    }
}
impl From<Block> for packed::Block {
    fn from(json: Block) -> Self {
        let Block {
            header,
            uncles,
            transactions,
            proposals,
        } = json;
        packed::Block::new_builder()
            .header(header.into())
            .uncles(uncles.into_iter().map(Into::into).pack())
            .transactions(transactions.into_iter().map(Into::into).pack())
            .proposals(proposals.into_iter().map(Into::into).pack())
            .build()
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct BlockView {
    pub header: HeaderView,
    pub uncles: Vec<UncleBlockView>,
    pub transactions: Vec<TransactionView>,
    pub proposals: Vec<ProposalShortId>,
}
impl From<rpc_types::BlockView> for BlockView {
    fn from(json: rpc_types::BlockView) -> BlockView {
        BlockView {
            header: json.header.into(),
            uncles: json.uncles.into_iter().map(Into::into).collect(),
            transactions: json.transactions.into_iter().map(Into::into).collect(),
            proposals: json.proposals,
        }
    }
}
impl From<BlockView> for core::BlockView {
    fn from(input: BlockView) -> Self {
        let BlockView {
            header,
            uncles,
            transactions,
            proposals,
        } = input;
        let block = Block {
            header: header.inner,
            uncles: uncles
                .into_iter()
                .map(|u| {
                    let UncleBlockView { header, proposals } = u;
                    UncleBlock {
                        header: header.inner,
                        proposals,
                    }
                })
                .collect(),
            transactions: transactions.into_iter().map(|tx| tx.inner).collect(),
            proposals,
        };
        let block: packed::Block = block.into();
        block.into_view()
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct BlockResponse {
    pub block: BlockView,
    pub cycles: Vec<Cycle>,
}

impl From<(ckb_jsonrpc_types::BlockView, Vec<Cycle>)> for BlockResponse {
    fn from(orig: (ckb_jsonrpc_types::BlockView, Vec<Cycle>)) -> BlockResponse {
        let (block, cycles) = orig;
        BlockResponse {
            block: block.into(),
            cycles,
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct PackedBlockResponse {
    pub block: JsonBytes,
    pub cycles: Vec<Cycle>,
}

impl From<(ckb_jsonrpc_types::JsonBytes, Vec<Cycle>)> for PackedBlockResponse {
    fn from(orig: (ckb_jsonrpc_types::JsonBytes, Vec<Cycle>)) -> PackedBlockResponse {
        let (block, cycles) = orig;
        PackedBlockResponse { block, cycles }
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct EpochView {
    pub number: EpochNumber,
    pub start_number: BlockNumber,
    pub length: BlockNumber,
    pub compact_target: rpc_types::Uint32,
}
impl From<rpc_types::EpochView> for EpochView {
    fn from(json: rpc_types::EpochView) -> EpochView {
        EpochView {
            number: json.number.into(),
            start_number: json.start_number.into(),
            length: json.length.into(),
            compact_target: json.compact_target,
        }
    }
}

/// Block base rewards.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct BlockIssuance {
    /// The primary base rewards.
    pub primary: Capacity,
    /// The secondary base rewards.
    pub secondary: Capacity,
}
impl From<rpc_types::BlockIssuance> for BlockIssuance {
    fn from(json: rpc_types::BlockIssuance) -> Self {
        Self {
            primary: json.primary.into(),
            secondary: json.secondary.into(),
        }
    }
}

/// Block rewards for miners.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct MinerReward {
    /// The primary base block reward allocated to miners.
    pub primary: Capacity,
    /// The secondary base block reward allocated to miners.
    pub secondary: Capacity,
    /// The transaction fees that are rewarded to miners because the transaction is committed in the block.
    ///
    /// Miners get 60% of the transaction fee for each transaction committed in the block.
    pub committed: Capacity,
    /// The transaction fees that are rewarded to miners because the transaction is proposed in the block or
    /// its uncles.
    ///
    /// Miners get 40% of the transaction fee for each transaction proposed in the block and
    /// committed later in its active commit window.
    pub proposal: Capacity,
}
impl From<rpc_types::MinerReward> for MinerReward {
    fn from(json: rpc_types::MinerReward) -> Self {
        Self {
            primary: json.primary.into(),
            secondary: json.secondary.into(),
            committed: json.committed.into(),
            proposal: json.proposal.into(),
        }
    }
}

/// Block Economic State.
///
/// It includes the rewards details and when it is finalized.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct BlockEconomicState {
    /// Block base rewards.
    pub issuance: BlockIssuance,
    /// Block rewards for miners.
    pub miner_reward: MinerReward,
    /// The total fees of all transactions committed in the block.
    pub txs_fee: Capacity,
    /// The block hash of the block which creates the rewards as cells in its cellbase transaction.
    pub finalized_at: H256,
}
impl From<rpc_types::BlockEconomicState> for BlockEconomicState {
    fn from(json: rpc_types::BlockEconomicState) -> Self {
        Self {
            issuance: json.issuance.into(),
            miner_reward: json.miner_reward.into(),
            txs_fee: json.txs_fee.into(),
            finalized_at: json.finalized_at,
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct TransactionProof {
    /// Block hash
    pub block_hash: H256,
    /// Merkle root of all transactions' witness hash
    pub witnesses_root: H256,
    /// Merkle proof of all transactions' hash
    pub proof: MerkleProof,
}
impl From<rpc_types::TransactionProof> for TransactionProof {
    fn from(json: rpc_types::TransactionProof) -> TransactionProof {
        TransactionProof {
            block_hash: json.block_hash,
            witnesses_root: json.witnesses_root,
            proof: json.proof.into(),
        }
    }
}
impl From<TransactionProof> for rpc_types::TransactionProof {
    fn from(json: TransactionProof) -> rpc_types::TransactionProof {
        rpc_types::TransactionProof {
            block_hash: json.block_hash,
            witnesses_root: json.witnesses_root,
            proof: json.proof.into(),
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct MerkleProof {
    /// Leaves indices in the CBMT that are proved present in the block.
    ///
    /// These are indices in the CBMT tree not the transaction indices in the block.
    pub indices: Vec<Uint32>,
    /// Hashes of all siblings along the paths to root.
    pub lemmas: Vec<H256>,
}
impl From<rpc_types::MerkleProof> for MerkleProof {
    fn from(json: rpc_types::MerkleProof) -> MerkleProof {
        MerkleProof {
            indices: json
                .indices
                .into_iter()
                .map(rpc_types::Uint32::value)
                .collect(),
            lemmas: json.lemmas,
        }
    }
}
impl From<MerkleProof> for rpc_types::MerkleProof {
    fn from(json: MerkleProof) -> rpc_types::MerkleProof {
        rpc_types::MerkleProof {
            indices: json.indices.into_iter().map(Into::into).collect(),
            lemmas: json.lemmas,
        }
    }
}

/// Merkle proof for transactions' witnesses in a block.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct TransactionAndWitnessProof {
    /// Block hash
    pub block_hash: H256,
    /// Merkle proof of all transactions' hash
    pub transactions_proof: MerkleProof,
    /// Merkle proof of transactions' witnesses
    pub witnesses_proof: MerkleProof,
}

impl From<rpc_types::TransactionAndWitnessProof> for TransactionAndWitnessProof {
    fn from(json: rpc_types::TransactionAndWitnessProof) -> TransactionAndWitnessProof {
        TransactionAndWitnessProof {
            block_hash: json.block_hash,
            transactions_proof: json.transactions_proof.into(),
            witnesses_proof: json.witnesses_proof.into(),
        }
    }
}

impl From<TransactionAndWitnessProof> for rpc_types::TransactionAndWitnessProof {
    fn from(value: TransactionAndWitnessProof) -> Self {
        rpc_types::TransactionAndWitnessProof {
            block_hash: value.block_hash,
            transactions_proof: value.transactions_proof.into(),
            witnesses_proof: value.witnesses_proof.into(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct ProposalWindow {
    /// The closest distance between the proposal and the commitment.
    pub closest: BlockNumber,
    /// The farthest distance between the proposal and the commitment.
    pub farthest: BlockNumber,
}
impl From<rpc_types::ProposalWindow> for ProposalWindow {
    fn from(json: rpc_types::ProposalWindow) -> ProposalWindow {
        ProposalWindow {
            closest: json.closest.into(),
            farthest: json.farthest.into(),
        }
    }
}

/// The information about one hardfork feature.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct HardForkFeature {
    /// The related RFC ID.
    pub rfc: String,
    /// The first epoch when the feature is enabled, `null` indicates that the RFC has never been enabled.
    pub epoch_number: Option<EpochNumber>,
}

impl From<rpc_types::HardForkFeature> for HardForkFeature {
    fn from(value: ckb_jsonrpc_types::HardForkFeature) -> Self {
        HardForkFeature {
            rfc: value.rfc,
            epoch_number: value.epoch_number.map(Into::into),
        }
    }
}

/// Hardfork information
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(transparent)]
pub struct HardForks {
    inner: Vec<HardForkFeature>,
}

impl From<rpc_types::HardForks> for HardForks {
    fn from(value: ckb_jsonrpc_types::HardForks) -> Self {
        let value: json_rpc::HardForks = serde_json::from_value(
            serde_json::to_value(value).expect("HardForks: serde_json::to_value shouldn't fail"),
        )
        .expect("json_rpc::HardForks: serde_json::from_value shouldn't fail");
        HardForks {
            inner: value.inner.into_iter().map(Into::into).collect(),
        }
    }
}

/// Response type of the RPC method `test_tx_pool_accept`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EntryCompleted {
    /// Cached tx cycles
    pub cycles: Cycle,
    /// Cached tx fee
    pub fee: Capacity,
}

impl From<ckb_jsonrpc_types::EntryCompleted> for EntryCompleted {
    fn from(value: ckb_jsonrpc_types::EntryCompleted) -> Self {
        Self {
            cycles: value.cycles.into(),
            fee: value.fee.into(),
        }
    }
}

/// SoftFork information
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum SoftFork {
    /// buried - the activation epoch is hard-coded into the client implementation
    Buried(Buried),
    /// rfc0043 - the activation is controlled by rfc0043 signaling
    Rfc0043(Rfc0043),
}

impl From<json_rpc::SoftFork> for SoftFork {
    fn from(value: json_rpc::SoftFork) -> Self {
        match value {
            json_rpc::SoftFork::Buried(buried) => SoftFork::Buried(buried.into()),
            json_rpc::SoftFork::Rfc0043(rfc0043) => SoftFork::Rfc0043(rfc0043.into()),
        }
    }
}

/// SoftForkStatus which is either `buried` (for soft fork deployments where the activation epoch is
/// hard-coded into the client implementation), or `rfc0043` (for soft fork deployments
/// where activation is controlled by rfc0043 signaling).
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SoftForkStatus {
    /// the activation epoch is hard-coded into the client implementation
    Buried,
    /// the activation is controlled by rfc0043 signaling
    Rfc0043,
}

impl From<json_rpc::SoftForkStatus> for SoftForkStatus {
    fn from(value: json_rpc::SoftForkStatus) -> Self {
        match value {
            json_rpc::SoftForkStatus::Buried => SoftForkStatus::Buried,
            json_rpc::SoftForkStatus::Rfc0043 => SoftForkStatus::Rfc0043,
        }
    }
}

/// Represent soft fork deployments where the activation epoch is
/// hard-coded into the client implementation
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Buried {
    /// SoftFork status
    pub status: SoftForkStatus,
    /// Whether the rules are active
    pub active: bool,
    /// The first epoch  which the rules will be enforced
    pub epoch: EpochNumber,
}

impl From<json_rpc::Buried> for Buried {
    fn from(value: json_rpc::Buried) -> Self {
        Buried {
            status: value.status.into(),
            active: value.active,
            epoch: value.epoch.into(),
        }
    }
}

/// RFC0043 deployment params
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Deployment {
    /// Determines which bit in the `version` field of the block is to be used to signal the softfork lock-in and activation.
    /// It is chosen from the set {0,1,2,...,28}.
    pub bit: u8,
    /// Specifies the first epoch in which the bit gains meaning.
    pub start: EpochNumber,
    /// Specifies an epoch at which the miner signaling ends.
    /// Once this epoch has been reached, if the softfork has not yet locked_in (excluding this epoch block's bit state),
    /// the deployment is considered failed on all descendants of the block.
    pub timeout: EpochNumber,
    /// Specifies the epoch at which the softfork is allowed to become active.
    pub min_activation_epoch: EpochNumber,
    /// Specifies length of epochs of the signalling period.
    pub period: EpochNumber,
    /// Specifies the minimum ratio of block per `period`,
    /// which indicate the locked_in of the softfork during the `period`.
    pub threshold: Ratio,
}

impl From<rpc_types::Deployment> for Deployment {
    fn from(value: ckb_jsonrpc_types::Deployment) -> Self {
        Deployment {
            bit: value.bit,
            start: value.start.into(),
            timeout: value.timeout.into(),
            min_activation_epoch: value.min_activation_epoch.into(),
            period: value.period.into(),
            threshold: value.threshold.into(),
        }
    }
}

/// Represent soft fork deployments
/// where activation is controlled by rfc0043 signaling
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Rfc0043 {
    /// SoftFork status
    pub status: SoftForkStatus,
    /// RFC0043 deployment params
    pub rfc0043: Deployment,
}

impl From<json_rpc::Rfc0043> for Rfc0043 {
    fn from(value: json_rpc::Rfc0043) -> Self {
        Rfc0043 {
            status: value.status.into(),
            rfc0043: value.rfc0043.into(),
        }
    }
}

/// Consensus defines various parameters that influence chain consensus
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct Consensus {
    /// Names the network.
    pub id: String,
    /// The genesis block hash
    pub genesis_hash: H256,
    /// The dao type hash
    pub dao_type_hash: H256,
    /// The secp256k1_blake160_sighash_all_type_hash
    pub secp256k1_blake160_sighash_all_type_hash: Option<H256>,
    /// The secp256k1_blake160_multisig_all_type_hash
    pub secp256k1_blake160_multisig_all_type_hash: Option<H256>,
    /// The initial primary_epoch_reward
    pub initial_primary_epoch_reward: Capacity,
    /// The secondary primary_epoch_reward
    pub secondary_epoch_reward: Capacity,
    /// The maximum amount of uncles allowed for a block
    pub max_uncles_num: Uint64,
    /// The expected orphan_rate
    pub orphan_rate_target: core::RationalU256,
    /// The expected epoch_duration
    pub epoch_duration_target: Uint64,
    /// The two-step-transaction-confirmation proposal window
    pub tx_proposal_window: ProposalWindow,
    /// The two-step-transaction-confirmation proposer reward ratio
    pub proposer_reward_ratio: core::RationalU256,
    /// The Cellbase maturity
    pub cellbase_maturity: EpochNumberWithFraction,
    /// This parameter indicates the count of past blocks used in the median time calculation
    pub median_time_block_count: Uint64,
    /// Maximum cycles that all the scripts in all the commit transactions can take
    pub max_block_cycles: Cycle,
    /// Maximum number of bytes to use for the entire block
    pub max_block_bytes: Uint64,
    /// The block version number supported
    pub block_version: Version,
    /// The tx version number supported
    pub tx_version: Version,
    /// The "TYPE_ID" in hex
    pub type_id_code_hash: H256,
    /// The Limit to the number of proposals per block
    pub max_block_proposals_limit: Uint64,
    /// Primary reward is cut in half every halving_interval epoch
    pub primary_epoch_reward_halving_interval: Uint64,
    /// Keep difficulty be permanent if the pow is dummy
    pub permanent_difficulty_in_dummy: bool,
    /// Hardfork features
    pub hardfork_features: HardForks,
    /// Softforks
    pub softforks: HashMap<DeploymentPos, SoftFork>,
}

impl From<rpc_types::Consensus> for Consensus {
    fn from(json: ckb_jsonrpc_types::Consensus) -> Self {
        Consensus {
            id: json.id,
            genesis_hash: json.genesis_hash,
            dao_type_hash: json.dao_type_hash,
            secp256k1_blake160_sighash_all_type_hash: json.secp256k1_blake160_sighash_all_type_hash,
            secp256k1_blake160_multisig_all_type_hash: json
                .secp256k1_blake160_multisig_all_type_hash,
            initial_primary_epoch_reward: json.initial_primary_epoch_reward.into(),
            secondary_epoch_reward: json.secondary_epoch_reward.into(),
            max_uncles_num: json.max_uncles_num.into(),
            orphan_rate_target: json.orphan_rate_target,
            epoch_duration_target: json.epoch_duration_target.into(),
            tx_proposal_window: json.tx_proposal_window.into(),
            proposer_reward_ratio: json.proposer_reward_ratio,
            cellbase_maturity: json.cellbase_maturity.into(),
            median_time_block_count: json.median_time_block_count.into(),
            max_block_cycles: json.max_block_cycles.into(),
            max_block_bytes: json.max_block_bytes.into(),
            block_version: json.block_version.into(),
            tx_version: json.tx_version.into(),
            type_id_code_hash: json.type_id_code_hash,
            max_block_proposals_limit: json.max_block_proposals_limit.into(),
            primary_epoch_reward_halving_interval: json
                .primary_epoch_reward_halving_interval
                .into(),
            permanent_difficulty_in_dummy: json.permanent_difficulty_in_dummy,
            hardfork_features: json.hardfork_features.into(),
            softforks: {
                json.softforks
                    .into_iter()
                    .map(|(k, v)| {
                        (k.into(), {
                            let v = serde_json::to_value(v)
                                .expect("softforks: serde_json::to_value should not fail");
                            let v: json_rpc::SoftFork = serde_json::from_value(v)
                                .expect("softforks: serde_json::from_value should not fail");
                            v.into()
                        })
                    })
                    .collect()
            },
        }
    }
}

/// The possible softfork deployment state
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentState {
    /// First state that each softfork starts.
    /// The 0 epoch is by definition in this state for each deployment.
    Defined,
    /// For epochs past the `start` epoch.
    Started,
    /// For one epoch after the first epoch period with STARTED epochs of
    /// which at least `threshold` has the associated bit set in `version`.
    LockedIn,
    /// For all epochs after the LOCKED_IN epoch.
    Active,
    /// For one epoch period past the `timeout_epoch`, if LOCKED_IN was not reached.
    Failed,
}

impl From<rpc_types::DeploymentState> for DeploymentState {
    fn from(value: rpc_types::DeploymentState) -> Self {
        match value {
            rpc_types::DeploymentState::Defined => DeploymentState::Defined,
            rpc_types::DeploymentState::Started => DeploymentState::Started,
            rpc_types::DeploymentState::LockedIn => DeploymentState::LockedIn,
            rpc_types::DeploymentState::Active => DeploymentState::Active,
            rpc_types::DeploymentState::Failed => DeploymentState::Failed,
        }
    }
}

/// An object containing various state info regarding deployments of consensus changes
#[derive(Deserialize, Serialize, Debug)]
pub struct DeploymentInfo {
    /// determines which bit in the `version` field of the block is to be used to signal the softfork lock-in and activation.
    /// It is chosen from the set {0,1,2,...,28}.
    pub bit: u8,
    /// specifies the first epoch in which the bit gains meaning.
    pub start: EpochNumber,
    /// specifies an epoch at which the miner signaling ends.
    /// Once this epoch has been reached,
    /// if the softfork has not yet locked_in (excluding this epoch block's bit state),
    /// the deployment is considered failed on all descendants of the block.
    pub timeout: EpochNumber,
    /// specifies the epoch at which the softfork is allowed to become active.
    pub min_activation_epoch: EpochNumber,
    /// the length in epochs of the signalling period
    pub period: EpochNumber,
    /// the ratio of blocks with the version bit set required to activate the feature
    pub threshold: Ratio,
    /// The first epoch which the current state applies
    pub since: EpochNumber,
    /// With each epoch and softfork, we associate a deployment state. The possible states are:
    /// * `DEFINED` is the first state that each softfork starts. The blocks of 0 epoch is by definition in this state for each deployment.
    /// * `STARTED` for all blocks reach or past the start_epoch.
    /// * `LOCKED_IN` for one period after the first period with STARTED blocks of which at least threshold has the associated bit set in version.
    /// * `ACTIVE` for all blocks after the LOCKED_IN period.
    /// * `FAILED` for all blocks after the timeout_epoch, if LOCKED_IN was not reached.
    pub state: DeploymentState,
}

impl From<rpc_types::DeploymentInfo> for DeploymentInfo {
    fn from(value: ckb_jsonrpc_types::DeploymentInfo) -> Self {
        DeploymentInfo {
            bit: value.bit,
            start: value.start.into(),
            timeout: value.timeout.into(),
            min_activation_epoch: value.min_activation_epoch.into(),
            period: value.period.into(),
            threshold: value.threshold.into(),
            since: value.since.into(),
            state: value.state.into(),
        }
    }
}

/// Deployment name
#[derive(Clone, Hash, Deserialize, Serialize, Debug, Ord, PartialOrd, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentPos {
    /// Dummy
    Testdummy,
    /// light client protocol
    LightClient,
}

impl From<rpc_types::DeploymentPos> for DeploymentPos {
    fn from(value: ckb_jsonrpc_types::DeploymentPos) -> Self {
        match value {
            rpc_types::DeploymentPos::Testdummy => DeploymentPos::Testdummy,
            rpc_types::DeploymentPos::LightClient => DeploymentPos::LightClient,
        }
    }
}

/// Chain information.
#[derive(Deserialize, Serialize, Debug)]
pub struct DeploymentsInfo {
    /// requested block hash
    pub hash: H256,
    /// requested block epoch
    pub epoch: EpochNumber,
    /// deployments info
    pub deployments: BTreeMap<DeploymentPos, DeploymentInfo>,
}

impl From<rpc_types::DeploymentsInfo> for DeploymentsInfo {
    fn from(value: ckb_jsonrpc_types::DeploymentsInfo) -> Self {
        DeploymentsInfo {
            hash: value.hash,
            epoch: value.epoch.into(),
            deployments: value
                .deployments
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }
}

// =========
//  cell.rs
// =========

/// TODO: Make `cell::CellData` public
// #[derive(Debug, Serialize, Deserialize)]
// pub struct CellWithStatus {
//     pub cell: Option<CellInfo>,
//     pub status: String,
// }
// impl From<rpc_types::CellWithStatus> for CellWithStatus {
//     fn from(json: rpc_types::CellWithStatus) -> CellWithStatus {
//         CellWithStatus {
//             cell: json.cell.map(Into::into),
//             status: json.status,
//         }
//     }
// }

// #[derive(Debug, Serialize, Deserialize)]
// pub struct CellInfo {
//     pub output: CellOutput,
//     pub data: Option<CellData>,
// }
// impl From<rpc_types::CellInfo> for CellInfo {
//     fn from(json: rpc_types::CellInfo) -> CellInfo {
//         CellInfo {
//             output: json.output.into(),
//             data: json.data.map(Into::into),
//         }
//     }
// }

// ==========
//  alert.rs
// ==========
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct Alert {
    pub id: AlertId,
    pub cancel: AlertId,
    pub min_version: Option<String>,
    pub max_version: Option<String>,
    pub priority: AlertPriority,
    pub notice_until: Timestamp,
    pub message: String,
    pub signatures: Vec<JsonBytes>,
}
impl From<rpc_types::Alert> for Alert {
    fn from(json: rpc_types::Alert) -> Alert {
        Alert {
            id: json.id.into(),
            cancel: json.cancel.into(),
            min_version: json.min_version,
            max_version: json.max_version,
            priority: json.priority.into(),
            notice_until: json.notice_until.into(),
            message: json.message,
            signatures: json.signatures,
        }
    }
}
impl From<Alert> for packed::Alert {
    fn from(json: Alert) -> Self {
        let Alert {
            id,
            cancel,
            min_version,
            max_version,
            priority,
            notice_until,
            message,
            signatures,
        } = json;
        let raw = packed::RawAlert::new_builder()
            .id(id.pack())
            .cancel(cancel.pack())
            .min_version(min_version.pack())
            .max_version(max_version.pack())
            .priority(priority.pack())
            .notice_until(notice_until.0.pack())
            .message(message.pack())
            .build();
        packed::Alert::new_builder()
            .raw(raw)
            .signatures(signatures.into_iter().map(Into::into).pack())
            .build()
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct AlertMessage {
    pub id: AlertId,
    pub priority: AlertPriority,
    pub notice_until: Timestamp,
    pub message: String,
}
impl From<rpc_types::AlertMessage> for AlertMessage {
    fn from(json: rpc_types::AlertMessage) -> AlertMessage {
        AlertMessage {
            id: json.id.into(),
            priority: json.priority.into(),
            notice_until: json.notice_until.into(),
            message: json.message,
        }
    }
}

// ===============
//  chain_info.rs
// ===============
#[derive(Deserialize, Serialize, Debug)]
pub struct ChainInfo {
    // network name
    pub chain: String,
    // median time for the current tip block
    pub median_time: Timestamp,
    // the current epoch number
    pub epoch: EpochNumber,
    // the current difficulty
    pub difficulty: U256,
    // estimate of whether this node is in InitialBlockDownload mode
    pub is_initial_block_download: bool,
    // any network and blockchain warnings
    pub alerts: Vec<AlertMessage>,
}
impl From<rpc_types::ChainInfo> for ChainInfo {
    fn from(json: rpc_types::ChainInfo) -> ChainInfo {
        ChainInfo {
            chain: json.chain,
            median_time: json.median_time.into(),
            epoch: json.epoch.into(),
            difficulty: json.difficulty,
            is_initial_block_download: json.is_initial_block_download,
            alerts: json.alerts.into_iter().map(Into::into).collect(),
        }
    }
}

// ========
//  net.rs
// ========
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct LocalNode {
    pub version: String,
    pub node_id: String,
    pub active: bool,
    pub addresses: Vec<NodeAddress>,
    pub protocols: Vec<LocalNodeProtocol>,
    pub connections: Uint64,
}
impl From<rpc_types::LocalNode> for LocalNode {
    fn from(json: rpc_types::LocalNode) -> LocalNode {
        LocalNode {
            version: json.version,
            node_id: json.node_id,
            active: json.active,
            addresses: json.addresses.into_iter().map(Into::into).collect(),
            protocols: json.protocols.into_iter().map(Into::into).collect(),
            connections: json.connections.value(),
        }
    }
}
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct LocalNodeProtocol {
    pub id: Uint64,
    pub name: String,
    pub support_versions: Vec<String>,
}
impl From<rpc_types::LocalNodeProtocol> for LocalNodeProtocol {
    fn from(json: rpc_types::LocalNodeProtocol) -> LocalNodeProtocol {
        LocalNodeProtocol {
            id: json.id.value(),
            name: json.name,
            support_versions: json.support_versions,
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct RemoteNode {
    pub version: String,
    pub node_id: String,
    pub addresses: Vec<NodeAddress>,
    pub is_outbound: bool,
    pub connected_duration: Uint64,
    pub last_ping_duration: Option<Uint64>,
    pub sync_state: Option<PeerSyncState>,
    pub protocols: Vec<RemoteNodeProtocol>,
}
impl From<rpc_types::RemoteNode> for RemoteNode {
    fn from(json: rpc_types::RemoteNode) -> RemoteNode {
        RemoteNode {
            version: json.version,
            node_id: json.node_id,
            addresses: json.addresses.into_iter().map(Into::into).collect(),
            is_outbound: json.is_outbound,
            connected_duration: json.connected_duration.value(),
            last_ping_duration: json.last_ping_duration.map(|duration| duration.value()),
            sync_state: json.sync_state.map(Into::into),
            protocols: json.protocols.into_iter().map(Into::into).collect(),
        }
    }
}
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct RemoteNodeProtocol {
    pub id: Uint64,
    pub version: String,
}
impl From<rpc_types::RemoteNodeProtocol> for RemoteNodeProtocol {
    fn from(json: rpc_types::RemoteNodeProtocol) -> RemoteNodeProtocol {
        RemoteNodeProtocol {
            id: json.id.value(),
            version: json.version,
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct PeerSyncState {
    pub best_known_header_hash: Option<Byte32>,
    pub best_known_header_number: Option<Uint64>,
    pub last_common_header_hash: Option<Byte32>,
    pub last_common_header_number: Option<Uint64>,
    pub unknown_header_list_size: Uint64,
    pub inflight_count: Uint64,
    pub can_fetch_count: Uint64,
}
impl From<rpc_types::PeerSyncState> for PeerSyncState {
    fn from(json: rpc_types::PeerSyncState) -> PeerSyncState {
        PeerSyncState {
            best_known_header_hash: json.best_known_header_hash,
            best_known_header_number: json.best_known_header_number.map(|number| number.value()),
            last_common_header_hash: json.last_common_header_hash,
            last_common_header_number: json.last_common_header_number.map(|number| number.value()),
            unknown_header_list_size: json.unknown_header_list_size.value(),
            inflight_count: json.inflight_count.value(),
            can_fetch_count: json.can_fetch_count.value(),
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct SyncState {
    pub ibd: bool,
    pub best_known_block_number: BlockNumber,
    pub best_known_block_timestamp: Timestamp,
    pub orphan_blocks_count: Uint64,
    pub inflight_blocks_count: Uint64,
    /// Is ckb reached the assume_valid_target? If no assume_valid_target, this will be true.
    pub assume_valid_target_reached: bool,
    /// The assume_valid_target specified by ckb, if no assume_valid_target, this will be all zero.
    pub assume_valid_target: Byte32,
    /// Is ckb reached the min_chain_work?
    pub min_chain_work_reached: bool,
    /// This field acts as a security measure to ensure that a node only
    /// synchronizes with other nodes that have a significant amount of
    /// computational work invested in them, thereby preventing certain types
    /// of attacks and ensuring network integrity. Only the mainnet uses a
    /// hardcoded value for this field.
    pub min_chain_work: Uint128,
    pub fast_time: Uint64,
    pub normal_time: Uint64,
    pub low_time: Uint64,
}
impl From<rpc_types::SyncState> for SyncState {
    fn from(json: rpc_types::SyncState) -> SyncState {
        SyncState {
            ibd: json.ibd,
            best_known_block_number: json.best_known_block_number.into(),
            best_known_block_timestamp: json.best_known_block_timestamp.into(),
            orphan_blocks_count: json.orphan_blocks_count.value(),
            inflight_blocks_count: json.inflight_blocks_count.value(),
            assume_valid_target_reached: json.assume_valid_target_reached,
            assume_valid_target: json.assume_valid_target,
            min_chain_work_reached: json.min_chain_work_reached,
            min_chain_work: json.min_chain_work,
            fast_time: json.fast_time.value(),
            normal_time: json.normal_time.value(),
            low_time: json.low_time.value(),
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct NodeAddress {
    pub address: String,
    pub score: Uint64,
}
impl From<rpc_types::NodeAddress> for NodeAddress {
    fn from(json: rpc_types::NodeAddress) -> NodeAddress {
        NodeAddress {
            address: json.address,
            score: json.score.into(),
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct BannedAddr {
    pub address: String,
    pub ban_until: Timestamp,
    pub ban_reason: String,
    pub created_at: Timestamp,
}
impl From<rpc_types::BannedAddr> for BannedAddr {
    fn from(json: rpc_types::BannedAddr) -> BannedAddr {
        BannedAddr {
            address: json.address,
            ban_until: json.ban_until.into(),
            ban_reason: json.ban_reason,
            created_at: json.created_at.into(),
        }
    }
}

// =========
//  pool.rs
// =========
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct TxPoolInfo {
    pub tip_hash: H256,
    pub tip_number: BlockNumber,
    pub pending: Uint64,
    pub proposed: Uint64,
    pub orphan: Uint64,
    pub total_tx_size: Uint64,
    pub total_tx_cycles: Uint64,
    pub min_fee_rate: Uint64,
    pub last_txs_updated_at: Timestamp,
}
impl From<rpc_types::TxPoolInfo> for TxPoolInfo {
    fn from(json: rpc_types::TxPoolInfo) -> TxPoolInfo {
        TxPoolInfo {
            tip_hash: json.tip_hash,
            tip_number: json.tip_number.value(),
            pending: json.pending.into(),
            proposed: json.proposed.into(),
            orphan: json.orphan.into(),
            total_tx_size: json.total_tx_size.into(),
            total_tx_cycles: json.total_tx_cycles.into(),
            min_fee_rate: json.min_fee_rate.value(),
            last_txs_updated_at: json.last_txs_updated_at.into(),
        }
    }
}

/// Transaction verbose info
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct TxPoolEntry {
    /// Consumed cycles.
    pub cycles: Uint64,
    /// The transaction serialized size in block.
    pub size: Uint64,
    /// The transaction fee.
    pub fee: Capacity,
    /// Size of in-tx-pool ancestor transactions
    pub ancestors_size: Uint64,
    /// Cycles of in-tx-pool ancestor transactions
    pub ancestors_cycles: Uint64,
    /// Number of in-tx-pool ancestor transactions
    pub ancestors_count: Uint64,
}
impl From<rpc_types::TxPoolEntry> for TxPoolEntry {
    fn from(json: rpc_types::TxPoolEntry) -> TxPoolEntry {
        TxPoolEntry {
            cycles: json.cycles.into(),
            size: json.size.into(),
            fee: json.fee.into(),
            ancestors_size: json.ancestors_size.into(),
            ancestors_cycles: json.ancestors_cycles.into(),
            ancestors_count: json.ancestors_count.into(),
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct TxPoolEntries {
    /// Pending tx verbose info
    pub pending: HashMap<H256, TxPoolEntry>,
    /// Proposed tx verbose info
    pub proposed: HashMap<H256, TxPoolEntry>,
}
impl From<rpc_types::TxPoolEntries> for TxPoolEntries {
    fn from(json: rpc_types::TxPoolEntries) -> TxPoolEntries {
        TxPoolEntries {
            pending: json
                .pending
                .into_iter()
                .map(|(key, value)| (key, value.into()))
                .collect(),
            proposed: json
                .proposed
                .into_iter()
                .map(|(key, value)| (key, value.into()))
                .collect(),
        }
    }
}

/// All transactions in tx-pool.
///
/// `RawTxPool` is equivalent to [`TxPoolIds`][] `|` [`TxPoolEntries`][].
///
/// [`TxPoolIds`]: struct.TxPoolIds.html
/// [`TxPoolEntries`]: struct.TxPoolEntries.html
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(untagged)]
pub enum RawTxPool {
    /// verbose = false
    Ids(TxPoolIds),
    /// verbose = true
    Verbose(TxPoolEntries),
}

impl From<rpc_types::RawTxPool> for RawTxPool {
    fn from(json: rpc_types::RawTxPool) -> RawTxPool {
        match json {
            rpc_types::RawTxPool::Ids(ids) => RawTxPool::Ids(ids),
            rpc_types::RawTxPool::Verbose(verbose) => RawTxPool::Verbose(verbose.into()),
        }
    }
}

/// Response result of the RPC method `estimate_cycles`.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct EstimateCycles {
    /// The count of cycles that the VM has consumed to verify this transaction.
    pub cycles: Cycle,
}

impl From<rpc_types::EstimateCycles> for EstimateCycles {
    fn from(json: rpc_types::EstimateCycles) -> EstimateCycles {
        EstimateCycles {
            cycles: json.cycles.into(),
        }
    }
}

/// The fee_rate statistics information, includes mean and median, unit: shannons per kilo-weight
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct FeeRateStatistics {
    /// mean
    pub mean: Uint64,
    /// median
    pub median: Uint64,
}

impl From<rpc_types::FeeRateStatistics> for FeeRateStatistics {
    fn from(json: rpc_types::FeeRateStatistics) -> FeeRateStatistics {
        FeeRateStatistics {
            mean: json.mean.into(),
            median: json.median.into(),
        }
    }
}

/// Response type of the RPC method `get_indexer_tip`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IndexerTip {
    pub block_hash: H256,
    pub block_number: BlockNumber,
}

impl From<ckb_indexer::Tip> for IndexerTip {
    fn from(tip: ckb_indexer::Tip) -> IndexerTip {
        IndexerTip {
            block_hash: tip.block_hash,
            block_number: tip.block_number.into(),
        }
    }
}

/// Response type of the RPC method `get_cells`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Cell {
    pub output: CellOutput,
    pub output_data: Option<JsonBytes>,
    pub out_point: OutPoint,
    pub block_number: BlockNumber,
    pub tx_index: Uint32,
}

impl From<ckb_indexer::Cell> for Cell {
    fn from(cell: ckb_indexer::Cell) -> Cell {
        Cell {
            output: cell.output.into(),
            output_data: cell.output_data.map(Into::into),
            out_point: cell.out_point.into(),
            block_number: cell.block_number.into(),
            tx_index: cell.tx_index.into(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum Tx {
    Ungrouped(TxWithCell),
    Grouped(TxWithCells),
}

impl From<ckb_indexer::Tx> for Tx {
    fn from(tx: ckb_indexer::Tx) -> Tx {
        match tx {
            ckb_indexer::Tx::Ungrouped(tx_with_cell) => Tx::Ungrouped(tx_with_cell.into()),
            ckb_indexer::Tx::Grouped(tx_with_cells) => Tx::Grouped(tx_with_cells.into()),
        }
    }
}

/// Response type of the RPC method `get_transactions`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxWithCell {
    pub tx_hash: H256,
    pub block_number: BlockNumber,
    pub tx_index: Uint32,
    pub io_index: Uint32,
    pub io_type: CellType,
}

impl From<ckb_indexer::TxWithCell> for TxWithCell {
    fn from(tx_with_cell: ckb_indexer::TxWithCell) -> TxWithCell {
        TxWithCell {
            tx_hash: tx_with_cell.tx_hash,
            block_number: tx_with_cell.block_number.into(),
            tx_index: tx_with_cell.tx_index.into(),
            io_index: tx_with_cell.io_index.into(),
            io_type: tx_with_cell.io_type,
        }
    }
}

/// Response type of the RPC method `get_transactions`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxWithCells {
    pub tx_hash: H256,
    pub block_number: BlockNumber,
    pub tx_index: Uint32,
    pub cells: Vec<(CellType, Uint32)>,
}

impl From<ckb_indexer::TxWithCells> for TxWithCells {
    fn from(tx_with_cells: ckb_indexer::TxWithCells) -> TxWithCells {
        TxWithCells {
            tx_hash: tx_with_cells.tx_hash,
            block_number: tx_with_cells.block_number.into(),
            tx_index: tx_with_cells.tx_index.into(),
            cells: tx_with_cells
                .cells
                .into_iter()
                .map(|(cell_type, io_index)| (cell_type, io_index.into()))
                .collect(),
        }
    }
}

/// Response type of the RPC method `get_cells_capacity`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CellsCapacity {
    pub capacity: Capacity,
    pub block_hash: H256,
    pub block_number: BlockNumber,
}

impl From<ckb_indexer::CellsCapacity> for CellsCapacity {
    fn from(json: ckb_indexer::CellsCapacity) -> CellsCapacity {
        CellsCapacity {
            capacity: json.capacity.into(),
            block_hash: json.block_hash,
            block_number: json.block_number.into(),
        }
    }
}

pub fn parse_order(order_str: &str) -> Result<Order, String> {
    match order_str.to_lowercase().as_str() {
        "desc" => Ok(Order::Desc),
        "asc" => Ok(Order::Asc),
        _ => Err(format!("Invalid order: {}", order_str)),
    }
}
