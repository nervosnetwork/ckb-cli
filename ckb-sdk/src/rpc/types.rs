use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
use std::convert::TryFrom;

pub use ckb_jsonrpc_types::{
    self as rpc_types, Byte32, DepType, JsonBytes, ProposalShortId, ScriptHashType, TxStatus,
    Uint128,
};
use ckb_types::{core, packed, prelude::*, H256, U256};

use super::primitive::{Capacity, EpochNumberWithFraction, Since, Timestamp};
use crate::constants::{DAO_TYPE_HASH, MULTISIG_TYPE_HASH, SIGHASH_TYPE_HASH};

type Version = u32;
type BlockNumber = u64;
type EpochNumber = u64;
type AlertId = u32;
type AlertPriority = u32;
type Uint32 = u32;
type Uint64 = u64;

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

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct TransactionWithStatus {
    pub transaction: TransactionView,
    /// Indicate the Transaction status
    pub tx_status: TxStatus,
}
impl From<rpc_types::TransactionWithStatus> for TransactionWithStatus {
    fn from(json: rpc_types::TransactionWithStatus) -> TransactionWithStatus {
        TransactionWithStatus {
            transaction: json.transaction.into(),
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
    pub uncles_hash: H256,
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
            uncles_hash: json.uncles_hash,
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
            uncles_hash,
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
            .uncles_hash(uncles_hash.pack())
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

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct BlockReward {
    pub total: Capacity,
    pub primary: Capacity,
    pub secondary: Capacity,
    pub tx_fee: Capacity,
    pub proposal_reward: Capacity,
}
impl From<rpc_types::BlockReward> for BlockReward {
    fn from(json: rpc_types::BlockReward) -> BlockReward {
        BlockReward {
            total: json.total.into(),
            primary: json.primary.into(),
            secondary: json.secondary.into(),
            tx_fee: json.tx_fee.into(),
            proposal_reward: json.proposal_reward.into(),
        }
    }
}
impl From<BlockReward> for core::BlockReward {
    fn from(json: BlockReward) -> Self {
        Self {
            total: core::Capacity::shannons(json.total.0),
            primary: core::Capacity::shannons(json.primary.0),
            secondary: core::Capacity::shannons(json.secondary.0),
            tx_fee: core::Capacity::shannons(json.tx_fee.0),
            proposal_reward: core::Capacity::shannons(json.proposal_reward.0),
        }
    }
}

// =========
//  cell.rs
// =========
#[derive(Debug, Serialize, Deserialize)]
pub struct CellOutputWithOutPoint {
    pub out_point: OutPoint,
    pub block_hash: H256,
    pub capacity: Capacity,
    pub lock: Script,
    #[serde(rename = "type")]
    pub type_: Option<Script>,
    //// TODO: update those fields
    // pub output_data_len: Uint64,
    // pub cellbase: bool,
}
impl From<rpc_types::CellOutputWithOutPoint> for CellOutputWithOutPoint {
    fn from(json: rpc_types::CellOutputWithOutPoint) -> CellOutputWithOutPoint {
        CellOutputWithOutPoint {
            out_point: json.out_point.into(),
            block_hash: json.block_hash,
            capacity: json.capacity.into(),
            lock: json.lock.into(),
            type_: json.type_.map(Into::into),
            // output_data_len: json.output_data_len.into(),
            // cellbase: json.cellbase,
        }
    }
}

//// TODO: Make `cell::CellData` public
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

// ============
//  indexer.rs
// ============
#[derive(Debug, Serialize, Deserialize)]
pub struct LiveCell {
    pub created_by: TransactionPoint,
    pub cell_output: CellOutput,
    //// TODO: update those fields
    // pub output_data_len: Uint64,
    // pub cellbase: bool,
}
impl From<rpc_types::LiveCell> for LiveCell {
    fn from(json: rpc_types::LiveCell) -> LiveCell {
        LiveCell {
            created_by: json.created_by.into(),
            cell_output: json.cell_output.into(),
            // output_data_len: json.output_data_len.into(),
            // cellbase: json.cellbase,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CellTransaction {
    pub created_by: TransactionPoint,
    pub consumed_by: Option<TransactionPoint>,
}
impl From<rpc_types::CellTransaction> for CellTransaction {
    fn from(json: rpc_types::CellTransaction) -> CellTransaction {
        CellTransaction {
            created_by: json.created_by.into(),
            consumed_by: json.consumed_by.map(Into::into),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionPoint {
    pub block_number: BlockNumber,
    pub tx_hash: H256,
    pub index: Uint64,
}
impl From<rpc_types::TransactionPoint> for TransactionPoint {
    fn from(json: rpc_types::TransactionPoint) -> TransactionPoint {
        TransactionPoint {
            block_number: json.block_number.into(),
            tx_hash: json.tx_hash,
            index: json.index.into(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LockHashIndexState {
    pub lock_hash: H256,
    pub block_number: BlockNumber,
    pub block_hash: H256,
}
impl From<rpc_types::LockHashIndexState> for LockHashIndexState {
    fn from(json: rpc_types::LockHashIndexState) -> LockHashIndexState {
        LockHashIndexState {
            lock_hash: json.lock_hash,
            block_number: json.block_number.into(),
            block_hash: json.block_hash,
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

// =========
//  sync.rs
// =========
//// TODO make PeerState fields public
// #[derive(Deserialize, Serialize, Debug)]
// pub struct PeerState {
//     // TODO use peer_id
//     // peer session id
//     pub peer: Uint32,
//     // last updated timestamp
//     pub last_updated: Timestamp,
//     // blocks count has request but not receive response yet
//     pub blocks_in_flight: Uint32,
// }
// impl From<rpc_types::PeerState> for PeerState {
//     fn from(json: rpc_types::PeerState) -> PeerState {
//         PeerState {
//             peer: json.peer.into(),
//             last_updated: json.last_updated.into(),
//             blocks_in_flight: json.blocks_in_flight.into()
//         }
//     }
// }
