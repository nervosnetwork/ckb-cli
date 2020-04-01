use super::util::minimal_unlock_point;
use crate::subcommands::dao::util::calculate_dao_maximum_withdraw4;
use ckb_index::LiveCellInfo;
use ckb_sdk::{constants::MIN_SECP_CELL_CAPACITY, GenesisInfo, HttpRpcClient, Since, SinceType};
use ckb_types::core::Capacity;
use ckb_types::{
    bytes::Bytes,
    core::{HeaderView, ScriptHashType, TransactionBuilder, TransactionView},
    packed::{self, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
};
use std::collections::HashSet;

// NOTE: We assume all inputs are from same account
#[derive(Debug)]
pub(crate) struct DAOBuilder {
    genesis_info: GenesisInfo,
    tx_fee: u64,
    live_cells: Vec<LiveCellInfo>,
}

impl DAOBuilder {
    pub(crate) fn new(
        genesis_info: GenesisInfo,
        tx_fee: u64,
        live_cells: Vec<LiveCellInfo>,
    ) -> Self {
        Self {
            genesis_info,
            tx_fee,
            live_cells,
        }
    }

    pub(crate) fn deposit(&self, deposit_capacity: u64) -> Result<TransactionView, String> {
        let genesis_info = &self.genesis_info;
        let inputs = self
            .live_cells
            .iter()
            .map(|txo| CellInput::new(txo.out_point(), 0))
            .collect::<Vec<_>>();
        let witnesses = inputs
            .iter()
            .map(|_| Default::default())
            .collect::<Vec<_>>();
        let (output, output_data) = {
            // NOTE: Here give null lock script to the output. It's caller's duty to fill the lock
            let output = CellOutput::new_builder()
                .capacity(deposit_capacity.pack())
                .type_(Some(dao_type_script(&self.genesis_info)?).pack())
                .build();
            let output_data = Bytes::from(&[0u8; 8][..]).pack();
            (output, output_data)
        };
        let cell_deps = vec![genesis_info.dao_dep()];
        let tx = TransactionBuilder::default()
            .inputs(inputs)
            .output(output)
            .output_data(output_data)
            .cell_deps(cell_deps)
            .witnesses(witnesses);

        let input_capacity = self.live_cells.iter().map(|txo| txo.capacity).sum::<u64>();
        let change_capacity = input_capacity - deposit_capacity - self.tx_fee;
        if change_capacity >= MIN_SECP_CELL_CAPACITY {
            let change = CellOutput::new_builder()
                .capacity(change_capacity.pack())
                .build();
            Ok(tx.output(change).output_data(Default::default()).build())
        } else {
            Ok(tx.build())
        }
    }

    pub(crate) fn prepare(
        &self,
        rpc_client: &mut HttpRpcClient,
    ) -> Result<TransactionView, String> {
        let genesis_info = &self.genesis_info;
        let dao_type_hash = genesis_info.dao_type_hash();
        let mut deposit_cells: Vec<LiveCellInfo> = Vec::new();
        let mut change_cells: Vec<LiveCellInfo> = Vec::new();
        for cell in self.live_cells.iter() {
            if cell
                .type_hashes
                .as_ref()
                .map(|(code_hash, _)| &code_hash.pack() == dao_type_hash)
                .unwrap_or(false)
            {
                deposit_cells.push(cell.clone());
            } else {
                change_cells.push(cell.clone());
            }
        }
        let deposit_txo_headers = {
            let deposit_out_points = deposit_cells
                .iter()
                .map(|txo| txo.out_point())
                .collect::<Vec<_>>();
            self.txo_headers(rpc_client, deposit_out_points)?
        };

        let inputs = self
            .live_cells
            .iter()
            .map(|txo| CellInput::new(txo.out_point(), 0))
            .collect::<Vec<_>>();
        // NOTE: Prepare output has the same capacity, type script, lock script as the input
        let outputs = deposit_txo_headers
            .iter()
            .map(|(_, output, _)| output.clone())
            .collect::<Vec<_>>();
        let outputs_data = deposit_txo_headers.iter().map(|(_, _, header)| {
            let deposit_number = header.number();
            Bytes::from(deposit_number.to_le_bytes().to_vec()).pack()
        });
        let cell_deps = vec![genesis_info.dao_dep()];
        let header_deps = deposit_txo_headers
            .iter()
            .map(|(_, _, header)| header.hash())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let witnesses = (0..inputs.len())
            .map(|_| WitnessArgs::default().as_bytes().pack())
            .collect::<Vec<_>>();
        let tx = TransactionBuilder::default()
            .inputs(inputs)
            .outputs(outputs)
            .cell_deps(cell_deps)
            .header_deps(header_deps)
            .witnesses(witnesses)
            .outputs_data(outputs_data);

        let change_capacity =
            change_cells.iter().map(|txo| txo.capacity).sum::<u64>() - self.tx_fee;
        let change = CellOutput::new_builder()
            .capacity(change_capacity.pack())
            .build();
        Ok(tx.output(change).output_data(Default::default()).build())
    }

    pub(crate) fn withdraw(
        &self,
        rpc_client: &mut HttpRpcClient,
    ) -> Result<TransactionView, String> {
        let genesis_info = &self.genesis_info;
        let prepare_txo_headers = {
            let prepare_out_points = self
                .live_cells
                .iter()
                .map(|txo| txo.out_point())
                .collect::<Vec<_>>();
            self.txo_headers(rpc_client, prepare_out_points)?
        };
        let deposit_txo_headers = {
            let deposit_out_points = prepare_txo_headers
                .iter()
                .map(|(out_point, _, _)| {
                    let tx: packed::Transaction = rpc_client
                        .get_transaction(out_point.tx_hash().unpack())?
                        .expect("checked above")
                        .transaction
                        .inner
                        .into();
                    let tx = tx.into_view();
                    let input = tx
                        .inputs()
                        .get(out_point.index().unpack())
                        .expect("prepare out_point has the same index with deposit input");
                    Ok(input.previous_output())
                })
                .collect::<Result<Vec<_>, String>>()?;
            self.txo_headers(rpc_client, deposit_out_points)?
        };

        let inputs = deposit_txo_headers
            .iter()
            .zip(prepare_txo_headers.iter())
            .map(|((_, _, deposit_header), (out_point, _, prepare_header))| {
                let minimal_unlock_point = minimal_unlock_point(deposit_header, prepare_header);
                let since = Since::new(
                    SinceType::EpochNumberWithFraction,
                    minimal_unlock_point.full_value(),
                    false,
                );
                CellInput::new(out_point.clone(), since.value())
            });
        let total_capacity = deposit_txo_headers
            .iter()
            .zip(prepare_txo_headers.iter())
            .map(|((_, output, deposit_header), (_, _, prepare_header))| {
                const DAO_OUTPUT_DATA_LEN: usize = 8;
                let occupied_capacity = output
                    .occupied_capacity(Capacity::bytes(DAO_OUTPUT_DATA_LEN).unwrap())
                    .unwrap();
                calculate_dao_maximum_withdraw4(
                    deposit_header,
                    prepare_header,
                    output,
                    occupied_capacity.as_u64(),
                )
            })
            .sum::<u64>();
        let output_capacity = total_capacity - self.tx_fee;
        let output = CellOutput::new_builder()
            .capacity(output_capacity.pack())
            .build();
        let cell_deps = vec![genesis_info.dao_dep()];
        let header_deps = deposit_txo_headers
            .iter()
            .chain(prepare_txo_headers.iter())
            .map(|(_, _, header)| header.hash())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let witnesses = deposit_txo_headers
            .iter()
            .map(|(_, _, header)| {
                let index = header_deps
                    .iter()
                    .position(|hash| hash == &header.hash())
                    .unwrap() as u64;
                WitnessArgs::new_builder()
                    .input_type(Some(Bytes::from(index.to_le_bytes().to_vec())).pack())
                    .build()
                    .as_bytes()
                    .pack()
            })
            .collect::<Vec<_>>();
        Ok(TransactionBuilder::default()
            .inputs(inputs)
            .output(output)
            .cell_deps(cell_deps)
            .header_deps(header_deps)
            .witnesses(witnesses)
            .output_data(Default::default())
            .build())
    }

    fn txo_headers(
        &self,
        rpc_client: &mut HttpRpcClient,
        out_points: Vec<OutPoint>,
    ) -> Result<Vec<(OutPoint, CellOutput, HeaderView)>, String> {
        let mut ret = Vec::new();
        for out_point in out_points.into_iter() {
            let tx_status = rpc_client
                .get_transaction(out_point.tx_hash().unpack())?
                .ok_or_else(|| "get_transaction None".to_string())?;
            let tx: packed::Transaction = tx_status.transaction.inner.into();
            let tx = tx.into_view();
            let header: HeaderView = {
                let block_hash = tx_status
                    .tx_status
                    .block_hash
                    .ok_or_else(|| "Tx is not on-chain".to_owned())?;
                rpc_client
                    .get_header(block_hash)?
                    .expect("checked above")
                    .into()
            };

            let output_index: u32 = out_point.index().unpack();
            let output = tx
                .outputs()
                .get(output_index as usize)
                .ok_or_else(|| "OutPoint is out of index".to_owned())?;
            ret.push((out_point, output, header))
        }
        Ok(ret)
    }
}

fn dao_type_script(genesis_info: &GenesisInfo) -> Result<Script, String> {
    Ok(Script::new_builder()
        .hash_type(ScriptHashType::Type.into())
        .code_hash(genesis_info.dao_type_hash().clone())
        .build())
}
