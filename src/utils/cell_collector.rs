use std::collections::HashSet;
use std::path::PathBuf;

use ckb_index::{IndexDatabase, LiveCellInfo};
use ckb_sdk::traits::{
    CellCollector, CellCollectorError, CellQueryOptions, LiveCell, MaturityOption,
    PrimaryScriptType,
};
use ckb_sdk::util::get_max_mature_number;
use ckb_types::{
    core::HeaderView,
    packed::{OutPoint, Transaction},
    prelude::*,
    H256,
};

use crate::utils::index::{with_db, IndexController};
use crate::utils::other::is_mature;
use crate::utils::rpc::HttpRpcClient;

pub struct LocalCellCollector {
    index_dir: PathBuf,
    index_controller: IndexController,
    rpc_client: HttpRpcClient,
    genesis_header: Option<HeaderView>,
    wait_for_sync: bool,

    locked_cells: HashSet<(H256, u32)>,
    offchain_live_cells: Vec<LiveCell>,
}

impl LocalCellCollector {
    pub fn new(
        index_dir: PathBuf,
        index_controller: IndexController,
        rpc_client: HttpRpcClient,
        genesis_header: Option<HeaderView>,
        wait_for_sync: bool,
    ) -> LocalCellCollector {
        LocalCellCollector {
            index_dir,
            index_controller,
            rpc_client,
            genesis_header,
            wait_for_sync,
            locked_cells: HashSet::default(),
            offchain_live_cells: Vec::new(),
        }
    }

    fn genesis_header(&mut self) -> Result<HeaderView, String> {
        if self.genesis_header.is_none() {
            let header: HeaderView = self
                .rpc_client
                .get_header_by_number(0)?
                .expect("Can not get genesis header")
                .into();
            self.genesis_header = Some(header);
        }
        Ok(self.genesis_header.clone().unwrap())
    }

    fn with_db<F, T>(&mut self, func: F) -> Result<T, CellCollectorError>
    where
        F: FnOnce(IndexDatabase) -> T,
    {
        let genesis_header = self
            .genesis_header()
            .map_err(|err| CellCollectorError::Other(err.into()))?;
        with_db(
            func,
            &mut self.rpc_client,
            genesis_header,
            &self.index_dir,
            self.index_controller.clone(),
            self.wait_for_sync,
        )
        .map_err(|err| CellCollectorError::Internal(err.into()))
    }
}

impl CellCollector for LocalCellCollector {
    fn collect_live_cells(
        &mut self,
        query: &CellQueryOptions,
        apply_changes: bool,
    ) -> Result<(Vec<LiveCell>, u64), CellCollectorError> {
        let max_mature_number = get_max_mature_number(self.rpc_client.client())
            .map_err(|err| CellCollectorError::Internal(err.into()))?;
        let mut total_capacity = 0;
        let (mut cells, rest_cells): (Vec<_>, Vec<_>) = self
            .offchain_live_cells
            .clone()
            .into_iter()
            .partition(|cell| {
                if total_capacity < query.min_total_capacity
                    && query.match_cell(cell, Some(max_mature_number))
                {
                    let capacity: u64 = cell.output.capacity().unpack();
                    total_capacity += capacity;
                    true
                } else {
                    false
                }
            });
        if apply_changes {
            self.offchain_live_cells = rest_cells;
        }

        if total_capacity < query.min_total_capacity {
            let locked_cells = self.locked_cells.clone();
            // NOTE: order is ignored in current cell collector implementation
            let mut limit = query.limit.unwrap_or(u32::max_value());
            let terminator = |_, info: &LiveCellInfo| {
                if total_capacity >= query.min_total_capacity || limit == 0 {
                    (true, false)
                } else if locked_cells.contains(&(info.tx_hash.clone(), info.output_index)) {
                    (false, false)
                } else if match_cell(info, query, max_mature_number) {
                    total_capacity += info.capacity;
                    limit -= 1;
                    (
                        total_capacity >= query.min_total_capacity || limit == 0,
                        true,
                    )
                } else {
                    (false, false)
                }
            };
            let primary_hash = query.primary_script.calc_script_hash();
            let from_number = query.block_range.map(|range| range.start);
            let infos = match query.primary_type {
                PrimaryScriptType::Lock => self.with_db(|db| {
                    db.get_live_cells_by_lock(primary_hash, from_number, terminator)
                })?,
                PrimaryScriptType::Type => self.with_db(|db| {
                    db.get_live_cells_by_type(primary_hash, from_number, terminator)
                })?,
            };
            for info in infos {
                let cell_with_status = self
                    .rpc_client
                    .get_live_cell(OutPoint::new(info.tx_hash.pack(), info.output_index), true)
                    .map_err(|err| CellCollectorError::Other(err.into()))?;
                let cell = cell_with_status.cell.ok_or_else(|| {
                    CellCollectorError::Other(
                        format!(
                            "cell is status is unknown, tx_hash: {:x}, output_index: {}",
                            info.tx_hash, info.output_index
                        )
                        .into(),
                    )
                })?;
                cells.push(LiveCell {
                    output: cell.output.into(),
                    output_data: cell.data.unwrap().content.into_bytes(),
                    out_point: OutPoint::new(info.tx_hash.pack(), info.output_index),
                    block_number: info.number,
                    tx_index: info.index.tx_index,
                });
            }
        }

        if apply_changes {
            for cell in &cells {
                self.lock_cell(cell.out_point.clone())?;
            }
        }
        Ok((cells, total_capacity))
    }

    fn lock_cell(&mut self, out_point: OutPoint) -> Result<(), CellCollectorError> {
        self.locked_cells
            .insert((out_point.tx_hash().unpack(), out_point.index().unpack()));
        Ok(())
    }

    fn apply_tx(&mut self, tx: Transaction) -> Result<(), CellCollectorError> {
        let tx_view = tx.into_view();
        let tx_hash = tx_view.hash();
        for out_point in tx_view.input_pts_iter() {
            self.lock_cell(out_point)?;
        }
        for (output_index, (output, data)) in tx_view.outputs_with_data_iter().enumerate() {
            let out_point = OutPoint::new(tx_hash.clone(), output_index as u32);
            let info = LiveCell {
                output: output.clone(),
                output_data: data.clone(),
                out_point,
                block_number: 0,
                tx_index: 0,
            };
            self.offchain_live_cells.push(info);
        }
        Ok(())
    }

    fn reset(&mut self) {
        self.locked_cells.clear();
        self.offchain_live_cells.clear();
    }
}

fn match_cell(info: &LiveCellInfo, query: &CellQueryOptions, max_mature_number: u64) -> bool {
    // only check secondary script here
    if let Some(script) = query.secondary_script.as_ref() {
        let script_hash: H256 = script.calc_script_hash().unpack();
        match query.primary_type {
            PrimaryScriptType::Lock => {
                if info.type_hashes.as_ref().map(|(_, hash)| hash) != Some(&script_hash) {
                    return false;
                }
            }
            PrimaryScriptType::Type => {
                if info.lock_hash != script_hash {
                    return false;
                }
            }
        }
    }

    if let Some(range) = query.data_len_range {
        if !range.match_value(info.data_bytes) {
            return false;
        }
    }
    if let Some(range) = query.capacity_range {
        if !range.match_value(info.capacity) {
            return false;
        }
    }
    if let Some(range) = query.block_range {
        if !range.match_value(info.number) {
            return false;
        }
    }

    let cell_is_mature = is_mature(info, max_mature_number);
    match query.maturity {
        MaturityOption::Mature if cell_is_mature => {}
        MaturityOption::Immature if !cell_is_mature => {}
        MaturityOption::Both => {}
        // Skip this live cell
        _ => return false,
    }
    true
}
