use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{Error, Result};
use ckb_index::{CellIndex, IndexDatabase, LiveCellInfo};
use ckb_sdk::{GenesisInfo, HttpRpcClient, HumanCapacity};
use ckb_types::{packed, prelude::*, H256};

use crate::utils::{
    index::{with_db, IndexController},
    other::is_mature,
};

pub struct CellCollector<'a> {
    rpc_client: &'a mut HttpRpcClient,
    genesis_info: &'a GenesisInfo,
    index_dir: &'a PathBuf,
    index_controller: IndexController,
    wait_for_sync: bool,
    max_mature_number: u64,
    locked_cells: HashSet<(H256, u32)>,
    // lock_hash => live cell
    offchain_live_cells: Vec<LiveCellInfo>,
}

impl<'a> CellCollector<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        genesis_info: &'a GenesisInfo,
        index_dir: &'a PathBuf,
        index_controller: IndexController,
        wait_for_sync: bool,
        max_mature_number: u64,
    ) -> CellCollector<'a> {
        CellCollector {
            rpc_client,
            genesis_info,
            index_dir,
            index_controller,
            wait_for_sync,
            max_mature_number,
            locked_cells: Default::default(),
            offchain_live_cells: Default::default(),
        }
    }

    pub fn lock_cell(&mut self, tx_hash: H256, index: u32) {
        log::debug!("lock cell, tx_hash: {:#x}, index: {}", tx_hash, index);
        self.locked_cells.insert((tx_hash, index));
    }
    pub fn apply_tx(&mut self, tx: packed::Transaction) {
        let tx_view = tx.into_view();
        let tx_hash: H256 = tx_view.hash().unpack();
        log::debug!("apply transaction to cell collector: {:#x}", tx_hash);
        for out_point in tx_view.input_pts_iter() {
            self.lock_cell(out_point.tx_hash().unpack(), out_point.index().unpack());
        }
        for (output_index, (output, data)) in tx_view.outputs_with_data_iter().enumerate() {
            let type_hashes = output.type_().to_opt().map(|_| Default::default());
            let capacity: u64 = output.capacity().unpack();
            log::debug!(
                "manual add live cell, tx-hash: {:#x}, index: {}, capacity: {}",
                tx_hash,
                output_index,
                HumanCapacity(capacity)
            );
            let info = LiveCellInfo {
                tx_hash: tx_hash.clone(),
                output_index: output_index as u32,
                data_bytes: data.len() as u64,
                type_hashes,
                lock_hash: output.lock().calc_script_hash().unpack(),
                capacity,
                number: Default::default(),
                index: CellIndex {
                    tx_index: Default::default(),
                    output_index: output_index as u32,
                },
            };
            self.offchain_live_cells.push(info);
        }
    }

    pub fn collect_one(
        &mut self,
        lock_hash: H256,
        apply_changes: bool,
    ) -> Result<(Vec<LiveCellInfo>, u64)> {
        self.collect_live_cells(lock_hash, 1, apply_changes)
    }

    pub fn collect_live_cells(
        &mut self,
        lock_hash: H256,
        capacity: u64,
        apply_changes: bool,
    ) -> Result<(Vec<LiveCellInfo>, u64)> {
        fn enough_capacity(from_capacity: u64, to_capacity: u64) -> bool {
            from_capacity >= to_capacity
        }

        let mut collected_capacity = 0;
        let (mut infos, rest_infos): (Vec<_>, Vec<_>) = self
            .offchain_live_cells
            .clone()
            .into_iter()
            .partition(|info| {
                if enough_capacity(collected_capacity, capacity) {
                    false
                } else if info.lock_hash == lock_hash
                    && info.type_hashes.is_none()
                    && info.data_bytes == 0
                {
                    log::debug!(
                        "got offchain live cell tx-hash: {:#x}, index: {}",
                        info.tx_hash,
                        info.output_index
                    );
                    collected_capacity += info.capacity;
                    true
                } else {
                    log::debug!(
                        "skip offchain live cell tx-hash: {:#x}, index: {}",
                        info.tx_hash,
                        info.output_index
                    );
                    false
                }
            });
        if apply_changes {
            self.offchain_live_cells = rest_infos;
        }
        if enough_capacity(collected_capacity, capacity) {
            return Ok((infos, collected_capacity));
        }

        let max_mature_number: u64 = self.max_mature_number;
        let locked_cells = self.locked_cells.clone();
        let mut terminator = |_, info: &LiveCellInfo| {
            if locked_cells.contains(&(info.tx_hash.clone(), info.output_index)) {
                log::debug!(
                    "skip locked live cell tx-hash: {:#x}, index: {}",
                    info.tx_hash,
                    info.output_index
                );
            }
            if enough_capacity(collected_capacity, capacity) {
                (true, false)
            } else if info.type_hashes.is_none()
                && info.data_bytes == 0
                && is_mature(info, max_mature_number)
                && !locked_cells.contains(&(info.tx_hash.clone(), info.output_index))
            {
                collected_capacity += info.capacity;
                (enough_capacity(collected_capacity, capacity), true)
            } else {
                (false, false)
            }
        };

        let func =
            |db: IndexDatabase| db.get_live_cells_by_lock(lock_hash.pack(), None, &mut terminator);
        let more_infos = with_db(
            func,
            self.rpc_client,
            self.genesis_info.clone(),
            self.index_dir,
            self.index_controller.clone(),
            self.wait_for_sync,
        )
        .map_err(Error::msg)?;
        infos.extend(more_infos);
        if apply_changes {
            for info in &infos {
                self.lock_cell(info.tx_hash.clone(), info.output_index);
            }
        }
        Ok((infos, collected_capacity))
    }
}
