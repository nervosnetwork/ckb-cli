use anyhow::{anyhow, Result};
use ckb_index::LiveCellInfo;
use ckb_sdk::{
    constants::SECP_SIGNATURE_SIZE, Address, AddressPayload, HumanCapacity, MultisigConfig,
};
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, FeeRate, TransactionBuilder},
    packed,
    prelude::*,
    H256,
};

use super::cell_collector::CellCollector;
use super::state_change::ChangeInfo;
use super::WARN_FEE_CAPACITY;

pub fn build_tx<T: ChangeInfo>(
    from_address: &Address,
    collector: &mut CellCollector,
    fee_rate: u64,
    cell_deps: Vec<packed::CellDep>,
    multisig_config: Option<&MultisigConfig>,
    lock_script: &packed::Script,
    infos: &[T],
) -> Result<Option<packed::Transaction>> {
    let to_capacity: u64 = infos
        .iter()
        .filter_map(|info| {
            if info.has_new_output() {
                Some(info.occupied_capacity(lock_script))
            } else {
                None
            }
        })
        .sum();
    if to_capacity == 0 {
        return Ok(None);
    }

    let from_lock_hash: H256 = packed::Script::from(from_address.payload())
        .calc_script_hash()
        .unpack();
    let (mut inputs, mut input_capacities): (Vec<_>, Vec<_>) =
        infos.iter().filter_map(|info| info.build_input()).unzip();
    if inputs.is_empty() {
        let (more_infos, more_capacity) = collector.collect_one(from_lock_hash, true)?;
        inputs.extend(more_infos.into_iter().map(|info| info.input()));
        input_capacities.push(more_capacity);
    }
    if inputs.is_empty() {
        return Err(anyhow!(
            "Capacity(mature) not enough from {}, require more than {}",
            from_address,
            to_capacity,
        ));
    }
    let first_cell_input = &inputs[0];
    let (outputs, outputs_data): (Vec<_>, Vec<_>) = infos
        .iter()
        .filter_map(|info| info.build_cell_output(lock_script, first_cell_input))
        .unzip();
    let init_input_total_capacity: u64 = input_capacities.into_iter().sum();
    let base_tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        // update witnesses for calculate transaction fee
        .witnesses(inputs.iter().map(|_| Bytes::default().pack()))
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.into_iter().map(|data| data.pack()))
        .build()
        .data();
    let (final_tx, input_total_capacity, output_total_capacity) = tx_adjust_fee(
        base_tx,
        init_input_total_capacity,
        collector,
        fee_rate,
        from_address.payload(),
        multisig_config,
    )?;
    log::info!(
        "transaction fee: {}",
        HumanCapacity(input_total_capacity - output_total_capacity)
    );
    assert!(input_total_capacity > output_total_capacity);
    assert!(input_total_capacity - output_total_capacity < WARN_FEE_CAPACITY);
    Ok(Some(final_tx))
}

fn tx_fill_inputs(
    base_tx: packed::Transaction,
    mut input_total_capacity: u64,
    from_lock_hash: H256,
    collector: &mut CellCollector,
) -> Result<(packed::Transaction, u64, u64)> {
    let output_total_capacity: u64 = base_tx
        .raw()
        .outputs()
        .into_iter()
        .zip(base_tx.raw().outputs_data().into_iter())
        .map(|(output, data)| {
            output
                .occupied_capacity(Capacity::bytes(data.len()).unwrap())
                .unwrap()
                .as_u64()
        })
        .sum();
    let new_tx = if output_total_capacity > input_total_capacity {
        let (more_infos, more_capacity) = collector.collect_live_cells(
            from_lock_hash,
            output_total_capacity - input_total_capacity,
            true,
        )?;
        let more_inputs: Vec<_> = more_infos.into_iter().map(|info| info.input()).collect();
        input_total_capacity += more_capacity;
        base_tx
            .as_advanced_builder()
            // update witnesses for calculate transaction fee
            .witnesses(more_inputs.iter().map(|_| Bytes::default().pack()))
            .inputs(more_inputs.pack())
            .build()
            .data()
    } else {
        base_tx
    };
    Ok((new_tx, input_total_capacity, output_total_capacity))
}

pub fn tx_adjust_fee(
    base_tx: packed::Transaction,
    init_input_total_capacity: u64,
    collector: &mut CellCollector,
    fee_rate_value: u64,
    from_address_payload: &AddressPayload,
    multisig_config: Option<&MultisigConfig>,
) -> Result<(packed::Transaction, u64, u64)> {
    const MOLECULE_NUMBER_SIZE: usize = 4;

    let from_lock = packed::Script::from(from_address_payload);
    let from_lock_hash: H256 = from_lock.calc_script_hash().unpack();

    let (filled_tx, input_total_capacity, output_total_capacity) = tx_fill_inputs(
        base_tx,
        init_input_total_capacity,
        from_lock_hash.clone(),
        collector,
    )?;
    if input_total_capacity < output_total_capacity {
        return Err(anyhow!(
            "Not enough capacity to build the transaction, expected more than {}, got {}",
            HumanCapacity(output_total_capacity),
            HumanCapacity(input_total_capacity),
        ));
    }

    let delta_capacity = input_total_capacity - output_total_capacity;
    let fee_rate = FeeRate::from_u64(fee_rate_value);
    let sighash_lock_witness_size = packed::WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; SECP_SIGNATURE_SIZE])).pack())
        .build()
        .as_slice()
        .len();
    let multisig_lock_witness_size = multisig_config
        .map(|config| {
            let total_data_len = SECP_SIGNATURE_SIZE * (config.threshold() as usize)
                + config.to_witness_data().len();
            packed::WitnessArgs::new_builder()
                .lock(Some(Bytes::from(vec![0u8; total_data_len])).pack())
                .build()
                .as_slice()
                .len()
        })
        .unwrap_or_default();
    let tx_size = filled_tx.as_reader().serialized_size_in_block()
        + sighash_lock_witness_size
        + multisig_lock_witness_size;
    let min_fee = fee_rate.fee(tx_size).as_u64();
    log::info!(
        "input-total: {}, output-total: {}, delta-capacity: {}, tx-size: {}, fee-rate: {}, min-fee: {}",
        HumanCapacity(input_total_capacity),
        HumanCapacity(output_total_capacity),
        HumanCapacity(delta_capacity),
        tx_size,
        fee_rate_value,
        HumanCapacity(min_fee),
    );
    if min_fee == delta_capacity {
        log::info!("transaction fee fit perfectly!");
        return Ok((filled_tx, input_total_capacity, output_total_capacity));
    }

    let base_change_cell_output = packed::CellOutput::new_builder().lock(from_lock).build();
    let witness_offset_length = MOLECULE_NUMBER_SIZE * 2;
    let input_serialized_size =
        packed::CellInput::default().as_slice().len() + witness_offset_length;
    let change_data_offset_length = MOLECULE_NUMBER_SIZE * 2;
    let change_output_serialized_size =
        base_change_cell_output.as_slice().len() + MOLECULE_NUMBER_SIZE + change_data_offset_length;
    let change_cell_occupied_capacity = base_change_cell_output
        .occupied_capacity(Capacity::zero())
        .unwrap()
        .as_u64();

    if collector
        .collect_one(from_lock_hash.clone(), false)?
        .0
        .is_empty()
        && min_fee > delta_capacity
    {
        return Err(anyhow!("No more live cells to pay transaction fee"));
    }
    if min_fee < delta_capacity
        && (delta_capacity - min_fee)
            <= fee_rate
                .fee(input_serialized_size + change_output_serialized_size)
                .as_u64()
    {
        log::info!("fee rate too high no need to adjust it by collect more inputs");
        return Ok((filled_tx, input_total_capacity, output_total_capacity));
    }

    let mut extra_infos: Vec<LiveCellInfo> = Vec::new();
    let mut extra_capacity: u64 = 0;
    loop {
        let final_tx_size =
            tx_size + input_serialized_size * extra_infos.len() + change_output_serialized_size;
        let final_min_fee = fee_rate.fee(final_tx_size).as_u64();
        let final_delta_capacity = delta_capacity + extra_capacity;
        log::info!(
            "final-min-fee: {}, extra-capacity: {}",
            HumanCapacity(final_min_fee),
            HumanCapacity(extra_capacity)
        );
        if final_delta_capacity >= change_cell_occupied_capacity + final_min_fee {
            let change_capacity = final_delta_capacity - final_min_fee;
            log::info!(
                "have enough capacity for change cell, change capacity: {}",
                HumanCapacity(change_capacity)
            );
            let change_output = base_change_cell_output
                .as_builder()
                .capacity(Capacity::shannons(change_capacity).pack())
                .build();
            let final_tx = filled_tx
                .as_advanced_builder()
                .witnesses(extra_infos.iter().map(|_| Bytes::default().pack()))
                .inputs(extra_infos.into_iter().map(|info| info.input()))
                .output(change_output)
                .output_data(Bytes::default().pack())
                .build()
                .data();
            return Ok((
                final_tx,
                input_total_capacity + extra_capacity,
                output_total_capacity + change_capacity,
            ));
        } else {
            if extra_infos.len() >= 5 {
                return Err(anyhow!("load >= 5 extra input cells, something is wrong!"));
            }

            log::info!("try to collect one more live cell ...");
            let (more_infos, more_capacity) =
                collector.collect_one(from_lock_hash.clone(), true)?;
            if more_infos.is_empty()
                && final_delta_capacity < change_cell_occupied_capacity + final_min_fee
            {
                log::info!("have no capacity for change cell");
                if final_delta_capacity >= WARN_FEE_CAPACITY {
                    eprintln!(
                        "WARNING: current transaction fee = {} CKB, not enough live cell to reduce transaction fee to less than {} CKB, try to transfer some capacity to this address",
                        HumanCapacity(final_delta_capacity),
                        HumanCapacity(WARN_FEE_CAPACITY),
                    );
                }
                // no cpacity for put the change cell
                let final_tx = filled_tx
                    .as_advanced_builder()
                    .witnesses(extra_infos.iter().map(|_| Bytes::default().pack()))
                    .inputs(extra_infos.into_iter().map(|info| info.input()))
                    .build()
                    .data();
                return Ok((
                    final_tx,
                    input_total_capacity + extra_capacity,
                    output_total_capacity,
                ));
            }
            log::info!("collected {} more live cells", more_infos.len());
            extra_infos.extend(more_infos);
            extra_capacity += more_capacity;
        }
    }
}
