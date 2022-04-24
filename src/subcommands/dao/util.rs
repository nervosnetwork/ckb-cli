use crate::subcommands::Output;
use crate::utils::{
    other::check_lack_of_capacity,
    printer::{OutputFormat, Printable},
    rpc::HttpRpcClient,
};
use ckb_index::LiveCellInfo;
use ckb_sdk::util::calculate_dao_maximum_withdraw4;
use ckb_types::core::{Capacity, TransactionView};
use ckb_types::{core::HeaderView, packed, prelude::*};

pub(crate) fn calculate_dao_maximum_withdraw(
    rpc_client: &mut HttpRpcClient,
    prepare_cell: &LiveCellInfo,
) -> Result<u64, String> {
    // Get the deposit_header and prepare_header corresponding to the `prepare_cell`
    let prepare_tx_status = rpc_client
        .get_transaction(prepare_cell.tx_hash.clone())?
        .ok_or_else(|| "invalid prepare out_point, the tx is not found".to_string())?;
    let prepare_block_hash = prepare_tx_status
        .tx_status
        .block_hash
        .ok_or("invalid prepare out_point, the tx is not committed")?;
    let prepare_tx = {
        let tx: packed::Transaction = prepare_tx_status
            .transaction
            .ok_or("rejected transaction")?
            .inner
            .into();
        tx.into_view()
    };
    let deposit_out_point = prepare_tx
        .inputs()
        .get(prepare_cell.index.output_index as usize)
        .ok_or_else(|| "invalid prepare tx".to_string())?
        .previous_output();
    let deposit_tx_status = {
        let deposit_tx_hash = deposit_out_point.tx_hash();
        rpc_client
            .get_transaction(deposit_tx_hash.unpack())?
            .ok_or_else(|| "invalid deposit out_point, the tx is not found".to_string())?
    };
    let deposit_block_hash = deposit_tx_status
        .tx_status
        .block_hash
        .ok_or("invalid deposit out_point, the tx is not committed")?;
    let deposit_tx = {
        let tx: packed::Transaction = deposit_tx_status
            .transaction
            .ok_or("rejected transaction")?
            .inner
            .into();
        tx.into_view()
    };
    let (output, output_data) = {
        deposit_tx
            .output_with_data(deposit_out_point.index().unpack())
            .ok_or_else(|| "invalid deposit out_point, the cell is not found".to_string())?
    };
    let deposit_header: HeaderView = rpc_client
        .get_header(deposit_block_hash)?
        .ok_or_else(|| "failed to get deposit_header".to_string())?
        .into();
    let prepare_header: HeaderView = rpc_client
        .get_header(prepare_block_hash)?
        .ok_or_else(|| "failed to get prepare_header".to_string())?
        .into();

    // Calculate maximum withdraw of the deposited_output
    //
    // NOTE: It is safe to use `unwrap` for the data we fetch from ckb node.
    let occupied_capacity = output
        .occupied_capacity(Capacity::bytes(output_data.len()).unwrap())
        .unwrap();
    Ok(calculate_dao_maximum_withdraw4(
        &deposit_header,
        &prepare_header,
        &output,
        occupied_capacity.as_u64(),
    ))
}

pub(crate) fn send_transaction(
    rpc_client: &mut HttpRpcClient,
    transaction: TransactionView,
    debug: bool,
) -> Result<Output, String> {
    check_lack_of_capacity(&transaction)?;
    let transaction_view: ckb_jsonrpc_types::TransactionView = transaction.clone().into();
    if debug {
        eprintln!(
            "[Send Transaction]:\n{}",
            transaction_view.render(OutputFormat::Yaml, false)
        );
    }

    let resp = rpc_client.send_transaction(transaction.data(), None)?;
    Ok(Output::new_output(resp))
}
