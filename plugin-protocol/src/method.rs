pub const QUIT: &str = "quit";
pub const GET_CONFIG: &str = "get_config";
pub const READ_PASSWORD: &str = "read_password";
pub const PRINT_STDOUT: &str = "print_stdout";
pub const PRINT_STDERR: &str = "print_stderr";
pub const RPC_URL_CHANGED: &str = "rpc_url_changed";
pub const SUB_COMMAND: &str = "sub_command";

pub const CALLBACK_PREFIX: &str = "callback_";
pub const CALLBACK_SEND_TRANSACTION: &str = "callback_send_transaction";

pub const RPC_PREFIX: &str = "rpc_";
pub const RPC_GET_BLOCK: &str = "rpc_get_block";
pub const RPC_GET_BLOCK_BY_NUMBER: &str = "rpc_get_block_by_number";
pub const RPC_GET_BLOCK_HASH: &str = "rpc_get_block_hash";
pub const RPC_GET_CELLBASE_OUTPUT_CAPACITY_DETAILS: &str =
    "rpc_get_cellbase_output_capacity_details";

pub const INDEXER_PREFIX: &str = "indexer_";
pub const INDEXER_TIP_HEADER: &str = "indexer_tip_header";
pub const INDEXER_LAST_HEADER: &str = "indexer_last_header";
pub const INDEXER_GET_CAPACITY: &str = "indexer_get_capacity";
pub const INDEXER_GET_LIVE_CELLS: &str = "indexer_get_live_cells";
pub const INDEXER_GET_TOPN: &str = "indexer_get_topn";
pub const INDEXER_GET_INDEXER_INFO: &str = "indexer_get_indexer_info";
pub const INDEXER_ANY: &str = "indexer_any";

pub const KEYSTORE_PREFIX: &str = "keystore_";
pub const KEYSTORE_LIST_ACCOUNT: &str = "keystore_list_account";
pub const KEYSTORE_HAS_ACCOUNT: &str = "keystore_has_account";
pub const KEYSTORE_CREATE_ACCOUNT: &str = "keystore_create_account";
pub const KEYSTORE_UPDATE_PASSWORD: &str = "keystore_update_password";
pub const KEYSTORE_IMPORT: &str = "keystore_import";
pub const KEYSTORE_IMPORT_ACCOUNT: &str = "keystore_import_account";
pub const KEYSTORE_EXPORT: &str = "keystore_export";
pub const KEYSTORE_SIGN: &str = "keystore_sign";
pub const KEYSTORE_EXTENDED_PUBKEY: &str = "keystore_extended_pubkey";
pub const KEYSTORE_DERIVED_KEY_SET: &str = "keystore_derived_key_set";
pub const KEYSTORE_DERIVED_KEY_SET_BY_INDEX: &str = "keystore_derived_key_set_by_index";
pub const KEYSTORE_ANY: &str = "keystore_any";
