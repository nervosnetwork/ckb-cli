# ckb-cli
CKB command line tool

## Features
```
>> rpc: Invoke RPC call to node

    get_block                               Get block content by hash
    get_block_by_number                     Get block content by block number
    get_block_hash                          Get block hash by block number
    get_cellbase_output_capacity_details    Get block header content by hash
    get_cells_by_lock_hash                  Get cells by lock script hash
    get_current_epoch                       Get current epoch information
    get_epoch_by_number                     Get epoch information by epoch number
    get_header                              Get block header content by hash
    get_header_by_number                    Get block header by block number
    get_live_cell                           Get live cell (live means unspent)
    get_tip_block_number                    Get tip block number
    get_tip_header                          Get tip header
    get_transaction                         Get transaction content by transaction hash
    deindex_lock_hash                       Remove index for live cells and transactions by the hash of lock script
    get_live_cells_by_lock_hash             Get the live cells collection by the hash of lock script
    get_transactions_by_lock_hash           Get the transactions collection by the hash of lock script. Returns
                                            empty array when the `lock_hash` has not been indexed yet
    index_lock_hash                         Create index for live cells and transactions by the hash of lock script
    get_banned_addresses                    Get all banned IPs/Subnets
    get_peers                               Get connected peers
    local_node_info                         Get local node information
    set_ban                                 Insert or delete an IP/Subnet from the banned list
    tx_pool_info                            Get transaction pool information
    get_blockchain_info                     Get chain information
    add_node                                Connect to a node
    remove_node                             Disconnect a node
    broadcast_transaction                   Broadcast transaction without verify

>> wallet: Transfer / query balance (with local index) / key utils

    transfer               Transfer capacity to an address (can have data)
    deposit-dao            Deposit capacity into NervosDAO(can have data)
    withdraw-dao           Withdraw capacity from NervosDAO(can have data)
    get-capacity           Get capacity by lock script hash or address or lock arg or pubkey
    get-dao-capacity       Get NervosDAO deposited capacity by lock script hash or address or lock arg or pubkey
    get-live-cells         Get live cells by lock/type/code  hash
    get-lock-by-address    Get lock script (include hash) by address
    db-metrics             Show index database metrics
    top-capacity           Show top n capacity owned by lock script hash

>> account: Manage accounts

    list      List all accounts
    new       Create a new account and print related information.
    import    Import an unencrypted private key from <privkey-path> and create a new account.
    unlock    Unlock an account
    update    Update password of an account
    export    Export master private key and chain code as hex plain text (USE WITH YOUR OWN RISK)

>> util: Utilities

    key-info              Show public information of a secp256k1 private key (from file) or public key
    serialize-tx          Serialize a transaction from json file to hex binary or hash
    deserialize-tx        Deserialize a transaction from binary hex to json
    serialize-script      Serialize a script from json file to hex binary or hash
    deserialize-script    Deserialize a script from hex binary to json

>> mock-tx: Handle mock transactions (verify/send)

    template    Print mock transaction template
    complete    Complete the mock transaction
    verify      Verify a mock transaction in local
    send        Complete then send a transaction
```

## Build this project
```
git clone https://github.com/nervosnetwork/ckb-cli.git
cd ckb-cli
cargo install --path . -f
```

## Usage

Better export an env first (or give in argument)

```
export API_URL=http://127.0.0.1:8114
```

Directly go to **gorgeous** interactive mode:

```
ckb-cli
```

Show available commands
``` shell
# Top level help doc
ckb-cli --help
# RPC help doc
ckb-cli rpc --help
```

### Example: Get tip header (yaml output format)

```
ckb-cli rpc get_tip_header
```

**Response:**
``` yaml
version: "0"
parent_hash: 0xb379bf3d369fccadfa69fa2273a8f596489b69dab996ca02a3eb1ae4cf765ca3
timestamp: "1567775474688"
number: "102"
epoch: "0"
transactions_root: 0xc4991d3e261c27a0ce7ea9801de5f0a5f56ffb82a29d7a6e8e7cf44dbb2db114
witnesses_root: 0x39116bc1a56f5ca82cf5226f172f97ff8a8d9626ca7e41d8cd92e76666e069f8
proposals_hash: 0x0000000000000000000000000000000000000000000000000000000000000000
difficulty: 0x4000000
uncles_hash: 0x0000000000000000000000000000000000000000000000000000000000000000
uncles_count: "0"
dao: 0x0100000000000000af9a31ce318a230000cc083d71c4350000d774f0356a0000
nonce: "1876243812404095811"
hash: 0x0384ebc55b7cb56e51044743e05fb83a4edb7173524339c35df4c71fcdb0854d
```

### Example: Get live cell (json output format)
```
ckb-cli rpc get_live_cell --tx-hash 0x4ec75b5a8de8d180853d5046760a99285c73283a5dc528f81d6ee056f5335172 --index 0 --output-format json
```

**Response:**
``` json
{
  "cell": {
    "capacity": "125000000000",
    "lock": {
      "args": [
        "0x64257f00b6b63e987609fa9be2d0c86d351020fb"
      ],
      "code_hash": "0x1892ea40d82b53c678ff88312450bbb17e164d7a3e0a90941aa58839f56f8df2",
      "hash_type": "type"
    },
    "type": null
  },
  "status": "live"
}
```
