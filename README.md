# ckb-cli
CKB command line tool

## Features
```
>> rpc: Invoke RPC call to node

    get_block                 Get block content by hash
    get_block_by_number       Get block content by block number
    get_block_hash            Get block hash by block number
    get_cells_by_lock_hash    Get cells by lock script hash
    get_current_epoch         Get current epoch information
    get_epoch_by_number       Get epoch information by epoch number
    get_live_cell             Get live cell (live means unspent)
    get_tip_block_number      Get tip block number
    get_tip_header            Get tip header
    get_transaction           Get transaction content by transaction hash
    get_peers                 Get connected peers
    local_node_info           Get local node information
    tx_pool_info              Get transaction pool information
    get_blockchain_info       Get chain information

>> wallet: Tranfer / query balance(with local index) / key utils

    transfer               Transfer capacity to an address (can have data)
    key-info               Show public information of a secp256k1 private key (from file) or public key
    get-capacity           Get capacity by lock script hash or address or lock arg or pubkey
    get-live-cells         Get live cells by lock script hash
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
parent_hash: 0xbb6b3dc93b82840014bc675e8359456cf71a1d09af9d901d807e6fa52be0c194
timestamp: "1562125018195"
number: "8983"
epoch: "12"
transactions_root: 0x467d8f40699910190305861c688ce0e4d28113434cbe5a57e3aad34d203f2c7e
witnesses_root: 0x4580baec10b07f6e1e37c8ecc4e287efe87b3d7fa47872b97a9a1b1a84104167
proposals_hash: 0x1773e9e580feb6787023ee31dfd971fccb718628052bc9601f6ea8b47c6c3ae0
difficulty: 0x49490
uncles_hash: 0xfc3add54f50bf3de7c2c40702b6a46a0ecc7a5250fb0ac09fac4c53235b44abe
uncles_count: "1"
seal:
  nonce: "6966906004188122030"
  proof: 0x0f1200009319000057200000c5210000dc30000007410000084e00007a630000776600008668000060760000ab7f0000
hash: 0x3ec0bbca4eb9f1a56332b9336827e27115589944583d3bdeac37ab27c181e6ef
```

### Example: Get live cell (json output format)
```
ckb-cli rpc get_live_cell --hash 0x938ebf9761e6fc1e0cbc0694d0a329a4cf00c5dea290bee0b274f71a3d2ae6de --tx-hash 0x23510d46adf6cfc28d658582d9fdcfb51f4450706bd520e5249973a736585579 --index 0
```

**Response:**
``` json
{
  "cell": {
    "capacity": "2030044660982",
    "data": "0x",
    "lock": {
      "args": [
        "0xd074c75f81e7f462066498e71c93a476a07d8033"
      ],
      "code_hash": "0xa6c987e2fbf5ba00cd1a83edbb1a53db088c6d1869f866a5e758a0fb99ff53a1"
    },
    "type": null
  },
  "status": "live"
}
```
