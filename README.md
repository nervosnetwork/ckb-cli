# ckb-cli
CKB command line tool

## Features
```
>> rpc: Invoke RPC call to node

    get_tip_header            Get tip header
    get_block                 Get block content by hash
    get_block_hash            Get block hash by block number
    get_block_by_number       Get block content by block number
    get_transaction           Get transaction content by transaction hash
    get_cells_by_lock_hash    Get cells by lock script hash
    get_live_cell             Get live cell (live means unspent)
    get_current_epoch         Get current epoch information
    get_epoch_by_number       Get epoch information by epoch number
    local_node_info           Get local node information
    tx_pool_info              Get transaction pool information
    get_peers                 Get connected peers
    

>> wallet: tranfer / query balance(with local index) / key utils

    transfer        Transfer capacity to a address (can have data)
    get-capacity    Get capacity by lock script hash
    get-balance     Get balance by address (balance is capacity)
    top             Show top n capacity owned by lock script hash
    generate-key    Generate a random secp256k1 privkey and save to file (print block_assembler config)
    key-info        Show public information of a secp256k1 private key (file)

```

## Build this project
```
cargo build
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
./target/debug/ckb-cli --help
# RPC help doc
./target/debug/ckb-cli rpc --help
```

### Example: Get tip header

```
./target/debug/ckb-cli rpc get_tip_header
```

**Response:**
``` json
{
  "difficulty": "0x1000",
  "epoch": "7",
  "hash": "0xae4cad5b18de8a34b569e754d8acaa4de37377fc6fa377d2842033f4c3d36488",
  "number": "13701",
  "parent_hash": "0x797905db0d2402101d06014ae349e0f163d39ee700dba4e67e71b171dd388d52",
  "proposals_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "seal": {
    "nonce": "1990243765011657333",
    "proof": "0x500c0000bc0f000061260000be2d00006b320000d838000055470000c3490000514a000041750000e1790000d07a0000"
  },
  "timestamp": "1557739087615",
  "transactions_root": "0x07fb3173000ea423625fdfcf410be15b464aa02298649f6179c7135485f569ee",
  "uncles_count": "0",
  "uncles_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "version": "0",
  "witnesses_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
}
```

### Example: Get live cell
```
./target/debug/ckb-cli rpc get_live_cell --hash 0x938ebf9761e6fc1e0cbc0694d0a329a4cf00c5dea290bee0b274f71a3d2ae6de --tx-hash 0x23510d46adf6cfc28d658582d9fdcfb51f4450706bd520e5249973a736585579 --index 0
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
