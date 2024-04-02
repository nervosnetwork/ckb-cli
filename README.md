# ckb-cli
CKB command line tool

## Features
```
    rpc         Invoke RPC call to node
    account     Manage accounts
    mock-tx     Handle mock transactions (verify/send)
    tx          Handle common sighash/multisig transaction
    util        Utilities
    molecule    Molecule encode/decode utilities
    wallet      Transfer / query balance (with local index) / key utils
    dao         Deposit / prepare / withdraw / query NervosDAO balance (with local index) / key utils
```

All second level sub-commands are listed in [wiki page](https://github.com/nervosnetwork/ckb-cli/wiki/Sub-Commands).

## Build this project
```
git clone https://github.com/nervosnetwork/ckb-cli.git
cd ckb-cli
cargo install --path . -f --locked
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
extra_hash: 0x0000000000000000000000000000000000000000000000000000000000000000
uncles_count: "0"
dao: 0x0100000000000000af9a31ce318a230000cc083d71c4350000d774f0356a0000
nonce: "1876243812404095811"
hash: 0x0384ebc55b7cb56e51044743e05fb83a4edb7173524339c35df4c71fcdb0854d
```

### Example: Get live cell (json output format)
```
ckb-cli rpc get_live_cell --tx-hash 0x4ec75b5a8de8d180853d5046760a99285c73283a5dc528f81d6ee056f5335172 --index 0
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

### Example: Indexer get cells (yaml output format)

Prepare file searchkey.json as input parameters:

```json
{
    "script": {
        "code_hash": "0xbbad126377d45f90a8ee120da988a2d7332c78ba8fd679aab478a19d6c133494",
        "hash_type": "data1",
        "args": "0x"
    },
    "script_type": "type",
    "script_search_mode": "prefix",
    "filter": {
        "output_data": "0xa58618a553",
        "output_data_filter_mode": "partial"
    },
    "with_data": false
}
```

```
ckb-cli rpc get_cells --json-path ./searchkey.json --order asc --limit 1
```
Response:

```yaml
last_cursor: 0x60bbad126377d45f90a8ee120da988a2d7332c78ba8fd679aab478a19d6c1334940215a27c046d5994a234629566f7e813c76a6ba9f9ec0338a11cbcc6629695ef7500000000009f78950000000100000001
objects:
  - block_number: 10451093
    out_point:
      index: 1
      tx_hash: 0x05a29ec877603526c25744634359fda6ba8d390b48a8c4830fcc7a196fccb9c3
    output:
      capacity: "22381.0"
      lock:
        args: 0x01cc0af0af911dd40853b8c8dfee90b32f8d1ecad600
        code_hash: 0xf329effd1c475a2978453c8600e1eaf0bc2087ee093c3ee64cc96ec6847752cb
        hash_type: type
      type:
        args: 0x15a27c046d5994a234629566f7e813c76a6ba9f9ec0338a11cbcc6629695ef75
        code_hash: 0xbbad126377d45f90a8ee120da988a2d7332c78ba8fd679aab478a19d6c133494
        hash_type: data1
    output_data: ~
    tx_index: 1
```

### Example: Indexer get transactions (yaml output format)

Prepare file searchkey.json as input parameters:

```json
{
    "script": {
        "code_hash": "0xbbad126377d45f90a8ee120da988a2d7332c78ba8fd679aab478a19d6c133494",
        "hash_type": "data1",
        "args": "0x"
    },
    "script_type": "type",
    "script_search_mode": "prefix",
    "with_data": false
}
```

```
ckb-cli rpc get_transactions --json-path ./searchkey.json --order asc --limit 3
```
Response:

```yaml
last_cursor: 0xa0bbad126377d45f90a8ee120da988a2d7332c78ba8fd679aab478a19d6c13349402013368282f4cde04254a3a6a2027b33f7c974046a4d5cbd96bc47d7f058c18090000000000b29e04000000050000000000
objects:
  - block_number: 10375179
    io_index: 1
    io_type: output
    tx_hash: 0x551ec96717c336b74bbb2e56a1cb9c73e2a9d4b56321079b454cfc1c0e6036ac
    tx_index: 7
  - block_number: 11705844
    io_index: 0
    io_type: output
    tx_hash: 0xd690aa336c0d05808e08a97ba2f3031b7691341df9002b305c2d27cb116e2705
    tx_index: 5
  - block_number: 11705860
    io_index: 0
    io_type: input
    tx_hash: 0xa3282c23227992933eee0a07e5cbf52ca62006b98f2d113ebf579c5e59cf5a62
    tx_index: 5
  ```