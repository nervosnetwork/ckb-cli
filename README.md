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
