# ckb-cli API Server

**Usage**:
```
ckb-cli server --help
Start advanced API server

USAGE:
    ckb-cli server [FLAGS] [OPTIONS] --listen <listen>

FLAGS:
        --wait-for-sync    Ensure the index-store synchronizes completely before command being executed

OPTIONS:
        --listen <listen>                  Rpc server listen address (when --privkey-path is given ip MUST be 127.0.0.1)
                                           [default: 127.0.0.1:3000]
        --privkey-path <privkey-path>      Private key file path (only read first line)
```

* API Doc
  * [`transfer`](#transfer)
  * [`get_capacity_by_address`](#get_capacity_by_address)
  * [`get_capacity_by_lock_hash`](#get_capacity_by_lock_hash)
  * [`get_live_cells_by_address`](#get_live_cells_by_address)
  * [`get_live_cells_by_lock_hash`](#get_live_cells_by_lock_hash)
  * [`get_live_cells_by_type_hash`](#get_live_cells_by_type_hash)
  * [`get_live_cells_by_code_hash`](#get_live_cells_by_code_hash)


## API Doc

### `transfer`

Transfer capacity to an address. Enabled when start server with `--privkey-path** argument.

**Attention**: `capacity` and `tx_fee` unit are Shannon.

See: `ckb-cli wallet transfer --help`

#### Parameters
The parameters of `transfer` method is different from other methods, this method use only one object as it's parameter.

    transfer_args          - A JSON object of type TransferArgs

TransferArgs fields:

    capacity            - The capacity (unit: Shannon)
    tx_fee              - The transaction fee capacity (unit: Shannon)
    to_address          - Target address
    from_locked_address - (optional) The time locked multisig address to search live cells
    to_data             - (optional) Hex data store in target cell

#### Examples

```bash
echo '{
    "id": 2,
    "jsonrpc": "2.0",
    "method": "transfer",
    "params": [{
        "capacity": 200000000000,
        "tx_fee": 1000,
        "to_address": "ckt1qyqdfjzl8ju2vfwjtl4mttx6me09hayzfldq8m3a0y",
        "from_locked_address": null,
        "to_data": null
    }]
}' \
| tr -d '\n' \
| curl -H 'content-type: application/json' -d @- \
http://localhost:3000
```

```json
{
  "jsonrpc": "2.0",
  "result": "0x14afd2df9bf130962f3d30e17fb68fbab91fbf93189240a77fdc633dc39e6d5a",
  "id": 2
}
```


### `get_capacity_by_address`

Get capacity by address

See: `ckb-cli wallet get-capacity --help`

#### Parameters

    address - Target address

#### Examples

```bash
echo '{
    "id": 2,
    "jsonrpc": "2.0",
    "method": "get_capacity_by_address",
    "params": ["ckt1qyqdfjzl8ju2vfwjtl4mttx6me09hayzfldq8m3a0y"]
}' \
| tr -d '\n' \
| curl -H 'content-type: application/json' -d @- \
http://localhost:3000
```

```json
{
  "jsonrpc": "2.0",
  "result": {
    "dao": 0,
    "immature": 0,
    "total": 3000000009000
  },
  "id": 2
}
```


### `get_capacity_by_lock_hash`

Get capacity by lock script hash

See: `ckb-cli wallet get-capacity --help`

#### Parameters

    lock_hash - Lock script hash


#### Examples

```bash
echo '{
    "id": 2,
    "jsonrpc": "2.0",
    "method": "get_capacity_by_lock_hash",
    "params": ["0x951f5af7606e2905a556a2774b99de803f0dac47e06129ecd3d4c42243b290ed"]
}' \
| tr -d '\n' \
| curl -H 'content-type: application/json' -d @- \
http://localhost:3000
```

```json
{
  "jsonrpc": "2.0",
  "result": {
    "dao": 0,
    "immature": 0,
    "total": 3000000009000
  },
  "id": 2
}
```


### `get_live_cells_by_address`

Get live cells by address

See: `ckb-cli wallet get-live-cells --help`

#### Parameters

    address - Target address
    from    - (optional) Search from block number (included)
    to      - (optional) Search to block number (included)
    limit   - Get live cells <= limit


#### Examples

```bash
echo '{
    "id": 2,
    "jsonrpc": "2.0",
    "method": "get_live_cells_by_address",
    "params": ["ckt1qyqdfjzl8ju2vfwjtl4mttx6me09hayzfldq8m3a0y", null, null, 2]
}' \
| tr -d '\n' \
| curl -H 'content-type: application/json' -d @- \
http://localhost:3000
```

```json
{
  "jsonrpc": "2.0",
  "result": {
    "current_capacity": 2200000009000,
    "current_count": 2,
    "live_cells": [
      {
        "info": {
          "capacity": 2000000009000,
          "data_bytes": 0,
          "index": {
            "output_index": 1,
            "tx_index": 1
          },
          "lock_hash": "0x951f5af7606e2905a556a2774b99de803f0dac47e06129ecd3d4c42243b290ed",
          "number": 62800,
          "tx_hash": "0xd3f1df20a4b87c01d77b0ab9877c9270c512ce3e9a4443deb0eb685112fc24e5",
          "output_index": 1,
          "type_hashes": null
        },
        "mature": true
      },
      {
        "info": {
          "capacity": 200000000000,
          "data_bytes": 0,
          "index": {
            "output_index": 0,
            "tx_index": 1
          },
          "lock_hash": "0x951f5af7606e2905a556a2774b99de803f0dac47e06129ecd3d4c42243b290ed",
          "number": 86682,
          "tx_hash": "0x962562e730cbab29fcfed8c2aff9da8936f669c2236957107da12c357d6847af",
          "output_index": 0,
          "type_hashes": null
        },
        "mature": true
      }
    ]
  },
  "id": 2
}
```


### `get_live_cells_by_lock_hash`

Get live cells by lock script hash

See: `ckb-cli wallet get-live-cells --help`

`Parameters`/`Examples` are similar to `get_live_cells_by_address`.


### `get_live_cells_by_type_hash`

Get live cells by type script hash

See: `ckb-cli wallet get-live-cells --help`

`Parameters`/`Examples` are similar to `get_live_cells_by_address`.


### `get_live_cells_by_code_hash`

Get live cells by type script's code hash

See: `ckb-cli wallet get-live-cells --help`

`Parameters`/`Examples` are similar to `get_live_cells_by_address`.
