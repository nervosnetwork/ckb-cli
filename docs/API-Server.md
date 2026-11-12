# ckb-cli API Server

**Usage**:
```
ckb-cli server --help
Start advanced API server

USAGE:
    ckb-cli server [FLAGS] [OPTIONS] --auth-token <auth-token>

OPTIONS:
        --listen <listen>                  Rpc server listen address (when --privkey-path is given ip MUST be 127.0.0.1)
                                           [default: 127.0.0.1:3000]
        --privkey-path <privkey-path>      Private key file path (only read first line)
        --auth-token <auth-token>          Token that clients must send in the `Authorization: Bearer <token>` header
```

## Authentication

The server must be started with `--auth-token`. The token must be non-empty printable ASCII without spaces; use a long random value, for example the output of `openssl rand -hex 32`.

Every request that calls a method must carry the header `Authorization: Bearer <token>`, including read-only methods and servers started without `--privkey-path`. Requests without the header or with a wrong token get a `401 Unauthorized` response, and no method is run.

`OPTIONS` requests (CORS preflight) are answered without the token, because they don't run any method.

Anyone who knows the token can use every method, including `transfer`, which spends from the key given by `--privkey-path` without further confirmation. A website opened in a browser on the same machine can still send requests to the server, but without the token it can't make the server run any method. Keep the token secret: it is visible to other local users in the process list while the server is running.

## Starting the server

```bash
AUTH_TOKEN=$(openssl rand -hex 32)
ckb-cli server --auth-token "$AUTH_TOKEN" --privkey-path ./privkey
```

Omit `--privkey-path` to start the server without `transfer`. The examples below send `$AUTH_TOKEN` from the same shell; clients in other shells or programs need the same token value.

* API Doc
  * [`transfer`](#transfer)
  * [`get_capacity_by_address`](#get_capacity_by_address)


## API Doc

### `transfer`

Transfer capacity to an address. Enabled when start server with `--privkey-path` argument.

**Attention**: `capacity` unit are Shannon.

See: `ckb-cli wallet transfer --help`

#### Parameters
The parameters of `transfer` method is different from other methods, this method use only one object as it's parameter.

    transfer_args          - A JSON object of type TransferArgs

TransferArgs fields:

    capacity            - The capacity (unit: Shannon)
    fee_rate            - The transaction fee rate (unit: shannons/KB)
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
        "fee_rate": 1000,
        "to_address": "ckt1qyqdfjzl8ju2vfwjtl4mttx6me09hayzfldq8m3a0y",
        "from_locked_address": null,
        "to_data": null
    }]
}' \
| tr -d '\n' \
| curl -H 'content-type: application/json' -H "Authorization: Bearer $AUTH_TOKEN" -d @- \
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
| curl -H 'content-type: application/json' -H "Authorization: Bearer $AUTH_TOKEN" -d @- \
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
