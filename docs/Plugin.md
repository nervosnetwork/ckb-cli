# Basic architecture
ckb-cli communicate with plugins by starting a plugin process and read/write request/response tough stdin/stdout. So it should be possible to write them in any language, and a crashing plugin should not cause ckb-cli crash.

There are 4 role types.

```rust
pub enum PluginRole {
    // The argument is for if keystore need password
    KeyStore { require_password: bool },
    Indexer,
    // The argument is for where the sub-command is injected to.
    SubCommand { name: String },
    // The argument is for the callback function name
    Callback { name: CallbackName },
}
```

The `key_store` and `indexer` role plugin can replace the default implementation and can be accessed by all plugins by sending request to stdout and then receive response from stdin.

The `sub_command` role plugin will add a top level sub-command in ckb-cli, the plugin will need to parse the command line argument itself.

The `callback` role plugin will be called when certain event happend (send transaction for example).

Here is the config return as the response of `get_config` method.

```rust
struct PluginConfig {
    name: String,
    description: String,
    daemon: bool,
    roles: Vec<PluginRole>,
}
```

One plugin can have multiple roles.

A plugin can define as `daemon` pluign, ckb-cli will start all actived `daemon` plugin processes when ckb-cli start and let them keep running. ckb-cli will start a non-daemon when needed, send request to its stdin and wait the response from its stdout then kill the process.

The plugin can access rpc request by `rpc_` prefixed methods, they are just proxies of [CKB json-rpc](https://github.com/nervosnetwork/ckb/blob/develop/rpc/README.md) calls. It is useful when implement your own indexer.

# RPC protocol
The rpc is follow jsonrpc 2.0 protocol. For rust user, `plugin-protocl` package provide a more semantic interface.

## Get config of the plugin

#### Request
```javascript
{
    "params": [],
    "method": "get_config",
    "id": 0,
    "jsonrpc": "2.0"
}
```

#### Response
```javascript
{
    "result": {
        "type": "plugin_config",
        "content": {
            "roles": [
                {
                    "role": "key_store",
                    "require_password": true
                }
            ],
            "name": "demo_keystore",
            "description": "It's a keystore for demo",
            "daemon": true
        }
    },
    "id": 0,
    "jsonrpc": "2.0"
}
```

## keystore methods

### List accounts
#### Request
```javascript
{
    "params": [],
    "method": "keystore_list_account",
    "id": 0,
    "jsonrpc": "2.0"
}
```

#### Response
```javascript
{
    "result": {
        "type": "h160_vec",
        "content": [
            "0xe22f7f385830a75e50ab7fc5fd4c35b134f1e84b",
            "0x13e41d6f9292555916f17b4882a5477c01270142",
            "0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64"
        ]
    },
    "id": 0,
    "jsonrpc": "2.0"
}
```

### Create an account

#### Request
```javascript
{
    "params": [
        // (optional) The password to encrypt the account
        "123"
    ],
    "method": "keystore_create_account",
    "id": 0,
    "jsonrpc": "2.0"
}
```

#### Response
```javascript
{
    "result": {
        "type": "h160",
        "content": "0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64"
    },
    "id": 0,
    "jsonrpc": "2.0"
}
```

### Update password

#### Request
```javascript
{
    "params": [
        // The blake160 hash of the public key (account identifier)
        "0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64",
        // The password to decrypt the account
        "123",
        // The password to encrypt the account
        "123"
    ],
    "method": "keystore_update_password",
    "id": 0,
    "jsonrpc": "2.0"
}
```

#### Response
```javascript
{
    "result": {
        "type": "ok"
    },
    "id": 0,
    "jsonrpc": "2.0"
}
```

### Import an account

#### Request
```javascript
{
    "params": [
        // The secp256k1 key of master private key
        "0x0303030303030303030303030303030303030303030303030303030303030303",
        // The chain code of master private key
        "0x0404040404040404040404040404040404040404040404040404040404040404",
        // (optional) The password to encrypt the account
        "123"
    ],
    "method": "keystore_import",
    "id": 0,
    "jsonrpc": "2.0"
}
```

### Export an account

#### Request
```javascript
{
    "params": [
        // The blake160 hash of the public key (account identifier)
        "0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64",
        // (optional) The password to encrypt the account
        "123"
    ],
    "method": "keystore_export",
    "id": 0,
    "jsonrpc": "2.0"
}
```

#### Response
```javascript
{
    "result": {
        "type": "master_private_key",
        "content": {
            "privkey": "0x0303030303030303030303030303030303030303030303030303030303030303",
            "chain_code": "0x0404040404040404040404040404040404040404040404040404040404040404"
        }
    },
    "id": 0,
    "jsonrpc": "2.0"
}
```

### Sign a message

#### Request
```javascript
{
    "params": [
        // The blake160 hash of the public key (account identifier)
        "0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64",
        // A derivation key path ("m" for master key)
        "m/44'/309'/0'/0/19",
        // The message to sign (H256)
        "0xe203d8260a0eb9d0ec8f69976e2108d9e50d0c8fb1920a67d10d61cb9993e284",
        // The sign target, a transaction or any message
        {
          "type": "transaction",
          "content": {
            "version": "0x0",
            "cell_deps": [
              {
                "out_point": {
                  "tx_hash": "0xd6ae21528966b5926a95b5dfa75281e91f071af492ba7879aff29d671c7bb523",
                  "index": "0x0"
                },
                "dep_type": "dep_group"
              }
            ],
            "header_deps": [],
            "inputs": [
              {
                "since": "0x0",
                "previous_output": {
                  "tx_hash": "0xb79cc8daf20601d5cefda345951e21390fc5e2c6dab33c7a39207f64fb947731",
                  "index": "0x7"
                }
              }
            ],
            "outputs": [
              {
                "capacity": "0x174876e800",
                "lock": {
                  "code_hash": "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                  "hash_type": "type",
                  "args": "0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64"
                },
                "type": null
              },
              {
                "capacity": "0x1bc16d5005b88180",
                "lock": {
                  "code_hash": "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                  "hash_type": "type",
                  "args": "0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7"
                },
                "type": null
              }
            ],
            "outputs_data": [
              "0x",
              "0x"
            ],
            "witnesses": []
          }
        },
        // Sign use recoverable signature
        true,
        // (optional) The password to decrypt the account
        "123"
    ],
    "method": "keystore_sign",
    "id": 0,
    "jsonrpc": "2.0"
}
```

#### Response
```javascript
{
    "result": {
        "type": "bytes",
        "content": "0x0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101"
    },
    "id": 0,
    "jsonrpc": "2.0"
}
```

### Get the extended public key of an account

#### Request
```javascript
{
    "params": [
        // The blake160 hash of the public key (account identifier)
        "0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64",
        // A derivation key path ("m" for master key)
        "m/44'/309'/0'/0/19",
        // (optional) The password to decrypt the account
        "123"
    ],
    "method": "keystore_extended_pubkey",
    "id": 0,
    "jsonrpc": "2.0"
}
```
#### Response
```javascript
{
    "result": {
        "type": "bytes",
        "content": "0x02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"
    },
    "id": 0,
    "jsonrpc": "2.0"
}
```

### Get derived key set (for HD wallet cell collection)

#### Request
```javascript
{
    "params": [
        // The blake160 hash of the public key (account identifier)
        "0xe8b7cfc565396a49efe154e81fe02c2bca9f3621",
        // Maximum external keys to search
        100,
        // The last change address been used (for know the next change address)
        "0xe8b7cfc565396a49efe154e81fe02c2bca9f3621",
        // Maximum change keys to search
        10000,
        // (optional) The password to decrypt the account
        "123"
    ],
    "method": "keystore_derived_key_set",
    "id": 0,
    "jsonrpc": "2.0"
}
```

#### Response
```javascript
{
    "result": {
        "type": "derived_key_set",
        "content": {
            "external": [
                [
                    "m/44'/309'/0'/0/19",
                    "0x13e41d6f9292555916f17b4882a5477c01270142"
                ],
                [
                    "m/44'/309'/0'/0/20",
                    "0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64"
                ]
            ],
            "change": [
                [
                    "m/44'/309'/0'/1/19",
                    "0x13e41d6f9292555916f17b4882a5477c01270142"
                ],
                [
                    "m/44'/309'/0'/1/20",
                    "0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64"
                ]
            ]
        }
    },
    "id": 0,
    "jsonrpc": "2.0"
}
```

### Get derived key set by path index

#### Request
```javascript
{
    "params": [
        // The blake160 hash of the public key (account identifier)
        "0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64",
        // The external path start index, include the starting index (template: "m/44'/309'/0'/0/{index}")
        0,
        // The length of external derived key
        20,
        // The change path start index, include the starting index (template: "m/44'/309'/0'/1/{index}")
        0,
        // The length of change derived key
        10,
        // (optional) The password to decrypt the account
        "123"
    ],
    "method": "keystore_derived_key_set_by_index",
    "id": 0,
    "jsonrpc": "2.0"
}
```

#### Response
```javascript
{
    "result": {
        "type": "derived_key_set",
        "content": {
            "external": [
                [
                    "m/44'/309'/0'/0/19",
                    "0x13e41d6f9292555916f17b4882a5477c01270142"
                ],
                [
                    "m/44'/309'/0'/0/20",
                    "0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64"
                ]
            ],
            "change": [
                [
                    "m/44'/309'/0'/1/19",
                    "0x13e41d6f9292555916f17b4882a5477c01270142"
                ],
                [
                    "m/44'/309'/0'/1/20",
                    "0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64"
                ]
            ]
        }
    },
    "id": 0,
    "jsonrpc": "2.0"
}
```

# A keystore demo plugin

First you need build the ckb-cli and the example plugin:
```shell
# Build ckb-cli
cargo build
# Build example keystore plugin
cd plugin-protocol
cargo build --examples
```

Then, start ckb-cli and install the plugin:
```shell
./target/debug/ckb-cli
CKB> plugin install --binary-path ./target/debug/examples/keystore
daemon: true
description: "It's a keystore for demo"
name: demo_keystore
```

If you want see all the debug log messages from plugin module, you can start ckb-cli by:

```shell
RUST_LOG=ckb_cli::plugin=debug ./target/debug/ckb-cli
```

Show the detail infromation of the plugin:
``` shell
CKB> plugin info --name demo_keystore
daemon: true
description: "It's a keystore for demo"
is_active: true
name: demo_keystore
roles:
  - require_password: true
    role: key_store
```

Sign a message by recoverable signature to test the plugin:
``` shell
CKB> util sign-message --from-account 0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64 --message 0xe203d8260a0eb9d0ec8f69976e2108d9e50d0c8fb1920a67d10d61cb9993e284 --recoverable
Password: ***
recoverable: true
signature: 0x0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101
```

If you don't want the plugin, just deactive it.
``` shell
CKB> plugin deactive --name demo_keystore
Plugin demo_keystore is deactived!

CKB> util sign-message --from-account 0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64 --message 0xe203d8260a0eb9d0ec8f69976e2108d9e50d0c8fb1920a67d10d61cb9993e284 --recoverable
Password: ***
Account not found: b39bbc0b3673c7d36450bc14cfcdad2d559c6c64
```
