# v1.15.0
* [Breaking Change] Add `--multisig-code-hash` flag to specify `MultisigScript::V2` or `MultisigScript::Legacy` #631

# v1.14.0
* Upgrade rust-toolchain to 1.85.0
* Add --zero-lock flag for deploy subcommand to permit `[lock].code_hash` is all zero

# v1.13.0
* Update ckb dependencies to `v0.200.0`
* Update ckb-sdk to `v3.7.0`
* Fix `tx add-input` to keep existing cell_deps
* Fix `tx add-input` to accept unknown input when skip-check is supplied
* Complete get-transaction RPC implementation
* Adapt TransactionDependencyProvider async trait with TxDepProviderWrapper

# v1.12.0
* Update ckb dependencies to `v0.118.0`
* Add `clear_tx_verify_queue` subcommand
* Add `NetworkType::Preview` support
* Remove orphan_blocks_size from SyncState
* Apply cargo clippy fixes
* Upgrade GitHub Actions runners

# v1.11.0
* Update ckb dependencies to `v0.117.0`
* Update ckb-sdk to `v3.2.1`
* Support include tx_pool for get_live_cell
* Fix RPC generate_epochs argument name

# v1.9.0
* Update ckb dependencies to `v0.116.1`
* Add `test_tx_pool_accept` subcommand
* General maintenance and bug fixes

# v1.8.0
* Update ckb dependencies to `v0.115.0`
* Fix `sign-txs` multisig support for full address
* Support `force redeploy cells`

# v1.7.0
* Update ckb dependencies to `v0.114.0`
* Update ckb-sdk to `v3.1.0`
* Add RPC commands: `get_indexer_tip`, `get_cells`, `get_cells_capacity`, `get_transactions`
* Support `add-input` when cell command
* Support `generate_epochs` functionality
* Breaking change: `generate_epoch` no longer accepts arguments
* Remove Optional wrapper from `Consensus.dao_type_hash`

# v1.6.0
* Update ckb-sdk to `v3.0.1`
* Use native-tls-vendored feature for static OpenSSL linking
* Fix `get_fee_rate_statistics` to return an Option
* Upgrade ahash to `v0.7.7`
* Packaging improvements

# v1.5.0
* Update ckb dependencies to `v0.111.0`
* Update ckb-sdk to `v3.0.0`
* Add RPC subcommands: `get_deployments_info`, `get_transaction_and_witness_proof`, `verify_transaction_and_witness_proof`
* Fix `get_consensus` subcommand
* Set secure permissions: `700` for keystore directory, `600` for private key files
* Support packed header and block with cycles
* Support index_tx_pool in tests
* Upgrade rust toolchain to `1.71.1`
* Generate binaries for Apple Silicon
* Use stderr for non-JSON log information
* Fix integration tests with retry logic for DAO operations
* Security fixes and dependency upgrades

# v1.4.0
* Update ckb dependencies from `v0.105.1` to `v0.106.0`
* Update dep ckb-sdk to `v2.4.0`

# v1.3.0
* Add deploy subcommand, this is a more advanced version of `capsule deploy` #515
  - more resonable CKB transaction structure
  - support `multisig` lock
* Add `--max-tx-fee` argument to subcommands, so that you can transfer all your CKB to another address more easy #517
  - `wallet transfer`
  - `sudt`
  - `dao`

# v1.2.0
* Update ckb deps from `v0.104.0` to `v0.105.1`
* Update deps
  - ckb-sdk to `v2.3.0`
  - secp256k1 to `v0.24`
  - bitcoin to `v0.27`
* Support ckb-indexer rpc from ckb node
* Add `account bitcoin-xpub` subcommand

# v1.1.0
* Update ckb deps from `v0.103.0` to `v0.104.0`
* **BREAKING**: remove `ckb-index` crate, and effect following subcommands:
  - remove `index` subcommand
  - remove `wallet top-capacity` subcommand
  - remove `wallet get-capacity --lock-hash` support
  - remove `wallet get-live-cells --lock-hash` support
  - remove `wallet get-live-cells --type-hash` support
  - remove `wallet get-live-cells --code-hash` support
* Use [`ckb-indexer`][ckb-indexer-repo] as index backend
* Update `ckb-sdk` to `v2.0.0`
* Guide user to select ckb/ckb-indexer url for the first time
* Add `--local-only` flag to not check alerts and get network type when startup

# v1.0.0
* Update ckb from `v0.101.3` to `v0.103.0`
* Remove `ckb-sdk` from `ckb-cli` and created as an [standalone repository](https://github.com/nervosnetwork/ckb-sdk-rust)
* Add `ckb-signer` sub-crate for keystore implementation
* Use new `ckb-sdk` to refactor:
  - `wallet transfer`
  - `dao deposit`
  - `dao prepare`
  - `dao withdraw`
* Replace `tx-fee` argument with `fee-rate` argument and the default value is `1000`'
* Refactor `AddressParser`
* Add [`sudt`][sudt-wiki] subcommand
* Short address use ckb2021 address format

* * * * *

# v0.15.0
* Compatible with ckb-v0.15.z
* Use rocksdb as index database backend
* Add web3 v3 keystore support


[sudt-wiki]: https://github.com/nervosnetwork/ckb-cli/wiki/UDT-(sudt)-Operations-Tutorial
[ckb-indexer-repo]: https://github.com/nervosnetwork/ckb-indexer
