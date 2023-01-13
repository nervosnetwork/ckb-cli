# v1.4.1
* `get_block` and `get_block_by_number` support parameter `with_cycles`

# v1.4.0
* Update ckb deps from `v0.105.1` to `v0.106.0`
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
