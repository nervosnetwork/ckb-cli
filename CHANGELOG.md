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
