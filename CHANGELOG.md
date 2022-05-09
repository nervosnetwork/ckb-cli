# v0.103.0
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
* Implement `CellCollector` for `ckb-cli/ckb-index`
* Implement `Signer` for `PrivkeyWrapper` and `KeyStoreHandler`

# v0.15.0
* Compatible with ckb-v0.15.z
* Use rocksdb as index database backend
* Add web3 v3 keystore support
