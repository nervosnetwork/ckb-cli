use crate::miner::Miner;
use crate::setup::Setup;
use crate::spec::Spec;
use std::fs;
use tempfile::tempdir;

pub struct Plugin;

impl Spec for Plugin {
    fn run(&self, setup: &mut Setup) {
        let output = setup.cli("plugin list");
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        assert!(value.as_sequence().unwrap().is_empty());

        let output = setup.cli("account list");
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        assert!(value.as_sequence().unwrap().is_empty());

        let output = setup.cli(&format!(
            "plugin install --binary-path {}",
            setup.keystore_plugin_bin
        ));
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        assert_eq!(value["name"].as_str().unwrap(), "demo_keystore_no_password");
        assert_eq!(value["daemon"].as_bool().unwrap(), true);

        let output = setup.cli("plugin list");
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        assert_eq!(value.as_sequence().unwrap().len(), 1);

        let output = setup.cli("account list");
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        let accounts = value.as_sequence().unwrap();
        assert_eq!(accounts.len(), 3);
        assert_eq!(
            accounts[0]["lock_arg"],
            "0xe22f7f385830a75e50ab7fc5fd4c35b134f1e84b"
        );
        assert_eq!(
            accounts[0]["lock_hash"],
            "0x59fbdd52b9967b47270b207d352e6f59616a2f03b24a9710c087b379ac0f8d09"
        );

        let output = setup
            .cli("account import-from-plugin --account-id 0x1111111f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8");
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        assert_eq!(
            value["lock_arg"],
            "0x1111111111111111111222222222222222222222"
        );

        let tempdir = tempdir().expect("create tempdir failed");
        let extended_privkey_path = format!(
            "{}/exported-privkey",
            tempdir.path().to_str().unwrap().to_owned()
        );
        let _output = setup.cli(&format!("account export --lock-arg 0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64 --extended-privkey-path {}", extended_privkey_path));
        let privkey_content = fs::read_to_string(extended_privkey_path).unwrap();
        assert_eq!(privkey_content, "0303030303030303030303030303030303030303030303030303030303030303\n0404040404040404040404040404040404040404040404040404040404040404");

        let output = setup.cli(&format!("wallet transfer --from-account {} --to-address ckt1qyqt8xaupvm8837nv3gtc9x0ekkj64vud3jq5t63cs --capacity 1000 --tx-fee 0.1", Miner::address()));
        // Means the signature is filled but is wrong: https://github.com/nervosnetwork/ckb-system-scripts/wiki/Error-codes
        assert!(output.contains("ValidationFailure(-31)"));

        let output = setup
            .cli("account extended-address --lock-arg 0xef8484612fefa725097ecef6dce0e19e0d77fb79");
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        assert_eq!(
            value["lock_arg"],
            "0xef8484612fefa725097ecef6dce0e19e0d77fb79"
        );

        let output = setup
            .cli("account bip44-addresses --lock-arg 0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64");
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        assert_eq!(
            value["receiving"][0]["address"],
            "ckb1qyqp8eqad7ffy42ezmchkjyz54rhcqf8q9pqrn323p"
        );
        assert_eq!(value["receiving"][0]["path"], "m/44'/309'/0'/0/19");
        assert_eq!(
            value["change"][1]["address"],
            "ckb1qyqt8xaupvm8837nv3gtc9x0ekkj64vud3jqfwyw5v"
        );
        assert_eq!(value["change"][1]["path"], "m/44'/309'/0'/1/20");

        let _output = setup.cli("plugin deactive --name demo_keystore_no_password");
        let output = setup.cli("account list");
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        assert!(value.as_sequence().unwrap().is_empty());
        let output = setup.cli("plugin list");
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        assert_eq!(value.as_sequence().unwrap().len(), 1);

        let _output = setup.cli("plugin uninstall --name demo_keystore_no_password");
        let output = setup.cli("account list");
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        assert!(value.as_sequence().unwrap().is_empty());
        let output = setup.cli("plugin list");
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        assert!(value.as_sequence().unwrap().is_empty());
    }
}
