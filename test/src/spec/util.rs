use crate::setup::Setup;
use crate::spec::Spec;
use std::fs;
use tempfile::tempdir;

pub struct Util;

pub const ACCOUNT_PRIVKEY: &str =
    "0x3b5ca3bd98b6a57f36b3f6fa138c4004e92a37dee39069606ee65c742e5f9170";
pub const ACCOUNT_ADDRESS: &str = "ckt1qyqp76jus2sst4qy57nnphuqgsmlmzkv2l7s8ksggy";

impl Spec for Util {
    fn run(&self, setup: &mut Setup) {
        let tempdir = tempdir().expect("create tempdir failed");
        let path = tempdir.path().to_str().unwrap().to_owned();
        let account_privkey = format!("{}/account", path);
        fs::write(&account_privkey, ACCOUNT_PRIVKEY).unwrap();

        let output = setup.cli(&format!(
            "util sign-data --binary-hex 0xdeadbeef --privkey-path {}",
            account_privkey
        ));
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        let message = value["message"].as_str().unwrap();
        let signature0 = value["signature"].as_str().unwrap();
        assert_eq!(
            message,
            "0x81604242d6308051ae7cfd9d67a3b5f3cdd9446c009a82a20d5b6d30d9289ba9"
        );
        assert_eq!(signature0, "0xdfb707ff4facf2f7ed9da0ab2660ae911f356eff0d100e1f1b6f18dcfb8a49b54bf3c5741578a12fc261fa55eeb5902dea501f175c16b4b32a664a223da911b1");

        let output = setup.cli(&format!(
            "util sign-data --binary-hex 0xdeadbeef --privkey-path {} --no-magic-bytes",
            account_privkey
        ));
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        let message = value["message"].as_str().unwrap();
        let signature1 = value["signature"].as_str().unwrap();
        assert_eq!(
            message,
            "0x761b06536d4d9580de9b63a3d5c5a5da0c6826c39775a7ce5039ac7e0f7f5dbc"
        );
        assert_eq!(signature1, "0x3f5aad8439367a7840deffbf3ee7657b9b225c553f7d5a4f766d99ac78128a6f7de732923d4dcf4551ff97421f104aa33d83d14362ab276502580cdd66fd56ee");

        let output = setup.cli(&format!(
            "util sign-message --message {} --privkey-path {}",
            message, account_privkey
        ));
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        let signature2 = value["signature"].as_str().unwrap();
        assert_eq!(signature1, signature2);

        let output = setup.cli(&format!(
            "util verify-signature --message {} --signature {} --privkey-path {}",
            message, signature1, account_privkey,
        ));
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        let pubkey = value["pubkey"].as_str().unwrap();
        let recoverable = value["recoverable"].as_bool().unwrap();
        let verify_ok = value["verify-ok"].as_bool().unwrap();
        assert_eq!(
            pubkey,
            "0x0237813f0b34ddccaef22947e934fa0af384d1551ab1ad268860a8fe65a1f8f69d"
        );
        assert!(!recoverable);
        assert!(verify_ok);

        let output = setup.cli(&format!(
            "util verify-signature --message {} --signature {} --privkey-path {}",
            message,
            "0xaaaaaa8439367a7840deffbf3ee7657b9b225c553f7d5a4f766d99ac78128a6f7de732923d4dcf4551ff97421f104aa33d83d14362ab276502580cdd66fd56ee",
            account_privkey,
        ));
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        let verify_ok = value["verify-ok"].as_bool().unwrap();
        assert!(!verify_ok);

        // Recoverable signature
        let output = setup.cli(&format!(
            "util sign-data --binary-hex 0xdeadbeef --privkey-path {} --recoverable",
            account_privkey
        ));
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        let message = value["message"].as_str().unwrap();
        let signature = value["signature"].as_str().unwrap();
        assert_eq!(
            message,
            "0x81604242d6308051ae7cfd9d67a3b5f3cdd9446c009a82a20d5b6d30d9289ba9"
        );
        assert_eq!(signature, "0xdfb707ff4facf2f7ed9da0ab2660ae911f356eff0d100e1f1b6f18dcfb8a49b54bf3c5741578a12fc261fa55eeb5902dea501f175c16b4b32a664a223da911b100");

        let output = setup.cli(&format!(
            "util verify-signature --message {} --signature {} --privkey-path {}",
            message, signature, account_privkey,
        ));
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        let pubkey = value["pubkey"].as_str().unwrap();
        let recoverable = value["recoverable"].as_bool().unwrap();
        let verify_ok = value["verify-ok"].as_bool().unwrap();
        assert_eq!(
            pubkey,
            "0x0237813f0b34ddccaef22947e934fa0af384d1551ab1ad268860a8fe65a1f8f69d"
        );
        assert!(recoverable);
        assert!(verify_ok);

        let output = setup.cli(&format!(
            "util verify-signature --message {} --signature {} --privkey-path {}",
            message,
            "0xaaaaaa8439367a7840deffbf3ee7657b9b225c553f7d5a4f766d99ac78128a6f7de732923d4dcf4551ff97421f104aa33d83d14362ab276502580cdd66fd56ee00",
            account_privkey,
        ));
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        let recoverable = value["recoverable"].as_bool().unwrap();
        let verify_ok = value["verify-ok"].as_bool().unwrap();
        assert!(recoverable);
        assert!(!verify_ok);

        let output = setup.cli("util address-info --address ckt1qn0wcya8hrssq4u4gyuyejh5k53rwvly54yrcwhvjhwufsw4afdjynxzuefxyp9wdghglncj77k5wt6p59sx6kukyjlwh5s467qgp8m2jyzt6r7d9jr0s9q8764qnqvze3mzrdks4p5c3j");
        let value: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
        assert_eq!(value["extra"]["address-type"].as_str().unwrap(), "FullType");
        assert_eq!(value["extra"]["data-encoding"].as_str().unwrap(), "bech32");
        assert_eq!(value["network"].as_str().unwrap(), "ckb_testnet");
        assert_eq!(
            value["lock_script"]["code_hash"].as_str().unwrap(),
            "0xdeec13a7b8e100579541384ccaf4b5223733e4a5483c3aec95ddc4c1d5ea5b22"
        );
        assert_eq!(value["lock_script"]["hash_type"].as_str().unwrap(), "type");
        assert_eq!(value["lock_script"]["args"].as_str().unwrap(), "0x4cc2e6526204ae6a2e8fcf12f7ad472f41a1606d5b9624beebd215d780809f6a9104bd0fcd2c86f81407f6aa098182cc7621b6d0");
    }

    fn spec_name(&self) -> &'static str {
        "Util"
    }
}
