use crate::setup::Setup;
use crate::spec::Spec;
use log::info;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::{env, fs};
use tempfile::tempdir;

pub struct AccountKeystorePerm;

const CLI_PASSWORD: &str = "abc123456";

impl Spec for AccountKeystorePerm {
    fn run(&self, setup: &mut Setup) {
        let output = setup.cli_command(&["account", "new"], &[CLI_PASSWORD, CLI_PASSWORD]);
        info!("output = {}", output);
        assert!(output.contains("lock_arg: "));
        assert!(output.contains("lock_hash: "));

        // get lock_args: from output
        let lock_arg = output.split("lock_arg: ").collect::<Vec<&str>>()[1]
            .split('\n')
            .collect::<Vec<&str>>()[0];
        info!("lock_arg = {}", lock_arg);

        let ckb_cli_home = env::var("CKB_CLI_HOME").expect("CKB_CLI_HOME not set");
        info!("ckb_cli_home = {}", ckb_cli_home);

        // print a number to octal
        let keystore_path = PathBuf::from(ckb_cli_home).join("keystore");
        info!(
            "keystore: 0o{:o}",
            fs::metadata(&keystore_path).unwrap().permissions().mode()
        );
        assert_eq!(
            fs::metadata(&keystore_path).unwrap().permissions().mode(),
            0o40700
        );

        // iterator files under keystore_path
        fs::read_dir(keystore_path).unwrap().for_each(|file| {
            let file_path = file.unwrap().path();
            info!(
                "file: {}: 0o{:o}",
                file_path.display(),
                fs::metadata(&file_path).unwrap().permissions().mode(),
            );
            assert_eq!(
                fs::metadata(&file_path).unwrap().permissions().mode(),
                0o100600
            );
        })
    }

    fn spec_name(&self) -> &'static str {
        "AccountKeystorePerm"
    }
}

pub struct AccountKeystoreExportPerm;

impl Spec for AccountKeystoreExportPerm {
    fn run(&self, setup: &mut Setup) {
        let output = setup.cli_command(&["account", "new"], &[CLI_PASSWORD, CLI_PASSWORD]);
        info!("output = {}", output);
        assert!(output.contains("lock_arg: "));
        assert!(output.contains("lock_hash: "));
        // get lock_args: from output
        let lock_arg = output.split("lock_arg: ").collect::<Vec<&str>>()[1]
            .split('\n')
            .collect::<Vec<&str>>()[0];
        info!("lock_arg = {}", lock_arg);

        let ckb_cli_home = env::var("CKB_CLI_HOME").expect("CKB_CLI_HOME not set");
        info!("ckb_cli_home = {}", ckb_cli_home);

        let export_dir = tempdir().expect("create temp dir failed");
        let export_file = export_dir.path().join("export.private");

        assert!(export_file.is_absolute());

        let output = setup.cli_command(
            &[
                "account",
                "export",
                "--lock-arg",
                lock_arg,
                "--extended-privkey-path",
                export_file.to_str().unwrap(),
            ],
            &[CLI_PASSWORD],
        );
        assert!(output.contains("Success exported account as extended privkey to"));

        info!(
            "export.privkey : 0o{:o}",
            fs::metadata(&export_file).unwrap().permissions().mode()
        );
        assert_eq!(
            fs::metadata(&export_file).unwrap().permissions().mode(),
            0o100400
        );
    }

    fn spec_name(&self) -> &'static str {
        "AccountKeystoreExportPerm"
    }
}

pub struct AccountKeystoreUpdatePassword;

impl Spec for AccountKeystoreUpdatePassword {
    fn run(&self, setup: &mut Setup) {
        let output = setup.cli_command(&["account", "new"], &[CLI_PASSWORD, CLI_PASSWORD]);
        info!("output = {}", output);
        assert!(output.contains("lock_arg: "));
        assert!(output.contains("lock_hash: "));

        // get lock_args: from output
        let lock_arg = output.split("lock_arg: ").collect::<Vec<&str>>()[1]
            .split('\n')
            .collect::<Vec<&str>>()[0];
        info!("lock_arg = {}", lock_arg);

        let ckb_cli_home = env::var("CKB_CLI_HOME").expect("CKB_CLI_HOME not set");
        info!("ckb_cli_home = {}", ckb_cli_home);

        let keystore_path = PathBuf::from(ckb_cli_home).join("keystore");

        const NEW_CLI_PASSWORD: &str = "new_1234567a";
        let output = setup.cli_command(
            &["account", "update", "--lock-arg", lock_arg],
            &[CLI_PASSWORD, NEW_CLI_PASSWORD, NEW_CLI_PASSWORD],
        );
        info!("output = {}", output);

        assert!(output.contains("status: success"));

        // iterator files under keystore_path
        fs::read_dir(keystore_path).unwrap().for_each(|file| {
            let file_path = file.unwrap().path();
            info!(
                "file: {}: 0o{:o}",
                file_path.display(),
                fs::metadata(&file_path).unwrap().permissions().mode(),
            );
            assert_eq!(
                fs::metadata(&file_path).unwrap().permissions().mode(),
                0o100600
            );
        })
    }

    fn spec_name(&self) -> &'static str {
        "AccountKeystoreUpdatePassword"
    }
}
