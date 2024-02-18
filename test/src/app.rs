use std::path::Path;

#[derive(Debug, Clone)]
pub struct App {
    ckb_bin: String,
    cli_bin: String,
    keystore_plugin_bin: String,
}

impl App {
    pub fn init() -> Self {
        let matches = Self::matches();
        let ckb_bin = matches.get_one::<String>("ckb-bin").unwrap().to_owned();
        let cli_bin = matches.get_one::<String>("cli-bin").unwrap().to_owned();
        let keystore_plugin_bin: String = matches
            .get_one::<String>("keystore-plugin")
            .unwrap()
            .to_owned();
        assert!(
            Path::new(&ckb_bin).exists(),
            "ckb-bin binary not exists: {}",
            ckb_bin
        );
        assert!(
            Path::new(&cli_bin).exists(),
            "ckb-cli binary not exists: {}",
            cli_bin
        );
        assert!(
            Path::new(&cli_bin).exists(),
            "keystore plugin binary not exists: {}",
            keystore_plugin_bin,
        );
        Self {
            ckb_bin,
            cli_bin,
            keystore_plugin_bin,
        }
    }

    pub fn ckb_bin(&self) -> &str {
        &self.ckb_bin
    }

    pub fn cli_bin(&self) -> &str {
        &self.cli_bin
    }

    pub fn keystore_plugin_bin(&self) -> &str {
        &self.keystore_plugin_bin
    }

    fn matches() -> clap::ArgMatches {
        clap::Command::new("ckb-cli-test")
            .arg(
                clap::Arg::new("ckb-bin")
                    .long("ckb-bin")
                    .required(true)
                    .value_name("PATH")
                    .help("Path to ckb executable"),
            )
            .arg(
                clap::Arg::new("cli-bin")
                    .long("cli-bin")
                    .required(true)
                    .value_name("PATH")
                    .help("Path to ckb-cli executable"),
            )
            .arg(
                clap::Arg::new("keystore-plugin")
                    .long("keystore-plugin")
                    .required(true)
                    .value_name("PATH")
                    .help("Path to keystore plugin executable"),
            )
            .get_matches()
    }
}
