use clap;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct App {
    ckb_bin: String,
    cli_bin: String,
}

impl App {
    pub fn init() -> Self {
        let matches = Self::matches();
        let ckb_bin = matches.value_of("ckb-bin").unwrap().to_string();
        let cli_bin = matches.value_of("cli-bin").unwrap().to_string();
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
        Self { ckb_bin, cli_bin }
    }

    pub fn ckb_bin(&self) -> &str {
        &self.ckb_bin
    }

    pub fn cli_bin(&self) -> &str {
        &self.cli_bin
    }

    fn matches() -> clap::ArgMatches {
        clap::App::new("ckb-cli-test")
            .arg(
                clap::Arg::with_name("ckb-bin")
                    .long("ckb-bin")
                    .takes_value(true)
                    .required(true)
                    .value_name("PATH")
                    .about("Path to ckb executable"),
            )
            .arg(
                clap::Arg::with_name("cli-bin")
                    .long("cli-bin")
                    .takes_value(true)
                    .required(true)
                    .value_name("PATH")
                    .about("Path to ckb-cli executable"),
            )
            .get_matches()
    }
}
