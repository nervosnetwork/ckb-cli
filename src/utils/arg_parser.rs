use std::fmt::Display;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::str::FromStr;

use ckb_sdk::{Address, NetworkType, SecpKey, ONE_CKB};
use clap::ArgMatches;
use faster_hex::hex_decode;
use numext_fixed_hash::{H160, H256};
use url::Url;

pub trait ArgParser<T> {
    fn parse(&self, input: &str) -> Result<T, String>;

    fn validate(&self, input: String) -> Result<(), String> {
        self.parse(&input)
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    fn from_matches<R: From<T>>(&self, matches: &ArgMatches, name: &str) -> Result<R, String> {
        self.from_matches_opt(matches, name, true)
            .map(|opt| opt.unwrap())
    }

    fn from_matches_opt<R: From<T>>(
        &self,
        matches: &ArgMatches,
        name: &str,
        required: bool,
    ) -> Result<Option<R>, String> {
        if required && !matches.is_present(name) {
            return Err(format!("<{}> is required", name));
        }
        matches
            .value_of(name)
            .map(|input| self.parse(input).map(Into::into))
            .transpose()
    }

    fn from_matches_vec<R: From<T>>(
        &self,
        matches: &ArgMatches,
        name: &str,
    ) -> Result<Vec<R>, String> {
        matches
            .values_of_lossy(name)
            .unwrap_or_else(Vec::new)
            .into_iter()
            .map(|input| self.parse(&input).map(Into::into))
            .collect()
    }
}

#[derive(Debug, Default)]
pub struct FromStrParser<T: FromStr> {
    _t: PhantomData<T>,
}

impl<T> ArgParser<T> for FromStrParser<T>
where
    T: FromStr,
    <T as FromStr>::Err: Display,
{
    fn parse(&self, input: &str) -> Result<T, String> {
        T::from_str(input).map_err(|err| err.to_string())
    }
}

pub struct UrlParser;

impl ArgParser<Url> for UrlParser {
    fn parse(&self, input: &str) -> Result<Url, String> {
        Url::parse(input).map_err(|err| err.to_string())
    }
}

pub struct HexParser;

impl ArgParser<Vec<u8>> for HexParser {
    fn parse(&self, mut input: &str) -> Result<Vec<u8>, String> {
        if input.starts_with("0x") || input.starts_with("0X") {
            input = &input[2..];
        }
        if input.len() % 2 != 0 {
            return Err(format!("Invalid hex string lenth: {}", input.len()));
        }
        let mut bytes = vec![0u8; input.len() / 2];
        hex_decode(input.as_bytes(), &mut bytes)
            .map_err(|err| format!("parse hex string failed: {:?}", err))?;
        Ok(bytes)
    }
}

#[derive(Default)]
pub struct FixedHashParser<T> {
    _h: PhantomData<T>,
}

impl ArgParser<H256> for FixedHashParser<H256> {
    fn parse(&self, input: &str) -> Result<H256, String> {
        let bytes = HexParser.parse(input)?;
        H256::from_slice(&bytes).map_err(|err| err.to_string())
    }
}

impl ArgParser<H160> for FixedHashParser<H160> {
    fn parse(&self, input: &str) -> Result<H160, String> {
        let bytes = HexParser.parse(input)?;
        H160::from_slice(&bytes).map_err(|err| err.to_string())
    }
}

#[derive(Default)]
pub struct PathParser {
    should_exists: bool,
}

impl ArgParser<PathBuf> for PathParser {
    fn parse(&self, input: &str) -> Result<PathBuf, String> {
        let path = PathBuf::from(input);
        if self.should_exists && !path.exists() {
            Err(format!("path <{}> not exists", input))
        } else {
            Ok(path)
        }
    }
}

#[derive(Default)]
pub struct FilePathParser {
    path_parser: PathParser,
}

impl FilePathParser {
    pub fn new(should_exists: bool) -> FilePathParser {
        FilePathParser {
            path_parser: PathParser { should_exists },
        }
    }
}

impl ArgParser<PathBuf> for FilePathParser {
    fn parse(&self, input: &str) -> Result<PathBuf, String> {
        let path = self.path_parser.parse(input)?;
        if path.exists() && !path.is_file() {
            Err(format!("path <{}> is not file", input))
        } else {
            Ok(path)
        }
    }
}

#[derive(Default)]
pub struct DirPathParser {
    path_parser: PathParser,
}

// impl DirPathParser {
//     pub fn new(should_exists: bool) -> DirPathParser {
//         DirPathParser { path_parser: PathParser { should_exists } }
//     }
// }

impl ArgParser<PathBuf> for DirPathParser {
    fn parse(&self, input: &str) -> Result<PathBuf, String> {
        let path = self.path_parser.parse(input)?;
        if path.exists() && !path.is_dir() {
            Err(format!("path <{}> is not directory", input))
        } else {
            Ok(path)
        }
    }
}

pub struct PrivkeyPathParser;

impl ArgParser<SecpKey> for PrivkeyPathParser {
    fn parse(&self, input: &str) -> Result<SecpKey, String> {
        SecpKey::from_privkey_path(input)
    }
}

pub struct PubkeyHexParser;

impl ArgParser<SecpKey> for PubkeyHexParser {
    fn parse(&self, input: &str) -> Result<SecpKey, String> {
        SecpKey::from_pubkey_str(input)
    }
}

pub struct AddressParser;

impl ArgParser<Address> for AddressParser {
    fn parse(&self, input: &str) -> Result<Address, String> {
        Address::from_input(NetworkType::TestNet, input)
    }
}

/// Default unit CKB format: xxx.xxxxx
pub struct CapacityParser;

impl ArgParser<u64> for CapacityParser {
    fn parse(&self, input: &str) -> Result<u64, String> {
        let parts = input.trim().split('.').collect::<Vec<_>>();
        let mut capacity = ONE_CKB
            * parts
                .get(0)
                .ok_or_else(|| format!("Missing input"))?
                .parse::<u64>()
                .map_err(|err| err.to_string())?;
        if let Some(shannon_str) = parts.get(1) {
            if shannon_str.len() > 8 {
                return Err(format!("decimal part too long: {}", shannon_str.len()));
            }
            let shannon = shannon_str.parse::<u32>().map_err(|err| err.to_string())?;
            capacity += shannon as u64;
        }
        Ok(capacity)
    }
}
