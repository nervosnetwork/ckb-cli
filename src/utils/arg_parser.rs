use std::fmt::Display;
use std::fs;
use std::io::Read;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use ckb_sdk::{
    bitcoin::{
        hashes::Hash as HashTrait,
        util::address::{Address as BitcoinAddress, Payload},
        util::key::PrivateKey as BitcoinPrivateKey,
    },
    wallet::{zeroize_privkey, MasterPrivKey},
    Address, NetworkType, OldAddress, ONE_CKB,
};
use ckb_types::{packed::OutPoint, prelude::*, H160, H256};
use clap::ArgMatches;
use faster_hex::hex_decode;
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
            .map(Option::unwrap)
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

#[allow(dead_code)]
pub struct NullParser;
impl ArgParser<String> for NullParser {
    fn parse(&self, input: &str) -> Result<String, String> {
        Ok(input.to_owned())
    }
}

#[allow(dead_code)]
pub enum EitherValue<TA, TB> {
    A(TA),
    B(TB),
}

#[allow(dead_code)]
pub struct EitherParser<TA, TB, A, B> {
    a: A,
    b: B,
    _ta: PhantomData<TA>,
    _tb: PhantomData<TB>,
}

impl<TA, TB, A, B> EitherParser<TA, TB, A, B>
where
    A: ArgParser<TA>,
    B: ArgParser<TB>,
{
    #[allow(dead_code)]
    pub fn new(a: A, b: B) -> Self {
        EitherParser {
            a,
            b,
            _ta: PhantomData,
            _tb: PhantomData,
        }
    }
}

impl<TA, TB, A, B> ArgParser<EitherValue<TA, TB>> for EitherParser<TA, TB, A, B>
where
    A: ArgParser<TA>,
    B: ArgParser<TB>,
{
    fn parse(&self, input: &str) -> Result<EitherValue<TA, TB>, String> {
        self.a
            .parse(input)
            .map(EitherValue::A)
            .or_else(|_| self.b.parse(input).map(EitherValue::B))
    }
}

#[derive(Debug, Default)]
pub struct FromStrParser<T: FromStr> {
    _t: PhantomData<T>,
}

impl<T: FromStr> FromStrParser<T> {
    pub fn new() -> FromStrParser<T> {
        FromStrParser { _t: PhantomData }
    }
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

pub struct PrivkeyWrapper(pub secp256k1::SecretKey);

// For security purpose
impl Drop for PrivkeyWrapper {
    fn drop(&mut self) {
        zeroize_privkey(&mut self.0);
    }
}

impl std::ops::Deref for PrivkeyWrapper {
    type Target = secp256k1::SecretKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct PrivkeyPathParser;

impl ArgParser<PrivkeyWrapper> for PrivkeyPathParser {
    fn parse(&self, input: &str) -> Result<PrivkeyWrapper, String> {
        let path: PathBuf = FilePathParser::new(true).parse(input)?;
        let mut content = String::new();
        let mut file = fs::File::open(&path).map_err(|err| err.to_string())?;
        file.read_to_string(&mut content)
            .map_err(|err| err.to_string())?;
        let privkey_string: String = content
            .split_whitespace()
            .next()
            .map(ToOwned::to_owned)
            .ok_or_else(|| "File is empty".to_string())?;
        let data: H256 = FixedHashParser::<H256>::default().parse(privkey_string.as_str())?;
        secp256k1::SecretKey::from_slice(data.as_bytes())
            .map(PrivkeyWrapper)
            .map_err(|err| format!("Invalid secp256k1 secret key format, error: {}", err))
    }
}

pub struct ExtendedPrivkeyPathParser;

impl ArgParser<MasterPrivKey> for ExtendedPrivkeyPathParser {
    fn parse(&self, input: &str) -> Result<MasterPrivKey, String> {
        let path: PathBuf = FilePathParser::new(true).parse(input)?;
        let mut content = String::new();
        let mut file = fs::File::open(&path).map_err(|err| err.to_string())?;
        file.read_to_string(&mut content)
            .map_err(|err| err.to_string())?;
        let lines = content
            .split_whitespace()
            .map(ToOwned::to_owned)
            .take(2)
            .collect::<Vec<String>>();
        if lines.len() < 2 {
            return Err("Not enough line for parse extended private key".to_owned());
        }
        let hash_parser = FixedHashParser::<H256>::default();
        let line1: H256 = hash_parser.parse(&lines[0])?;
        let line2: H256 = hash_parser.parse(&lines[1])?;
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&line1.as_bytes()[0..32]);
        bytes[32..64].copy_from_slice(&line2.as_bytes()[0..32]);
        MasterPrivKey::from_bytes(bytes).map_err(|err| err.to_string())
    }
}

pub struct BitcoinPrivateKeyWrapper {
    inner: BitcoinPrivateKey,
}

impl BitcoinPrivateKeyWrapper {
    pub fn secp_privkey(&self) -> &secp256k1::SecretKey {
        &self.inner.key
    }
}

impl Drop for BitcoinPrivateKeyWrapper {
    fn drop(&mut self) {
        zeroize_privkey(&mut self.inner.key);
    }
}

pub struct WifPrivkeyParser;

impl ArgParser<BitcoinPrivateKeyWrapper> for WifPrivkeyParser {
    fn parse(&self, input: &str) -> Result<BitcoinPrivateKeyWrapper, String> {
        BitcoinPrivateKey::from_wif(input)
            .map_err(|err| err.to_string())
            .map(|inner| BitcoinPrivateKeyWrapper { inner })
    }
}

pub struct PubkeyHexParser;

impl ArgParser<secp256k1::PublicKey> for PubkeyHexParser {
    fn parse(&self, input: &str) -> Result<secp256k1::PublicKey, String> {
        let data = HexParser.parse(input)?;
        secp256k1::PublicKey::from_slice(&data)
            .map_err(|err| format!("Invalid secp256k1 public key format, error: {}", err))
    }
}

pub struct AddressParser;

impl ArgParser<Address> for AddressParser {
    fn parse(&self, input: &str) -> Result<Address, String> {
        if let Ok((_network, address)) = Address::from_input(input) {
            return Ok(address);
        }

        let prefix = input.chars().take(3).collect::<String>();
        let network = NetworkType::from_prefix(prefix.as_str())
            .ok_or_else(|| format!("Invalid address prefix: {}", prefix))?;
        let old_address = OldAddress::from_input(network, input)?;
        Ok(Address::new_default(old_address.hash().clone()))
    }
}

pub struct BitcoinAddressParser;

impl ArgParser<H160> for BitcoinAddressParser {
    fn parse(&self, input: &str) -> Result<H160, String> {
        match BitcoinAddress::from_str(input)
            .map_err(|err| err.to_string())?
            .payload
        {
            Payload::PubkeyHash(hash) => Ok(H160::from_slice(&hash.into_inner()[..]).unwrap()),
            Payload::WitnessProgram { ref program, .. } if program.len() == 20 => {
                Ok(H160::from_slice(program.as_slice()).unwrap())
            }
            payload => Err(format!("Invalid address payload: {:?}", payload)),
        }
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
                .ok_or_else(|| "Missing input".to_owned())?
                .parse::<u64>()
                .map_err(|err| err.to_string())?;
        if let Some(shannon_str) = parts.get(1) {
            let shannon_str = shannon_str.trim();
            if shannon_str.len() > 8 {
                return Err(format!("decimal part too long: {}", shannon_str.len()));
            }
            let mut shannon = shannon_str.parse::<u32>().map_err(|err| err.to_string())?;
            for _ in 0..(8 - shannon_str.len()) {
                shannon *= 10;
            }
            capacity += u64::from(shannon);
        }
        Ok(capacity)
    }
}

#[allow(dead_code)]
pub struct OutPointParser;

impl ArgParser<OutPoint> for OutPointParser {
    fn parse(&self, input: &str) -> Result<OutPoint, String> {
        let parts = input.split('-').collect::<Vec<_>>();
        if parts.len() != 2 {
            return Err(format!(
                "Invalid OutPoint: {}, format: {{tx-hash}}-{{index}}",
                input
            ));
        }
        let tx_hash: H256 = FixedHashParser::<H256>::default().parse(parts[0])?;
        let index = FromStrParser::<u32>::default().parse(parts[1])?;
        Ok(OutPoint::new(tx_hash.pack(), index))
    }
}

pub struct DurationParser;

impl ArgParser<Duration> for DurationParser {
    fn parse(&self, input: &str) -> Result<Duration, String> {
        if input.is_empty() {
            return Err("Missing input".to_owned());
        }
        let input_lower = input.to_lowercase();
        let value_part = &input_lower[0..input_lower.len() - 1];
        let value: u64 = value_part.parse::<u64>().map_err(|err| err.to_string())?;
        let unit_part = &input_lower[input_lower.len() - 1..input_lower.len()];
        let seconds = match unit_part {
            "s" => value,
            "m" => value * 60,
            "h" => value * 3600,
            "d" => value * 3600 * 24,
            _ => {
                return Err(
                    "Please give an unit, {{s: second, m: minute, h: hour, d: day}}".to_owned(),
                );
            }
        };
        Ok(Duration::from_secs(seconds))
    }
}

pub struct AccountIdParser;
impl ArgParser<Address> for AccountIdParser {
    fn parse(&self, input: &str) -> Result<Address, String> {
        FixedHashParser::<H160>::default()
            .parse(input)
            .map(|blake160| Address::from_lock_arg(blake160.as_bytes()).unwrap())
            .or_else(|_| AddressParser.parse(input))
            .or_else(|_| {
                BitcoinAddressParser
                    .parse(input)
                    .map(|hash| Address::from_ripemd160(hash.as_bytes()).unwrap())
            })
    }
}

#[cfg(test)]
mod tests {
    use ckb_types::{h160, h256};
    use std::net::IpAddr;

    use super::*;

    #[test]
    fn test_from_str() {
        assert_eq!(FromStrParser::<u64>::default().parse("456"), Ok(456));
        assert_eq!(FromStrParser::<i64>::default().parse("-34"), Ok(-34));
        assert_eq!(
            FromStrParser::<IpAddr>::new().parse("192.168.1.1"),
            Ok("192.168.1.1".parse().unwrap())
        );
        assert!(FromStrParser::<u64>::default().parse("-34").is_err());
        assert!(FromStrParser::<u64>::default().parse("xxy").is_err());
        assert!(FromStrParser::<u64>::default().parse("3x").is_err());
    }

    #[test]
    fn test_hex() {
        assert_eq!(HexParser.parse("0x3a"), Ok(vec![0x3a]));
        assert_eq!(HexParser.parse("0Xaa"), Ok(vec![0xaa]));
        assert_eq!(HexParser.parse("3a6665"), Ok(vec![0x3a, 0x66, 0x65]));
        assert!(HexParser.parse("0x3a665").is_err());
        assert!(HexParser.parse("abcdefghi").is_err());
    }

    #[test]
    fn test_fixed_hash() {
        assert_eq!(
            FixedHashParser::<H256>::default()
                .parse("0xac71d52d9c1c693a4136513d7c62b0a6441b14ced02518650fe673dfcb6c016c"),
            Ok(h256!(
                "0xac71d52d9c1c693a4136513d7c62b0a6441b14ced02518650fe673dfcb6c016c"
            )),
        );
        assert_eq!(
            FixedHashParser::<H256>::default()
                .parse("ac71d52d9c1c693a4136513d7c62b0a6441b14ced02518650fe673dfcb6c016c"),
            Ok(h256!(
                "0xac71d52d9c1c693a4136513d7c62b0a6441b14ced02518650fe673dfcb6c016c"
            )),
        );
        assert!(FixedHashParser::<H256>::default()
            .parse("71d52d9c1c693a4136513d7c62b0a6441b14ced02518650fe673dfcb6c016c")
            .is_err());
        assert!(FixedHashParser::<H256>::default()
            .parse("71d52d9c1c693a4136513d7c62b0a6441b14ced02518650fe673dfcb6c016ccccc")
            .is_err());
    }

    #[test]
    fn test_wif_privkey() {
        assert_eq!(
            WifPrivkeyParser
                .parse("cUt1biwGTVH9J2r5fJcaLf3Gf5DF1RwxaDQ3ufpMR5Q5DusSc6jh")
                .unwrap()
                .secp_privkey(),
            &secp256k1::SecretKey::from_slice(
                HexParser
                    .parse("d9c435411b7a44329db8684d3afc120dddf2c7d20b4917295d319561c75d8dc1")
                    .unwrap()
                    .as_slice()
            )
            .unwrap()
        )
    }

    #[test]
    fn test_address() {
        // Old address, lock-arg: e22f7f385830a75e50ab7fc5fd4c35b134f1e84b
        assert_eq!(
            AddressParser.parse("ckt1q9gry5zgughh7wzcxzn4u59t0lzl6np4ky60r6ztpw69rl"),
            Ok(Address::new_default(h160!(
                "0xe22f7f385830a75e50ab7fc5fd4c35b134f1e84b"
            )))
        );
        // New address, lock-arg: 13e41d6F9292555916f17B4882a5477C01270142
        assert_eq!(
            AddressParser.parse("ckb1qyqp8eqad7ffy42ezmchkjyz54rhcqf8q9pqrn323p"),
            Ok(Address::new_default(h160!(
                "0x13e41d6F9292555916f17B4882a5477C01270142"
            )))
        );

        // Old address
        assert!(AddressParser
            .parse("kt1q9gry5zgzkfc6rznfaequqlcmdeh4fhta4uwn4qajhqxyc")
            .is_err());
        assert!(AddressParser
            .parse("ckt1q9gry5zgzkfc6rznfaequqlcmdeh4fhta4uwn4qajhqxy")
            .is_err());
        // New address
        assert!(AddressParser
            .parse("ckb1qyqp8eqad7ffy42ezmchkjyz54rhcqfpqrn323p")
            .is_err());
        assert!(AddressParser
            .parse("kb1qyqp8eqad7ffy42ezmchkjyz54rhcqf8q9pqrn323p")
            .is_err());
    }

    #[test]
    fn test_capacity() {
        assert_eq!(CapacityParser.parse("12345"), Ok(12345 * ONE_CKB));
        assert_eq!(
            CapacityParser.parse("12345.234"),
            Ok(12345 * ONE_CKB + 23_400_000)
        );
        assert_eq!(
            CapacityParser.parse("12345.23442222"),
            Ok(12345 * ONE_CKB + 23_442_222)
        );
        assert!(CapacityParser.parse("12345.234422224").is_err());
        assert!(CapacityParser.parse("abc.234422224").is_err());
        assert!(CapacityParser.parse("abc.abc").is_err());
        assert!(CapacityParser.parse("abc").is_err());
        assert!(CapacityParser.parse("-234").is_err());
        assert!(CapacityParser.parse("-234.3").is_err());
    }
}
