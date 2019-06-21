use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use bech32::{convert_bits, Bech32, ToBase32};
use bytes::Bytes;
use ckb_core::script::Script as CoreScript;
use crypto::secp::{Generator, Privkey, Pubkey};
use faster_hex::{hex_decode, hex_string};
use hash::blake2b_256;
use numext_fixed_hash::{H160, H256};
use secp256k1::key;
use serde_derive::{Deserialize, Serialize};

const PREFIX_MAINNET: &str = "ckb";
const PREFIX_TESTNET: &str = "ckt";
// \x01 is the P2PH version
const P2PH_MARK: &[u8] = b"\x01P2PH";

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NetworkType {
    MainNet,
    TestNet,
}

impl NetworkType {
    pub fn from_prefix(value: &str) -> Option<NetworkType> {
        match value {
            PREFIX_MAINNET => Some(NetworkType::MainNet),
            PREFIX_TESTNET => Some(NetworkType::TestNet),
            _ => None,
        }
    }

    pub fn to_prefix(self) -> &'static str {
        match self {
            NetworkType::MainNet => PREFIX_MAINNET,
            NetworkType::TestNet => PREFIX_TESTNET,
        }
    }

    pub fn from_raw_str(value: &str) -> Option<NetworkType> {
        match value {
            "ckb_mainnet" => Some(NetworkType::MainNet),
            "ckb_testnet" => Some(NetworkType::TestNet),
            _ => None,
        }
    }

    pub fn to_str(self) -> &'static str {
        match self {
            NetworkType::MainNet => "ckb_mainnet",
            NetworkType::TestNet => "ckb_testnet",
        }
    }
}

impl fmt::Display for NetworkType {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.to_str())
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AddressFormat {
    // SECP256K1 algorithm	PK
    #[allow(dead_code)]
    SP2K,
    // SECP256R1 algorithm	PK
    #[allow(dead_code)]
    SP2R,
    // SECP256K1 + blake160	blake160(pk)
    P2PH,
    // Alias of SP2K	PK
    #[allow(dead_code)]
    P2PK,
}

impl Default for AddressFormat {
    fn default() -> AddressFormat {
        AddressFormat::P2PH
    }
}

impl AddressFormat {
    pub fn from_bytes(format: &[u8]) -> Result<AddressFormat, String> {
        match format {
            P2PH_MARK => Ok(AddressFormat::P2PH),
            _ => Err(format!("Unsupported address format data: {:?}", format)),
        }
    }

    pub fn to_bytes(self) -> Result<Vec<u8>, String> {
        match self {
            AddressFormat::P2PH => Ok(P2PH_MARK.to_vec()),
            _ => Err(format!("Unsupported address format: {:?}", self)),
        }
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Address {
    format: AddressFormat,
    hash: H160,
}

impl Address {
    pub fn hash(&self) -> &H160 {
        &self.hash
    }

    pub fn lock_script(&self, code_hash: H256) -> CoreScript {
        CoreScript {
            args: vec![Bytes::from(self.hash.as_bytes())],
            code_hash,
        }
    }

    pub fn from_pubkey(format: AddressFormat, pubkey: &Pubkey) -> Result<Address, String> {
        if format != AddressFormat::P2PH {
            return Err("Only support P2PH for now".to_owned());
        }
        // Serialize pubkey as compressed format
        let hash = H160::from_slice(&blake2b_256(pubkey.serialize())[0..20])
            .expect("Generate hash(H160) from pubkey failed");
        Ok(Address { format, hash })
    }

    pub fn from_lock_arg(bytes: &[u8]) -> Result<Address, String> {
        let format = AddressFormat::P2PH;
        let hash = H160::from_slice(bytes).map_err(|err| err.to_string())?;
        Ok(Address { format, hash })
    }

    pub fn from_input(network: NetworkType, input: &str) -> Result<Address, String> {
        let value = Bech32::from_str(input).map_err(|err| err.to_string())?;
        if NetworkType::from_prefix(value.hrp())
            .filter(|input_network| input_network == &network)
            .is_none()
        {
            return Err(format!("Invalid hrp({}) for {}", value.hrp(), network));
        }
        let data = convert_bits(value.data(), 5, 8, false).unwrap();
        if data.len() != 25 {
            return Err(format!("Invalid input data length {}", data.len()));
        }
        let format = AddressFormat::from_bytes(&data[0..5])?;
        let hash = H160::from_slice(&data[5..25]).map_err(|err| err.to_string())?;
        Ok(Address { format, hash })
    }

    pub fn to_string(&self, network: NetworkType) -> String {
        let hrp = network.to_prefix();
        let mut data = [0; 25];
        let format_data = self.format.to_bytes().expect("Invalid address format");
        data[0..5].copy_from_slice(&format_data[0..5]);
        data[5..25].copy_from_slice(self.hash.as_fixed_bytes());
        let value = Bech32::new(hrp.to_string(), data.to_base32())
            .unwrap_or_else(|_| panic!("Encode address failed: hash={:?}", self.hash));
        format!("{}", value)
    }
}

pub struct SecpKey {
    pub privkey_path: Option<PathBuf>,
    pub privkey: Option<Privkey>,
    pub pubkey: Pubkey,
}

impl SecpKey {
    pub fn generate() -> SecpKey {
        let (privkey, pubkey) = Generator::new()
            .random_keypair()
            .expect("generate random key error");
        SecpKey {
            privkey_path: None,
            privkey: Some(privkey),
            pubkey,
        }
    }

    pub fn path_exists(&self) -> bool {
        self.privkey_path
            .as_ref()
            .map(|path| Path::new(path).exists())
            .unwrap_or(false)
    }

    pub fn corrupted(&self) -> bool {
        self.privkey_path
            .as_ref()
            .map(|path| match SecpKey::from_privkey_path(path) {
                Ok(key) => key.pubkey != self.pubkey,
                Err(_) => false,
            })
            .unwrap_or(false)
    }

    pub fn from_privkey(privkey: Privkey) -> Result<SecpKey, String> {
        let pubkey = privkey.pubkey().map_err(|err| err.to_string())?;
        Ok(SecpKey {
            privkey_path: None,
            privkey: Some(privkey),
            pubkey,
        })
    }

    pub fn from_pubkey(pubkey: Pubkey) -> SecpKey {
        SecpKey {
            privkey_path: None,
            privkey: None,
            pubkey,
        }
    }

    pub fn from_privkey_path<P: AsRef<Path>>(path: P) -> Result<SecpKey, String> {
        let path: PathBuf = path.as_ref().to_path_buf();
        let mut content = String::new();
        let mut file = fs::File::open(&path).map_err(|err| err.to_string())?;
        file.read_to_string(&mut content)
            .map_err(|err| err.to_string())?;
        let privkey_string: String = content
            .split_whitespace()
            .next()
            .map(ToOwned::to_owned)
            .ok_or_else(|| "File is empty".to_string())?;
        let privkey_str = if privkey_string.starts_with("0x") || privkey_string.starts_with("0X") {
            &privkey_string[2..]
        } else {
            privkey_string.as_str()
        };
        let privkey = Privkey::from_str(privkey_str.trim()).map_err(|err| err.to_string())?;
        let pubkey = privkey.pubkey().map_err(|err| err.to_string())?;
        Ok(SecpKey {
            privkey_path: Some(path),
            privkey: Some(privkey),
            pubkey,
        })
    }

    pub fn from_pubkey_str(mut pubkey_hex: &str) -> Result<SecpKey, String> {
        if pubkey_hex.starts_with("0x") || pubkey_hex.starts_with("0X") {
            pubkey_hex = &pubkey_hex[2..];
        }
        let mut pubkey_bytes = [0u8; 33];
        hex_decode(pubkey_hex.as_bytes(), &mut pubkey_bytes)
            .map_err(|err| format!("parse pubkey failed: {:?}", err))?;
        key::PublicKey::from_slice(&pubkey_bytes)
            .map_err(|err| err.to_string())
            .map(Into::into)
            .map(|pubkey| SecpKey {
                privkey_path: None,
                privkey: None,
                pubkey,
            })
    }

    pub fn save_to_path<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        if let Some(ref privkey) = self.privkey {
            let path = path.as_ref();
            if Path::new(path).exists() {
                return Err(format!(
                    "ERROR: output path ( {} ) already exists",
                    path.to_string_lossy()
                ));
            }
            let address = self.address()?;
            // TODO: support different network: testnet/mainnet
            let address_string = address.to_string(NetworkType::TestNet);
            let mut file = fs::File::create(path).map_err(|err| err.to_string())?;
            file.write(format!("{}\n", privkey.to_string()).as_bytes())
                .map_err(|err| err.to_string())?;
            file.write(format!("{}\n", address_string).as_bytes())
                .map_err(|err| err.to_string())?;
            Ok(())
        } else {
            Err("Privkey is empty".to_owned())
        }
    }

    pub fn address(&self) -> Result<Address, String> {
        // TODO: support other address format
        Address::from_pubkey(AddressFormat::default(), &self.pubkey)
    }

    pub fn pubkey_string(&self) -> String {
        hex_string(&self.pubkey.serialize()).expect("encode pubkey failed")
    }
}
