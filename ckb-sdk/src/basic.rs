use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

use super::chain::ONE_CKB;
use bech32::{convert_bits, Bech32, ToBase32};
use ckb_hash::blake2b_256;
use ckb_types::{
    core::ScriptHashType,
    packed::{Byte32, Script},
    prelude::*,
    H160, H256,
};
use serde_derive::{Deserialize, Serialize};

pub use old_addr::{Address as OldAddress, AddressFormat as OldAddressFormat};

const PREFIX_MAINNET: &str = "ckb";
const PREFIX_TESTNET: &str = "ckt";

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum NetworkType {
    MainNet = 0,
    TestNet = 1,
    Staging = 254,
    Dev = 255,
}

impl NetworkType {
    pub fn from_u8(v: u8) -> Option<NetworkType> {
        match v {
            0 => Some(NetworkType::MainNet),
            1 => Some(NetworkType::TestNet),
            254 => Some(NetworkType::Staging),
            255 => Some(NetworkType::Dev),
            _ => None,
        }
    }

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
            NetworkType::Staging => PREFIX_TESTNET,
            NetworkType::Dev => PREFIX_TESTNET,
        }
    }

    pub fn from_raw_str(value: &str) -> Option<NetworkType> {
        match value {
            "ckb" => Some(NetworkType::MainNet),
            "ckb_testnet" => Some(NetworkType::TestNet),
            "ckb_staging" => Some(NetworkType::Staging),
            "ckb_dev" => Some(NetworkType::Dev),
            _ => None,
        }
    }

    pub fn to_str(self) -> &'static str {
        match self {
            NetworkType::MainNet => "ckb",
            NetworkType::TestNet => "ckb_testnet",
            NetworkType::Staging => "ckb_staging",
            NetworkType::Dev => "ckb_dev",
        }
    }
}

impl fmt::Display for NetworkType {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.to_str())
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum AddressType {
    Default = 0x01,
    FullPayloadWithDataHash = 0x02,
    FullPayloadWithTypeHash = 0x04,
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum CodeHashIndex {
    // SECP256K1 + blake160
    Default = 0x00,
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Address {
    ty: AddressType,
    index: CodeHashIndex,
    hash: H160,
}

impl Address {
    pub fn new_default(hash: H160) -> Address {
        let ty = AddressType::Default;
        let index = CodeHashIndex::Default;
        Address { ty, index, hash }
    }

    pub fn hash(&self) -> &H160 {
        &self.hash
    }

    pub fn lock_script(&self, type_hash: Byte32) -> Script {
        Script::new_builder()
            .args(self.hash.as_bytes().pack())
            .code_hash(type_hash)
            .hash_type(ScriptHashType::Type.into())
            .build()
    }

    pub fn from_pubkey(pubkey: &secp256k1::PublicKey) -> Result<Address, String> {
        // Serialize pubkey as compressed format
        let hash = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
            .expect("Generate hash(H160) from pubkey failed");
        Ok(Self::new_default(hash))
    }

    pub fn from_lock_arg(bytes: &[u8]) -> Result<Address, String> {
        let hash = H160::from_slice(bytes).map_err(|err| err.to_string())?;
        Ok(Self::new_default(hash))
    }

    pub fn from_input(input: &str) -> Result<(NetworkType, Address), String> {
        let value = Bech32::from_str(input).map_err(|err| err.to_string())?;
        let network = NetworkType::from_prefix(value.hrp())
            .ok_or_else(|| format!("Invalid hrp: {}", value.hrp()))?;
        let data = convert_bits(value.data(), 5, 8, false).unwrap();
        if data.len() != 22 {
            return Err(format!("Invalid input data length {}", data.len()));
        }
        if data[0] != AddressType::Default as u8 {
            return Err(format!("Invalid address type: {:?}", data[0]));
        }
        if data[1] != CodeHashIndex::Default as u8 {
            return Err(format!("Invalid code hash index: {:?}", data[1]));
        }
        let hash = H160::from_slice(&data[2..22]).map_err(|err| err.to_string())?;
        Ok((network, Self::new_default(hash)))
    }

    pub fn display_with_prefix(&self, network: NetworkType) -> String {
        let hrp = network.to_prefix();
        let mut data = [0; 22];
        data[0] = self.ty as u8;
        data[1] = self.index as u8;
        data[2..22].copy_from_slice(self.hash.as_bytes());
        let value = Bech32::new(hrp.to_string(), data.to_base32())
            .unwrap_or_else(|_| panic!("Encode address failed: hash={:?}", self.hash));
        format!("{}", value)
    }

    #[allow(clippy::inherent_to_string)]
    #[deprecated(
        since = "0.25.0",
        note = "Name conflicts with the inherent to_string method. Use display_with_prefix instead."
    )]
    pub fn to_string(&self, network: NetworkType) -> String {
        self.display_with_prefix(network)
    }
}

mod old_addr {
    use super::{
        blake2b_256, convert_bits, Bech32, Deserialize, FromStr, NetworkType, Script,
        ScriptHashType, Serialize, ToBase32, H160, H256,
    };
    use ckb_crypto::secp::Pubkey;
    use ckb_types::prelude::*;

    // \x01 is the P2PH version
    const P2PH_MARK: &[u8] = b"\x01P2PH";

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
        pub fn new_default(hash: H160) -> Address {
            let format = AddressFormat::P2PH;
            Address { format, hash }
        }

        pub fn hash(&self) -> &H160 {
            &self.hash
        }

        pub fn lock_script(&self, code_hash: H256) -> Script {
            Script::new_builder()
                .args(self.hash.as_bytes().pack())
                .code_hash(code_hash.pack())
                .hash_type(ScriptHashType::Data.into())
                .build()
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

        pub fn display_with_prefix(&self, network: NetworkType) -> String {
            let hrp = network.to_prefix();
            let mut data = [0; 25];
            let format_data = self.format.to_bytes().expect("Invalid address format");
            data[0..5].copy_from_slice(&format_data[0..5]);
            data[5..25].copy_from_slice(self.hash.as_bytes());
            let value = Bech32::new(hrp.to_string(), data.to_base32())
                .unwrap_or_else(|_| panic!("Encode address failed: hash={:?}", self.hash));
            format!("{}", value)
        }

        #[allow(clippy::inherent_to_string)]
        #[deprecated(
            since = "0.25.0",
            note = "Name conflicts with the inherent to_string method. Use display_with_prefix instead."
        )]
        pub fn to_string(&self, network: NetworkType) -> String {
            self.display_with_prefix(network)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct HumanCapacity(pub u64);

impl From<u64> for HumanCapacity {
    fn from(value: u64) -> HumanCapacity {
        HumanCapacity(value)
    }
}

impl From<HumanCapacity> for u64 {
    fn from(value: HumanCapacity) -> u64 {
        value.0
    }
}

impl Deref for HumanCapacity {
    type Target = u64;
    fn deref(&self) -> &u64 {
        &self.0
    }
}

impl FromStr for HumanCapacity {
    type Err = String;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
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
        Ok(capacity.into())
    }
}

impl fmt::Display for HumanCapacity {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let ckb_part = self.0 / ONE_CKB;
        let shannon_part = self.0 % ONE_CKB;
        let shannon_part_string = format!("{:0>8}", shannon_part);
        let mut base = 10;
        let mut suffix_zero = 7;
        for i in 0..8 {
            if shannon_part % base > 0 {
                suffix_zero = i;
                break;
            }
            base *= 10;
        }
        if f.alternate() {
            write!(
                f,
                "{}.{} (CKB)",
                ckb_part,
                &shannon_part_string[..(8 - suffix_zero)]
            )
        } else {
            write!(
                f,
                "{}.{}",
                ckb_part,
                &shannon_part_string[..(8 - suffix_zero)]
            )
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ckb_types::h160;

    #[test]
    fn test_address() {
        // Sample from nervosnetwork RFC#21
        let hash = h160!("0x13e41d6F9292555916f17B4882a5477C01270142");
        let address = Address::new_default(hash);
        assert_eq!(
            address.display_with_prefix(NetworkType::MainNet),
            "ckb1qyqp8eqad7ffy42ezmchkjyz54rhcqf8q9pqrn323p"
        );
    }

    #[test]
    fn test_human_capacity() {
        for (input, capacity) in &[
            ("3.0", 3 * ONE_CKB),
            ("300.0", 300 * ONE_CKB),
            ("3.56", 356_000_000),
            ("3.0056", 300_560_000),
            ("3.10056", 310_056_000),
            ("3.10056123", 310_056_123),
            ("0.0056", 560_000),
            ("0.10056123", 10_056_123),
            ("12345.234", 12345 * ONE_CKB + 23_400_000),
            ("12345.23442222", 12345 * ONE_CKB + 23_442_222),
        ] {
            assert_eq!(HumanCapacity::from_str(input).unwrap(), (*capacity).into());
            assert_eq!(HumanCapacity::from(*capacity).to_string(), *input);
        }

        // Parse capacity without decimal part
        assert_eq!(
            HumanCapacity::from_str("12345"),
            Ok(HumanCapacity::from(12345 * ONE_CKB))
        );

        // Parse capacity failed
        assert!(HumanCapacity::from_str("12345.234422224").is_err());
        assert!(HumanCapacity::from_str("abc.234422224").is_err());
        assert!(HumanCapacity::from_str("abc.abc").is_err());
        assert!(HumanCapacity::from_str("abc").is_err());
        assert!(HumanCapacity::from_str("-234").is_err());
        assert!(HumanCapacity::from_str("-234.3").is_err());
    }
}
