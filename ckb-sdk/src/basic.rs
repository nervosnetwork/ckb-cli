use std::fmt;
use std::str::FromStr;

use bech32::{convert_bits, Bech32, ToBase32};
use ckb_hash::blake2b_256;
use ckb_types::{
    bytes::Bytes,
    core::{EpochNumberWithFraction, ScriptHashType},
    packed::{Byte32, Script},
    prelude::*,
    H160, H256,
};
use serde_derive::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

pub use old_addr::{Address as OldAddress, AddressFormat as OldAddressFormat};

const LOCK_TYPE_FLAG: u64 = 1 << 63;

const PREFIX_MAINNET: &str = "ckb";
const PREFIX_TESTNET: &str = "ckt";

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum NetworkType {
    MainNet = 0,
    TestNet = 1,
    Dev = 255,
}

impl NetworkType {
    pub fn from_u8(v: u8) -> Option<NetworkType> {
        match v {
            0 => Some(NetworkType::MainNet),
            1 => Some(NetworkType::TestNet),
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
            NetworkType::Dev => PREFIX_TESTNET,
        }
    }

    pub fn from_raw_str(value: &str) -> Option<NetworkType> {
        match value {
            "ckb" => Some(NetworkType::MainNet),
            "ckb_testnet" => Some(NetworkType::TestNet),
            "ckb_dev" => Some(NetworkType::Dev),
            _ => None,
        }
    }

    pub fn to_str(self) -> &'static str {
        match self {
            NetworkType::MainNet => "ckb",
            NetworkType::TestNet => "ckb_testnet",
            NetworkType::Dev => "ckb_dev",
        }
    }
}

impl fmt::Display for NetworkType {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.to_str())
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum AddressType {
    Default = 0x01,
    // Full payload with data hash
    FullData = 0x02,
    // Full payload with type hash
    FullType = 0x04,
}

impl AddressType {
    pub fn from_u8(value: u8) -> Result<AddressType, String> {
        match value {
            0x01 => Ok(AddressType::Default),
            0x02 => Ok(AddressType::FullData),
            0x04 => Ok(AddressType::FullType),
            _ => Err(format!("Invalid address type value: {}", value)),
        }
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum CodeHashIndex {
    // SECP256K1 + blake160
    Default = 0x00,
    // SECP256K1 + multisig
    Multisig = 0x01,
}

impl Default for CodeHashIndex {
    fn default() -> CodeHashIndex {
        CodeHashIndex::Default
    }
}

impl CodeHashIndex {
    pub fn from_u8(value: u8) -> Result<CodeHashIndex, String> {
        match value {
            0x00 => Ok(CodeHashIndex::Default),
            0x01 => Ok(CodeHashIndex::Multisig),
            _ => Err(format!("Invalid code hash index value: {}", value)),
        }
    }
}

// See: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0021-ckb-address-format/0021-ckb-address-format.md
#[derive(Hash, Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Address {
    ty: AddressType,
    index: Option<CodeHashIndex>,
    payload: Bytes,
}

impl Address {
    pub fn new_default(hash: H160) -> Address {
        let ty = AddressType::Default;
        let index = Some(CodeHashIndex::Default);
        let payload = hash.as_bytes().into();
        Address { ty, index, payload }
    }

    pub fn new_multisig(hash: H160) -> Address {
        let ty = AddressType::Default;
        let index = Some(CodeHashIndex::Multisig);
        let payload = hash.as_bytes().into();
        Address { ty, index, payload }
    }

    pub fn new_full_data(payload: Bytes) -> Address {
        let ty = AddressType::FullData;
        let index = None;
        Address { ty, index, payload }
    }

    pub fn new_full_type(payload: Bytes) -> Address {
        let ty = AddressType::FullType;
        let index = None;
        Address { ty, index, payload }
    }

    pub fn ty(&self) -> AddressType {
        self.ty
    }

    pub fn code_type(&self) -> ScriptHashType {
        match (self.ty, self.index) {
            (AddressType::Default, Some(CodeHashIndex::Default)) => ScriptHashType::Type,
            (AddressType::Default, Some(CodeHashIndex::Multisig)) => ScriptHashType::Type,
            (AddressType::FullData, None) => ScriptHashType::Data,
            (AddressType::FullType, None) => ScriptHashType::Type,
            _ => panic!(
                "Invalid address: ty: {:?}, index: {:?}",
                self.ty, self.index
            ),
        }
    }

    pub fn index(&self) -> Option<CodeHashIndex> {
        self.index
    }

    pub fn payload(&self) -> Bytes {
        self.payload.clone()
    }

    pub fn lock_script(&self, type_hash: Byte32) -> Result<Script, String> {
        // TODO: Use the code_hash corresponding to self.index
        if self.ty != AddressType::Default {
            Err(format!("Invalid address type: {:?}", self.ty))
        } else {
            Ok(Script::new_builder()
                .args(self.payload.pack())
                .code_hash(type_hash)
                .hash_type(ScriptHashType::Type.into())
                .build())
        }
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
        let ty = AddressType::from_u8(data[0])?;
        match ty {
            AddressType::Default => {
                if data.len() != 22 {
                    return Err(format!("Invalid input data length {}", data.len()));
                }
                let index = Some(CodeHashIndex::from_u8(data[1])?);
                let payload = Bytes::from(&data[2..22]);
                let address = Address { ty, index, payload };
                Ok((network, address))
            }
            AddressType::FullData | AddressType::FullType => {
                let index = None;
                let payload = Bytes::from(&data[1..]);
                let address = Address { ty, index, payload };
                Ok((network, address))
            }
        }
    }

    pub fn display_with_prefix(&self, network: NetworkType) -> String {
        let hrp = network.to_prefix();
        let data = match self.ty {
            AddressType::Default => {
                let mut data = vec![0; 22];
                data[0] = self.ty as u8;
                data[1] = self
                    .index
                    .expect("missing code hash index for default address type")
                    as u8;
                data[2..22].copy_from_slice(&self.payload);
                data
            }
            AddressType::FullData | AddressType::FullType => {
                let mut data = vec![0; self.payload.len() + 1];
                data[0] = self.ty as u8;
                data[1..].copy_from_slice(&self.payload);
                data
            }
        };
        let value = Bech32::new(hrp.to_string(), data.to_base32())
            .unwrap_or_else(|_| panic!("Encode address failed: payload={:?}", self.payload));
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

#[derive(Clone, Copy, Debug)]
pub enum SinceType {
    BlockNumber,
    EpochNumberWithFraction,
    Timestamp,
}

#[derive(Clone, Copy, Debug)]
pub struct Since(u64);

impl Since {
    pub fn new(ty: SinceType, value: u64, is_relative: bool) -> Since {
        let value = match ty {
            SinceType::BlockNumber => value,
            SinceType::EpochNumberWithFraction => 0x2000_0000_0000_0000 | value,
            SinceType::Timestamp => 0x4000_0000_0000_0000 | value,
        };
        if is_relative {
            Since(LOCK_TYPE_FLAG | value)
        } else {
            Since(value)
        }
    }

    pub fn new_absolute_epoch(epoch_number: u64) -> Since {
        let epoch = EpochNumberWithFraction::new(epoch_number, 0, 1);
        Self::new(
            SinceType::EpochNumberWithFraction,
            epoch.full_value(),
            false,
        )
    }

    pub fn value(self) -> u64 {
        self.0
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
}
