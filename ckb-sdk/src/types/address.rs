use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::str::FromStr;

use bech32::{self, convert_bits, ToBase32, Variant};
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_types::{
    bytes::Bytes,
    core::{DepType, ScriptHashType},
    packed::{Byte32, CellDep, OutPoint, Script},
    prelude::*,
    H160, H256,
};
use serde_derive::{Deserialize, Serialize};

use super::NetworkType;
use crate::constants::{
    AGGRON_ACP_CODE_HASH, AGGRON_ACP_DEP_TYPE, AGGRON_ACP_HASH_TYPE, AGGRON_ACP_INDEX,
    AGGRON_ACP_TX_HASH, LINA_ACP_CODE_HASH, LINA_ACP_DEP_TYPE, LINA_ACP_HASH_TYPE, LINA_ACP_INDEX,
    LINA_ACP_TX_HASH, MULTISIG_TYPE_HASH, SIGHASH_TYPE_HASH,
};
pub use old_addr::{Address as OldAddress, AddressFormat as OldAddressFormat};

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum AddressType {
    // full version identifies the hash_type and vm_version
    Full = 0x00,
    // short version for locks with popular code_hash
    Short = 0x01,
    // full version with hash_type = "Data", deprecated
    FullData = 0x02,
    // full version with hash_type = "Type", deprecated
    FullType = 0x04,
}

impl AddressType {
    pub fn from_u8(value: u8) -> Result<AddressType, String> {
        match value {
            0x00 => Ok(AddressType::Full),
            0x01 => Ok(AddressType::Short),
            0x02 => Ok(AddressType::FullData),
            0x04 => Ok(AddressType::FullType),
            _ => Err(format!("Invalid address type value: {}", value)),
        }
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum CodeHashIndex {
    // SECP256K1 + blake160
    Sighash = 0x00,
    // SECP256K1 + multisig
    Multisig = 0x01,
    // anyone_can_pay blake160(PK)
    Acp = 0x02,
}

impl CodeHashIndex {
    pub fn from_u8(value: u8) -> Result<CodeHashIndex, String> {
        match value {
            0x00 => Ok(CodeHashIndex::Sighash),
            0x01 => Ok(CodeHashIndex::Multisig),
            0x02 => Ok(CodeHashIndex::Acp),
            _ => Err(format!("Invalid code hash index value: {}", value)),
        }
    }
}

#[derive(Hash, Eq, PartialEq, Clone)]
pub enum AddressPayload {
    // Remain the address format before ckb2021.
    Short {
        index: CodeHashIndex,
        hash: H160,
    },
    Full {
        hash_type: ScriptHashType,
        code_hash: Byte32,
        args: Bytes,
    },
}

impl AddressPayload {
    pub fn try_to_script(&self, acp_config: Option<&AcpConfig>) -> Result<Script, String> {
        Script::try_from(AddressPayloadWithAcpConfig::new(self, acp_config))
    }
    pub fn try_from_script(
        script: &Script,
        acp_config: Option<&AcpConfig>,
    ) -> Result<AddressPayload, String> {
        AddressPayload::try_from(ScriptWithAcpConfig {
            lock: script,
            acp_config,
        })
    }
    pub fn new_short_sighash(hash: H160) -> AddressPayload {
        let index = CodeHashIndex::Sighash;
        AddressPayload::Short { index, hash }
    }
    pub fn new_short_multisig(hash: H160) -> AddressPayload {
        let index = CodeHashIndex::Multisig;
        AddressPayload::Short { index, hash }
    }
    pub fn new_short_acp(hash: H160) -> AddressPayload {
        let index = CodeHashIndex::Acp;
        AddressPayload::Short { index, hash }
    }

    pub fn new_full(hash_type: ScriptHashType, code_hash: Byte32, args: Bytes) -> AddressPayload {
        AddressPayload::Full {
            hash_type,
            code_hash,
            args,
        }
    }
    #[deprecated(since = "0.100.0-rc5", note = "Use AddressType::Full instead")]
    pub fn new_full_data(code_hash: Byte32, args: Bytes) -> AddressPayload {
        Self::new_full(ScriptHashType::Data, code_hash, args)
    }
    #[deprecated(since = "0.100.0-rc5", note = "Use AddressType::Full instead")]
    pub fn new_full_type(code_hash: Byte32, args: Bytes) -> AddressPayload {
        Self::new_full(ScriptHashType::Type, code_hash, args)
    }

    pub fn ty(&self, is_new: bool) -> AddressType {
        match self {
            AddressPayload::Short { .. } => AddressType::Short,
            AddressPayload::Full { hash_type, .. } => match (hash_type, is_new) {
                (ScriptHashType::Data, true) => AddressType::Full,
                (ScriptHashType::Data, false) => AddressType::FullData,
                (ScriptHashType::Data1, _) => AddressType::Full,
                (ScriptHashType::Type, true) => AddressType::Full,
                (ScriptHashType::Type, false) => AddressType::FullType,
            },
        }
    }
    pub fn is_sighash(&self) -> bool {
        matches!(self, AddressPayload::Short { index, .. } if *index == CodeHashIndex::Sighash)
    }
    pub fn is_multisig(&self) -> bool {
        matches!(self, AddressPayload::Short { index, .. } if *index == CodeHashIndex::Multisig)
    }

    pub fn hash_type(&self, acp_hash_type: ScriptHashType) -> ScriptHashType {
        match self {
            AddressPayload::Short { index, .. } => match index {
                CodeHashIndex::Acp => acp_hash_type,
                _ => ScriptHashType::Type,
            },
            AddressPayload::Full { hash_type, .. } => *hash_type,
        }
    }

    pub fn code_hash(&self, acp_code_hash: &Byte32) -> Byte32 {
        match self {
            AddressPayload::Short { index, .. } => match index {
                CodeHashIndex::Sighash => SIGHASH_TYPE_HASH.clone().pack(),
                CodeHashIndex::Multisig => MULTISIG_TYPE_HASH.clone().pack(),
                CodeHashIndex::Acp => acp_code_hash.clone(),
            },
            AddressPayload::Full { code_hash, .. } => code_hash.clone(),
        }
    }

    pub fn args(&self) -> Bytes {
        match self {
            AddressPayload::Short { hash, .. } => Bytes::from(hash.as_bytes().to_vec()),
            AddressPayload::Full { args, .. } => args.clone(),
        }
    }

    pub fn from_pubkey(pubkey: &secp256k1::PublicKey) -> AddressPayload {
        // Serialize pubkey as compressed format
        let hash = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
            .expect("Generate hash(H160) from pubkey failed");
        AddressPayload::new_short_sighash(hash)
    }

    pub fn display_with_network(&self, network: NetworkType, is_new: bool) -> String {
        let hrp = network.to_prefix();
        let data = match self {
            // payload = 0x01 | code_hash_index | args
            AddressPayload::Short { index, hash } => {
                let mut data = vec![0u8; 22];
                let is_new = false;
                data[0] = self.ty(is_new) as u8;
                data[1] = (*index) as u8;
                data[2..].copy_from_slice(hash.as_bytes());
                data
            }
            AddressPayload::Full {
                code_hash,
                hash_type,
                args,
            } => {
                if is_new {
                    // payload = 0x00 | code_hash | hash_type | args
                    let mut data = vec![0u8; 34 + args.len()];
                    data[0] = self.ty(is_new) as u8;
                    data[1..33].copy_from_slice(code_hash.as_slice());
                    data[33] = (*hash_type) as u8;
                    data[34..].copy_from_slice(args.as_ref());
                    data
                } else {
                    // payload = 0x02/0x04 | code_hash | args
                    let mut data = vec![0u8; 33 + args.len()];
                    data[0] = self.ty(is_new) as u8;
                    data[1..33].copy_from_slice(code_hash.as_slice());
                    data[33..].copy_from_slice(args.as_ref());
                    data
                }
            }
        };
        let variant = if is_new {
            bech32::Variant::Bech32m
        } else {
            bech32::Variant::Bech32
        };
        bech32::encode(hrp, data.to_base32(), variant)
            .unwrap_or_else(|_| panic!("Encode address failed: payload={:?}", self))
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Default)]
pub struct AcpConfig {
    code_hash: Byte32,
    hash_type: ScriptHashType,
    // CellDep
    tx_hash: Byte32,
    index: u32,
    dep_type: DepType,
}

#[derive(Hash, Eq, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct ReprAcpConfig {
    code_hash: H256,
    hash_type: json_types::ScriptHashType,
    // CellDep
    tx_hash: H256,
    index: u32,
    dep_type: json_types::DepType,
}

impl fmt::Debug for AcpConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hash_type_str = if self.hash_type == ScriptHashType::Type {
            "type"
        } else {
            "data"
        };
        let dep_type_str = if self.dep_type == DepType::DepGroup {
            "dep_group"
        } else {
            "code"
        };
        f.debug_struct("AcpConfig")
            .field("code_hash", &self.code_hash)
            .field("hash_type", &hash_type_str)
            .field("tx_hash", &self.tx_hash)
            .field("index", &self.index)
            .field("dep_type", &dep_type_str)
            .finish()
    }
}

impl fmt::Debug for ReprAcpConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hash_type_str = if self.hash_type == json_types::ScriptHashType::Type {
            "type"
        } else {
            "data"
        };
        let dep_type_str = if self.dep_type == json_types::DepType::DepGroup {
            "dep_group"
        } else {
            "code"
        };
        f.debug_struct("ReprAcpConfig")
            .field("code_hash", &self.code_hash)
            .field("hash_type", &hash_type_str)
            .field("tx_hash", &self.tx_hash)
            .field("index", &self.index)
            .field("dep_type", &dep_type_str)
            .finish()
    }
}

impl From<AcpConfig> for ReprAcpConfig {
    fn from(cfg: AcpConfig) -> ReprAcpConfig {
        ReprAcpConfig {
            code_hash: cfg.code_hash.unpack(),
            hash_type: cfg.hash_type.into(),
            tx_hash: cfg.tx_hash.unpack(),
            index: cfg.index,
            dep_type: cfg.dep_type.into(),
        }
    }
}
impl From<ReprAcpConfig> for AcpConfig {
    fn from(cfg: ReprAcpConfig) -> AcpConfig {
        AcpConfig {
            code_hash: cfg.code_hash.pack(),
            hash_type: cfg.hash_type.into(),
            tx_hash: cfg.tx_hash.pack(),
            index: cfg.index,
            dep_type: cfg.dep_type.into(),
        }
    }
}

impl AcpConfig {
    pub fn new(
        code_hash: Byte32,
        hash_type: ScriptHashType,
        tx_hash: Byte32,
        index: u32,
        dep_type: DepType,
    ) -> AcpConfig {
        AcpConfig {
            code_hash,
            hash_type,
            tx_hash,
            index,
            dep_type,
        }
    }
    pub fn from_network(network: NetworkType, acp_config: Option<&AcpConfig>) -> Option<AcpConfig> {
        match network {
            NetworkType::Mainnet => Some(AcpConfig::mainnet()),
            NetworkType::Testnet => Some(AcpConfig::testnet()),
            NetworkType::Dev => acp_config.cloned(),
        }
    }
    pub fn mainnet() -> AcpConfig {
        Self::lina()
    }
    pub fn testnet() -> AcpConfig {
        Self::aggron()
    }
    pub fn lina() -> AcpConfig {
        AcpConfig::new(
            LINA_ACP_CODE_HASH.pack(),
            LINA_ACP_HASH_TYPE,
            LINA_ACP_TX_HASH.pack(),
            LINA_ACP_INDEX,
            LINA_ACP_DEP_TYPE,
        )
    }
    pub fn aggron() -> AcpConfig {
        AcpConfig::new(
            AGGRON_ACP_CODE_HASH.pack(),
            AGGRON_ACP_HASH_TYPE,
            AGGRON_ACP_TX_HASH.pack(),
            AGGRON_ACP_INDEX,
            AGGRON_ACP_DEP_TYPE,
        )
    }

    pub fn code_hash(&self) -> &Byte32 {
        &self.code_hash
    }
    pub fn hash_type(&self) -> ScriptHashType {
        self.hash_type
    }
    pub fn script_match(&self, code_hash: &Byte32, hash_type: ScriptHashType) -> bool {
        &self.code_hash == code_hash && self.hash_type == hash_type
    }
    pub fn tx_hash(&self) -> &Byte32 {
        &self.tx_hash
    }
    pub fn index(&self) -> u32 {
        self.index
    }
    pub fn dep_type(&self) -> DepType {
        self.dep_type
    }
    pub fn cell_dep(&self) -> CellDep {
        let out_point = OutPoint::new_builder()
            .tx_hash(self.tx_hash.clone())
            .index(self.index.pack())
            .build();
        CellDep::new_builder()
            .out_point(out_point)
            .dep_type(self.dep_type.into())
            .build()
    }
}

pub struct AddressPayloadWithAcpConfig<'a> {
    pub payload: &'a AddressPayload,
    pub acp_config: Option<&'a AcpConfig>,
}

impl<'a> AddressPayloadWithAcpConfig<'a> {
    pub fn new(
        payload: &'a AddressPayload,
        acp_config: Option<&'a AcpConfig>,
    ) -> AddressPayloadWithAcpConfig<'a> {
        AddressPayloadWithAcpConfig {
            payload,
            acp_config,
        }
    }
}

pub struct ScriptWithAcpConfig<'a> {
    pub lock: &'a Script,
    /// When acp_config is None and got an invalid acp Script, convert to AddressPayload::Full
    pub acp_config: Option<&'a AcpConfig>,
}

impl<'a> ScriptWithAcpConfig<'a> {
    pub fn new(lock: &'a Script, acp_config: Option<&'a AcpConfig>) -> ScriptWithAcpConfig<'a> {
        ScriptWithAcpConfig { lock, acp_config }
    }
}

impl fmt::Debug for AddressPayload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AddressPayload::Short { index, hash } => f
                .debug_struct("AddressPayload")
                .field("category", &"short")
                .field("index", index)
                .field("hash", hash)
                .finish(),
            AddressPayload::Full {
                hash_type,
                code_hash,
                args,
            } => {
                let hash_type_str = if *hash_type == ScriptHashType::Type {
                    "type"
                } else {
                    "data"
                };
                f.debug_struct("AddressPayload")
                    .field("category", &"full")
                    .field("hash_type", &hash_type_str)
                    .field("code_hash", code_hash)
                    .field("args", args)
                    .finish()
            }
        }
    }
}

impl<'a> TryFrom<AddressPayloadWithAcpConfig<'a>> for Script {
    type Error = String;
    fn try_from(payload_with_cfg: AddressPayloadWithAcpConfig) -> Result<Script, String> {
        let AddressPayloadWithAcpConfig {
            payload,
            acp_config,
        } = payload_with_cfg;
        if let AddressPayload::Short { index, .. } = payload {
            if *index == CodeHashIndex::Acp && acp_config.is_none() {
                return Err(
                    "Anyone can pay config is required when convert from anyone can pay address to script"
                        .to_string(),
                );
            }
        }
        let hash_type = acp_config
            .as_ref()
            .map(|cfg| cfg.hash_type)
            .unwrap_or_default();
        let code_hash = acp_config
            .as_ref()
            .map(|cfg| cfg.code_hash.clone())
            .unwrap_or_default();
        Ok(Script::new_builder()
            .hash_type(payload.hash_type(hash_type).into())
            .code_hash(payload.code_hash(&code_hash))
            .args(payload.args().pack())
            .build())
    }
}

impl<'a> TryFrom<ScriptWithAcpConfig<'a>> for AddressPayload {
    type Error = String;
    fn try_from(lock_with_cfg: ScriptWithAcpConfig) -> Result<AddressPayload, String> {
        let ScriptWithAcpConfig { lock, acp_config } = lock_with_cfg;
        let hash_type: ScriptHashType = lock.hash_type().try_into().expect("Invalid hash_type");
        let code_hash = lock.code_hash();
        let code_hash_h256: H256 = code_hash.unpack();
        let args = lock.args().raw_data();
        let is_acp = (hash_type == LINA_ACP_HASH_TYPE && code_hash_h256 == LINA_ACP_CODE_HASH)
            || (hash_type == AGGRON_ACP_HASH_TYPE && code_hash_h256 == AGGRON_ACP_CODE_HASH)
            || acp_config
                .as_ref()
                .map(|cfg| cfg.script_match(&code_hash, hash_type))
                .unwrap_or(false);
        if is_acp && (args.len() < 20 || args.len() > 22) {
            return Err(format!(
                "Invalid anyone can pay lock args length: {}, expected: 20 <= length <= 22 ",
                args.len()
            ));
        }
        if args.len() == 20 {
            let hash = H160::from_slice(args.as_ref()).unwrap();
            if hash_type == ScriptHashType::Type && code_hash_h256 == SIGHASH_TYPE_HASH {
                Ok(AddressPayload::new_short_sighash(hash))
            } else if hash_type == ScriptHashType::Type && code_hash_h256 == MULTISIG_TYPE_HASH {
                Ok(AddressPayload::new_short_multisig(hash))
            } else if is_acp {
                Ok(AddressPayload::new_short_acp(hash))
            } else {
                Ok(AddressPayload::new_full(hash_type, code_hash, args))
            }
        } else {
            Ok(AddressPayload::new_full(hash_type, code_hash, args))
        }
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct Address {
    network: NetworkType,
    payload: AddressPayload,
    is_new: bool,
}

impl Address {
    pub fn new(network: NetworkType, payload: AddressPayload, is_new: bool) -> Address {
        Address {
            network,
            payload,
            is_new,
        }
    }
    /// The network type of current address
    pub fn network(&self) -> NetworkType {
        self.network
    }
    pub fn into_payload(self) -> AddressPayload {
        self.payload
    }
    /// The address payload
    pub fn payload(&self) -> &AddressPayload {
        &self.payload
    }
    /// If true the address is ckb2021 format, short address always use old format, see RFC21 for more details.
    pub fn is_new(&self) -> bool {
        self.is_new
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            self.payload.display_with_network(self.network, self.is_new)
        )
    }
}

impl FromStr for Address {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (hrp, data, variant) = bech32::decode(input).map_err(|err| err.to_string())?;
        let network =
            NetworkType::from_prefix(&hrp).ok_or_else(|| format!("Invalid hrp: {}", hrp))?;
        let data = convert_bits(&data, 5, 8, false).unwrap();
        let ty = AddressType::from_u8(data[0])?;
        match ty {
            // payload = 0x01 | code_hash_index | args
            AddressType::Short => {
                if variant != Variant::Bech32 {
                    return Err("short address must use bech32 encoding".to_string());
                }
                if data.len() != 22 {
                    return Err(format!("Invalid input data length {}", data.len()));
                }
                let index = CodeHashIndex::from_u8(data[1])?;
                let hash = H160::from_slice(&data[2..22]).unwrap();
                let payload = AddressPayload::Short { index, hash };
                Ok(Address {
                    network,
                    payload,
                    is_new: false,
                })
            }
            // payload = 0x02/0x04 | code_hash | args
            AddressType::FullData | AddressType::FullType => {
                if variant != Variant::Bech32 {
                    return Err(
                        "non-ckb2021 format full address must use bech32 encoding".to_string()
                    );
                }
                if data.len() < 33 {
                    return Err(format!("Insufficient data length: {}", data.len()));
                }
                let hash_type = if ty == AddressType::FullData {
                    ScriptHashType::Data
                } else {
                    ScriptHashType::Type
                };
                let code_hash = Byte32::from_slice(&data[1..33]).unwrap();
                let args = Bytes::from(data[33..].to_vec());
                let payload = AddressPayload::Full {
                    hash_type,
                    code_hash,
                    args,
                };
                Ok(Address {
                    network,
                    payload,
                    is_new: false,
                })
            }
            // payload = 0x00 | code_hash | hash_type | args
            AddressType::Full => {
                if variant != Variant::Bech32m {
                    return Err("ckb2021 format full address must use bech32m encoding".to_string());
                }
                if data.len() < 34 {
                    return Err(format!("Insufficient data length: {}", data.len()));
                }
                let code_hash = Byte32::from_slice(&data[1..33]).unwrap();
                let hash_type =
                    ScriptHashType::try_from(data[33]).map_err(|err| err.to_string())?;
                let args = Bytes::from(data[34..].to_vec());
                let payload = AddressPayload::Full {
                    hash_type,
                    code_hash,
                    args,
                };
                Ok(Address {
                    network,
                    payload,
                    is_new: true,
                })
            }
        }
    }
}

mod old_addr {
    use super::{
        bech32, blake2b_256, convert_bits, Deserialize, NetworkType, Script, ScriptHashType,
        Serialize, ToBase32, H160, H256,
    };
    use ckb_crypto::secp::Pubkey;
    use ckb_types::prelude::*;

    // \x01 is the P2PH version
    const P2PH_MARK: &[u8] = b"\x01P2PH";

    #[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
    pub enum AddressFormat {
        // SECP256K1 algorithm	PK
        #[allow(dead_code)]
        Sp2k,
        // SECP256R1 algorithm	PK
        #[allow(dead_code)]
        Sp2r,
        // SECP256K1 + blake160	blake160(pk)
        P2ph,
        // Alias of SP2K	PK
        #[allow(dead_code)]
        P2pk,
    }

    impl Default for AddressFormat {
        fn default() -> AddressFormat {
            AddressFormat::P2ph
        }
    }

    impl AddressFormat {
        pub fn from_bytes(format: &[u8]) -> Result<AddressFormat, String> {
            match format {
                P2PH_MARK => Ok(AddressFormat::P2ph),
                _ => Err(format!("Unsupported address format data: {:?}", format)),
            }
        }

        pub fn to_bytes(self) -> Result<Vec<u8>, String> {
            match self {
                AddressFormat::P2ph => Ok(P2PH_MARK.to_vec()),
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
            let format = AddressFormat::P2ph;
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
            if format != AddressFormat::P2ph {
                return Err("Only support P2PH for now".to_owned());
            }
            // Serialize pubkey as compressed format
            let hash = H160::from_slice(&blake2b_256(pubkey.serialize())[0..20])
                .expect("Generate hash(H160) from pubkey failed");
            Ok(Address { format, hash })
        }

        pub fn from_lock_arg(bytes: &[u8]) -> Result<Address, String> {
            let format = AddressFormat::P2ph;
            let hash = H160::from_slice(bytes).map_err(|err| err.to_string())?;
            Ok(Address { format, hash })
        }

        pub fn from_input(network: NetworkType, input: &str) -> Result<Address, String> {
            let (hrp, data, _variant) = bech32::decode(input).map_err(|err| err.to_string())?;
            if NetworkType::from_prefix(&hrp)
                .filter(|input_network| input_network == &network)
                .is_none()
            {
                return Err(format!("Invalid hrp({}) for {}", hrp, network));
            }
            let data = convert_bits(&data, 5, 8, false).unwrap();
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
            bech32::encode(hrp, data.to_base32(), bech32::Variant::Bech32)
                .unwrap_or_else(|_| panic!("Encode address failed: hash={:?}", self.hash))
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

#[cfg(test)]
mod test {
    use super::*;
    use ckb_types::{h160, h256};

    #[test]
    fn test_short_address() {
        let payload =
            AddressPayload::new_short_sighash(h160!("0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64"));
        let address = Address::new(NetworkType::Mainnet, payload, false);
        assert_eq!(
            address.to_string(),
            "ckb1qyqt8xaupvm8837nv3gtc9x0ekkj64vud3jqfwyw5v"
        );
        assert_eq!(
            address,
            Address::from_str("ckb1qyqt8xaupvm8837nv3gtc9x0ekkj64vud3jqfwyw5v").unwrap()
        );

        let payload =
            AddressPayload::new_short_multisig(h160!("0x4fb2be2e5d0c1a3b8694f832350a33c1685d477a"));
        let address = Address::new(NetworkType::Mainnet, payload, false);
        assert_eq!(
            address.to_string(),
            "ckb1qyq5lv479ewscx3ms620sv34pgeuz6zagaaqklhtgg"
        );
        assert_eq!(
            address,
            Address::from_str("ckb1qyq5lv479ewscx3ms620sv34pgeuz6zagaaqklhtgg").unwrap()
        );

        let payload =
            AddressPayload::new_short_acp(h160!("0x4fb2be2e5d0c1a3b8694f832350a33c1685d477a"));
        let address = Address::new(NetworkType::Mainnet, payload, false);
        assert_eq!(
            address.to_string(),
            "ckb1qypylv479ewscx3ms620sv34pgeuz6zagaaqvrugu7"
        );
    }

    #[test]
    fn test_old_full_address() {
        let hash_type = ScriptHashType::Type;
        let code_hash = Byte32::from_slice(
            h256!("0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8").as_bytes(),
        )
        .unwrap();
        let args = Bytes::from(h160!("0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64").as_bytes());
        let payload = AddressPayload::new_full(hash_type, code_hash, args);
        let address = Address::new(NetworkType::Mainnet, payload, false);
        assert_eq!(address.to_string(), "ckb1qjda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xw3vumhs9nvu786dj9p0q5elx66t24n3kxgj53qks");
        assert_eq!(address, Address::from_str("ckb1qjda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xw3vumhs9nvu786dj9p0q5elx66t24n3kxgj53qks").unwrap());
    }

    #[test]
    fn test_new_full_address() {
        let code_hash = Byte32::from_slice(
            h256!("0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8").as_bytes(),
        )
        .unwrap();
        let args = Bytes::from(h160!("0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64").as_bytes());

        let payload =
            AddressPayload::new_full(ScriptHashType::Type, code_hash.clone(), args.clone());
        let address = Address::new(NetworkType::Mainnet, payload, true);
        assert_eq!(address.to_string(), "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqdnnw7qkdnnclfkg59uzn8umtfd2kwxceqxwquc4");
        assert_eq!(address, Address::from_str("ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqdnnw7qkdnnclfkg59uzn8umtfd2kwxceqxwquc4").unwrap());

        let payload =
            AddressPayload::new_full(ScriptHashType::Data, code_hash.clone(), args.clone());
        let address = Address::new(NetworkType::Mainnet, payload, true);
        assert_eq!(address.to_string(), "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq9nnw7qkdnnclfkg59uzn8umtfd2kwxceqvguktl");
        assert_eq!(address, Address::from_str("ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq9nnw7qkdnnclfkg59uzn8umtfd2kwxceqvguktl").unwrap());

        let payload = AddressPayload::new_full(ScriptHashType::Data1, code_hash, args);
        let address = Address::new(NetworkType::Mainnet, payload, true);
        assert_eq!(address.to_string(), "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq4nnw7qkdnnclfkg59uzn8umtfd2kwxceqcydzyt");
        assert_eq!(address, Address::from_str("ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq4nnw7qkdnnclfkg59uzn8umtfd2kwxceqcydzyt").unwrap());
    }
}
