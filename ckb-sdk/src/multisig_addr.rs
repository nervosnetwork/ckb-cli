use crate::basic::AddressType;
use crate::NetworkType;
use bech32::{convert_bits, Bech32, ToBase32};
use ckb_hash::blake2b_256;
use ckb_types::{H160, H256};
use serde_derive::{Deserialize, Serialize};
use std::str::FromStr;

// NOTE: The present implementation only provide 1of1 multisig address
// in full payload format, with ty == FullPayloadWithTypeHash.

const ADDRESS_TYPE: AddressType = AddressType::FullPayloadWithTypeHash;

#[derive(Hash, Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct MultisigAddress {
    code_hash: H256,
    hash: H160,
    since: u64,
}

impl MultisigAddress {
    pub fn new(code_hash: H256, pubkey_hash: H160, since: u64) -> Result<Self, String> {
        let mut multi_script = vec![1u8, 1, 1, 1]; // [S, R, M, N]
        multi_script.extend_from_slice(pubkey_hash.0.as_ref());
        let hash =
            H160::from_slice(&blake2b_256(multi_script)[..20]).map_err(|err| err.to_string())?;

        Ok(Self {
            code_hash,
            hash,
            since,
        })
    }

    pub fn from_input(input: &str) -> Result<(NetworkType, Self), String> {
        let value = Bech32::from_str(input).map_err(|err| err.to_string())?;
        let network_type = NetworkType::from_prefix(value.hrp())
            .ok_or_else(|| format!("Invalid hrp: {}", value.hrp()))?;
        let data = convert_bits(value.data(), 5, 8, false).unwrap();
        if data.len() != 61 {
            return Err(format!(
                "Invalid input data length, expected: {}, actual: {}",
                61,
                data.len()
            ));
        }
        if data[0] != ADDRESS_TYPE as u8 {
            return Err(format!(
                "Invalid address type, expected: {}, actual: {}",
                ADDRESS_TYPE as u8, data[0]
            ));
        }

        let code_hash = H256::from_slice(&data[1..33]).map_err(|err| err.to_string())?;
        let hash = H160::from_slice(&data[33..53]).map_err(|err| err.to_string())?;
        let since = {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&data[53..61]);
            u64::from_le_bytes(bytes)
        };
        Ok((
            network_type,
            Self {
                code_hash,
                hash,
                since,
            },
        ))
    }

    pub fn display(&self, network_type: NetworkType) -> String {
        let hrp = network_type.to_prefix();
        let mut data = [0u8; 61];

        data[0] = ADDRESS_TYPE as u8;
        data[1..33].copy_from_slice(self.code_hash.0.as_ref());
        data[33..53].copy_from_slice(self.hash.0.as_ref());
        data[53..61].copy_from_slice(self.since.to_le_bytes().as_ref());

        let value = Bech32::new(hrp.to_string(), data.to_vec().to_base32())
            .unwrap_or_else(|_| panic!("Encode MultisigAddress failed: {:?}", self,));
        format!("{}", value)
    }
}
