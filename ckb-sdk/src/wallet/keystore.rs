//! Web3 Secret Storage
//! https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition

use aes_ctr::stream_cipher::generic_array::GenericArray;
use aes_ctr::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use aes_ctr::Aes128Ctr;
use faster_hex::hex_string;
use rand::Rng;

const SCRYPT_DK_STD_LOG_N: u8 = 18;
const SCRYPT_DK_STD_P: u32 = 1;
const SCRYPT_DK_LIGHT_LOG_N: u8 = 12;
const SCRYPT_DK_LIGHT_P: u32 = 6;
const SCRYPT_DK_R: u32 = 8;
const SCRYPT_DK_LEN: u32 = 32;

const DEFAULT_KDF_TYPE: &str = "scrypt";
const SUPPORT_CIPHER_TYPE: &str = "aes-128-ctr";
// const SUPPORT_PBKDF2_PRF: &str = "hmac-sha256";

// Example:
// ========
// {
//     "version": 3,
//     "id": "5f20d562-5ab8-4c15-8df6-4ba8fbddacba",
//     "crypto": {
//         "mac": "75ec9139e21805983da2ca8f2523aec5bd78cf5983b93f1306b913e80fabdb7d",
//         "kdfparams": {
//             "salt": "d27657804be7ef5b9c4d0ac513aa210eeb1ec64ad8f23d639aa579aebfc76832",
//             "r": 8,
//             "p": 1,
//             "n": 262144,
//             "dklen": 32
//         },
//         "kdf": "scrypt",
//         "cipherparams": {
//             "iv": "25e68fc8d166ee203c645868d5e0f94a"
//         },
//         "ciphertext": "383cca818805e1134e93d200db94b9babc798e6537373604543ae870c1d221e2",
//         "cipher": "aes-128-ctr"
//     }
// }
#[derive(Debug, Clone)]
pub struct ScryptParams {
    salt: [u8; 32],
    log_n: u8,
    p: u32,
    r: u32,
    dklen: u32,
}

impl Default for ScryptParams {
    fn default() -> ScryptParams {
        ScryptParams::new_standard()
    }
}

impl ScryptParams {
    pub fn new(salt: [u8; 32], log_n: u8, p: u32, r: u32, dklen: u32) -> ScryptParams {
        ScryptParams {
            salt,
            log_n,
            p,
            r,
            dklen,
        }
    }

    pub fn new_standard_with_salt(salt: [u8; 32]) -> ScryptParams {
        ScryptParams {
            salt,
            log_n: SCRYPT_DK_STD_LOG_N,
            p: SCRYPT_DK_STD_P,
            r: SCRYPT_DK_R,
            dklen: SCRYPT_DK_LEN,
        }
    }

    pub fn new_standard() -> ScryptParams {
        let mut rng = rand::thread_rng();
        let salt: [u8; 32] = rng.gen();
        ScryptParams {
            salt,
            log_n: SCRYPT_DK_STD_LOG_N,
            p: SCRYPT_DK_STD_P,
            r: SCRYPT_DK_R,
            dklen: SCRYPT_DK_LEN,
        }
    }

    pub fn new_light_with_salt(salt: [u8; 32]) -> ScryptParams {
        ScryptParams {
            salt,
            log_n: SCRYPT_DK_LIGHT_LOG_N,
            p: SCRYPT_DK_LIGHT_P,
            r: SCRYPT_DK_R,
            dklen: SCRYPT_DK_LEN,
        }
    }

    pub fn new_light() -> ScryptParams {
        let mut rng = rand::thread_rng();
        let salt: [u8; 32] = rng.gen();
        ScryptParams {
            salt,
            log_n: SCRYPT_DK_LIGHT_LOG_N,
            p: SCRYPT_DK_LIGHT_P,
            r: SCRYPT_DK_R,
            dklen: SCRYPT_DK_LEN,
        }
    }

    fn kdf_key(&self, password: &[u8]) -> [u8; 32] {
        let mut output = [0u8; 32];
        let params = scrypt::ScryptParams::new(self.log_n, self.r, self.p)
            .expect("Other scrypt arguments not supported");
        scrypt::scrypt(password, &self.salt, &params, &mut output)
            .expect("Output buffer length cannot invalid");
        output
    }

    pub fn to_json(&self) -> serde_json::Value {
        let salt_hex = hex_string(&self.salt).unwrap();
        serde_json::json!({
            "salt": salt_hex,
            "n": 1usize << self.log_n,
            "p": self.p,
            "r": self.r,
            "dklen": self.dklen,
        })
    }
}

// Example:
// ========
// {
//     "crypto" : {
//         "cipher" : "aes-128-ctr",
//         "cipherparams" : {
//             "iv" : "6087dab2f9fdbbfaddc31a909735c1e6"
//         },
//         "ciphertext" : "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
//         "kdf" : "pbkdf2",
//         "kdfparams" : {
//             "c" : 262144,
//             "dklen" : 32,
//             "prf" : "hmac-sha256",
//             "salt" : "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
//         },
//         "mac" : "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
//     },
//     "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
//     "version" : 3
// }
//
// TODO: supported pbkdf2
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Pbkdf2Params {
    prf: &'static str,
    salt: [u8; 32],
    c: usize,
    dklen: u32,
}

#[allow(dead_code)]
impl Pbkdf2Params {
    fn kdf_key(&self, _password: &[u8]) -> [u8; 32] {
        unimplemented!()
    }

    pub fn to_json(&self) -> serde_json::Value {
        let salt_hex = hex_string(&self.salt).unwrap();
        serde_json::json!({
            "prf": self.prf,
            "salt": salt_hex,
            "c": self.c,
            "dklen": self.dklen,
        })
    }
}

#[derive(Debug, Clone)]
pub enum KdfParams {
    Scrypt(ScryptParams),
    #[allow(dead_code)]
    Pbkdf2(Pbkdf2Params),
}

impl Default for KdfParams {
    fn default() -> KdfParams {
        KdfParams::Scrypt(ScryptParams::default())
    }
}

impl KdfParams {
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            KdfParams::Scrypt(params) => params.to_json(),
            KdfParams::Pbkdf2(params) => params.to_json(),
        }
    }

    fn kdf_key(&self, password: &[u8]) -> Result<[u8; 32], String> {
        match self {
            KdfParams::Scrypt(params) => Ok(params.kdf_key(password)),
            KdfParams::Pbkdf2(_) => Err("not support pbkdf2 yet".to_owned()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CipherParams {
    iv: [u8; 16],
}

impl CipherParams {
    pub fn new(iv: [u8; 16]) -> CipherParams {
        CipherParams { iv }
    }

    pub fn to_json(&self) -> serde_json::Value {
        let iv_hex = hex_string(&self.iv).unwrap();
        serde_json::json!({ "iv": iv_hex })
    }
}

impl Default for CipherParams {
    fn default() -> CipherParams {
        let mut rng = rand::thread_rng();
        let iv: [u8; 16] = rng.gen();
        CipherParams { iv }
    }
}

fn calculate_mac(ciphertext: &[u8], kdf_key: &[u8; 32]) -> [u8; 32] {
    let ciphertext_len = ciphertext.len();
    let mut mac_bytes = vec![0u8; 16 + ciphertext_len];
    mac_bytes[..16].copy_from_slice(&kdf_key[16..]);
    mac_bytes[16..16 + ciphertext_len].copy_from_slice(ciphertext);
    tiny_keccak::keccak256(&mac_bytes)
}

#[derive(Debug, Clone)]
pub struct Crypto {
    cipher: &'static str,
    ciphertext: Vec<u8>,
    cipherparams: CipherParams,
    kdf: &'static str,
    kdfparams: KdfParams,
    mac: [u8; 32],
}

impl Crypto {
    pub fn encrypt_key(
        key: &[u8],
        password: &[u8],
        kdfparams: KdfParams,
        cipherparams: CipherParams,
    ) -> Result<Crypto, String> {
        let kdf_key = kdfparams.kdf_key(password)?;
        let aes_key = GenericArray::from_slice(&kdf_key[..16]);
        let aes_iv = GenericArray::from_slice(&cipherparams.iv);
        let mut cipher = Aes128Ctr::new(aes_key, aes_iv);
        let mut ciphertext = key.to_vec();
        cipher.apply_keystream(&mut ciphertext);
        let mac = calculate_mac(&ciphertext, &kdf_key);
        Ok(Crypto {
            cipher: SUPPORT_CIPHER_TYPE,
            cipherparams,
            ciphertext,
            kdf: DEFAULT_KDF_TYPE,
            kdfparams,
            mac,
        })
    }

    /// Scrypt Standard
    pub fn encrypt_key_standard(key: &[u8], password: &[u8]) -> Crypto {
        let kdfparams = KdfParams::Scrypt(ScryptParams::new_standard());
        let cipherparams = CipherParams::default();
        Self::encrypt_key(key, password, kdfparams, cipherparams)
            .expect("encrypt key standard failed")
    }

    /// Scrypt light
    pub fn encrypt_key_light(key: &[u8], password: &[u8]) -> Crypto {
        let kdfparams = KdfParams::Scrypt(ScryptParams::new_light());
        let cipherparams = CipherParams::default();
        Self::encrypt_key(key, password, kdfparams, cipherparams).expect("encrypt key light failed")
    }

    pub fn decrypt(&self, password: &[u8]) -> Result<Vec<u8>, String> {
        let kdf_key = self.kdfparams.kdf_key(password)?;
        let aes_key = GenericArray::from_slice(&kdf_key[..16]);
        let aes_iv = GenericArray::from_slice(&self.cipherparams.iv);
        let mut cipher = Aes128Ctr::new(aes_key, aes_iv);
        let mut plaintext = self.ciphertext.clone();
        cipher.apply_keystream(&mut plaintext);
        Ok(plaintext)
    }

    pub fn check_password(&self, password: &[u8]) -> Result<bool, String> {
        let kdf_key = self.kdfparams.kdf_key(password)?;
        let mac = calculate_mac(&self.ciphertext, &kdf_key);
        Ok(mac == self.mac)
    }

    pub fn to_json(&self) -> serde_json::Value {
        let mac_hex = hex_string(&self.mac).unwrap();
        let ciphertext_hex = hex_string(&self.ciphertext).unwrap();
        serde_json::json!({
            "cipher": self.cipher,
            "ciphertext": ciphertext_hex,
            "cipherparams": self.cipherparams.to_json(),
            "kdf": self.kdf,
            "kdfparams": self.kdfparams.to_json(),
            "mac": mac_hex,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use faster_hex::hex_decode;

    struct TestData {
        json_data: serde_json::Value,
        password: Vec<u8>,
        secret_key: [u8; 32],
        crypto: Crypto,
    }

    fn test_data() -> TestData {
        // Light scrypt
        let json_data = serde_json::json!({
            "cipher": "aes-128-ctr",
            "ciphertext": "253397209cae86474e368720f9baa30f448767047d2cc5a7672ef121861974ed",
            "cipherparams": {
                "iv": "8bd8523e0048db3a4ae2534aec6d303a"
            },
            "kdf": "scrypt",
            "kdfparams": {
                "dklen": 32,
                "n": 4096,
                "p": 6,
                "r": 8,
                "salt": "be3d86c99f4895f99d1a0048afb61a34153fa83d5edd033fc914de2c502f57e7"
            },
            "mac": "4453cf5d4f6ec43d0664c3895c4ab9b1c9bcd2d02c7abb190c84375a42739099"
        });
        let password = b"123";

        let secret_hex = "8c8a06804785c73adf91b53a1174f6ee7280101bd30d0f3260cfb4449ed1e2ca";
        let salt_hex = "be3d86c99f4895f99d1a0048afb61a34153fa83d5edd033fc914de2c502f57e7";
        let iv_hex = "8bd8523e0048db3a4ae2534aec6d303a";
        let mut secret_key = [0u8; 32];
        hex_decode(secret_hex.as_bytes(), &mut secret_key).unwrap();
        let mut iv = [0u8; 16];
        hex_decode(iv_hex.as_bytes(), &mut iv).unwrap();
        let mut salt = [0u8; 32];
        hex_decode(salt_hex.as_bytes(), &mut salt).unwrap();

        let kdfparams = KdfParams::Scrypt(ScryptParams::new_light_with_salt(salt));
        let cipherparams = CipherParams { iv };
        let crypto = Crypto::encrypt_key(&secret_key, password, kdfparams, cipherparams).unwrap();

        TestData {
            json_data,
            password: password.to_vec(),
            secret_key,
            crypto,
        }
    }

    #[test]
    fn test_encrypt() {
        let data = test_data();
        println!(
            "output: {}",
            serde_json::to_string_pretty(&data.crypto.to_json()).unwrap()
        );
        assert_eq!(data.crypto.to_json(), data.json_data);
    }

    #[test]
    fn test_decrypt() {
        let data = test_data();
        assert_eq!(
            data.crypto.decrypt(&data.password).unwrap(),
            data.secret_key
        );
    }

    #[test]
    fn check_password() {
        let data = test_data();
        assert_eq!(data.crypto.check_password(&data.password).unwrap(), true);
        assert_eq!(data.crypto.check_password(b"xyz.1234").unwrap(), false);
    }
}
