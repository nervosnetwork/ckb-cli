use std::fmt::Debug;

use failure::Fail;
use secp256k1::recovery::RecoverableSignature;
use std::path::PathBuf;
use std::str::FromStr;

use crate::wallet::bip32::DerivationPath;
use crate::wallet::bip32::{ChildNumber, ExtendedPubKey};
use ckb_hash::blake2b_256;
use ckb_types::{H160, H256};

use super::ScryptType;

pub trait AbstractKeyStore: Sized {
    const SOURCE_NAME: &'static str;

    /// Error type for key store operations.
    type Err;

    /// Identifier for the individual accounts, i.e. those which per idiomatic
    /// use of UTXO are not reused between transactions for sake of the actors'
    /// privacy.
    ///
    /// This must always contain at least the a `H160` hash as mandated by the
    /// blockchain. It may also contain more information to different between
    /// underlying keystores, e.g. files vs hardware wallets.
    type AccountId;

    /// Capability for actions one can do with a private key, such as extend
    /// derived key pairs and sign messages.
    ///
    /// For a software key store, would probably be the actual private key, but
    /// for a hardware wallet would be merely the capability to communicate with
    /// that wallet.
    type AccountCap: AbstractMasterPrivKey;

    // Just box it because no `impl Trait` in traits for now
    fn list_accounts(&mut self) -> Result<Box<dyn Iterator<Item = Self::AccountId>>, Self::Err>;

    fn from_dir(dir: PathBuf, scrypt_type: ScryptType) -> Result<Self, Self::Err>;

    fn borrow_account<'a, 'b>(
        &'a mut self,
        account_id: &'b Self::AccountId,
    ) -> Result<&'a Self::AccountCap, Self::Err>;
}

pub trait AbstractMasterPrivKey: Sized {
    /// Error type for private key operations.
    type Err;

    fn extended_pubkey<P>(&self, path: &P) -> Result<ExtendedPubKey, Self::Err>
    where
        P: ?Sized + Debug + AsRef<[ChildNumber]>;

    fn derived_pubkey_hash<P>(&self, path: &P) -> Result<H160, Self::Err>
    where
        P: ?Sized + Debug + AsRef<[ChildNumber]>,
    {
        let extended_public_key = self.extended_pubkey(path)?;
        Ok(hash_publick_key(&extended_public_key.public_key))
    }

    fn sign<P>(&self, message: &H256, path: &P) -> Result<secp256k1::Signature, Self::Err>
    where
        P: ?Sized + Debug + AsRef<[ChildNumber]>;

    fn sign_recoverable<P>(
        &self,
        message: &H256,
        path: &P,
    ) -> Result<RecoverableSignature, Self::Err>
    where
        P: ?Sized + Debug + AsRef<[ChildNumber]>;

    fn derived_key_set<E>(
        &self,
        external_max_len: u32,
        change_last: &H160,
        change_max_len: u32,
    ) -> Result<DerivedKeySet, E>
    where
        E: From<Self::Err>,
        E: From<SearchDerivedAddrFailed>,
    {
        let mut external_key_set = Vec::new();
        for i in 0..external_max_len {
            let path_string = format!("m/44'/309'/0'/{}/{}", KeyChain::External as u8, i);
            let path = DerivationPath::from_str(path_string.as_str()).unwrap();
            let pubkey_hash = self.derived_pubkey_hash(&path)?;
            external_key_set.push((path, pubkey_hash.clone()));
        }

        let mut change_key_set = Vec::new();
        for i in 0..change_max_len {
            let path_string = format!("m/44'/309'/0'/{}/{}", KeyChain::Change as u8, i);
            let path = DerivationPath::from_str(path_string.as_str()).unwrap();
            let pubkey_hash = self.derived_pubkey_hash(&path)?;
            change_key_set.push((path, pubkey_hash.clone()));
            if change_last == &pubkey_hash {
                return Ok(DerivedKeySet {
                    external: external_key_set,
                    change: change_key_set,
                });
            }
        }
        Err(From::from(SearchDerivedAddrFailed))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum KeyChain {
    External = 0,
    Change = 1,
}

pub struct DerivedKeySet {
    pub external: Vec<(DerivationPath, H160)>,
    pub change: Vec<(DerivationPath, H160)>,
}

impl DerivedKeySet {
    pub fn get_path(&self, hash160: &H160) -> Option<(KeyChain, DerivationPath)> {
        for (path, pubkey_hash) in &self.external {
            if pubkey_hash == hash160 {
                return Some((KeyChain::External, path.clone()));
            }
        }
        for (path, pubkey_hash) in &self.change {
            if pubkey_hash == hash160 {
                return Some((KeyChain::Change, path.clone()));
            }
        }
        None
    }
}

#[derive(Debug, Fail, Eq, PartialEq)]
#[fail(display = "Search derived address failed")]
pub struct SearchDerivedAddrFailed;

pub fn hash_publick_key(public_key: &secp256k1::PublicKey) -> H160 {
    H160::from_slice(&blake2b_256(&public_key.serialize()[..])[0..20])
        .expect("Generate hash(H160) from pubkey failed")
}
