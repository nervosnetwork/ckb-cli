use std::fmt::Debug;

use std::path::PathBuf;

use crate::wallet::bip32::{ChildNumber, ExtendedPubKey};

use ckb_hash::blake2b_256;
use ckb_types::{H160, H256};

use secp256k1::recovery::RecoverableSignature;

use super::ScryptType;

pub trait AbstractKeyStore: Sized {
    const SOURCE_NAME: &'static str;

    /// Error type for key store operations.
    type Err;

    // /// Identifier for the individual accounts, i.e. those which per idiomatic
    // /// use of UTXO are not reused between transactions for sake of the actors'
    // /// privacy.
    // ///
    // /// This must always contain at least the a `H160` hash as mandated by the
    // /// blockchain. It may also contain more information to different between
    // /// underlying keystores, e.g. files vs hardware wallets.
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

    fn hash160<P>(&self, path: &P) -> Result<H160, Self::Err>
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
}

pub fn hash_publick_key(public_key: &secp256k1::PublicKey) -> H160 {
    H160::from_slice(&blake2b_256(&public_key.serialize()[..])[0..20])
        .expect("Generate hash(H160) from pubkey failed")
}
