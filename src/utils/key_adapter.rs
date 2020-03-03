use secp256k1::recovery::RecoverableSignature;

use ckb_types::{H160, H256};

use ckb_sdk::wallet::{AbstractMasterPrivKey, AbstractPrivKey, ChildNumber, ExtendedPubKey};
use ckb_sdk::SignerSingleShot;

/// This takes an existing key and forces its errors to be strings so different
/// types of keys can be the same same sort of trait object.
pub struct KeyAdapter<Key>(pub Key);

pub type FullyBoxedAbstractPrivkey = Box<
    dyn AbstractPrivKey<SignerSingleShot = Box<dyn SignerSingleShot<Err = String>>, Err = String>,
>;

impl<Key> AbstractMasterPrivKey for KeyAdapter<Key>
where
    Key: AbstractMasterPrivKey,
    Key::Err: ToString,
    Key::Privkey: 'static,
    <Key::Privkey as AbstractPrivKey>::Err: ToString,
{
    type Err = String;

    type Privkey = FullyBoxedAbstractPrivkey;

    fn extended_pubkey(&self, path: &[ChildNumber]) -> Result<ExtendedPubKey, Self::Err> {
        self.0.extended_pubkey(path).map_err(|e| e.to_string())
    }

    fn derived_pubkey_hash(&self, path: &[ChildNumber]) -> Result<H160, Self::Err> {
        self.0.derived_pubkey_hash(path).map_err(|e| e.to_string())
    }

    fn extended_privkey(&self, path: &[ChildNumber]) -> Result<Self::Privkey, Self::Err> {
        let x: Key::Privkey = self.0.extended_privkey(path).map_err(|e| e.to_string())?;
        Ok(Box::new(KeyAdapter(x)))
    }
}

impl<Key> AbstractPrivKey for KeyAdapter<Key>
where
    Key: AbstractPrivKey,
    Key::Err: ToString,
{
    type Err = String;

    type SignerSingleShot = Box<dyn SignerSingleShot<Err = String>>;

    fn public_key(&self) -> Result<secp256k1::PublicKey, Self::Err> {
        self.0.public_key().map_err(|e| e.to_string())
    }

    fn sign(&self, message: &H256) -> Result<secp256k1::Signature, Self::Err> {
        self.0.sign(message).map_err(|e| e.to_string())
    }

    fn begin_sign_recoverable(&self) -> SingerSingleShot {
        Box::new(KeyAdapter(self.0.begin_sign_recoverable()))
    }
}

impl<T> SignerSingleShot for KeyAdapter<T>
where
    Key: SignerSingleShot,
    Key::Err: ToString,
{
    type Err = String;
    fn append(&mut self, message_fragment: &[u8]) {
        self.0.append(message_fragment)
    }
    fn finalize(self) -> Result<RecoverableSignature, Self::Err> {
        Box::new(self.0).finalize().map_err(|e| e.to_string())
    }
}
