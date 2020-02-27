use secp256k1::recovery::RecoverableSignature;

use ckb_types::{H160, H256};

use ckb_sdk::wallet::{AbstractMasterPrivKey, AbstractPrivKey, ChildNumber, ExtendedPubKey};

/// This takes an existing key and forces its errors to be strings so different
/// types of keys can be the same same sort of trait object.
pub struct KeyAdapter<Key>(pub Key);

impl<Key> AbstractMasterPrivKey for KeyAdapter<Key>
where
    Key: AbstractMasterPrivKey,
    Key::Err: ToString,
    Key::Privkey: 'static,
    <Key::Privkey as AbstractPrivKey>::Err: ToString,
{
    type Err = String;

    type Privkey = Box<dyn AbstractPrivKey<Err = String>>;

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

    fn public_key(&self) -> Result<secp256k1::PublicKey, Self::Err> {
        self.0.public_key().map_err(|e| e.to_string())
    }

    fn sign(&self, message: &H256) -> Result<secp256k1::Signature, Self::Err> {
        self.0.sign(message).map_err(|e| e.to_string())
    }

    fn sign_recoverable(&self, message: &H256) -> Result<RecoverableSignature, Self::Err> {
        self.0.sign_recoverable(message).map_err(|e| e.to_string())
    }
}
