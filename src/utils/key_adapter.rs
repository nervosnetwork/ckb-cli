use dyn_clone::DynClone;
use secp256k1::recovery::RecoverableSignature;

use std::collections::{HashMap, HashSet};

use ckb_types::{H160, H256};

use ckb_sdk::{
    wallet::{
        AbstractMasterPrivKey, AbstractPrivKey, ChildNumber, ExtendedPubKey,
        FullyBoxedAbstractPrivkey,
    },
    FullyAbstractSingleShotSigner, SignerFnTrait, SignerSingleShot,
};

/// This takes an existing key and forces its errors to be strings so different
/// types of keys can be the same same sort of trait object.
#[repr(transparent)]
pub struct KeyAdapter<Key: ?Sized>(pub Key);

impl<T: ?Sized + DynClone> DynClone for KeyAdapter<T> {
    unsafe fn clone_box(&self) -> *mut () {
        Box::into_raw(dyn_clone::clone_box(&self.0)) as *mut _
    }
}

impl<Key> AbstractMasterPrivKey for KeyAdapter<Key>
where
    Key: ?Sized + AbstractMasterPrivKey + 'static,
    Key::Err: ToString,
    <Key::Privkey as AbstractPrivKey>::Err: ToString,
{
    type Err = String;

    type Privkey = FullyBoxedAbstractPrivkey<'static>;

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
    Key: ?Sized + AbstractPrivKey,
    Key::Err: ToString,
    Key::SignerSingleShot: 'static,
    <Key::SignerSingleShot as SignerSingleShot>::Err: ToString,
{
    type Err = String;

    type SignerSingleShot = FullyAbstractSingleShotSigner<'static>;

    fn public_key(&self) -> Result<secp256k1::PublicKey, Self::Err> {
        self.0.public_key().map_err(|e| e.to_string())
    }

    fn sign(&self, message: &H256) -> Result<secp256k1::Signature, Self::Err> {
        self.0.sign(message).map_err(|e| e.to_string())
    }

    fn begin_sign_recoverable(&self) -> Self::SignerSingleShot {
        Box::new(KeyAdapter(self.0.begin_sign_recoverable()))
    }
}

impl<T> SignerFnTrait for KeyAdapter<T>
where
    T: ?Sized + SignerFnTrait,
    T::SingleShot: 'static,
{
    type SingleShot = FullyAbstractSingleShotSigner<'static>;

    fn new_signature_builder(
        &mut self,
        lock_args: &HashSet<H160>,
    ) -> Result<Option<Self::SingleShot>, String> {
        self.0.new_signature_builder(lock_args).map(|v| {
            v.map(|v| {
                let x: Self::SingleShot = Box::new(KeyAdapter(v));
                x
            })
        })
    }
}

impl<T> SignerSingleShot for KeyAdapter<T>
where
    T: ?Sized + SignerSingleShot,
    T::Err: ToString,
{
    type Err = String;

    fn append(&mut self, message_fragment: &[u8]) {
        self.0.append(message_fragment)
    }

    fn finalize(self: Box<Self>) -> Result<RecoverableSignature, Self::Err> {
        // cannot do something safe and easy like reallocating because might be DST
        let inner: Box<T> = unsafe { Box::from_raw(&mut (*Box::into_raw(self)).0 as *mut _) };
        inner.finalize().map_err(|e| e.to_string())
    }
}
