use secp256k1::recovery::RecoverableSignature;

use ckb_hash::{new_blake2b, Blake2b};
use ckb_types::H256;

pub trait SignerSingleShot {
    type Err;

    fn append(&mut self, message_fragment: &[u8]);
    fn finalize(self) -> Result<RecoverableSignature, Self::Err>;
}

// Helper write impl via closure
impl<T, Err> SignerSingleShot for T
where
    T: FnMut(&[u8]) + FnOnce() -> Result<RecoverableSignature, Err>,
{
    type Err = Err;

    fn append(&mut self, message_fragment: &[u8]) {
        self(message_fragment)
    }
    fn finalize(self) -> Result<RecoverableSignature, Err> {
        self()
    }
}

pub struct SignPrehashedHelper<T, Err>
where
    T: FnOnce(H256) -> Result<RecoverableSignature, Err>,
{
    pub hasher: Blake2b,
    pub signer: T,
}

impl<T, Err> SignPrehashedHelper<T, Err>
where
    T: FnOnce(H256) -> Result<RecoverableSignature, Err>,
{
    pub fn new(signer: T) -> Self {
        Self {
            hasher: new_blake2b(),
            signer,
        }
    }
}

impl<T, Err> SignerSingleShot for SignPrehashedHelper<T, Err>
where
    T: FnOnce(H256) -> Result<RecoverableSignature, Err>,
{
    type Err = Err;

    fn append(&mut self, message_fragment: &[u8]) {
        self.hasher.update(message_fragment)
    }
    fn finalize(self) -> Result<RecoverableSignature, Err> {
        let mut message_hash = [0u8; 32];
        let Self { hasher, signer } = self;
        hasher.finalize(&mut message_hash);
        signer(H256::from(message_hash))
    }
}

pub struct SignEntireHelper<T, Err>
where
    T: FnOnce(Vec<u8>) -> Result<RecoverableSignature, Err>,
{
    pub buffer: Vec<u8>,
    pub signer: T,
}

impl<T, Err> SignEntireHelper<T, Err>
where
    T: FnOnce(Vec<u8>) -> Result<RecoverableSignature, Err>,
{
    pub fn new(signer: T) -> Self {
        Self {
            buffer: Vec::new(),
            signer,
        }
    }
}

impl<T, Err> SignerSingleShot for SignEntireHelper<T, Err>
where
    T: FnOnce(Vec<u8>) -> Result<RecoverableSignature, Err>,
{
    type Err = Err;

    fn append(&mut self, message_fragment: &[u8]) {
        self.buffer.extend_from_slice(message_fragment)
    }
    fn finalize(self) -> Result<RecoverableSignature, Err> {
        let Self { buffer, signer } = self;
        signer(buffer)
    }
}
