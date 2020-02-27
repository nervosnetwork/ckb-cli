use std::fmt::Debug;
use void::Void;

use ckb_crypto::secp::SECP256K1;
use ckb_sdk::wallet::{zeroize_privkey, AbstractPrivKey};
use ckb_types::H256;
use secp256k1::recovery::RecoverableSignature;

#[derive(Debug, Clone)]
pub struct PrivkeyWrapper(pub secp256k1::SecretKey);

// For security purpose
impl Drop for PrivkeyWrapper {
    fn drop(&mut self) {
        zeroize_privkey(&mut self.0);
    }
}

impl std::ops::Deref for PrivkeyWrapper {
    type Target = secp256k1::SecretKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AbstractPrivKey for PrivkeyWrapper {
    // TODO `secp256k1::Error`
    type Err = Void;

    fn public_key(&self) -> Result<secp256k1::PublicKey, Self::Err> {
        Ok(secp256k1::PublicKey::from_secret_key(&SECP256K1, self))
    }

    fn sign(&self, message: &H256) -> Result<secp256k1::Signature, Self::Err> {
        let message =
            secp256k1::Message::from_slice(message.as_bytes()).expect("Convert to message failed");
        Ok(SECP256K1.sign(&message, &self.0))
    }

    fn sign_recoverable(&self, message: &H256) -> Result<RecoverableSignature, Self::Err> {
        let message =
            secp256k1::Message::from_slice(message.as_bytes()).expect("Convert to message failed");
        Ok(SECP256K1.sign_recoverable(&message, &self.0))
    }
}
