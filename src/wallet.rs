use crate::error::Error;
use blake3::hash;
use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroize;

#[derive(Deserialize, Serialize)]
pub(crate) struct UnlockedWallet {
    keys: HashMap<KeyId, SigningKey>,
}

impl UnlockedWallet {
    pub fn public_for(&self, id: &KeyId) -> Option<VerifyingKey> {
        Some(self.keys.get(id)?.verifying_key().to_owned())
    }

    pub fn verify_with(
        &self,
        message: impl AsRef<[u8]>,
        id: &KeyId,
        signature: &Signature,
    ) -> bool {
        if let Some(vk) = self.public_for(id) {
            vk.verify(message.as_ref(), signature).is_ok()
        } else {
            false
        }
    }

    pub fn sign_with(&self, message: impl AsRef<[u8]>, id: &KeyId) -> Result<Signature, Error> {
        if let Some(sk) = self.keys.get(id) {
            Ok(sk.sign(message.as_ref()))
        } else {
            Err(Error::EcdsaFailed)
        }
    }
}

/// Transit type for crypto matherial secure storing
/// Other crypto purposes shoud be done with `UnlockedWallet`
/// Creates and is created from `UnlockedWallet` via serde_cbor ser/de-ser
pub(crate) struct LockedWallet {
    content: Vec<u8>,
}

impl LockedWallet {
    pub fn new(content: Vec<u8>) -> Self {
        Self { content }
    }

    pub fn unlock<S>(self, mut secret: S) -> Result<UnlockedWallet, Error>
    where
        S: AsRef<[u8]> + AsMut<[u8]>,
    {
        // TODO: implement crypto unlocking of content
        secret.as_mut().zeroize();
        Ok(serde_cbor::from_slice(self.content.as_slice())?)
    }
}

pub(crate) enum KeyType {
    Ed25519_256,
}

/// Used to identify crypto content through the entire app
pub(crate) type KeyId = [u8; 4];

/// Only this function to be used to generate key ids
pub fn key_id_generate(s: impl AsRef<[u8]>) -> KeyId {
    let mut r = [0u8; 4];
    hash(s.as_ref()).as_bytes()[..4]
        .into_iter()
        .enumerate()
        .map(|(i, v)| r[i] = *v);
    r
}

#[test]
fn hasher_test() {
    assert_ne!(key_id_generate("abc"), [0u8; 4]);
    assert_ne!(key_id_generate(br#"abcd"#), [0u8; 4]);
    assert_ne!(key_id_generate([1u8; 64]), [0u8; 4]);
}
