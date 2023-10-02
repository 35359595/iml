use crate::error::Error;
use blake3::hash;
use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use rand::rngs::OsRng;
use serde::{ser::SerializeSeq, Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroize;

#[derive(PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct UnlockedWallet {
    // TODO: fix this vec ugliness
    keys: HashMap<KeyId, SigningKey>,
}

impl UnlockedWallet {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    pub fn new_key(&mut self, key_type: KeyType, id: Option<KeyId>) -> Result<KeyId, Error> {
        match key_type {
            KeyType::Ed25519_256 => {
                let new_key = SigningKey::random(&mut OsRng {});
                let id = if let Some(id) = id {
                    id
                } else {
                    key_id_generate(new_key.verifying_key().to_sec1_bytes())
                };
                self.keys.insert(id, new_key);
                Ok(id)
            }
            _ => Err(Error::UnsupportedKeyType),
        }
    }

    pub fn new_key_for(&mut self, id: KeyId) -> Result<(), Error> {
        if let Some(_) = self.keys.get(&id) {
            Err(Error::KeyExistsForId)
        } else {
            self.keys.insert(id, SigningKey::random(&mut OsRng {}));
            Ok(())
        }
    }

    /// Moves key from `fro_id` to `to_id`
    pub fn move_key_for(&mut self, for_id: &KeyId, to_id: KeyId) -> Result<(), Error> {
        if let Some(k) = self.keys.remove(for_id) {
            self.keys.insert(to_id, k);
            Ok(())
        } else {
            Err(Error::KeyNotFound)
        }
    }

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

#[derive(Serialize, Deserialize)]
struct KeysEntry {
    id: KeyId,
    sk: [u8; 32],
}

impl From<(KeyId, SigningKey)> for KeysEntry {
    fn from(tuple: (KeyId, SigningKey)) -> Self {
        Self {
            id: tuple.0,
            sk: tuple.1.to_bytes().into(),
        }
    }
}

impl Serialize for UnlockedWallet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.keys.len()))?;
        self.keys
            .into_iter()
            .try_for_each(|e| seq.serialize_element(&KeysEntry::from(e)))?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for UnlockedWallet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self {
            keys: Vec::<KeysEntry>::deserialize(deserializer)?
                .into_iter()
                .map(|kv| (kv.id, SigningKey::from_bytes(&kv.sk.into()).unwrap()))
                .collect(),
        })
    }
}
