use crate::error::Error;
use arrayref::array_ref;
use blake3::hash;
use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use rand::{rngs::OsRng, RngCore};
use serde::{ser::SerializeSeq, Deserialize, Serialize};
use static_dh_ecdh::ecdh::ecdh::{FromBytes, KeyExchange, PkP256, SkP256, ToBytes, ECDHNISTP256};
use std::collections::HashMap;
use zeroize::Zeroize;

#[derive(PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct UnlockedWallet {
    // TODO: fix this vec ugliness
    keys: HashMap<KeyId, [u8; 32]>,
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
                self.keys.insert(id, new_key.to_bytes().into());
                Ok(id)
            }
            KeyType::EcdhP256 => {
                let mut seed = [0u8; 32];
                OsRng.fill_bytes(&mut seed);
                let new_sk = ECDHNISTP256::generate_private_key(seed);
                let new_pk = ECDHNISTP256::generate_public_key(&new_sk);
                let key_id = if let Some(id) = id {
                    id
                } else {
                    key_id_generate(new_pk.to_bytes())
                };
                self.keys.insert(key_id, new_sk.to_bytes().into());
                Ok(key_id)
            } //_ => Err(Error::UnsupportedKeyType),
        }
    }

    pub fn new_key_for(&mut self, id: KeyId) -> Result<(), Error> {
        if let Some(_) = self.keys.get(&id) {
            Err(Error::KeyExistsForId)
        } else {
            self.keys
                .insert(id, SigningKey::random(&mut OsRng {}).to_bytes().into());
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

    pub fn public_for(&self, id: &KeyId, key_type: KeyType) -> Option<[u8; 32]> {
        let sk_bytes = self.keys.get(id)?;
        match key_type {
            KeyType::Ed25519_256 => {
                if let Ok(sk) = SigningKey::from_slice(sk_bytes) {
                    let sk = sk.verifying_key().to_sec1_bytes();
                    Some(array_ref![sk, 0, 32].to_owned())
                } else {
                    None
                }
            }
            KeyType::EcdhP256 => {
                if let Ok(sk) = SkP256::from_bytes(sk_bytes) {
                    let sk = ECDHNISTP256::generate_public_key(&sk).to_bytes();
                    Some(array_ref![sk, 0, 32].to_owned())
                } else {
                    None
                }
            }
        }
    }

    pub fn verify_with(
        &self,
        message: impl AsRef<[u8]>,
        id: &KeyId,
        signature: &Signature,
    ) -> bool {
        if let Some(vk) = self.public_for(id, KeyType::Ed25519_256) {
            VerifyingKey::from_sec1_bytes(&vk)
                .is_ok_and(|vk| vk.verify(message.as_ref(), signature).is_ok())
        } else {
            false
        }
    }

    pub fn sign_with(&self, message: impl AsRef<[u8]>, id: &KeyId) -> Result<Signature, Error> {
        if let Some(sk) = self.keys.get(id) {
            Ok(SigningKey::from_bytes(sk.into())
                .map_err(|_| Error::UnsupportedKeyType)?
                .sign(message.as_ref()))
        } else {
            Err(Error::EcdsaFailed)
        }
    }

    pub fn diffie_hellman(
        &self,
        key_id: &KeyId,
        their_id: impl AsRef<[u8]>,
    ) -> Result<[u8; 32], Error> {
        if let Some(sk) = self.keys.get(key_id) {
            let our_s = SkP256::from_bytes(sk.as_ref())?;
            let their_pk = PkP256::from_bytes(their_id.as_ref())?;
            let dx = ECDHNISTP256::generate_shared_secret(&our_s, &their_pk)?.to_bytes();
            Ok(array_ref!(dx, 0, 32).to_owned())
        } else {
            Err(Error::KeyNotFound)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ed25519_256,
    EcdhP256,
}

/// Used to identify crypto content through the entire app
pub(crate) type KeyId = [u8; 4];

/// Only this function to be used to generate key ids
pub fn key_id_generate(s: impl AsRef<[u8]>) -> KeyId {
    let mut r = [0u8; 4];
    hash(s.as_ref()).as_bytes()[..4]
        .into_iter()
        .enumerate()
        .map(|(i, v)| r[i] = *v)
        .for_each(drop);
    r
}

#[test]
fn hasher_test() {
    assert_ne!(key_id_generate("abc"), [0u8; 4]);
    assert_ne!(key_id_generate(br#"abcd"#), [0u8; 4]);
    assert_ne!(key_id_generate([1u8; 64]), [0u8; 4]);
}

#[test]
fn pk_export_import_test() {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let new_sk = ECDHNISTP256::generate_private_key(seed);
    let new_pk = ECDHNISTP256::generate_public_key(&new_sk);
    let pk_bytes = new_pk.to_bytes();
    let pk_from_bytes = PkP256::from_bytes(&pk_bytes).unwrap();
    assert_eq!(new_pk, pk_from_bytes);
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

impl From<(KeyId, [u8; 32])> for KeysEntry {
    fn from(value: (KeyId, [u8; 32])) -> Self {
        Self {
            id: value.0,
            sk: value.1,
        }
    }
}

impl Serialize for UnlockedWallet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.keys.len()))?;
        // FIXME: remove this clone and make sure it's properly zeroized
        self.keys
            .clone()
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
                .map(|kv| (kv.id, kv.sk))
                .collect(),
        })
    }
}
