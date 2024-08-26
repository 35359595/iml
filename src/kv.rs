use anyhow::{Error, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use std::collections::HashMap;
use zeroize::Zeroize;

pub struct LockedVault(Vec<u8>);

impl LockedVault {
    pub fn new(content: impl AsRef<[u8]>) -> Self {
        Self(content.as_ref().to_vec())
    }

    pub fn unlock(self, key: String) -> Result<UnlockedVault> {
        UnlockedVault::unlock(key, self)
    }
}

/// Signing entry without direct key access
#[derive(serde::Serialize, serde::Deserialize)]
pub struct UnlockedVault {
    keys: HashMap<String, Vec<u8>>,
}

impl UnlockedVault {
    /// Unlocks the vault with the provided key.
    pub fn unlock(key: String, vault: LockedVault) -> Result<Self> {
        let cypher = XChaCha20Poly1305::new_from_slice(&key.as_bytes())
            .map_err(|_| Error::msg("Invalid unlock key provided."))?;
        let nonce = XNonce::from_slice(&[0; 24]);
        let decrypted = cypher
            .decrypt(nonce, vault.0.as_slice())
            .map_err(|_| Error::msg("Failed to unlock vault."))?;
        let keys = serde_cbor::from_slice::<HashMap<String, Vec<u8>>>(decrypted.as_slice())?;
        Ok(Self { keys })
    }

    /// Locks the vault with the provided key.
    /// Zeroizes all keys in the vault and intermidiate data.
    pub fn lock(mut self, key: &str) -> Result<LockedVault> {
        let cypher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|_| Error::msg("Invalid unlock key provided."))?;
        let nonce = XNonce::from_slice(&[0; 24]);
        let mut data = serde_cbor::to_vec(&self)?;
        let encrypted = cypher
            .encrypt(nonce, data.as_slice())
            .map_err(|_| Error::msg("Failed to lock vault."))?;
        for key in self.keys.values_mut() {
            key.zeroize();
        }
        data.zeroize();
        Ok(LockedVault(encrypted))
    }

    /// Signs the data with the provided key ID.
    pub fn sign(&self, data: impl AsRef<[u8]>, key_id: impl AsRef<str>) -> Result<Vec<u8>> {
        let key = self
            .keys
            .get(key_id.as_ref())
            .ok_or(Error::msg("No igning key found with given ID."))?;
        let key = SigningKey::from_slice(key.as_slice())
            .map_err(|_| Error::msg("Invalid signing key found."))?;
        let signature: Signature = key.sign(data.as_ref());
        Ok(signature.to_bytes().to_vec())
    }

    /// Verifies the signature of the data with the provided key ID.
    pub fn verify(
        &self,
        signature: impl AsRef<[u8]>,
        data: impl AsRef<[u8]>,
        key_id: impl AsRef<str>,
    ) -> Result<bool> {
        let key = self
            .keys
            .get(key_id.as_ref())
            .ok_or(Error::msg("No igning key found with given ID."))?;
        let key = VerifyingKey::from_sec1_bytes(key.as_slice())
            .map_err(|_| Error::msg("Invalid signing key found."))?;
        let signature = Signature::from_slice(signature.as_ref())
            .map_err(|_| Error::msg("Invalid signature provided."))?;
        Ok(key.verify(data.as_ref(), &signature).is_ok())
    }

    /// Adds a new key to the vault.
    pub fn add_key(&mut self, key_id: impl AsRef<str>) {
        let key = SigningKey::random(&mut OsRng::default());
        self.keys
            .insert(key_id.as_ref().to_string(), key.to_bytes().to_vec());
    }
}
