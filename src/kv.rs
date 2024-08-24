use anyhow::{Error, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use std::collections::HashMap;

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
pub struct UnlockedVault {
    keys: HashMap<String, Vec<u8>>,
}

impl UnlockedVault {
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

    pub fn lock(&mut self, key: &str) -> Option<LockedVault> {
        self.keys.remove(key).map(LockedVault)
    }
}
