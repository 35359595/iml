use crate::{
    error::Error,
    wallet::{key_id_generate, UnlockedWallet},
};

use super::Iml;
use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

impl Iml {
    pub fn verify(&self) -> bool {
        match self.previous() {
            Some(previous) => {
                if previous.get_civilization() + 1 != self.civilization {
                    return false;
                }
                let previous_sk = previous.get_next_sk();
                if previous_sk == self.get_current_sk() {
                    if verify_sig(&self) {
                        previous.verify()
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            None => {
                let id = self.get_id();
                let generated = hex::encode(&self.get_interacion_key());
                id == generated && verify_sig(&self)
            }
        }
    }
    /// Diffie-Hellman shared secret generator
    pub fn diffie_hellman(
        &self,
        wallet: &UnlockedWallet,
        their: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, Error> {
        wallet.diffie_hellman(&key_id_generate(self.get_interacion_key()), their)
    }
}

fn verify_sig(iml: &Iml) -> bool {
    if let Ok(vk1) = VerifyingKey::from_sec1_bytes(iml.get_current_sk()) {
        let vk = VerifyingKey::from(vk1);
        if let Ok(sig) = Signature::from_slice(&iml.proof()) {
            vk.verify(&iml.as_verifiable(), &sig).is_ok()
        } else {
            false
        }
    } else {
        false
    }
}
