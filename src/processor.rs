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
                let generated = blake3::hash(&self.current_sk).to_string();
                id == generated && verify_sig(&self)
            }
        }
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
