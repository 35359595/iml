use super::{Attachment, Iml};
use universal_wallet::{
    contents::{public_key_info::KeyType, Content},
    unlocked::UnlockedWallet,
};

impl Iml {
    pub fn new(wallet: &mut UnlockedWallet) -> Self {
        let current_sk_raw = wallet
            .new_key(KeyType::EcdsaSecp256k1VerificationKey2019, None)
            .unwrap();
        let next_sk_raw = wallet
            .new_key(KeyType::EcdsaSecp256k1VerificationKey2019, None)
            .unwrap();
        let current_sk = get_pk_bytes(current_sk_raw.content);
        let next_sk = get_pk_bytes(next_sk_raw.content);
        let id = blake3::hash(&current_sk).to_string();
        wallet.set_key_controller(&current_sk_raw.id, &format!("{}_sk_0", &id));
        let next_sk_controller = &format!("{}_sk_1", &id);
        wallet.set_key_controller(&next_sk_raw.id, next_sk_controller);
        let mut pre_signed = Iml {
            id: Some(id),
            current_sk,
            next_sk,
            ..Iml::default()
        };
        let sig = wallet
            .sign_raw(&current_sk_raw.id, &pre_signed.as_verifiable())
            .unwrap();
        pre_signed.proof = Some(sig);
        pre_signed
    }

    pub fn evolve(
        self,
        wallet: &mut UnlockedWallet,
        evolve_sk: bool,
        attachments: Option<Vec<Attachment>>,
    ) -> Self {
        if !evolve_sk && attachments.is_none() {
            return self;
        }
        let mut evolved = Iml::default();
        evolved.civilization = self.get_civilization() + 1;
        if evolve_sk {
            let current_controller =
                format!("{}_sk_{}", &self.get_id(), evolved.get_civilization());
            let new_current = wallet
                .get_content_by_controller(&current_controller)
                .unwrap()
                .clone();
            let next_sk_raw = wallet
                .new_key(
                    KeyType::EcdsaSecp256k1VerificationKey2019,
                    Some(vec![format!(
                        "{}_sk_{}",
                        &self.get_id(),
                        evolved.get_civilization() + 1
                    )]),
                )
                .unwrap();
            evolved.current_sk = get_pk_bytes(new_current);
            evolved.next_sk = get_pk_bytes(next_sk_raw.content);
        }
        evolved.inversion = serde_cbor::to_vec(&self).unwrap();
        let proof = wallet
            .sign_raw_by_controller(
                &format!("{}_sk_{}", &self.get_id(), evolved.get_civilization()),
                &evolved.as_verifiable(),
            )
            .unwrap();
        evolved.proof = Some(proof);
        evolved
    }

    pub fn re_evolve(
        wallet: &UnlockedWallet,
        id: &str,
        _attachments: Option<Vec<Attachment>>,
    ) -> Self {
        // TODO: re-attach attachments
        let mut iml = Iml::default();
        iml.id = Some(id.into());
        loop {
            iml.restore(wallet);
            if wallet
                .get_key_by_controller(&format!("{}_sk_{}", id, iml.get_civilization() + 2))
                .is_none()
            {
                break;
            }
        }
        iml
    }

    fn restore(&mut self, wallet: &UnlockedWallet) {
        let mut iml = Iml::default();
        if self.get_civilization() == 0 && !self.get_current_sk().is_empty() {
            iml.civilization = self.get_civilization() + 1;
        } else {
            iml.id = self.id.clone()
        }
        if let Some(content) = wallet.get_key_by_controller(&format!(
            "{}_sk_{}",
            &self.get_id(),
            iml.get_civilization()
        )) {
            if let Some(next_content) = wallet.get_key_by_controller(&format!(
                "{}_sk_{}",
                &self.get_id(),
                iml.get_civilization() + 1
            )) {
                if iml.get_civilization() > 0 {
                    iml.inversion = serde_cbor::to_vec(&self).unwrap();
                }
                iml.current_sk = get_pk_bytes(content.content);
                iml.next_sk = get_pk_bytes(next_content.content);
                iml.proof = Some(
                    wallet
                        .sign_raw_by_controller(
                            &format!("{}_sk_{}", &self.get_id(), iml.get_civilization()),
                            &iml.as_verifiable(),
                        )
                        .unwrap(),
                );
                *self = iml;
            }
        }
    }
}

fn get_pk_bytes(c: Content) -> Vec<u8> {
    match c {
        Content::PublicKey(pk) => pk.public_key,
        Content::KeyPair(kp) => kp.public_key.public_key,
        _ => vec![],
    }
}

#[test]
fn new_iml_plus_verification_test() {
    let mut wallet = UnlockedWallet::new("test");
    let iml = Iml::new(&mut wallet);
    assert_eq!(0, iml.get_civilization());
    assert!(iml.verify());
    let iml = iml.evolve(&mut wallet, true, None);
    assert_eq!(1, iml.get_civilization());
    assert!(iml.verify());
    let restored = Iml::re_evolve(&wallet, &iml.get_id(), None);
    assert_eq!(iml, restored);
}
