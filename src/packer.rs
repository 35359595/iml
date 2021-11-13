use super::{Attachment, Iml};
use universal_wallet::{
    contents::{public_key_info::KeyType, Content},
    unlocked::UnlockedWallet,
};

impl Iml {
    pub fn new(wallet: &mut UnlockedWallet) -> Self {
        let current_sk_raw = wallet
            .new_key(
                KeyType::EcdsaSecp256k1VerificationKey2019,
                Some(vec!["current_sk".into()]),
            )
            .unwrap();
        let next_sk_raw = wallet
            .new_key(
                KeyType::EcdsaSecp256k1VerificationKey2019,
                Some(vec!["next_sk".into()]),
            )
            .unwrap();
        let current_dh_raw = wallet
            .new_key(
                KeyType::X25519KeyAgreementKey2019,
                Some(vec!["current_dh".into()]),
            )
            .unwrap();
        let next_dh_raw = wallet
            .new_key(
                KeyType::X25519KeyAgreementKey2019,
                Some(vec!["next_dh".into()]),
            )
            .unwrap();
        let current_sk = get_pk_bytes(current_sk_raw.content);
        let next_sk = get_pk_bytes(next_sk_raw.content);
        let current_dh = get_pk_bytes(current_dh_raw.content);
        let next_dh = get_pk_bytes(next_dh_raw.content);
        let id = blake3::hash(&current_sk).to_string();
        wallet.set_key_controller(&current_sk_raw.id, &format!("{}_current_sk", &id));
        wallet.set_key_controller(&next_sk_raw.id, &format!("{}_next_sk", &id));
        wallet.set_key_controller(&current_dh_raw.id, &format!("{}_current_dh", &id));
        wallet.set_key_controller(&next_dh_raw.id, &format!("{}_next_dh", &id));
        let mut pre_signed = Iml {
            id,
            current_sk,
            next_sk,
            current_dh,
            next_dh,
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
        evolve_dh: bool,
        attachments: Option<Vec<Attachment>>,
    ) -> Self {
        if !evolve_sk && !evolve_dh && attachments.is_none() {
            return self;
        }
        let mut evolved = Iml::default();
        if evolve_sk {
            let new_current = wallet.get_key(&format!("{}_next_sk", &self.id)).unwrap();
            wallet.set_key_controller(&new_current.id, &format!("{}_current_sk", &self.id));
            let next_sk_raw = wallet
                .new_key(
                    KeyType::EcdsaSecp256k1VerificationKey2019,
                    Some(vec!["next_sk".into()]),
                )
                .unwrap();
            wallet.set_key_controller(&next_sk_raw.id, &format!("{}_next_sk", &self.id));
            evolved.current_sk = get_pk_bytes(new_current.content);
            evolved.next_sk = get_pk_bytes(next_sk_raw.content);
        }
        if evolve_dh {
            let new_current = wallet.get_key(&format!("{}_next_dh", &self.id)).unwrap();
            wallet.set_key_controller(&new_current.id, &format!("{}_current_dh", &self.id));
            let next_dh_raw = wallet
                .new_key(
                    KeyType::X25519KeyAgreementKey2019,
                    Some(vec!["next_dh".into()]),
                )
                .unwrap();
            wallet.set_key_controller(&next_dh_raw.id, &format!("{}_next_dh", &self.id));
            evolved.current_dh = get_pk_bytes(new_current.content);
            evolved.next_dh = get_pk_bytes(next_dh_raw.content);
        }
        evolved.civilization = self.get_civilization() + 1;
        evolved.inversion = serde_cbor::to_vec(&self).unwrap();
        let proof = wallet
            .sign_raw(
                &format!("{}_current_sk", &self.id),
                &evolved.as_verifiable(),
            )
            .unwrap();
        evolved.proof = Some(proof);
        evolved
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
}
