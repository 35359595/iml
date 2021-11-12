use super::Iml;
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
        let next_sk = get_pk_bytes(
            wallet
                .new_key(
                    KeyType::EcdsaSecp256k1RecoveryMethod2020,
                    Some(vec!["next_sk".into()]),
                )
                .unwrap()
                .content,
        );
        let current_dh = get_pk_bytes(
            wallet
                .new_key(
                    KeyType::X25519KeyAgreementKey2019,
                    Some(vec!["current_dh".into()]),
                )
                .unwrap()
                .content,
        );
        let next_dh = get_pk_bytes(
            wallet
                .new_key(
                    KeyType::X25519KeyAgreementKey2019,
                    Some(vec!["next_dh".into()]),
                )
                .unwrap()
                .content,
        );
        let current_sk = get_pk_bytes(current_sk_raw.content);
        let id = blake3::hash(&current_sk).to_string();
        // TODO: update all keys controllers to id ^
        let mut pre_signed = Iml {
            id,
            current_sk,
            next_sk,
            current_dh,
            next_dh,
            attachments: None,
            inversion: vec![],
            proof: None,
        };
        let sig = wallet
            .sign_raw(
                &current_sk_raw.id,
                &serde_cbor::to_vec(&pre_signed).unwrap(),
            )
            .unwrap();
        let mut proof: [u8; 32] = [0; 32];
        sig.into_iter().enumerate().for_each(|(i, u)| {
            if i < 32 {
                proof[i] = u
            }
        });
        pre_signed.proof = Some(proof);
        pre_signed
    }
}

fn get_pk_bytes(c: Content) -> [u8; 32] {
    let mut out: [u8; 32] = [0; 32];
    match c {
        Content::PublicKey(pk) => pk.public_key.into_iter().enumerate().for_each(|(i, u)| {
            if i < 32 {
                out[i] = u
            }
        }),
        Content::KeyPair(kp) => {
            kp.public_key
                .public_key
                .into_iter()
                .enumerate()
                .for_each(|(i, u)| {
                    if i < 32 {
                        out[i] = u
                    }
                })
        }
        _ => (),
    };
    out
}

#[test]
fn new_iml_test() {
    let mut wallet = UnlockedWallet::new("test");
    let iml = Iml::new(&mut wallet);
    println!(
        "Iml id: {} and full event: {:?}",
        &iml.id,
        serde_cbor::to_vec(&iml).unwrap()
    );
    assert!(true);
}
