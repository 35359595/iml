use super::{Attachment, Iml, KeyType, UnlockedWallet};
use libflate::deflate::{Decoder, Encoder};
use std::io::Read;

impl Iml {
    pub fn new(wallet: &mut UnlockedWallet) -> Self {
        let current_sk_id = wallet.new_key(KeyType::Ed25519_256, None).unwrap();
        let next_sk_id = wallet.new_key(KeyType::Ed25519_256, None).unwrap();
        let current_sk = wallet
            .public_for(&current_sk_id)
            .unwrap()
            .to_sec1_bytes()
            .into_vec();
        let next_sk = wallet
            .public_for(&next_sk_id)
            .unwrap()
            .to_sec1_bytes()
            .into_vec();
        let id = blake3::hash(current_sk.as_ref()).to_string();
        let mut pre_signed = Iml {
            id: Some(id),
            current_sk,
            next_sk,
            ..Iml::default()
        };
        let sig = wallet
            .sign_with(pre_signed.as_verifiable(), &current_sk_id)
            .unwrap()
            .to_vec();
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
                    KeyType::Ed25519_256,
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
        evolved.inversion = Some(serde_cbor::to_vec(&self).unwrap());
        let proof = wallet
            .sign_raw_by_controller(
                &format!("{}_sk_{}", &self.get_id(), evolved.get_civilization()),
                &evolved.as_verifiable(),
            )
            .unwrap();
        evolved.proof = Some(proof);
        evolved
    }

    /// Rebuilds entire state of Iml based on keys present in wallet and ID.
    ///
    /// # Parameters
    ///
    /// * `wallet` - Keywault with keys present for given id
    /// * `id` - identifier of Iml to be restored
    /// * `attachments` - optional attachments to be re-attached
    ///
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

    pub fn interact(&self, peer_id: &str) -> Self {
        todo!()
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
                    iml.inversion = Some(serde_cbor::to_vec(&self).unwrap());
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

    fn deflate(&self) -> Vec<u8> {
        let serialized = &serde_cbor::to_vec(&self).unwrap();
        let data = base64_url::encode(&serialized);
        let mut data = data.as_bytes();
        let mut encoder = Encoder::new(Vec::new());
        std::io::copy(&mut data, &mut encoder).unwrap();
        let deflated = encoder.finish().into_result().unwrap();
        println!(
            "from: {} to {} | {}%",
            serialized.len(),
            deflated.len(),
            deflated.len() * 100 / serialized.len()
        );
        deflated
    }

    pub(crate) fn inflate(data: &[u8]) -> Self {
        let mut decoder = Decoder::new(data);
        let mut decoded = String::new();
        decoder.read_to_string(&mut decoded).unwrap();
        serde_cbor::from_slice(&base64_url::decode(&decoded).unwrap()).unwrap()
    }
}

#[test]
fn new_iml_plus_verification_test() {
    let mut wallet = UnlockedWallet::new("test");
    let iml = Iml::new(&mut wallet);
    assert_eq!(0, iml.get_civilization());
    assert!(iml.verify());
    let iml = iml.evolve(&mut wallet, true, None);
    println!(
        "did:iml:{}",
        base64_url::encode(&serde_cbor::to_vec(&iml).unwrap())
    );
    assert_eq!(1, iml.get_civilization());
    assert!(iml.verify());
    let mut iml = iml.evolve(&mut wallet, true, None);
    println!(
        "did:iml:{}",
        base64_url::encode(&serde_cbor::to_vec(&iml).unwrap())
    );
    for _ in 0..15 {
        iml = iml.evolve(&mut wallet, true, None);
    }

    println!(
        "final size is: {}kb",
        serde_cbor::to_vec(&iml).unwrap().len() / 1024
    );
    let deflated = iml.deflate();
    println!("deflated to: {}kb", deflated.len() / 1024);
    println!("did:iml:{}", base64_url::encode(&deflated));

    //TODO: fix >1 evolution
    //let restored = Iml::re_evolve(&wallet, &iml.get_id(), None);
    //assert_eq!(iml, restored);
}
