use super::{Attachment, Iml, KeyType, UnlockedWallet};
use crate::{error::Error, wallet::key_id_generate, PayloadType};
use arrayref::array_ref;
use k256::ecdsa::{Signature, VerifyingKey};
use libflate::deflate::{Decoder, Encoder};
use std::{io::Read, sync::Arc};

impl Iml {
    pub fn new(wallet: &mut UnlockedWallet) -> Self {
        let current_sk_id = key_id_generate("sk_0");
        wallet
            .new_key(KeyType::Ed25519_256, Some(current_sk_id))
            .unwrap();
        let next_sk_id = key_id_generate("sk_1");
        wallet
            .new_key(KeyType::Ed25519_256, Some(next_sk_id))
            .unwrap();
        let current_sk = wallet.public_for(&current_sk_id).unwrap().to_sec1_bytes();
        let current_sk: [u8; 32] = array_ref!(current_sk, 0, 32).to_owned();
        let next_sk = wallet.public_for(&next_sk_id).unwrap().to_sec1_bytes();
        let next_sk = array_ref!(next_sk, 0, 32).to_owned();
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
            .to_bytes();
        let sig = array_ref!(sig, 0, 32).to_owned();
        pre_signed.proof = sig;
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
        // TODO: clean previous inversions for space saving?
        evolved.inversion = Some(self.deflate());
        // becomes current
        let current_controller = key_id_generate(format!("sk_{}", evolved.get_civilization()));
        // becomes next for new current
        let next_controller =
            key_id_generate(format!("sk_{}", evolved.get_civilization() + 1).into_bytes());
        if evolve_sk {
            wallet.new_key_for(next_controller).unwrap();
            let new_next = wallet.public_for(&next_controller).unwrap().to_sec1_bytes();
            // new next
            evolved.next_sk = array_ref!(new_next, 0, 32).to_owned();
            // new current is old next
            evolved.current_sk = self.next_sk;
        }
        // new proof with new current
        let proof = wallet
            .sign_with(&evolved.as_verifiable(), &current_controller)
            .unwrap()
            .to_bytes();
        evolved.proof = array_ref!(proof, 0, 32).to_owned();
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
        while wallet
            .public_for(&key_id_generate(format!(
                "sk_{}",
                iml.get_civilization() + 2
            )))
            .is_some()
        {
            println!("restoring for civilization {}", iml.get_civilization());
            iml.restore(wallet);
            iml.civilization += 1;
        }
        iml
    }

    pub fn interact(
        &mut self,
        wallet: Arc<UnlockedWallet>,
        peer: &VerifyingKey,
        payload: impl AsRef<[u8]>,
        payload_type: PayloadType,
    ) -> Result<Attachment, Error> {
        let sig = self.sign_with_current(wallet, &payload)?.to_vec();
        let proof = array_ref!(sig, 0, 32).to_owned();
        Ok(Attachment {
            parent: self.proof,
            payload: blake3::hash(payload.as_ref()).into(),
            payload_type,
            proof,
        })
    }

    fn sign_with_current(
        &self,
        wallet: Arc<UnlockedWallet>,
        payload: impl AsRef<[u8]>,
    ) -> Result<Signature, Error> {
        let current_id = key_id_generate(format!("sk_{}", self.civilization));
        wallet.as_ref().sign_with(payload, &current_id)
    }

    fn restore(&mut self, wallet: &UnlockedWallet) {
        //if self.get_civilization() == 0 && !self.get_current_sk().is_empty() {
        //    iml.civilization = self.get_civilization() + 1;
        //} else {
        //    iml.id = self.id.clone()
        //}
        if let Some(current) =
            wallet.public_for(&key_id_generate(format!("sk_{}", self.get_civilization())))
        {
            let next_id = key_id_generate(format!("sk_{}", self.get_civilization() + 1));
            if let Some(next) = wallet.public_for(&next_id) {
                if self.get_civilization() > 0 {
                    self.inversion = Some(self.deflate());
                }
                let current = current.to_sec1_bytes();
                self.current_sk = array_ref!(current, 0, 32).to_owned();
                let next = next.to_sec1_bytes();
                self.next_sk = array_ref!(next, 0, 32).to_owned();
                let proof = wallet
                    .sign_with(&self.as_verifiable(), &next_id)
                    .unwrap()
                    .to_vec();
                self.proof = array_ref!(proof, 0, 32).to_owned();
            }
        }
    }

    fn deflate(&self) -> Vec<u8> {
        let serialized = &serde_cbor::to_vec(&self).unwrap();
        let data = base64_url::encode(&serialized);
        let mut data = data.as_bytes();
        let mut encoder = Encoder::new(Vec::with_capacity(data.len()));
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

    pub(crate) fn inflate(data: impl AsRef<[u8]>) -> Self {
        let mut decoder = Decoder::new(data.as_ref());
        let mut decoded = String::new();
        decoder.read_to_string(&mut decoded).unwrap();
        serde_cbor::from_slice(&base64_url::decode(&decoded).unwrap()).unwrap()
    }
}

#[test]
fn new_iml_plus_verification_test() {
    let mut wallet = UnlockedWallet::new();
    let iml = Iml::new(&mut wallet);
    assert_eq!(0, iml.get_civilization());
    assert!(iml.verify());
    let iml = iml.evolve(&mut wallet, true, None);
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
    println!("deflating");
    let deflated = iml.deflate();
    println!("deflated to: {}kb", deflated.len() / 1024);
    println!("did:iml:{}", base64_url::encode(&deflated));

    let restored = Iml::re_evolve(&wallet, &iml.get_id(), None);
    assert_eq!(iml.get_civilization(), restored.get_civilization());
    // TODO: fix this assert
    //assert_eq!(iml, restored);
}
