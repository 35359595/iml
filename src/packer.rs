use super::{Attachment, Iml, KeyType, UnlockedWallet};
use crate::{
    error::Error,
    wallet::{key_id_generate, KeyId},
};
use crypto_secretbox::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng},
    Nonce, XSalsa20Poly1305,
};
use libflate::deflate::{Decoder, Encoder};
use static_dh_ecdh::ecdh::ecdh::{FromBytes, PkP256};
use std::io::{Read, Write};

/// DID parts separator
pub const SEPARATOR: char = ':';

impl Iml {
    /// Instantiates new, fully fresh, instance.
    /// WARN: Given wallet's `sk_0` and `sk_1` values will be overwritten if exist!
    pub fn new(wallet: &mut UnlockedWallet) -> Result<Self, Error> {
        let current_sk_id = key_id_generate("sk_0");
        wallet.new_key(KeyType::Ed25519_256, Some(current_sk_id))?;
        let next_sk_id = key_id_generate("sk_1");
        wallet.new_key(KeyType::Ed25519_256, Some(next_sk_id))?;
        let current_sk = wallet
            .public_for(&current_sk_id, KeyType::Ed25519_256)
            .ok_or(Error::EcdsaFailed)?
            .to_vec();
        let next_sk = wallet
            .public_for(&next_sk_id, KeyType::Ed25519_256)
            .ok_or(Error::EcdsaFailed)?
            .to_vec();
        let new_dh_id = wallet.new_key(KeyType::EcdhP256, None)?;
        let new_dh_pub = wallet
            .public_for(&new_dh_id, KeyType::EcdhP256)
            .ok_or(Error::ECDHCryptoError)?;
        let id = hex::encode(&new_dh_pub);
        let mut pre_signed = Iml {
            id,
            current_sk,
            next_sk,
            interaction_key: new_dh_pub,
            ..Iml::default()
        };
        let sig = wallet
            .sign_with(pre_signed.as_verifiable(), &current_sk_id)
            .unwrap();
        pre_signed.proof = Some(sig);
        Ok(pre_signed)
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
        evolved.inversion = Some(self.deflate(None).unwrap().0);
        evolved.id = self.id;
        // becomes current
        let current_controller = key_id_generate(format!("sk_{}", evolved.get_civilization()));
        // becomes next for new current
        let next_controller =
            key_id_generate(format!("sk_{}", evolved.get_civilization() + 1).into_bytes());
        if evolve_sk {
            wallet.new_key_for(next_controller).unwrap();
            let new_next = wallet
                .public_for(&next_controller, KeyType::Ed25519_256)
                .unwrap()
                .clone();
            // new next
            evolved.next_sk = new_next.to_vec();
            // new current is old next
            evolved.current_sk = self.next_sk;
        }
        // new proof with new current
        let proof = wallet
            .sign_with(evolved.as_verifiable(), &current_controller)
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
        id: impl AsRef<str> + ToString,
        _attachments: Option<Vec<Attachment>>,
    ) -> Self {
        // TODO: re-attach attachments
        let mut iml = Iml::default();
        iml.id = id.to_string();
        loop {
            iml.restore(wallet);
            if wallet
                .public_for(
                    &key_id_generate(format!("sk_{}", iml.get_civilization() + 2)),
                    KeyType::Ed25519_256,
                )
                .is_none()
            {
                break;
            }
        }
        iml
    }

    /// Pack-encrypt self for target did with only selected attachments (or none)
    pub fn interact(
        &self,
        wallet: &UnlockedWallet,
        their_did: impl AsRef<str>,
        attachments: Option<Vec<Attachment>>,
    ) -> Result<String, Error> {
        let them = Iml::from_did(
            their_did,
            wallet,
            key_id_generate(self.get_interacion_key()),
        )?;
        let their_pk = them.get_interacion_key();
        let mut to_pack = self.clone();
        to_pack.attachments = attachments;
        let dx = self.diffie_hellman(wallet, their_pk)?;
        to_pack.as_did(Some(dx.to_vec()))
    }

    pub fn from_did(
        did: impl AsRef<str>,
        wallet: &UnlockedWallet,
        our_id: KeyId,
    ) -> Result<Self, Error> {
        let split: Vec<&str> = did.as_ref().split(SEPARATOR).collect();
        let len = split.len();
        if len != 5
            || split[1] != "iml"
            // too expensive?
            || PkP256::from_bytes(&hex::decode(split[2])?).is_err()
        {
            return Err(Error::NotAnIml);
        }
        if split[0] != "did" {
            return Err(Error::NotADid);
        }
        // Authcrypt...
        if !split[4].is_empty() {
            let nonce = Nonce::from_slice(&hex::decode(split[4])?).to_owned();
            let dx = wallet.diffie_hellman(&our_id, hex::decode(split[2])?)?;
            Self::inflate(split[3], Some(dx), Some(nonce))
        } else {
            // RAW!!!
            Self::inflate(split[3], None, None)
        }
    }

    pub fn as_did(&self, dh: Option<Vec<u8>>) -> Result<String, Error> {
        let (deflated, nonce) = self.deflate(dh)?;
        Ok(format!("did:iml:{}:{}:{}", self.id, deflated, nonce))
    }

    fn restore(&mut self, wallet: &UnlockedWallet) {
        let mut iml = Iml::default();
        if self.get_civilization() == 0 && !self.get_current_sk().is_empty() {
            iml.civilization = self.get_civilization() + 1;
        } else {
            iml.id = self.id.clone()
        }
        if let Some(current) = wallet.public_for(
            &key_id_generate(format!("sk_{}", iml.get_civilization())),
            KeyType::Ed25519_256,
        ) {
            let next_id = key_id_generate(format!("sk_{}", iml.get_civilization() + 1));
            if let Some(next) = wallet.public_for(&next_id, KeyType::Ed25519_256) {
                if iml.get_civilization() > 0 {
                    iml.inversion = Some(self.deflate(None).unwrap().0);
                }
                iml.current_sk = current.to_vec();
                iml.next_sk = next.to_vec();
                iml.proof = Some(wallet.sign_with(iml.as_verifiable(), &next_id).unwrap());
                *self = iml;
            }
        }
    }

    /// Returns deflated, serialized and encrypted self + nonce
    fn deflate(&self, encrypt: Option<Vec<u8>>) -> Result<(String, String), Error> {
        // serialize
        let mut serialized = serde_cbor::to_vec(&self).unwrap();
        let mut nonce_string = String::default();
        // encrypt
        if let Some(dh) = encrypt {
            let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng);
            let cypher = XSalsa20Poly1305::new(GenericArray::from_slice(dh.as_ref()));
            serialized = cypher.encrypt(&nonce, serialized.as_ref())?;
            nonce_string = hex::encode(nonce);
        }
        // deflate
        let mut encoder = Encoder::new(Vec::new());
        encoder.write_all(&serialized)?;
        let deflated = encoder.finish().into_result().unwrap();
        // hex
        Ok((hex::encode(deflated), nonce_string))
    }

    pub(crate) fn inflate(
        data: impl AsRef<str>,
        decrypt: Option<Vec<u8>>,
        nonce: Option<Nonce>,
    ) -> Result<Self, Error> {
        // unhex
        let decoded_bytes = hex::decode(data.as_ref())?;
        // inflate
        let mut decoder = Decoder::new(&decoded_bytes[..]);
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded)?;
        // decrypt
        if let Some(dh) = decrypt {
            let nonce = nonce.ok_or(Error::CryptoBoxError("Nonce is required".to_string()))?;
            let cypher = XSalsa20Poly1305::new(GenericArray::from_slice(&dh));
            decoded = cypher.decrypt(&nonce, decoded.as_ref())?;
        }
        // de-serialize
        Ok(serde_cbor::from_slice(&decoded)?)
    }
}

#[test]
fn new_iml_plus_verification_test() {
    let mut wallet = UnlockedWallet::new();
    let iml = Iml::new(&mut wallet).unwrap();
    assert_eq!(0, iml.get_civilization());
    assert!(iml.verify());
    let iml = iml.evolve(&mut wallet, true, None);
    assert_eq!(1, iml.get_civilization());
    assert!(iml.verify());
    let mut iml = iml.evolve(&mut wallet, true, None);
    println!("{}", iml.as_did(None).unwrap());
    for i in 0..15 {
        iml = iml.evolve(&mut wallet, true, None);
        assert!(iml.verify());
        println!("Done {i} for {}", iml.id);
    }
    println!("deflating");
    let deflated = iml.deflate(None).unwrap();
    println!("deflated to: {}kb", deflated.0.len() / 1024);
    let inflated = Iml::inflate(deflated.0, None, None).unwrap();
    assert_eq!(iml, inflated);

    //TODO: fix >1 evolution
    //let restored = Iml::re_evolve(&wallet, &iml.get_id(), None);
    //assert_eq!(iml, restored);
}

#[test]
fn interact_proper_test() -> Result<(), Error> {
    let mut a_wallet = UnlockedWallet::new();
    let mut b_wallet = UnlockedWallet::new();
    let a = Iml::new(&mut a_wallet)?;
    let b = Iml::new(&mut b_wallet)?;
    let a_did = a.as_did(Some(a_wallet.diffie_hellman(
        &key_id_generate(a.get_interacion_key()), //38c
        b.get_interacion_key(),
    )?))?;
    let b_did = b.as_did(Some(b_wallet.diffie_hellman(
        &key_id_generate(b.get_interacion_key()), //4bc
        a.get_interacion_key(),
    )?))?;
    assert!(a.interact(&a_wallet, b_did, None).is_ok());
    assert!(b.interact(&b_wallet, a_did, None).is_ok());
    Ok(())
}
