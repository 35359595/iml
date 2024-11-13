use crate::{wallet::key_id_generate, LockedWallet, UnlockedWallet};

#[test]
fn serialization_deserialization_test() {
    let mut w = UnlockedWallet::new();
    w.new_key_for(key_id_generate("ivan")).unwrap();
    let s = serde_cbor::to_vec(&w).unwrap();
    let de_s = serde_cbor::from_slice(&s).unwrap();
    assert_eq!(w, de_s);
}

#[test]
fn lock_and_unlock_test() {
    let mut w = UnlockedWallet::new();
    w.new_key_for(key_id_generate("ivan")).unwrap();
    let to_compare = w.clone();
    const TEST_PASS: &str = "donotuseanywhere";
    let locked_raw = w.lock(TEST_PASS);
    let unlocked: UnlockedWallet = LockedWallet::new(locked_raw)
        .unlock(TEST_PASS.as_bytes().to_vec())
        .unwrap();
    assert_eq!(unlocked, to_compare);
}

#[test]
fn diffie_hellman_generation_works_test() {
    let mut alice = UnlockedWallet::new();
    let mut bob = UnlockedWallet::new();
    const ALICE_ID: [u8; 4] = [1u8; 4];
    const BOB_ID: [u8; 4] = [2u8; 4];
    alice
        .new_key(crate::wallet::KeyType::EcdhP256, Some(ALICE_ID))
        .unwrap();
    bob.new_key(crate::wallet::KeyType::EcdhP256, Some(BOB_ID))
        .unwrap();
    bob.new_key(crate::wallet::KeyType::Ed25519_256, Some(BOB_ID))
        .unwrap();
    let _ = bob.public_for(&BOB_ID, crate::wallet::KeyType::Ed25519_256);
    let a_pub = alice
        .public_for(&ALICE_ID, crate::wallet::KeyType::EcdhP256)
        .unwrap();
    let b_pub = bob
        .public_for(&BOB_ID, crate::wallet::KeyType::EcdhP256)
        .unwrap();
    let a_dh = alice.diffie_hellman(&ALICE_ID, b_pub).unwrap();
    let b_dh = bob.diffie_hellman(&BOB_ID, a_pub).unwrap();
    assert_eq!(a_dh, b_dh);
}
