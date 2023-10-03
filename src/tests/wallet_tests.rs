use crate::{wallet::key_id_generate, UnlockedWallet};

#[test]
fn serialization_deserialization_test() {
    let mut w = UnlockedWallet::new();
    w.new_key_for(key_id_generate("ivan")).unwrap();
    let s = serde_cbor::to_vec(&w).unwrap();
    let de_s = serde_cbor::from_slice(&s).unwrap();
    assert_eq!(w, de_s);
}
