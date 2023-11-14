use crate::{wallet::UnlockedWallet, Iml};

#[test]
fn instantiation_test() {
    let mut w = UnlockedWallet::new();
    // no panics sanity check
    let _ = Iml::new(&mut w);
}

#[test]
#[should_panic(
    expected = "called `Result::unwrap()` on an `Err` value: IoError(Custom { kind: InvalidData, error: \"LEN={} is not the one's complement of NLEN={}\" })"
)]
fn interact_implemented_test() {
    let mut w = UnlockedWallet::new();
    Iml::new(&mut w).interact(&w, "0x1234").unwrap();
}
