use crate::{wallet::UnlockedWallet, Iml};

#[test]
fn instantiation_test() {
    let mut w = UnlockedWallet::new();
    // no panics sanity check
    let _ = Iml::new(&mut w);
}

#[test]
#[should_panic(expected = "called `Result::unwrap()` on an `Err` value: NotAnIml")]
fn interact_implemented_test() {
    let mut w = UnlockedWallet::new();
    Iml::new(&mut w)
        .unwrap()
        .interact(&w, "0x1234", None)
        .unwrap();
}
