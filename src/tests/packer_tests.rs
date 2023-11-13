use crate::{wallet::UnlockedWallet, Iml};

#[test]
fn instantiation_test() {
    let mut w = UnlockedWallet::new();
    // no panics sanity check
    let _ = Iml::new(&mut w);
}

#[test]
#[should_panic]
fn interact_not_yet_implemented_test() {
    let mut w = UnlockedWallet::new();
    Iml::new(&mut w).interact("0x1234");
}
