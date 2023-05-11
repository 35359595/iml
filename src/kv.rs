use std::collections::HashMap;

pub(crate) struct LockedVault;

pub(crate) struct UnlockedVault {
    keys: HashMap<String, Vec<u8>>,
}

impl UnlockedVault {
    pub(crate) fn new(initial_key_id: impl Into<String>) -> Self {}
}
