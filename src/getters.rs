use super::{Attachment, Iml};

impl Iml {
    pub fn get_civilization(&self) -> u64 {
        self.civilization
    }
    pub fn get_current_sk(&self) -> &[u8] {
        &self.current_sk
    }
    pub fn get_next_sk(&self) -> &[u8] {
        &self.next_sk
    }
    pub fn get_current_dh(&self) -> &[u8] {
        &self.current_dh
    }
    pub fn get_next_dh(&self) -> &[u8] {
        &self.next_dh
    }
    pub fn previous(&self) -> Option<Iml> {
        if self.inversion.is_empty() {
            None
        } else {
            serde_cbor::from_slice(&self.inversion).unwrap()
        }
    }
    pub fn proof(&self) -> Vec<u8> {
        match self.proof.clone() {
            Some(p) => p,
            None => vec![],
        }
    }
    pub fn attachments(&self) -> Option<Vec<Attachment>> {
        match &self.attachments {
            Some(a) => Some(a.clone()),
            None => None,
        }
    }
    pub fn as_verifiable(&self) -> Vec<u8> {
        let verifiable = Iml {
            attachments: None,
            proof: None,
            ..self.clone()
        };
        serde_cbor::to_vec(&verifiable).unwrap()
    }
}
