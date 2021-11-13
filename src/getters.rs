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
    pub fn get_interacion_key(&self) -> Option<Vec<u8>> {
        self.interaction_key.clone()
    }
    // TODO: make it Result and error if cannot reach id
    pub fn get_id(&self) -> String {
        if self.get_civilization() == 0 {
            self.id.clone().unwrap_or_default()
        } else {
            match self.previous() {
                Some(previous) => previous.get_id(),
                None => String::default(),
            }
        }
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
