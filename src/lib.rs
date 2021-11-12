use serde::{Deserialize, Serialize};
mod packer;
pub use packer::*;
/// Inverted Microledger
///
#[derive(Serialize, Deserialize, Debug)]
pub struct Iml {
    /// Blake 3 hash of current_sk, next_sk, current_dh, next_dh joined
    ///
    pub id: String,
    /// Current ECDSA signing public key
    ///
    current_sk: [u8; 32],
    /// Next ECDSA signing public key
    ///
    next_sk: [u8; 32],
    /// Current DH agreement public key
    ///
    current_dh: [u8; 32],
    /// Next DH agreement public key
    ///
    next_dh: [u8; 32],
    /// Any usefull payload.
    /// Is not included into verification of Iml, but
    ///  has proof of it's own internally, therefore
    ///  is not required to be consistantly present
    ///  within inverted microledger log for proper
    ///  verification.
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    attachments: Option<Vec<Attachment>>,
    /// Inverted previous state of Iml.
    /// Can be encrypted for 1-to-1 interaction.
    /// In that case key is DH shared secret between
    /// our SK (pair of `current_dh`) and other partie's 'current_hd'.
    /// Empty `inversion` means inception Iml.
    ///
    inversion: Vec<u8>,
    /// ECDSA signature of rest of the Iml this proof and attachments excluded
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<[u8; 32]>,
}

/// Attachment structure.
/// Can be any payload.
///
#[derive(Serialize, Deserialize, Debug)]
pub struct Attachment {
    /// Useful data itself
    ///
    payload: Vec<u8>,
    /// Protocol specific type specifier.
    /// Defined per application.
    ///
    payload_type: Vec<u8>,
    /// ECDSA signature of rest of the Attachment.
    /// This proof is excluded from signature generation
    ///  and should not be included for correct verification.
    /// `current_sk` is used for signing from holding `Iml`.
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<[u8; 32]>,
}
