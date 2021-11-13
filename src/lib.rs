use serde::{Deserialize, Serialize};
mod getters;
mod packer;
mod processor;
pub use getters::*;
pub use packer::*;
pub use processor::*;
/// Inverted Microledger
///
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Iml {
    /// Blake 3 hash of current_sk, next_sk, current_dh, next_dh joined
    ///
    pub id: String,
    /// Indicates "age" of identifier.
    /// Is incremented on each evolution.
    /// Used to detect possible degradation on verification.
    ///
    civilization: u64,
    /// Current ECDSA signing public key
    ///
    current_sk: Vec<u8>,
    /// Next ECDSA signing public key
    ///
    next_sk: Vec<u8>,
    /// Current DH agreement public key
    ///
    current_dh: Vec<u8>,
    /// Next DH agreement public key
    ///
    next_dh: Vec<u8>,
    /// Any usefull payload.
    /// Is not included into verification of Iml, but
    ///  has proof of it's own internally, therefore
    ///  is not required to be consistantly present
    ///  within inverted microledger log for proper
    ///  verification.
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    attachments: Option<Vec<Attachment>>,
    /// Tthis property anchores attachment to the event.
    /// Mandatory field if any attachments were present.
    /// Stays in place even if attachments were withold
    ///  or moved to next evolution state.
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_of_attachments: Option<Vec<u8>>,
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
    proof: Option<Vec<u8>>,
}

/// Attachment structure.
/// Can be any payload.
///
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Attachment {
    /// `proof` of parent Iml
    ///
    parent: String,
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
    proof: Option<Vec<u8>>,
}
