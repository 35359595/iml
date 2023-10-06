use serde::{Deserialize, Serialize};
pub mod error;
mod getters;
mod packer;
mod processor;
mod wallet;
pub use getters::*;
pub use packer::*;
pub use processor::*;
pub(crate) use wallet::*;

#[cfg(test)]
mod tests;

/// Inverted Microledger
///
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct Iml {
    /// Blake 3 hash of first sk of the identifier.
    /// Never attached to higher level Imls.
    /// Can be resolved only if full Iml recoursion is parsable.
    ///
    /// Additionally used during interaction on public Iml to identify
    ///  recepient's Public key for KeyAgreement.
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Indicates "age" of identifier.
    /// Is incremented on each evolution.
    /// Used to detect possible degradation on verification.
    ///
    civilization: u64,
    /// Current ECDSA signing public key
    ///
    current_sk: [u8; 32],
    /// Next ECDSA signing public key
    ///
    next_sk: [u8; 32],
    /// Diffie-Hellman public key for shared secret generation
    ecdh: [u8; 32],
    /// Current interaction DH agreement public key
    /// If this property is present - `id` pionts out
    ///  which key to use to generate shared secret.
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    interaction_key: Option<Vec<u8>>,
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
    /// This field is not been signed in proof generation process.
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    inversion: Option<Vec<u8>>,
    /// ECDSA signature of rest of the Iml this proof and attachments excluded
    ///
    proof: [u8; 32],
}

/// Attachment structure.
/// Can be any payload.
///
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct Attachment {
    /// `proof` of parent Iml
    /// As attachments can be delivered separately from IML - we use parent's
    /// signature as proof of origin
    ///
    parent: [u8; 32],
    /// Blake3 256 bit hash of data been interacted upon
    ///
    payload: [u8; 32],
    /// Identifies type of the attachment
    ///
    payload_type: PayloadType,
    /// ECDSA signature of rest of the Attachment.
    /// This proof is excluded from signature generation
    ///  and should not be included for correct verification.
    /// `current_sk` is used for signing from holding `Iml`.
    ///
    proof: [u8; 32],
}

/// Types of accepted payloads within IML
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub enum PayloadType {
    /// Used as satelite owner/origin identifying attachment to unique created content
    Content,
    /// Identifies interaction seal with other IML[s]
    Interaction,
    /// Any bytes blob of whatever
    #[default]
    Blob,
}
