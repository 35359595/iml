use chacha20poly1305::aead::Error as ChaChaError;
use serde_cbor::Error as CborError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("CBOR serialization/deserialization error")]
    CborFailed,
    #[error("ECDSA cryptography error")]
    EcdsaFailed,
    #[error("Key was already generated for given id")]
    KeyExistsForId,
    #[error("Key not found")]
    KeyNotFound,
    #[error("Key type is not supported (yet?)")]
    UnsupportedKeyType,
    #[error("Chacha crypto failed {0}")]
    Chacha(String),
}

impl From<CborError> for Error {
    fn from(_: CborError) -> Self {
        Error::CborFailed
    }
}

impl From<ChaChaError> for Error {
    fn from(value: ChaChaError) -> Self {
        Error::Chacha(value.to_string())
    }
}
