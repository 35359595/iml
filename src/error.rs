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
}

impl From<CborError> for Error {
    fn from(_: CborError) -> Self {
        Error::CborFailed
    }
}
