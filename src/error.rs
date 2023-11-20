use serde_cbor::Error as CborError;
use static_dh_ecdh::CryptoError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("CBOR serialization/deserialization error")]
    CborFailed,
    #[error("ECDSA cryptography error")]
    EcdsaFailed,
    #[error("ECDH Cryptography error")]
    ECDHCryptoError,
    #[error("Key was already generated for given id")]
    KeyExistsForId,
    #[error("Key not found")]
    KeyNotFound,
    #[error("Key type is not supported (yet?)")]
    UnsupportedKeyType,
    #[error("Incorrect did string")]
    NotADid,
    #[error("Incorrect did IML string")]
    NotAnIml,
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    HexError(#[from] hex::FromHexError),
}

impl From<CborError> for Error {
    fn from(_: CborError) -> Self {
        Error::CborFailed
    }
}

impl From<CryptoError> for Error {
    fn from(_: CryptoError) -> Self {
        Error::ECDHCryptoError
    }
}
