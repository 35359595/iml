use serde_cbor::Error as CborError;

pub enum Error {
    CborFailed,
    EcdsaFailed,
}

impl From<CborError> for Error {
    fn from(_: CborError) -> Self {
        Error::CborFailed
    }
}
