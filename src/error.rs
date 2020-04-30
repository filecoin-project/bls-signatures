use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Size mismatch")]
    SizeMismatch,
    #[error("Io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Group decode error: {0}")]
    GroupDecode(#[from] groupy::GroupDecodingError),
    #[error("Prime field decode error: {0}")]
    FieldDecode(#[from] ff::PrimeFieldDecodingError),
    #[error("Invalid Private Key")]
    InvalidPrivateKey,
}
