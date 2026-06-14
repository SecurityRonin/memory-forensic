//! DPAPI decryption utilities for Windows memory forensics.

pub mod chrome;
pub mod dpapi_blob;
pub mod decrypt;

#[derive(Debug, thiserror::Error)]
pub enum DpapiError {
    #[error("data too short: need at least {needed} bytes, got {got}")]
    TooShort { needed: usize, got: usize },
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u32),
    #[error("unsupported algorithm ID: {0:#010x}")]
    UnsupportedAlgId(u32),
    #[error("invalid key or IV length")]
    InvalidKeyLength,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("HMAC verification failed")]
    HmacMismatch,
    #[error("UTF-16 decode error")]
    Utf16Error,
}
