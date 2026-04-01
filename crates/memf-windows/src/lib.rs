#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Windows kernel memory forensic walkers.
//!
//! Provides process, thread, driver, and DLL enumeration
//! by walking Windows NT kernel data structures in physical memory dumps.

pub mod process;
pub mod types;

pub use types::*;

/// Error type for memf-windows operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Core memory reading error.
    #[error("core error: {0}")]
    Core(#[from] memf_core::Error),

    /// Symbol resolution error.
    #[error("symbol error: {0}")]
    Symbol(#[from] memf_symbols::Error),

    /// Walker-specific error.
    #[error("walker error: {0}")]
    Walker(String),
}

/// A Result alias for memf-windows.
pub type Result<T> = std::result::Result<T, Error>;
