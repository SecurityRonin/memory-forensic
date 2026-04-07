#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Linux kernel memory forensic walkers.
//!
//! Provides process, network connection, and kernel module enumeration
//! by walking kernel data structures in physical memory dumps.

pub mod bash;
pub mod check_hooks;
pub mod check_modules;
pub mod cmdline;
pub mod elfinfo;
pub mod envvars;
pub mod files;
pub mod fs;
pub mod kaslr;
pub mod malfind;
pub mod maps;
pub mod modules;
pub mod network;
pub mod process;
pub mod psxview;
pub mod syscalls;
pub mod thread;
pub mod tty_check;
pub mod types;

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

pub use types::*;

/// Error type for memf-linux operations.
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

/// A Result alias for memf-linux.
pub type Result<T> = std::result::Result<T, Error>;

/// A plugin that walks Linux kernel data structures.
///
/// Implementations provide specific enumeration logic (processes,
/// connections, modules) using an [`ObjectReader`] for memory access.
pub trait WalkerPlugin: Send + Sync {
    /// Human-readable name of this walker.
    fn name(&self) -> &str;

    /// Probe whether this walker can operate on the current memory image.
    /// Returns a confidence score 0-100.
    fn probe<P: PhysicalMemoryProvider>(&self, reader: &ObjectReader<P>) -> u8;

    /// Enumerate running processes.
    fn processes<P: PhysicalMemoryProvider>(
        &self,
        reader: &ObjectReader<P>,
    ) -> Result<Vec<ProcessInfo>>;

    /// Enumerate network connections.
    fn connections<P: PhysicalMemoryProvider>(
        &self,
        reader: &ObjectReader<P>,
    ) -> Result<Vec<ConnectionInfo>>;

    /// Enumerate loaded kernel modules.
    fn modules<P: PhysicalMemoryProvider>(
        &self,
        reader: &ObjectReader<P>,
    ) -> Result<Vec<ModuleInfo>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        let e = Error::Walker("test error".into());
        assert_eq!(e.to_string(), "walker error: test error");
    }
}
