#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Linux kernel memory forensic walkers.
//!
//! Provides process, network connection, and kernel module enumeration
//! by walking kernel data structures in physical memory dumps.

pub mod arp;
pub mod bash;
pub mod bpf;
pub mod ebpf_progs;
pub mod ftrace;
pub mod keyboard_notifiers;
pub mod kmsg;
pub mod mountinfo;
pub mod boot_time;
pub mod capabilities;
pub mod cgroups;
pub mod check_afinfo;
pub mod check_creds;
pub mod check_fops;
pub mod check_hooks;
pub mod check_idt;
pub mod check_modules;
pub mod cmdline;
pub mod crontab;
pub mod deleted_exe;
pub mod dmesg;
pub mod elfinfo;
pub mod envvars;
pub mod files;
pub mod fs;
pub mod iomem;
pub mod ipc;
pub mod kthread;
pub mod kaslr;
pub mod kernel_timers;
pub mod library_list;
pub mod ld_preload;
pub mod malfind;
pub mod maps;
pub mod modules;
pub mod modxview;
pub mod namespaces;
pub mod netfilter;
pub mod network;
pub mod process;
pub mod psaux;
pub mod ptrace;
pub mod psxview;
pub mod seccomp;
pub mod signal_handlers;
pub mod ssh_keys;
pub mod syscalls;
pub mod thread;
pub mod tty_check;
pub mod unix_sockets;
pub mod zombie_orphan;
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
