#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Linux kernel memory forensic walkers.
//!
//! Provides process, network connection, and kernel module enumeration
//! by walking kernel data structures in physical memory dumps.

pub mod arp;
pub mod bash;
pub mod boot_time;
pub mod bpf;
pub mod capabilities;
pub mod cgroups;
pub mod check_afinfo;
pub mod check_creds;
pub mod check_fops;
pub mod check_hooks;
pub mod check_idt;
pub mod check_modules;
pub mod cmdline;
pub mod container_escape;
pub mod correlate;
pub mod cpu_pinning;
pub mod crontab;
pub mod deleted_exe;
pub mod dentry_cache;
pub mod dmesg;
pub mod ebpf_progs;
pub mod elfinfo;
pub mod envvars;
pub mod files;
pub mod fs;
pub mod ftrace;
pub mod fuse_abuse;
pub mod futex_forensics;
pub mod io_uring;
pub mod iomem;
pub mod ipc;
pub mod kaslr;
pub mod kernel_timers;
pub mod keyboard_notifiers;
pub mod kmsg;
pub mod kthread;
pub mod ld_preload;
pub mod library_list;
pub mod malfind;
pub mod maps;
pub mod memfd_create;
pub mod modules;
pub mod modxview;
pub mod mountinfo;
pub mod namespaces;
pub mod netfilter;
pub mod netlink_audit;
pub mod network;
pub mod oom_events;
pub mod pam_hooks;
pub mod perf_event;
pub mod proc_hidden;
pub mod process;
pub mod psaux;
pub mod psxview;
pub mod ptrace;
pub mod raw_sockets;
pub mod seccomp;
pub mod shared_mem_anomaly;
pub mod signal_handlers;
pub mod ssh_keys;
pub mod syscalls;
pub mod systemd_units;
pub mod thread;
pub mod timerfd_signalfd;
pub mod tmpfs_recovery;
pub mod tty_check;
pub mod types;
pub mod unix_sockets;
pub mod user_ns_escalation;
pub mod vdso_tamper;
pub mod zombie_orphan;

#[cfg(test)]
pub mod testing;

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
    ///
    /// Prefer [`WalkFailed`] for new code.
    #[error("walker error: {0}")]
    Walker(String),

    /// A required kernel symbol was not found in the ISF.
    #[error("kernel symbol not found: {name}")]
    MissingKernelSymbol { name: String },

    /// A required struct field was not found in the ISF.
    #[error("ISF missing field: {struct_name}.{field_name}")]
    MissingField { struct_name: String, field_name: String },

    /// A walker-specific failure with context.
    #[error("walker '{walker}' failed: {reason}")]
    WalkFailed {
        /// Name of the walker; must be a `'static` string literal.
        walker: &'static str,
        reason: String,
    },

    /// A list walk failure with context.
    #[error("list walk failed in walker '{walker}': {reason}")]
    ListWalkFailed {
        /// Name of the walker; must be a `'static` string literal.
        walker: &'static str,
        reason: String,
    },
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

    #[test]
    fn error_missing_kernel_symbol_contains_name() {
        let e = Error::MissingKernelSymbol { name: "init_task".to_owned() };
        assert!(e.to_string().contains("init_task"));
    }

    #[test]
    fn error_missing_field_contains_struct_and_field() {
        let e = Error::MissingField {
            struct_name: "task_struct".to_owned(),
            field_name: "mm".to_owned(),
        };
        assert!(e.to_string().contains("task_struct"));
        assert!(e.to_string().contains("mm"));
    }

    #[test]
    fn error_walk_failed_contains_walker_name() {
        let e = Error::WalkFailed {
            walker: "walk_processes",
            reason: "list corrupted".to_owned(),
        };
        assert!(e.to_string().contains("walk_processes"));
        assert!(e.to_string().contains("list corrupted"));
    }

    #[test]
    fn error_list_walk_failed_contains_walker_and_reason() {
        let e = Error::ListWalkFailed {
            walker: "walk_processes",
            reason: "cycle detected".to_owned(),
        };
        assert!(e.to_string().contains("walk_processes"));
        assert!(e.to_string().contains("cycle detected"));
    }
}
