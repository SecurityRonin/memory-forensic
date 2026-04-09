//! Linux process signal handler inspection for malware detection.
//!
//! Inspects signal handlers for each process. Malware sometimes installs
//! custom signal handlers to prevent termination (ignoring SIGTERM/SIGKILL),
//! restart on SIGSEGV, or communicate via signals (SIGUSR1/SIGUSR2).
//! MITRE ATT&CK T1036.
//!
//! The kernel stores signal handling state in `task_struct.sighand`, which
//! points to a `sighand_struct` containing an array of `k_sigaction` entries
//! (one per signal, 1-31 for standard signals). Each `k_sigaction` contains
//! a `sigaction` struct with an `sa_handler` field:
//! - 0 (`SIG_DFL`): default handler
//! - 1 (`SIG_IGN`): signal is ignored
//! - other: address of a custom signal handler function

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Signal handler information extracted from a process's `task_struct`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SignalHandlerInfo {
    /// Process ID.
    pub pid: u32,
    /// Process command name.
    pub comm: String,
    /// Signal number (1-31).
    pub signal: u32,
    /// Human-readable signal name (e.g., "SIGTERM").
    pub signal_name: String,
    /// Raw `sa_handler` value from the kernel.
    pub handler: u64,
    /// Handler type description: "SIG_DFL", "SIG_IGN", or hex address.
    pub handler_type: String,
    /// Whether this signal handler configuration is suspicious.
    pub is_suspicious: bool,
}

/// Map a signal number to its human-readable name.
///
/// Covers the standard POSIX signals relevant to forensic analysis.
/// Returns `"UNKNOWN"` for unrecognised signal numbers.
pub fn signal_name(sig: u32) -> &'static str {
    match sig {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        6 => "SIGABRT",
        9 => "SIGKILL",
        10 => "SIGUSR1",
        11 => "SIGSEGV",
        12 => "SIGUSR2",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        17 => "SIGCHLD",
        _ => "UNKNOWN",
    }
}

/// Describe the handler type based on the raw `sa_handler` value.
///
/// - `0` maps to `"SIG_DFL"` (default disposition).
/// - `1` maps to `"SIG_IGN"` (signal ignored).
/// - Any other value is formatted as a 16-digit hex address.
pub fn handler_type(handler: u64) -> String {
    match handler {
        0 => "SIG_DFL".to_string(),
        1 => "SIG_IGN".to_string(),
        _ => format!("0x{:016x}", handler),
    }
}

/// Classify whether a signal handler configuration is suspicious.
///
/// A handler is considered suspicious if:
/// - SIGTERM (15) or SIGHUP (1) is set to `SIG_IGN` (1) -- process resists
///   termination, common in persistent malware.
/// - SIGSEGV (11) has a custom handler (not `SIG_DFL` or `SIG_IGN`) --
///   self-healing malware that catches segfaults to restart or re-inject.
/// - SIGKILL (9) has been tampered with (any non-default handler) --
///   impossible under normal circumstances, indicates kernel-level rootkit.
pub fn classify_signal_handler(signal: u32, handler: u64) -> bool {
    match signal {
        // SIGTERM or SIGHUP ignored -> anti-termination
        15 | 1 => handler == 1,
        // SIGSEGV with custom handler -> self-healing malware
        11 => handler != 0 && handler != 1,
        // SIGKILL tampered -> kernel rootkit (normally impossible)
        9 => handler != 0,
        _ => false,
    }
}

/// Walk signal handlers for all processes found via the `init_task` list.
///
/// For each process, reads `task_struct.sighand` to locate the
/// `sighand_struct`, then iterates over the `action` array (signals 1-31).
/// For each signal, reads the `sa_handler` field from the `sigaction`
/// struct embedded in each `k_sigaction` entry. Only entries classified
/// as suspicious by [`classify_signal_handler`] are included in the
/// output.
///
/// Returns `Ok(Vec::new())` if the required symbols (`init_task`,
/// `sighand_struct.action`, etc.) are missing from the profile.
pub fn walk_signal_handlers<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
) -> Result<Vec<SignalHandlerInfo>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Helper: create an ObjectReader from ISF and page table builders.
    fn make_reader(
        isf: &IsfBuilder,
        builder: PageTableBuilder,
    ) -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let json = isf.build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();
        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn signal_name_sigterm() {
        assert_eq!(signal_name(15), "SIGTERM");
    }

    #[test]
    fn signal_name_unknown() {
        assert_eq!(signal_name(99), "UNKNOWN");
    }

    #[test]
    fn handler_default() {
        assert_eq!(handler_type(0), "SIG_DFL");
    }

    #[test]
    fn handler_ignore() {
        assert_eq!(handler_type(1), "SIG_IGN");
    }

    #[test]
    fn classify_sigterm_ignored_suspicious() {
        // SIGTERM (15) with SIG_IGN (1) should be suspicious.
        assert!(classify_signal_handler(15, 1));
        // SIGTERM with SIG_DFL should NOT be suspicious.
        assert!(!classify_signal_handler(15, 0));
        // SIGTERM with a custom handler should NOT be suspicious
        // (only SIG_IGN is flagged for SIGTERM).
        assert!(!classify_signal_handler(15, 0xFFFF_8000_0001_0000));
    }

    #[test]
    fn classify_sigsegv_handler_suspicious() {
        // SIGSEGV (11) with a custom handler is suspicious (self-healing).
        assert!(classify_signal_handler(11, 0xFFFF_8000_0001_0000));
        // SIGSEGV with SIG_DFL is NOT suspicious.
        assert!(!classify_signal_handler(11, 0));
        // SIGSEGV with SIG_IGN is NOT suspicious (just ignoring it).
        assert!(!classify_signal_handler(11, 1));
    }

    #[test]
    fn walk_no_symbol_returns_empty() {
        // When required symbols are missing, walk should return empty Vec.
        let isf = IsfBuilder::new();
        let ptb = PageTableBuilder::new();
        let reader = make_reader(&isf, ptb);

        let result = walk_signal_handlers(&reader);
        // With todo!(), this will panic -- that's the RED phase.
        // Once implemented, missing init_task should return Ok(vec![]).
        assert!(result.unwrap().is_empty());
    }
}
