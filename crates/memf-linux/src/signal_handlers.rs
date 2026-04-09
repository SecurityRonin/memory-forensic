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
/// Number of standard POSIX signals to inspect (1-31).
const MAX_SIGNALS: u32 = 31;

/// Walk signal handlers for all processes found via the `init_task` list.
pub fn walk_signal_handlers<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<SignalHandlerInfo>> {
    // Resolve init_task symbol to start walking the task list.
    let init_task_addr = match reader.symbols().symbol_address("init_task") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    // Resolve task_struct.tasks for the linked list walk.
    let tasks_offset = match reader.symbols().field_offset("task_struct", "tasks") {
        Some(off) => off,
        None => return Ok(Vec::new()),
    };

    // Resolve sighand_struct.action (array of k_sigaction).
    let action_offset = match reader.symbols().field_offset("sighand_struct", "action") {
        Some(off) => off,
        None => return Ok(Vec::new()),
    };

    // Resolve k_sigaction size for array stride.
    let k_sigaction_size = match reader.symbols().struct_size("k_sigaction") {
        Some(s) if s > 0 => s,
        _ => return Ok(Vec::new()),
    };

    // Walk the task list.
    let head_vaddr = init_task_addr + tasks_offset;
    let task_addrs = reader.walk_list(head_vaddr, "task_struct", "tasks")?;

    let mut results = Vec::new();

    // Process init_task and all tasks in the list.
    let all_tasks = std::iter::once(init_task_addr).chain(task_addrs.iter().copied());

    for task_addr in all_tasks {
        // Read pid and comm for this task.
        let pid: u32 = match reader.read_field(task_addr, "task_struct", "pid") {
            Ok(p) => p,
            Err(_) => continue,
        };
        let comm = reader
            .read_field_string(task_addr, "task_struct", "comm", 16)
            .unwrap_or_default();

        // Read the sighand pointer.
        let sighand_ptr: u64 = match reader.read_field(task_addr, "task_struct", "sighand") {
            Ok(p) => p,
            Err(_) => continue,
        };
        if sighand_ptr == 0 {
            continue;
        }

        let action_base = sighand_ptr + action_offset;

        // Iterate over signals 1-31.
        for sig in 1..=MAX_SIGNALS {
            // Each k_sigaction entry: action_base + (sig - 1) * k_sigaction_size.
            // k_sigaction embeds sigaction at offset 0; sa_handler is resolved
            // by read_field via the "sigaction"/"sa_handler" symbol pair.
            let entry_addr = action_base + u64::from(sig - 1) * k_sigaction_size;

            let sa_handler: u64 = reader
                .read_field(entry_addr, "sigaction", "sa_handler")
                .unwrap_or(0);

            let suspicious = classify_signal_handler(sig, sa_handler);
            if suspicious {
                results.push(SignalHandlerInfo {
                    pid,
                    comm: comm.clone(),
                    signal: sig,
                    signal_name: signal_name(sig).to_string(),
                    handler: sa_handler,
                    handler_type: handler_type(sa_handler),
                    is_suspicious: true,
                });
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder};
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

        let result = walk_signal_handlers(&reader).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn walk_sigterm_ignored_detected() {
        // Set up a single process with SIGTERM handler set to SIG_IGN (1).
        let init_task_vaddr: u64 = 0xFFFF_8800_0000_0000;
        let init_task_paddr: u64 = 0x0010_0000;

        // Layout constants.
        let tasks_offset: u64 = 776;
        let pid_offset: u64 = 872;
        let comm_offset: u64 = 1496;
        let sighand_field_offset: u64 = 1600;

        let sighand_vaddr: u64 = 0xFFFF_8800_0010_0000;
        let sighand_paddr: u64 = 0x0020_0000;
        let action_offset: u64 = 0;
        let k_sigaction_size: u64 = 152;

        // SIGTERM is signal 15 -> action[14] (0-indexed).
        let sigterm_entry_paddr =
            sighand_paddr + action_offset + u64::from(15u32 - 1) * k_sigaction_size;

        let isf = IsfBuilder::new()
            .add_symbol("init_task", init_task_vaddr)
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_struct("task_struct", 2048)
            .add_field("task_struct", "tasks", tasks_offset, "list_head")
            .add_field("task_struct", "pid", pid_offset, "int")
            .add_field("task_struct", "comm", comm_offset, "char")
            .add_field("task_struct", "sighand", sighand_field_offset, "pointer")
            .add_struct("sighand_struct", 4864)
            .add_field("sighand_struct", "action", action_offset, "k_sigaction")
            .add_struct("k_sigaction", k_sigaction_size)
            .add_struct("sigaction", 152)
            .add_field("sigaction", "sa_handler", 0, "pointer");

        // Build the page tables. The task list is circular: tasks.next points
        // back to &init_task.tasks so walk_list returns empty (only init_task).
        let tasks_vaddr = init_task_vaddr + tasks_offset;

        let ptb = PageTableBuilder::new()
            // Map init_task pages (need enough for comm at offset 1496+)
            .map_4k(init_task_vaddr, init_task_paddr, flags::WRITABLE)
            .map_4k(
                init_task_vaddr + 0x1000,
                init_task_paddr + 0x1000,
                flags::WRITABLE,
            )
            // Map sighand_struct pages (need space for action array)
            .map_4k(sighand_vaddr, sighand_paddr, flags::WRITABLE)
            .map_4k(
                sighand_vaddr + 0x1000,
                sighand_paddr + 0x1000,
                flags::WRITABLE,
            )
            .map_4k(
                sighand_vaddr + 0x2000,
                sighand_paddr + 0x2000,
                flags::WRITABLE,
            )
            // task_struct.tasks.next -> points back to itself (circular)
            .write_phys_u64(init_task_paddr + tasks_offset, tasks_vaddr)
            // task_struct.pid = 666
            .write_phys_u64(init_task_paddr + pid_offset, 666)
            // task_struct.comm = "malware\0"
            .write_phys(init_task_paddr + comm_offset, b"malware\0")
            // task_struct.sighand = pointer to sighand_struct
            .write_phys_u64(init_task_paddr + sighand_field_offset, sighand_vaddr)
            // SIGTERM (signal 15) sa_handler = 1 (SIG_IGN)
            .write_phys_u64(sigterm_entry_paddr, 1u64);

        let reader = make_reader(&isf, ptb);
        let result = walk_signal_handlers(&reader).unwrap();

        // Should detect SIGTERM being ignored as suspicious.
        assert!(!result.is_empty(), "expected at least one suspicious entry");

        let sigterm_entry = result.iter().find(|e| e.signal == 15);
        assert!(sigterm_entry.is_some(), "expected SIGTERM entry");

        let entry = sigterm_entry.unwrap();
        assert_eq!(entry.pid, 666);
        assert_eq!(entry.comm, "malware");
        assert_eq!(entry.signal_name, "SIGTERM");
        assert_eq!(entry.handler, 1);
        assert_eq!(entry.handler_type, "SIG_IGN");
        assert!(entry.is_suspicious);
    }
}
