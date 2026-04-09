//! Linux ptrace relationship detection for debugging/injection analysis.
//!
//! `ptrace` is the Linux debugging/tracing syscall. Attackers use it for
//! process injection (`PTRACE_POKETEXT`), anti-debugging (tracing themselves),
//! and credential theft (intercepting syscalls of privileged processes).
//!
//! This module detects active ptrace relationships by inspecting
//! `task_struct.ptrace` flags and comparing `parent` vs `real_parent`
//! pointers (ptrace reparents the tracee under the tracer).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{ProcessInfo, Result};

// ---------------------------------------------------------------------------
// Known debugger process names (benign tracers)
// ---------------------------------------------------------------------------

/// Well-known debugger/tracer binaries that are expected to ptrace.
const KNOWN_DEBUGGERS: &[&str] = &[
    "gdb", "lldb", "strace", "ltrace", "valgrind", "perf",
];

/// High-value target processes -- tracing these by a non-debugger is suspicious.
const HIGH_VALUE_TARGETS: &[&str] = &[
    "sshd", "login", "passwd", "sudo", "su", "gpg-agent",
];

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A detected ptrace relationship between a tracer and a tracee process.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PtraceRelationship {
    /// PID of the tracing process.
    pub tracer_pid: u32,
    /// Name of the tracer process.
    pub tracer_name: String,
    /// PID of the traced process.
    pub tracee_pid: u32,
    /// Name of the traced (target) process.
    pub tracee_name: String,
    /// Heuristic flag: true if this relationship looks suspicious.
    pub is_suspicious: bool,
}

// ---------------------------------------------------------------------------
// Classifier
// ---------------------------------------------------------------------------

/// Classify whether a ptrace relationship is suspicious.
///
/// Rules:
/// - Known debuggers (`gdb`, `lldb`, `strace`, `ltrace`, `valgrind`, `perf`)
///   tracing anything are **benign**.
/// - A non-debugger tracing a high-value target (`sshd`, `login`, `passwd`,
///   `sudo`, `su`, `gpg-agent`) is **suspicious**.
/// - Self-tracing (tracer name == tracee name) by a non-debugger is
///   **suspicious** (common anti-debug technique).
/// - An empty tracer name is **suspicious** (hidden/corrupt process).
/// - All other cases are **benign** (normal process tracing normal process).
pub fn classify_ptrace(tracer_name: &str, tracee_name: &str) -> bool {
    // Empty tracer name is always suspicious (hidden/corrupt process).
    if tracer_name.is_empty() {
        return true;
    }

    // Known debuggers tracing anything are benign.
    if KNOWN_DEBUGGERS.iter().any(|&d| d == tracer_name) {
        return false;
    }

    // Non-debugger tracing a high-value target is suspicious.
    if HIGH_VALUE_TARGETS.iter().any(|&t| t == tracee_name) {
        return true;
    }

    // Self-tracing by a non-debugger is suspicious (anti-debug technique).
    if tracer_name == tracee_name {
        return true;
    }

    // Normal process tracing a normal process -- benign.
    false
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

/// Scan for active ptrace relationships across the given process list.
///
/// For each process, reads `task_struct.ptrace` (u32 flags). If nonzero the
/// process is being traced. The tracer is identified by comparing
/// `task_struct.parent` (current parent, may be reparented by ptrace) against
/// `task_struct.real_parent` (biological parent). When they differ, `parent`
/// is the tracer.
///
/// Returns an empty `Vec` if the process list is empty.
pub fn scan_ptrace_relationships<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    processes: &[ProcessInfo],
) -> Result<Vec<PtraceRelationship>> {
    if processes.is_empty() {
        return Ok(Vec::new());
    }

    let mut results = Vec::new();

    for proc in processes {
        match read_ptrace_info(reader, proc) {
            Ok(Some(rel)) => results.push(rel),
            Ok(None) => continue,     // not being traced
            Err(_) => continue,       // unreadable task_struct, skip
        }
    }

    Ok(results)
}

/// Read ptrace information from a single process's `task_struct`.
///
/// Returns `Ok(None)` if the process is not being traced (`ptrace` flags == 0).
fn read_ptrace_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    proc: &ProcessInfo,
) -> Result<Option<PtraceRelationship>> {
    // Read task_struct.ptrace (u32 flags) -- nonzero means being traced.
    let ptrace_flags: u32 = reader.read_field(proc.vaddr, "task_struct", "ptrace")?;
    if ptrace_flags == 0 {
        return Ok(None);
    }

    // Compare parent vs real_parent to identify the tracer.
    // ptrace reparents the tracee: parent becomes the tracer while
    // real_parent remains the biological parent.
    let parent_ptr: u64 = reader.read_pointer(proc.vaddr, "task_struct", "parent")?;
    let real_parent_ptr: u64 =
        reader.read_pointer(proc.vaddr, "task_struct", "real_parent")?;

    if parent_ptr == real_parent_ptr || parent_ptr == 0 {
        // No reparenting detected or parent is NULL -- can't identify tracer.
        return Ok(None);
    }

    // The parent (tracer) task_struct: read its PID and comm.
    let tracer_pid: u32 =
        reader.read_field::<u64>(parent_ptr, "task_struct", "pid")? as u32;
    let tracer_name =
        reader.read_field_string(parent_ptr, "task_struct", "comm", 16)?;

    let tracee_name = proc.comm.clone();
    let is_suspicious = classify_ptrace(&tracer_name, &tracee_name);

    Ok(Some(PtraceRelationship {
        tracer_pid,
        tracer_name,
        tracee_pid: proc.pid as u32,
        tracee_name,
        is_suspicious,
    }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    /// Helper: build a minimal ProcessInfo for testing.
    #[allow(dead_code)]
    fn fake_process(pid: u64, comm: &str, vaddr: u64) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: 1,
            comm: comm.to_string(),
            state: crate::types::ProcessState::Running,
            vaddr,
            cr3: None,
            start_time: 0,
        }
    }

    // -----------------------------------------------------------------------
    // classify_ptrace tests
    // -----------------------------------------------------------------------

    #[test]
    fn classify_gdb_tracing_anything_is_benign() {
        assert!(
            !classify_ptrace("gdb", "target_app"),
            "gdb is a known debugger; tracing anything should be benign"
        );
    }

    #[test]
    fn classify_strace_tracing_bash_is_benign() {
        assert!(
            !classify_ptrace("strace", "bash"),
            "strace is a known debugger; tracing bash should be benign"
        );
    }

    #[test]
    fn classify_unknown_tracing_sshd_is_suspicious() {
        assert!(
            classify_ptrace("evil_inject", "sshd"),
            "non-debugger tracing sshd (high-value target) should be suspicious"
        );
    }

    #[test]
    fn classify_unknown_tracing_passwd_is_suspicious() {
        assert!(
            classify_ptrace("malware", "passwd"),
            "non-debugger tracing passwd (high-value target) should be suspicious"
        );
    }

    #[test]
    fn classify_self_tracing_by_non_debugger_is_suspicious() {
        assert!(
            classify_ptrace("sneaky", "sneaky"),
            "self-tracing by a non-debugger is an anti-debug technique; should be suspicious"
        );
    }

    #[test]
    fn classify_empty_tracer_name_is_suspicious() {
        assert!(
            classify_ptrace("", "victim"),
            "empty tracer name indicates hidden/corrupt process; should be suspicious"
        );
    }

    #[test]
    fn classify_normal_process_tracing_normal_process_is_benign() {
        assert!(
            !classify_ptrace("my_app", "helper_proc"),
            "normal process tracing a non-high-value target should be benign"
        );
    }

    // -----------------------------------------------------------------------
    // scan_ptrace_relationships tests
    // -----------------------------------------------------------------------

    #[test]
    fn scan_ptrace_empty_processes_returns_empty_vec() {
        let isf = IsfBuilder::new();
        let ptb = PageTableBuilder::new();
        let reader = make_reader(&isf, ptb);

        let result = scan_ptrace_relationships(&reader, &[]).unwrap();
        assert!(
            result.is_empty(),
            "expected empty vec for empty process list"
        );
    }
}
