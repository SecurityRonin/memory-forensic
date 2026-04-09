//! Suspicious thread detection for injection analysis.
//!
//! Detects threads with anomalous characteristics indicative of code injection:
//! - Threads with start addresses in unbacked/RWX memory
//! - Orphan threads (not associated with any loaded module)
//! - Threads whose start address doesn't match any known DLL
//!
//! These indicators reveal when malware injects code into a legitimate process
//! and spawns threads to execute it. Common techniques like process hollowing,
//! DLL injection, and shellcode injection leave distinctive thread artifacts.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

/// Information about a suspicious thread detected during injection analysis.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SuspiciousThreadInfo {
    /// Process ID owning this thread.
    pub pid: u32,
    /// Name of the owning process.
    pub process_name: String,
    /// Thread ID.
    pub tid: u32,
    /// Thread start address (`Win32StartAddress`).
    pub start_address: u64,
    /// Which DLL contains the start address, or "unknown".
    pub start_module: String,
    /// Start address not in any loaded module.
    pub is_orphan: bool,
    /// Start address falls within a read-write-execute VAD region.
    pub in_rwx_memory: bool,
    /// Thread belongs to a system process.
    pub is_system_thread: bool,
    /// Human-readable reason why this thread was flagged.
    pub reason: String,
    /// Whether this thread is classified as suspicious.
    pub is_suspicious: bool,
}

/// System processes where orphan threads are highly suspicious.
const SYSTEM_PROCESSES: &[&str] = &[
    "csrss.exe",
    "smss.exe",
    "services.exe",
    "lsass.exe",
    "wininit.exe",
    "svchost.exe",
];

/// DLLs commonly used as injection targets / trampolines.
const KNOWN_INJECTION_TARGETS: &[&str] = &[
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
];

/// Classify whether a thread is suspicious based on its characteristics.
///
/// Returns `(is_suspicious, reason)` where `reason` is a human-readable
/// explanation of why the thread was flagged.
///
/// Classification rules (in priority order):
/// 1. Orphan thread in a system process -> highly suspicious
/// 2. Thread in RWX memory -> suspicious
/// 3. Orphan thread (start address in no module) -> suspicious
/// 4. Known injection target DLL with orphan -> suspicious
/// 5. Normal thread in a known module -> benign
pub fn classify_suspicious_thread(
    start_module: &str,
    is_orphan: bool,
    in_rwx_memory: bool,
    process_name: &str,
) -> (bool, String) {
    let proc_lower = process_name.to_lowercase();
    let is_system = SYSTEM_PROCESSES.iter().any(|&s| proc_lower == s);

    // Rule 1: System process with orphan thread -> highly suspicious
    if is_orphan && is_system {
        return (
            true,
            format!(
                "orphan thread in system process {}; thread start address not in any loaded module",
                process_name
            ),
        );
    }

    // Rule 2: Thread starts in RWX memory -> suspicious
    if in_rwx_memory {
        return (
            true,
            "thread starts in read-write-execute memory".to_string(),
        );
    }

    // Rule 3: Orphan thread (start address not in any module)
    if is_orphan {
        return (
            true,
            "thread start address not in any loaded module".to_string(),
        );
    }

    // Rule 4: Known injection target with orphan status
    // (This is a secondary check: if we reach here, is_orphan is false,
    //  but start_module is a common injection target — only flag if
    //  combined with other signals. Since is_orphan is false here,
    //  this combination doesn't apply. Keep for clarity.)
    let _mod_lower = start_module.to_lowercase();
    if KNOWN_INJECTION_TARGETS
        .iter()
        .any(|&t| _mod_lower == t)
        && is_orphan
    {
        return (
            true,
            format!(
                "thread in known injection target {} with orphan status",
                start_module
            ),
        );
    }

    // Rule 5: Normal thread in a known module -> benign
    (false, String::new())
}

/// Walk all processes and detect threads with suspicious characteristics.
///
/// For each process, walks the thread list and compares each thread's
/// start address against the process's loaded DLL address ranges (from
/// PEB LDR) and checks VAD protection for the containing region.
///
/// Returns only threads that are flagged as suspicious.
/// Returns `Ok(Vec::new())` if required symbols are missing (graceful degradation).
pub fn walk_suspicious_threads<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<SuspiciousThreadInfo>> {
    // Graceful degradation: check for required symbol
    let Some(_ps_head) = reader.symbols().symbol_address("PsActiveProcessHead") else {
        return Ok(Vec::new());
    };

    todo!("walk_suspicious_threads: implement process/thread iteration with DLL and VAD checks")
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ---------------------------------------------------------------
    // classify_suspicious_thread tests
    // ---------------------------------------------------------------

    #[test]
    fn orphan_thread_suspicious() {
        let (suspicious, reason) =
            classify_suspicious_thread("unknown", true, false, "notepad.exe");
        assert!(suspicious, "orphan thread should be suspicious");
        assert!(
            reason.contains("not in any loaded module"),
            "reason should mention orphan: {reason}"
        );
    }

    #[test]
    fn rwx_memory_suspicious() {
        let (suspicious, reason) =
            classify_suspicious_thread("ntdll.dll", false, true, "explorer.exe");
        assert!(suspicious, "RWX memory thread should be suspicious");
        assert!(
            reason.contains("read-write-execute"),
            "reason should mention RWX: {reason}"
        );
    }

    #[test]
    fn normal_module_benign() {
        let (suspicious, reason) =
            classify_suspicious_thread("kernel32.dll", false, false, "notepad.exe");
        assert!(!suspicious, "normal thread in known module should be benign");
        assert!(reason.is_empty(), "benign reason should be empty: {reason}");
    }

    #[test]
    fn system_process_orphan_suspicious() {
        let (suspicious, reason) =
            classify_suspicious_thread("unknown", true, false, "csrss.exe");
        assert!(
            suspicious,
            "orphan thread in system process should be suspicious"
        );
        assert!(
            reason.contains("system process"),
            "reason should mention system process: {reason}"
        );
        assert!(
            reason.contains("csrss.exe"),
            "reason should name the process: {reason}"
        );
    }

    #[test]
    fn known_injection_target_suspicious() {
        // Orphan thread in a known injection target DLL context.
        // When is_orphan=true and start_module is a known target,
        // the orphan rule fires first.
        let (suspicious, reason) =
            classify_suspicious_thread("ntdll.dll", true, false, "notepad.exe");
        assert!(
            suspicious,
            "orphan thread with injection target should be suspicious"
        );
        assert!(
            reason.contains("not in any loaded module"),
            "reason should explain orphan: {reason}"
        );
    }

    #[test]
    fn empty_module_benign() {
        // Thread with empty start_module but not orphan and not RWX -> benign
        let (suspicious, reason) = classify_suspicious_thread("", false, false, "notepad.exe");
        assert!(
            !suspicious,
            "non-orphan thread with empty module should be benign"
        );
        assert!(reason.is_empty(), "benign reason should be empty: {reason}");
    }

    #[test]
    fn rwx_overrides_known_module() {
        // Even if thread is in a known module, RWX memory is suspicious
        let (suspicious, reason) =
            classify_suspicious_thread("kernel32.dll", false, true, "notepad.exe");
        assert!(
            suspicious,
            "RWX memory should be suspicious even in known module"
        );
        assert!(
            reason.contains("read-write-execute"),
            "reason should mention RWX: {reason}"
        );
    }

    // ---------------------------------------------------------------
    // walk_suspicious_threads tests
    // ---------------------------------------------------------------

    #[test]
    fn walk_suspicious_threads_no_symbol() {
        // IsfBuilder::new() has no PsActiveProcessHead symbol -> empty Vec.
        let isf = IsfBuilder::new()
            .add_struct("_EPROCESS", 0x1000)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_suspicious_threads(&reader).unwrap();
        assert!(
            result.is_empty(),
            "should return empty Vec when PsActiveProcessHead symbol is missing"
        );
    }
}
