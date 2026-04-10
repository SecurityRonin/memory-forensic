//! Linux kernel thread enumeration and anomaly detection.
//!
//! Enumerates kernel threads and flags suspicious ones. Rootkits commonly
//! create kernel threads to maintain persistence. Kernel threads have
//! specific characteristics: their `mm` pointer is NULL (meaning `cr3` is
//! `None` in `ProcessInfo`) and their parent is typically `kthreadd` (pid 2).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{ProcessInfo, Result};

/// Minimum address for the kernel address space on x86_64.
/// Addresses below this are userspace. A kernel thread function pointer
/// in userspace range is suspicious (possible rootkit manipulation).
const KERNEL_SPACE_MIN: u64 = 0xFFFF_0000_0000_0000;

/// Information about a kernel thread extracted from memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KernelThreadInfo {
    /// Process ID of the kernel thread.
    pub pid: u32,
    /// Thread name from `task_struct.comm`.
    pub name: String,
    /// Thread function pointer (`threadfn`) -- where the thread started.
    pub start_fn_addr: u64,
    /// Whether heuristic analysis flagged this thread as suspicious.
    pub is_suspicious: bool,
    /// Human-readable reason for the suspicious flag.
    pub reason: Option<String>,
}

/// Walk the given process list and extract kernel thread information.
///
/// Kernel threads are identified by having `cr3 == None` (mm pointer is
/// NULL). For each kernel thread, the thread function pointer is read
/// from memory when available, and the thread is classified for anomalies.
///
/// Returns `Ok(Vec::new())` when required symbols are missing.
pub fn walk_kernel_threads<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    processes: &[ProcessInfo],
) -> Result<Vec<KernelThreadInfo>> {
    let mut kthreads = Vec::new();

    for proc in processes {
        // Kernel threads have mm == NULL, which means cr3 is None.
        if proc.cr3.is_some() {
            continue;
        }

        let pid = proc.pid as u32;
        let name = proc.comm.clone();

        // Try to read the thread function pointer from the kthread struct.
        // In Linux, kernel threads store their function pointer in
        // `task_struct -> set_child_tid` (overloaded for kthreads) or via
        // the kthread struct. We attempt to read it; if the symbol/field
        // is missing we fall back to 0.
        let start_fn_addr: u64 = reader
            .read_field(proc.vaddr, "task_struct", "set_child_tid")
            .unwrap_or(0);

        let (is_suspicious, reason) = classify_kthread(&name, start_fn_addr);

        kthreads.push(KernelThreadInfo {
            pid,
            name,
            start_fn_addr,
            is_suspicious,
            reason,
        });
    }

    Ok(kthreads)
}

/// Classify a kernel thread as benign or suspicious.
///
/// Returns `(is_suspicious, reason)`. A thread is considered suspicious if:
/// - Its name is empty (unnamed kernel thread)
/// - Its name contains sequences of hex characters (random-looking names)
/// - Its start function address is in userspace range (below `KERNEL_SPACE_MIN`)
pub fn classify_kthread(name: &str, start_fn_addr: u64) -> (bool, Option<String>) {
    // Check 1: unnamed kernel thread
    if name.is_empty() {
        return (true, Some("unnamed kernel thread".into()));
    }

    // Check 2: start function in userspace range
    if start_fn_addr != 0 && start_fn_addr < KERNEL_SPACE_MIN {
        return (
            true,
            Some(format!(
                "thread function at userspace address {start_fn_addr:#x}"
            )),
        );
    }

    // Check 3: name looks like random hex (rootkit-generated)
    if looks_like_hex_name(name) {
        return (
            true,
            Some(format!("name '{name}' contains suspicious hex pattern")),
        );
    }

    (false, None)
}

/// Check whether a name looks like random hex characters.
///
/// Returns `true` if the name contains a run of 8+ hex digits, which is
/// unusual for legitimate kernel thread names.
fn looks_like_hex_name(name: &str) -> bool {
    // Count the longest consecutive run of hex digits in the name.
    // A run of 8+ is suspicious -- legitimate kernel thread names like
    // "kworker/0:0", "ksoftirqd/0", "migration/0" don't have such runs.
    let mut run = 0u32;
    for ch in name.chars() {
        if ch.is_ascii_hexdigit() {
            run += 1;
            if run >= 8 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // classify_kthread tests (pure function, no mock memory needed)
    // ---------------------------------------------------------------

    #[test]
    fn classify_kthread_benign() {
        // A well-known kernel worker thread at a kernel address is benign.
        let (suspicious, reason) = classify_kthread("kworker/0:0", 0xFFFF_FFFF_8100_0000);
        assert!(!suspicious, "kworker should not be suspicious");
        assert!(reason.is_none());
    }

    #[test]
    fn classify_kthread_suspicious_unnamed() {
        // An empty name is suspicious -- legitimate kernel threads always
        // have a name set via kthread_create / kthread_run.
        let (suspicious, reason) = classify_kthread("", 0xFFFF_FFFF_8100_0000);
        assert!(suspicious, "unnamed thread should be suspicious");
        assert!(reason.is_some());
        let r = reason.unwrap();
        assert!(
            r.to_lowercase().contains("unnamed") || r.to_lowercase().contains("empty"),
            "reason should mention unnamed/empty, got: {r}"
        );
    }

    #[test]
    fn classify_kthread_suspicious_userspace_fn() {
        // A kernel thread whose start function is in userspace range is
        // highly suspicious -- indicates possible rootkit manipulation.
        let (suspicious, reason) = classify_kthread("worker", 0x0000_7F00_0000_0000);
        assert!(suspicious, "userspace fn addr should be suspicious");
        assert!(reason.is_some());
        let r = reason.unwrap();
        assert!(
            r.to_lowercase().contains("userspace") || r.to_lowercase().contains("user"),
            "reason should mention userspace, got: {r}"
        );
    }

    #[test]
    fn classify_kthread_suspicious_hex_name() {
        // A name that looks like random hex is suspicious.
        let (suspicious, reason) = classify_kthread("a1b2c3d4e5f6", 0xFFFF_FFFF_8100_0000);
        assert!(suspicious, "hex-looking name should be suspicious");
        assert!(reason.is_some());
    }

    #[test]
    fn classify_kthread_benign_short_hex() {
        // Short names that happen to be hex-ish but are common (e.g. "md")
        // should not trigger the hex heuristic.
        let (suspicious, _) = classify_kthread("md", 0xFFFF_FFFF_8100_0000);
        assert!(!suspicious, "short common name should not be suspicious");
    }

    // ---------------------------------------------------------------
    // walk_kernel_threads tests
    // ---------------------------------------------------------------

    #[test]
    fn walk_kthreads_empty() {
        // Empty process list should produce empty result.
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "comm", 32, "char")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_kernel_threads(&reader, &[]).unwrap();
        assert!(
            result.is_empty(),
            "empty process list should give empty kthread list"
        );
    }

    #[test]
    fn walk_kthreads_filters_userspace() {
        // Processes with cr3 = Some(_) are userspace and should be excluded.
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "comm", 32, "char")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let processes = vec![ProcessInfo {
            pid: 100,
            ppid: 1,
            comm: "bash".into(),
            state: crate::ProcessState::Running,
            vaddr: 0xFFFF_8000_0010_0000,
            cr3: Some(0x1000),
            start_time: 0,
        }];

        let result = walk_kernel_threads(&reader, &processes).unwrap();
        assert!(
            result.is_empty(),
            "userspace process should not appear in kthread list"
        );
    }

    #[test]
    fn walk_kthreads_includes_kernel_thread() {
        // A process with cr3 = None is a kernel thread and should be included.
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "comm", 32, "char")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let processes = vec![ProcessInfo {
            pid: 2,
            ppid: 0,
            comm: "kthreadd".into(),
            state: crate::ProcessState::Sleeping,
            vaddr: 0xFFFF_8000_0010_0000,
            cr3: None,
            start_time: 0,
        }];

        let result = walk_kernel_threads(&reader, &processes).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].pid, 2);
        assert_eq!(result[0].name, "kthreadd");
        assert!(
            !result[0].is_suspicious,
            "kthreadd should not be suspicious"
        );
    }

    // ---------------------------------------------------------------
    // looks_like_hex_name tests
    // ---------------------------------------------------------------

    #[test]
    fn hex_name_detection() {
        assert!(looks_like_hex_name("a1b2c3d4e5f6"));
        assert!(looks_like_hex_name("deadbeef01234567"));
        assert!(!looks_like_hex_name("kworker/0:0"));
        assert!(!looks_like_hex_name("ksoftirqd/0"));
        assert!(!looks_like_hex_name("md"));
        assert!(!looks_like_hex_name(""));
    }
}
