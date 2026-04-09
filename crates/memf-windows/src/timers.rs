//! Windows kernel timer (`_KTIMER`) enumeration.
//!
//! Kernel timers are used by rootkits and malware for periodic callbacks —
//! DPC (Deferred Procedure Call) routines that execute at DISPATCH_LEVEL.
//! Enumerating timers reveals hidden periodic execution:
//!
//! - Rootkits scheduling periodic callbacks to re-hook or hide artifacts
//! - Malware using timers for C2 beaconing or payload staging
//! - Legitimate drivers with periodic work items
//!
//! The kernel maintains `KiTimerTableListHead`, an array of 256
//! `_KTIMER_TABLE_ENTRY` structures. Each entry contains a `_LIST_ENTRY`
//! head for a doubly-linked list of `_KTIMER` objects.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

/// Maximum number of timers to enumerate across all buckets (safety limit).
const MAX_TIMERS: usize = 16384;

/// Number of timer table buckets in `KiTimerTableListHead`.
const TIMER_TABLE_SIZE: usize = 256;

/// Information about a kernel timer recovered from memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KernelTimerInfo {
    /// Timer object virtual address.
    pub address: u64,
    /// When the timer fires (100ns intervals, absolute or relative).
    pub due_time: i64,
    /// Repeat period in milliseconds (0 = one-shot).
    pub period: u32,
    /// Virtual address of the `_KDPC` structure.
    pub dpc_address: u64,
    /// DPC callback function address (`DeferredRoutine`).
    pub dpc_routine: u64,
    /// DPC context parameter (`DeferredContext`).
    pub dpc_context: u64,
    /// Whether the DPC routine looks suspicious (outside kernel image).
    pub is_suspicious: bool,
}

/// Classify a timer's DPC routine as suspicious based on kernel address range.
///
/// A DPC routine pointing outside the kernel image (`ntoskrnl.exe`) range
/// suggests the callback lives in pool memory or a third-party module,
/// which is a common rootkit technique.
///
/// - `dpc_routine == 0` → not suspicious (timer has no DPC set)
/// - `dpc_routine` within `[kernel_base, kernel_base + kernel_size)` → benign
/// - `dpc_routine` outside that range → suspicious
pub fn classify_timer(dpc_routine: u64, kernel_base: u64, kernel_size: u64) -> bool {
    todo!("implement classify_timer")
}

/// Enumerate kernel timers from the `KiTimerTableListHead` array.
///
/// Walks all 256 timer table buckets. Each bucket contains a doubly-linked
/// list of `_KTIMER` structures. For each timer, reads the DPC pointer and
/// its `DeferredRoutine` / `DeferredContext` fields.
///
/// Returns `Ok(Vec::new())` if the required symbol (`KiTimerTableListHead`)
/// is not present in the symbol table.
pub fn walk_timers<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<KernelTimerInfo>> {
    todo!("implement walk_timers")
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // --- classify_timer tests ---

    /// DPC routine within kernel image range is benign.
    #[test]
    fn classify_timer_in_kernel_range_benign() {
        let kernel_base: u64 = 0xfffff800_04000000;
        let kernel_size: u64 = 0x00800000; // 8 MB
        let routine = kernel_base + 0x1000; // inside kernel

        assert!(!classify_timer(routine, kernel_base, kernel_size));
    }

    /// DPC routine outside kernel image range is suspicious.
    #[test]
    fn classify_timer_outside_kernel_suspicious() {
        let kernel_base: u64 = 0xfffff800_04000000;
        let kernel_size: u64 = 0x00800000;
        let routine = 0xfffff880_01000000; // far outside kernel

        assert!(classify_timer(routine, kernel_base, kernel_size));
    }

    /// DPC routine == 0 means no DPC is set; not suspicious.
    #[test]
    fn classify_timer_zero_not_suspicious() {
        let kernel_base: u64 = 0xfffff800_04000000;
        let kernel_size: u64 = 0x00800000;

        assert!(!classify_timer(0, kernel_base, kernel_size));
    }

    /// DPC routine just below kernel base is suspicious.
    #[test]
    fn classify_timer_just_below_kernel_suspicious() {
        let kernel_base: u64 = 0xfffff800_04000000;
        let kernel_size: u64 = 0x00800000;
        let routine = kernel_base - 1; // one byte below

        assert!(classify_timer(routine, kernel_base, kernel_size));
    }

    /// DPC routine at exactly kernel_base (boundary) is benign.
    #[test]
    fn classify_timer_at_kernel_boundary_benign() {
        let kernel_base: u64 = 0xfffff800_04000000;
        let kernel_size: u64 = 0x00800000;

        assert!(!classify_timer(kernel_base, kernel_base, kernel_size));
    }

    /// DPC routine far away from kernel in user-space range is suspicious.
    #[test]
    fn classify_timer_far_away_suspicious() {
        let kernel_base: u64 = 0xfffff800_04000000;
        let kernel_size: u64 = 0x00800000;
        let routine = 0x00007ff6_12340000; // user-mode address

        assert!(classify_timer(routine, kernel_base, kernel_size));
    }

    // --- walk_timers tests ---

    /// No KiTimerTableListHead symbol → empty Vec.
    #[test]
    fn walk_timers_no_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("_KTIMER", 0x40)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_timers(&reader).unwrap();
        assert!(result.is_empty());
    }
}
