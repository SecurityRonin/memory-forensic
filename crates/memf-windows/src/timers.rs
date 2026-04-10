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
    if dpc_routine == 0 {
        return false;
    }
    // Suspicious if the DPC routine falls outside the kernel image range.
    !(dpc_routine >= kernel_base && dpc_routine < kernel_base.wrapping_add(kernel_size))
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
    // Resolve the timer table array symbol.
    let table_head = match reader.symbols().symbol_address("KiTimerTableListHead") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    // Determine kernel image range for suspicion heuristic.
    // Try KiServiceTable first (always in ntoskrnl), fall back to a wide range.
    let (kernel_base, kernel_size) = match reader.symbols().symbol_address("ntoskrnl") {
        Some(base) => {
            // Assume a generous 16 MB kernel image unless we know better.
            (base, 0x0100_0000_u64)
        }
        None => {
            // Use KiTimerTableListHead itself as an anchor — the symbol lives
            // inside ntoskrnl. Assume the kernel spans +/- 16 MB from that point.
            (table_head.wrapping_sub(0x0080_0000), 0x0100_0000_u64)
        }
    };

    // Read layout offsets, falling back to typical Windows 10 values.
    let timer_list_entry_off = reader
        .symbols()
        .field_offset("_KTIMER", "TimerListEntry")
        .unwrap_or(0x00);

    let due_time_off = reader
        .symbols()
        .field_offset("_KTIMER", "DueTime")
        .unwrap_or(0x18);

    let period_off = reader
        .symbols()
        .field_offset("_KTIMER", "Period")
        .unwrap_or(0x24);

    let dpc_off = reader
        .symbols()
        .field_offset("_KTIMER", "Dpc")
        .unwrap_or(0x30);

    let dpc_routine_off = reader
        .symbols()
        .field_offset("_KDPC", "DeferredRoutine")
        .unwrap_or(0x18);

    let dpc_context_off = reader
        .symbols()
        .field_offset("_KDPC", "DeferredContext")
        .unwrap_or(0x20);

    // Each _KTIMER_TABLE_ENTRY starts with a _LIST_ENTRY (Flink, Blink).
    let entry_size = reader
        .symbols()
        .struct_size("_KTIMER_TABLE_ENTRY")
        .unwrap_or(0x20);

    let mut timers = Vec::new();

    for bucket in 0..TIMER_TABLE_SIZE {
        let entry_addr = table_head.wrapping_add((bucket as u64).wrapping_mul(entry_size));

        // Read Flink from the _LIST_ENTRY at the start of this bucket.
        let flink = match reader.read_bytes(entry_addr, 8) {
            Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            _ => continue,
        };

        // Walk the doubly-linked list of _KTIMER structures in this bucket.
        let mut current = flink;

        for _ in 0..MAX_TIMERS {
            // If we've looped back to the bucket head, this chain is done.
            if current == entry_addr || current == 0 {
                break;
            }

            // container_of: TimerListEntry is at timer_list_entry_off within _KTIMER.
            let timer_addr = current.wrapping_sub(timer_list_entry_off);

            // Read DueTime (i64, 8 bytes).
            let due_time = match reader.read_bytes(timer_addr.wrapping_add(due_time_off), 8) {
                Ok(bytes) if bytes.len() == 8 => i64::from_le_bytes(bytes[..8].try_into().unwrap()),
                _ => 0,
            };

            // Read Period (u32, 4 bytes).
            let period = match reader.read_bytes(timer_addr.wrapping_add(period_off), 4) {
                Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
                _ => 0,
            };

            // Read DPC pointer (u64).
            let dpc_address = match reader.read_bytes(timer_addr.wrapping_add(dpc_off), 8) {
                Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                _ => 0,
            };

            // Read DPC fields if the pointer is non-null.
            let (dpc_routine, dpc_context) = if dpc_address != 0 {
                let routine = match reader.read_bytes(dpc_address.wrapping_add(dpc_routine_off), 8)
                {
                    Ok(bytes) if bytes.len() == 8 => {
                        u64::from_le_bytes(bytes[..8].try_into().unwrap())
                    }
                    _ => 0,
                };
                let context = match reader.read_bytes(dpc_address.wrapping_add(dpc_context_off), 8)
                {
                    Ok(bytes) if bytes.len() == 8 => {
                        u64::from_le_bytes(bytes[..8].try_into().unwrap())
                    }
                    _ => 0,
                };
                (routine, context)
            } else {
                (0, 0)
            };

            let is_suspicious = classify_timer(dpc_routine, kernel_base, kernel_size);

            timers.push(KernelTimerInfo {
                address: timer_addr,
                due_time,
                period,
                dpc_address,
                dpc_routine,
                dpc_context,
                is_suspicious,
            });

            if timers.len() >= MAX_TIMERS {
                break;
            }

            // Follow Flink to next entry.
            current = match reader.read_bytes(current, 8) {
                Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                _ => break,
            };
        }

        if timers.len() >= MAX_TIMERS {
            break;
        }
    }

    Ok(timers)
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

    /// DPC routine at the exact end of the kernel image (kernel_base + kernel_size)
    /// is just outside the range — suspicious.
    #[test]
    fn classify_timer_at_end_of_kernel_suspicious() {
        let kernel_base: u64 = 0xfffff800_04000000;
        let kernel_size: u64 = 0x00800000;
        let routine = kernel_base + kernel_size; // exactly at the end, exclusive

        assert!(classify_timer(routine, kernel_base, kernel_size));
    }

    /// DPC routine one byte before end of kernel range is benign.
    #[test]
    fn classify_timer_one_before_end_benign() {
        let kernel_base: u64 = 0xfffff800_04000000;
        let kernel_size: u64 = 0x00800000;
        let routine = kernel_base + kernel_size - 1; // last valid byte

        assert!(!classify_timer(routine, kernel_base, kernel_size));
    }

    // ── walk_timers body: actual timer in a bucket ────────────────────

    /// Walk body: bucket 0 contains one timer. Covers lines 130–211.
    ///
    /// Memory layout (all identity-mapped):
    ///   table_vaddr (bucket 0 = entry_addr): Flink → timer_list_entry_vaddr
    ///   timer_list_entry_vaddr:
    ///     offset  0: Flink → entry_addr (back to bucket head, terminates)
    ///     offset +0x18: DueTime = 0x4321 (timer_list_entry_off=0, due_time_off=0x18)
    ///     offset +0x24: Period = 100 (period_off=0x24)
    ///     offset +0x30: Dpc ptr → dpc_vaddr (dpc_off=0x30)
    ///   dpc_vaddr:
    ///     offset +0x18: DeferredRoutine = 0xFFFF_8001_0000 (inside kernel range)
    ///     offset +0x20: DeferredContext = 0xABCD
    #[test]
    fn walk_timers_with_one_timer_in_bucket() {
        let table_vaddr: u64 = 0xFFFF_8000_00A0_0000;
        // Use a tight layout: 256 buckets × 0x20 = 0x2000, but we only really need 2 pages.
        // Bucket 0 = entry_addr = table_vaddr.
        // Place the timer at table_vaddr + 0x2000 (next page area).
        let timer_vaddr: u64 = table_vaddr.wrapping_add(0x2000); // timer_list_entry = timer_addr (off=0)
        let dpc_vaddr: u64   = table_vaddr.wrapping_add(0x3000);

        // Physical pages (identity map).
        let table_paddr0: u64 = 0x00A0_0000;
        let table_paddr1: u64 = 0x00A1_0000;
        let timer_paddr: u64  = 0x00A2_0000;
        let dpc_paddr: u64    = 0x00A3_0000;

        let kernel_base: u64 = 0xFFFF_8001_0000_0000u64;
        let dpc_routine: u64 = kernel_base + 0x1000; // inside kernel

        let entry_size: u64 = 0x20;

        // Page 0 and Page 1 of the timer table: all buckets' Flinka → themselves,
        // except bucket 0 whose Flink → timer_vaddr.
        let mut page0 = vec![0u8; 4096];
        let mut page1 = vec![0u8; 4096];
        for bucket in 0u64..256 {
            let entry_addr = table_vaddr + bucket * entry_size;
            let flink = if bucket == 0 { timer_vaddr } else { entry_addr };
            let byte_off = (bucket * entry_size) as usize;
            if byte_off + 8 <= 4096 {
                page0[byte_off..byte_off + 8].copy_from_slice(&flink.to_le_bytes());
            } else {
                let off_in_p1 = byte_off - 4096;
                if off_in_p1 + 8 <= 4096 {
                    page1[off_in_p1..off_in_p1 + 8].copy_from_slice(&flink.to_le_bytes());
                }
            }
        }

        // Timer page: timer_list_entry_off=0 → timer_addr = timer_vaddr.
        let mut timer_page = vec![0u8; 4096];
        // Flink at +0 = table_vaddr (bucket 0 head) → terminates the chain.
        timer_page[0..8].copy_from_slice(&table_vaddr.to_le_bytes());
        // DueTime at +0x18 = 0x4321
        timer_page[0x18..0x20].copy_from_slice(&0x4321i64.to_le_bytes());
        // Period at +0x24 = 100
        timer_page[0x24..0x28].copy_from_slice(&100u32.to_le_bytes());
        // Dpc ptr at +0x30 = dpc_vaddr
        timer_page[0x30..0x38].copy_from_slice(&dpc_vaddr.to_le_bytes());

        // DPC page.
        let mut dpc_page = vec![0u8; 4096];
        // DeferredRoutine at +0x18
        dpc_page[0x18..0x20].copy_from_slice(&dpc_routine.to_le_bytes());
        // DeferredContext at +0x20 = 0xABCD
        dpc_page[0x20..0x28].copy_from_slice(&0xABCDu64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_symbol("KiTimerTableListHead", table_vaddr)
            .add_symbol("ntoskrnl", kernel_base)
            .add_struct("_KTIMER", 0x40)
            .add_struct("_KTIMER_TABLE_ENTRY", 0x20)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(table_vaddr,          table_paddr0, flags::WRITABLE)
            .map_4k(table_vaddr + 0x1000, table_paddr1, flags::WRITABLE)
            .map_4k(timer_vaddr,          timer_paddr,  flags::WRITABLE)
            .map_4k(dpc_vaddr,            dpc_paddr,    flags::WRITABLE)
            .write_phys(table_paddr0, &page0)
            .write_phys(table_paddr1, &page1)
            .write_phys(timer_paddr,  &timer_page)
            .write_phys(dpc_paddr,    &dpc_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_timers(&reader).unwrap();
        assert_eq!(result.len(), 1, "should find exactly one timer");
        let t = &result[0];
        assert_eq!(t.address, timer_vaddr);
        assert_eq!(t.due_time, 0x4321);
        assert_eq!(t.period, 100);
        assert_eq!(t.dpc_address, dpc_vaddr);
        assert_eq!(t.dpc_routine, dpc_routine);
        assert_eq!(t.dpc_context, 0xABCD);
        assert!(!t.is_suspicious, "routine inside kernel range should not be suspicious");
    }

    /// KernelTimerInfo serializes correctly.
    #[test]
    fn kernel_timer_info_serializes() {
        let info = KernelTimerInfo {
            address: 0xFFFF_8000_1234_0000,
            due_time: 132_000_000_000_i64,
            period: 1000,
            dpc_address: 0xFFFF_8000_DEAD_0000,
            dpc_routine: 0xFFFF_8000_BEEF_0100,
            dpc_context: 0,
            is_suspicious: true,
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"period\":1000"));
        assert!(json.contains("\"is_suspicious\":true"));
        assert!(json.contains("\"dpc_context\":0"));
    }

    #[test]
    fn classify_timer_zero_size_kernel_suspicious() {
        // If kernel_size is 0, any non-zero routine is outside the (empty) range.
        let kernel_base: u64 = 0xfffff800_04000000;
        let routine = kernel_base; // even at the base

        // Range [base, base+0) is empty, so even kernel_base is suspicious.
        assert!(classify_timer(routine, kernel_base, 0));
    }

    /// No KiTimerTableListHead symbol → empty Vec.
    #[test]
    fn walk_timers_no_symbol() {
        let isf = IsfBuilder::new().add_struct("_KTIMER", 0x40).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_timers(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// KiTimerTableListHead present and mapped, but all buckets have Flink == entry_addr
    /// (empty timer lists) → exercises the full bucket-walking loop, returns empty.
    ///
    /// We only map a small number of buckets (enough for the first few) to avoid
    /// excessive physical memory use. The rest will fail to read and be skipped.
    #[test]
    fn walk_timers_with_symbol_empty_buckets() {
        // KiTimerTableListHead symbol + _KTIMER_TABLE_ENTRY size = 0x20 (default).
        // 256 buckets × 0x20 = 0x2000 bytes = 2 pages.
        // We'll map 2 pages for the table so the walker can read all 256 buckets.
        // Each bucket's Flink (first 8 bytes) points back to its own entry_addr
        // to indicate an empty list.

        let table_vaddr: u64 = 0xFFFF_8000_0090_0000;
        let table_paddr0: u64 = 0x0090_0000;
        let table_paddr1: u64 = 0x0091_0000;

        let isf = IsfBuilder::new()
            .add_symbol("KiTimerTableListHead", table_vaddr)
            .add_struct("_KTIMER", 0x40)
            .add_struct("_KTIMER_TABLE_ENTRY", 0x20)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Build 2 pages for the timer table.
        // Each entry is 0x20 bytes. Flink (first 8 bytes of entry) = entry_addr.
        let entry_size: u64 = 0x20;
        let mut page0 = [0u8; 4096];
        let mut page1 = [0u8; 4096];

        for bucket in 0u64..256 {
            let entry_addr = table_vaddr + bucket * entry_size;
            let flink_bytes = entry_addr.to_le_bytes();

            let byte_off = (bucket * entry_size) as usize;
            if byte_off + 8 <= 4096 {
                page0[byte_off..byte_off + 8].copy_from_slice(&flink_bytes);
            } else {
                let off_in_p1 = byte_off - 4096;
                if off_in_p1 + 8 <= 4096 {
                    page1[off_in_p1..off_in_p1 + 8].copy_from_slice(&flink_bytes);
                }
            }
        }

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(table_vaddr, table_paddr0, flags::WRITABLE)
            .map_4k(table_vaddr + 0x1000, table_paddr1, flags::WRITABLE)
            .write_phys(table_paddr0, &page0)
            .write_phys(table_paddr1, &page1)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_timers(&reader).unwrap_or_default();
        assert!(result.is_empty(), "all empty timer buckets should yield no timers");
    }
}
