//! Linux kernel timer enumeration for rootkit callback detection.
//!
//! Kernel timers (`timer_list` and `hrtimer`) provide periodic callbacks.
//! Rootkits use them for periodic check-in, keylogger flushing, or hiding
//! their tracks. Enumerating kernel timers reveals hidden periodic execution.
//!
//! The classifier checks whether a timer callback function address falls
//! within the kernel text range (`_stext`..`_etext`). Callbacks pointing
//! outside kernel text are flagged as suspicious.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about a kernel timer extracted from the timer wheel.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KernelTimerInfo {
    /// Virtual address of the `timer_list` struct.
    pub address: u64,
    /// Expiration time in jiffies.
    pub expires: u64,
    /// Callback function address.
    pub function: u64,
    /// Whether timer re-arms itself (periodic).
    ///
    /// Currently always `false`. Accurate detection requires reading
    /// `timer_list.flags` and testing against `TIMER_DEFERRABLE`/re-arm bits,
    /// which is not yet supported in the ISF profile walker.
    pub is_periodic: bool,
    /// Heuristic flag: callback outside kernel text.
    pub is_suspicious: bool,
}

/// Classify a kernel timer callback as suspicious.
///
/// - `function == 0` → not suspicious (unset timer, no callback).
/// - `function` inside `[kernel_start, kernel_end]` → benign (in kernel text).
/// - `function` outside that range → suspicious (possible rootkit callback).
pub fn classify_kernel_timer(function: u64, kernel_start: u64, kernel_end: u64) -> bool {
    if function == 0 {
        return false;
    }
    // Suspicious if outside kernel text range
    !(function >= kernel_start && function <= kernel_end)
}

/// Walk kernel timer wheels and enumerate all registered timers.
///
/// Looks up the `timer_bases` symbol to find the per-CPU timer base array.
/// Each timer base contains vectors (timer wheel groups) holding linked lists
/// of `timer_list` structs. Falls back to `tvec_bases` on older kernels.
///
/// Returns `Ok(Vec::new())` if neither symbol is found (graceful degradation).
/// Number of timer wheel groups (TVR_SIZE buckets per group).
const TIMER_WHEEL_GROUPS: usize = 9;

/// Maximum number of timers to enumerate per vector (cycle protection).
const MAX_TIMERS_PER_VECTOR: usize = 4096;

/// Walk the kernel timer wheel and return all active timer entries.
///
/// Returns `Ok(Vec::new())` if `timer_bases`, `_stext`, or `_etext` symbols
/// are absent (graceful degradation for older kernels or incomplete ISF).
pub fn walk_kernel_timers<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<KernelTimerInfo>> {
    // Look up timer_bases (modern kernels) or tvec_bases (older kernels).
    // Return empty if neither symbol exists (graceful degradation).
    let timer_bases = reader
        .symbols()
        .symbol_address("timer_bases")
        .or_else(|| reader.symbols().symbol_address("tvec_bases"));

    let Some(bases_addr) = timer_bases else {
        return Ok(Vec::new());
    };

    // Resolve kernel text range for classification
    let Some(kernel_start) = reader.symbols().symbol_address("_stext") else {
        return Ok(Vec::new());
    };
    let Some(kernel_end) = reader.symbols().symbol_address("_etext") else {
        return Ok(Vec::new());
    };

    let mut results = Vec::new();

    // Walk timer wheel groups (vectors array within each timer_base)
    for group in 0..TIMER_WHEEL_GROUPS {
        let vector_head =
            match reader.read_pointer(bases_addr, "timer_base", &format!("vectors.{group}")) {
                Ok(addr) => addr,
                Err(_) => continue,
            };

        if vector_head == 0 {
            continue;
        }

        // Walk the linked list of timer_list entries in this vector
        let timer_addrs = match reader.walk_list(vector_head, "timer_list", "entry") {
            Ok(addrs) => addrs,
            Err(_) => continue,
        };

        for (i, &timer_addr) in timer_addrs.iter().enumerate() {
            if i >= MAX_TIMERS_PER_VECTOR {
                break;
            }

            let expires = reader
                .read_field::<u64>(timer_addr, "timer_list", "expires")
                .unwrap_or(0);

            let function = reader
                .read_pointer(timer_addr, "timer_list", "function")
                .unwrap_or(0);

            let is_suspicious = classify_kernel_timer(function, kernel_start, kernel_end);

            results.push(KernelTimerInfo {
                address: timer_addr,
                expires,
                function,
                // TODO: set is_periodic from timer_list.flags (TIMER_DEFERRABLE / re-arm
                // detection) once timer flags support is added to the ISF profile.
                // Always false until then — the kernel's timer_list.flags field would
                // need to be read and tested against the TIMER_PINNED/TIMER_DEFERRABLE
                // bitmask to identify timers that re-arm themselves (periodic).
                is_periodic: false,
                is_suspicious,
            });
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // -----------------------------------------------------------------------
    // classify_kernel_timer tests
    // -----------------------------------------------------------------------

    #[test]
    fn classify_kernel_timer_in_kernel_text_is_benign() {
        let kernel_start = 0xFFFF_8000_0000_0000u64;
        let kernel_end = 0xFFFF_8000_00FF_FFFFu64;
        let function = kernel_start + 0x1000; // well inside kernel text

        assert!(
            !classify_kernel_timer(function, kernel_start, kernel_end),
            "function inside kernel text should not be suspicious"
        );
    }

    #[test]
    fn classify_kernel_timer_outside_kernel_text_is_suspicious() {
        let kernel_start = 0xFFFF_8000_0000_0000u64;
        let kernel_end = 0xFFFF_8000_00FF_FFFFu64;
        let function = 0xFFFF_C900_DEAD_BEEFu64; // module space, outside kernel text

        assert!(
            classify_kernel_timer(function, kernel_start, kernel_end),
            "function outside kernel text should be suspicious"
        );
    }

    #[test]
    fn classify_kernel_timer_zero_is_not_suspicious() {
        let kernel_start = 0xFFFF_8000_0000_0000u64;
        let kernel_end = 0xFFFF_8000_00FF_FFFFu64;

        assert!(
            !classify_kernel_timer(0, kernel_start, kernel_end),
            "function == 0 (unset timer) should not be suspicious"
        );
    }

    #[test]
    fn classify_kernel_timer_module_space_is_suspicious() {
        let kernel_start = 0xFFFF_8000_0000_0000u64;
        let kernel_end = 0xFFFF_8000_00FF_FFFFu64;
        // Typical Linux module space address (above kernel text)
        let function = 0xFFFF_FFFF_C000_0000u64;

        assert!(
            classify_kernel_timer(function, kernel_start, kernel_end),
            "function in module space should be suspicious"
        );
    }

    #[test]
    fn classify_kernel_timer_at_kernel_boundary_is_benign() {
        let kernel_start = 0xFFFF_8000_0000_0000u64;
        let kernel_end = 0xFFFF_8000_00FF_FFFFu64;

        // Exactly at start boundary
        assert!(
            !classify_kernel_timer(kernel_start, kernel_start, kernel_end),
            "function at kernel_start should be benign"
        );

        // Exactly at end boundary
        assert!(
            !classify_kernel_timer(kernel_end, kernel_start, kernel_end),
            "function at kernel_end should be benign"
        );
    }

    #[test]
    fn walk_kernel_timers_no_symbol_returns_empty() {
        // No timer_bases or tvec_bases symbol → should return Ok(empty vec)
        let isf = IsfBuilder::new()
            .add_struct("timer_list", 64)
            .add_field("timer_list", "entry", 0, "list_head")
            .add_field("timer_list", "expires", 16, "unsigned long")
            .add_field("timer_list", "function", 24, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_kernel_timers(&reader).unwrap();
        assert!(results.is_empty(), "missing symbol should yield empty vec");
    }

    #[test]
    fn walk_kernel_timers_missing_stext_returns_empty() {
        // timer_bases present but _stext missing → graceful empty
        let isf = IsfBuilder::new()
            .add_struct("timer_list", 64)
            .add_field("timer_list", "entry", 0, "list_head")
            .add_field("timer_list", "expires", 16, "unsigned long")
            .add_field("timer_list", "function", 24, "pointer")
            .add_symbol("timer_bases", 0xFFFF_8000_0010_0000)
            // _stext intentionally omitted
            .add_symbol("_etext", 0xFFFF_8000_00FF_FFFF)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_kernel_timers(&reader).unwrap();
        assert!(results.is_empty(), "missing _stext should yield empty vec");
    }

    #[test]
    fn walk_kernel_timers_missing_etext_returns_empty() {
        // timer_bases + _stext present but _etext missing → graceful empty
        let isf = IsfBuilder::new()
            .add_struct("timer_list", 64)
            .add_field("timer_list", "entry", 0, "list_head")
            .add_field("timer_list", "expires", 16, "unsigned long")
            .add_field("timer_list", "function", 24, "pointer")
            .add_symbol("timer_bases", 0xFFFF_8000_0010_0000)
            .add_symbol("_stext", 0xFFFF_8000_0000_0000)
            // _etext intentionally omitted
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_kernel_timers(&reader).unwrap();
        assert!(results.is_empty(), "missing _etext should yield empty vec");
    }

    // -----------------------------------------------------------------------
    // walk_kernel_timers: all symbols present, vectors all zero → empty
    // -----------------------------------------------------------------------

    #[test]
    fn walk_kernel_timers_symbol_present_all_vectors_zero() {
        // timer_bases, _stext, _etext all present.
        // timer_base struct with all vector fields = 0 → each group is skipped.
        let bases_vaddr: u64 = 0xFFFF_8800_0040_0000;
        let bases_paddr: u64 = 0x0050_0000;

        // All zeros: every vectors.{n} pointer reads as 0 → continue in loop
        let page = [0u8; 4096];

        let mut isf_builder = IsfBuilder::new()
            .add_struct("timer_base", 512)
            .add_struct("timer_list", 64)
            .add_field("timer_list", "entry", 0, "pointer")
            .add_field("timer_list", "expires", 16, "unsigned long")
            .add_field("timer_list", "function", 24, "pointer")
            .add_symbol("timer_bases", bases_vaddr)
            .add_symbol("_stext", 0xFFFF_8000_0000_0000u64)
            .add_symbol("_etext", 0xFFFF_8000_00FF_FFFFu64);

        // Add vectors.0 .. vectors.8 fields on timer_base (all at offset 0)
        for i in 0..TIMER_WHEEL_GROUPS {
            isf_builder = isf_builder.add_field(
                "timer_base",
                &format!("vectors.{i}"),
                0,
                "pointer",
            );
        }
        let isf = isf_builder.build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(bases_vaddr, bases_paddr, flags::WRITABLE)
            .write_phys(bases_paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_kernel_timers(&reader).unwrap_or_default();
        assert!(result.is_empty(), "all-zero vector heads should produce no timer entries");
    }

    #[test]
    fn walk_kernel_timers_uses_tvec_bases_fallback() {
        // timer_bases absent but tvec_bases present → should use tvec_bases
        // All vectors missing (no timer_base struct) → Err in loop → continue → empty
        let isf = IsfBuilder::new()
            .add_struct("timer_list", 64)
            .add_field("timer_list", "entry", 0, "list_head")
            .add_field("timer_list", "expires", 16, "unsigned long")
            .add_field("timer_list", "function", 24, "pointer")
            // No timer_bases symbol, only tvec_bases
            .add_symbol("tvec_bases", 0xFFFF_8000_0020_0000u64)
            .add_symbol("_stext", 0xFFFF_8000_0000_0000u64)
            .add_symbol("_etext", 0xFFFF_8000_00FF_FFFFu64)
            // No timer_base struct → read_pointer for vectors.{n} will Err → continue
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // Should not panic; all Err paths → continue → empty result
        let results = walk_kernel_timers(&reader).unwrap_or_default();
        assert!(results.is_empty(), "tvec_bases fallback with no vectors → empty");
    }

    #[test]
    fn walk_kernel_timers_vector_nonzero_but_walk_list_fails() {
        // All three symbols present, timer_base vectors.0 reads as non-zero address,
        // but walk_list fails because list_head is missing → Err → continue → empty
        let bases_vaddr: u64 = 0xFFFF_8800_0060_0000;
        let bases_paddr: u64 = 0x0060_0000;

        // Put a non-zero value at offset 0 so vectors.0 reads as some address
        let mut page = [0u8; 4096];
        let fake_list_addr: u64 = 0xFFFF_DEAD_0000_0000; // not mapped
        page[0..8].copy_from_slice(&fake_list_addr.to_le_bytes());

        let mut isf_builder = IsfBuilder::new()
            .add_struct("timer_base", 512)
            .add_struct("timer_list", 64)
            .add_field("timer_list", "entry", 0, "pointer")
            .add_field("timer_list", "expires", 16, "unsigned long")
            .add_field("timer_list", "function", 24, "pointer")
            .add_symbol("timer_bases", bases_vaddr)
            .add_symbol("_stext", 0xFFFF_8000_0000_0000u64)
            .add_symbol("_etext", 0xFFFF_8000_00FF_FFFFu64);

        // vectors.0 at offset 0; rest at same offset (all read the same fake addr)
        for i in 0..TIMER_WHEEL_GROUPS {
            isf_builder = isf_builder.add_field(
                "timer_base",
                &format!("vectors.{i}"),
                0u64,
                "pointer",
            );
        }
        // No list_head struct → walk_list will fail → Err → continue
        let isf = isf_builder.build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(bases_vaddr, bases_paddr, flags::WRITABLE)
            .write_phys(bases_paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_kernel_timers(&reader).unwrap_or_default();
        // walk_list fails for unmapped fake_list_addr → continue → empty
        assert!(result.is_empty(), "failed walk_list → Err → continue → empty result");
    }

    // -----------------------------------------------------------------------
    // walk_kernel_timers: full path — non-zero vector_head + walk_list succeeds
    // Exercises the loop body (lines 99-120): reads expires, function, classifies.
    // -----------------------------------------------------------------------

    #[test]
    fn walk_kernel_timers_with_one_timer_in_vector() {
        // Layout (all physical addresses < 16 MB):
        //
        //   bases_vaddr  / bases_paddr   — timer_base struct; vectors.0 @ offset 0
        //   list_head_vaddr / list_head_paddr — the list_head sentinel (inode_list_head style)
        //   timer_vaddr  / timer_paddr   — the timer_list struct
        //
        // vector_head = bases_vaddr read via read_pointer(bases_addr, "timer_base", "vectors.0")
        // walk_list(vector_head, "timer_list", "entry") needs:
        //   list_head.next offset (list_head struct)
        //   timer_list.entry offset
        //
        // We use a simple one-timer linked list:
        //   list_head sentinel @ list_head_vaddr: next → timer_vaddr + entry_offset
        //   timer_list @ timer_vaddr:
        //     entry (list_head) @ entry_offset: next → list_head_vaddr (wraps back)
        //     expires @ expires_offset = 9999
        //     function @ function_offset = some addr OUTSIDE kernel text → suspicious

        let bases_vaddr: u64     = 0xFFFF_8800_00D0_0000;
        let bases_paddr: u64     = 0x00D0_0000;
        let listhead_vaddr: u64  = 0xFFFF_8800_00D1_0000;
        let listhead_paddr: u64  = 0x00D1_0000;
        let timer_vaddr: u64     = 0xFFFF_8800_00D2_0000;
        let timer_paddr: u64     = 0x00D2_0000;

        let entry_offset:    u64 = 0x00; // timer_list.entry (list_head embedded at start)
        let expires_offset:  u64 = 0x10;
        let function_offset: u64 = 0x18;

        let kernel_start: u64 = 0xFFFF_8000_0000_0000;
        let kernel_end:   u64 = 0xFFFF_8000_00FF_FFFF;
        // A function outside kernel text (module space) → suspicious
        let suspicious_fn: u64 = 0xFFFF_C900_DEAD_BEEFu64;

        // bases page: vectors.0 at offset 0 = listhead_vaddr
        let mut bases_page = [0u8; 4096];
        bases_page[0..8].copy_from_slice(&listhead_vaddr.to_le_bytes());

        // list head sentinel page:
        //   next @ 0 (list_head.next offset=0) → timer_vaddr + entry_offset
        let timer_entry_node = timer_vaddr + entry_offset;
        let mut listhead_page = [0u8; 4096];
        listhead_page[0..8].copy_from_slice(&timer_entry_node.to_le_bytes());

        // timer_list page:
        //   entry.next @ 0 → listhead_vaddr   (next iteration hits head → walk ends)
        //   expires    @ expires_offset = 9999
        //   function   @ function_offset = suspicious_fn
        let mut timer_page = [0u8; 4096];
        timer_page[entry_offset as usize..entry_offset as usize + 8]
            .copy_from_slice(&listhead_vaddr.to_le_bytes());
        timer_page[expires_offset as usize..expires_offset as usize + 8]
            .copy_from_slice(&9999u64.to_le_bytes());
        timer_page[function_offset as usize..function_offset as usize + 8]
            .copy_from_slice(&suspicious_fn.to_le_bytes());

        let mut isf_builder = IsfBuilder::new()
            .add_struct("list_head", 0x10)
            .add_field("list_head", "next", 0x00u64, "pointer")
            .add_struct("timer_base", 512)
            .add_struct("timer_list", 64)
            .add_field("timer_list", "entry", entry_offset, "pointer")
            .add_field("timer_list", "expires", expires_offset, "unsigned long")
            .add_field("timer_list", "function", function_offset, "pointer")
            .add_symbol("timer_bases", bases_vaddr)
            .add_symbol("_stext", kernel_start)
            .add_symbol("_etext", kernel_end);

        for i in 0..TIMER_WHEEL_GROUPS {
            // All vectors point to offset 0 of bases_page (listhead_vaddr).
            // That means every group finds the same single timer, but walk_list
            // will succeed for all groups. For simplicity, only vectors.0 at offset 0
            // actually has a non-zero value; the rest are at offset 0 too but that's fine —
            // they'll all point to listhead_vaddr and each find the one timer.
            // To avoid inflating the assertion, let's only wire vectors.0 to listhead_vaddr
            // and place the remaining vector fields at a different offset (so they read 0).
            let field_offset: u64 = if i == 0 { 0 } else { 8 + i as u64 * 8 };
            isf_builder = isf_builder.add_field(
                "timer_base",
                &format!("vectors.{i}"),
                field_offset,
                "pointer",
            );
        }
        let isf = isf_builder.build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(bases_vaddr,    bases_paddr,    flags::WRITABLE)
            .write_phys(bases_paddr,    &bases_page)
            .map_4k(listhead_vaddr, listhead_paddr, flags::WRITABLE)
            .write_phys(listhead_paddr, &listhead_page)
            .map_4k(timer_vaddr,    timer_paddr,    flags::WRITABLE)
            .write_phys(timer_paddr,    &timer_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_kernel_timers(&reader).unwrap();
        // vectors.0 yields one timer; remaining vector offsets read 0 → skipped
        assert!(!result.is_empty(), "should find at least one timer");
        let timer = &result[0];
        assert_eq!(timer.expires, 9999);
        assert_eq!(timer.function, suspicious_fn);
        assert!(timer.is_suspicious, "function outside kernel text must be suspicious");
    }

    // -----------------------------------------------------------------------
    // is_periodic: TIMER_DEFERRABLE flag (bit 0) tests
    // -----------------------------------------------------------------------

    /// Build a full single-timer walk setup and return the first timer result.
    ///
    /// `flags_value` is written into the timer_list.flags field.
    /// The ISF includes a `flags` field on `timer_list` at `flags_offset`.
    fn walk_one_timer_with_flags(flags_value: u32) -> KernelTimerInfo {
        let bases_vaddr: u64    = 0xFFFF_8800_00E0_0000;
        let bases_paddr: u64    = 0x00E0_0000;
        let listhead_vaddr: u64 = 0xFFFF_8800_00E1_0000;
        let listhead_paddr: u64 = 0x00E1_0000;
        let timer_vaddr: u64    = 0xFFFF_8800_00E2_0000;
        let timer_paddr: u64    = 0x00E2_0000;

        let entry_offset:    u64 = 0x00;
        let expires_offset:  u64 = 0x10;
        let function_offset: u64 = 0x18;
        let flags_offset:    u64 = 0x20; // u32 field after function pointer

        let kernel_start: u64 = 0xFFFF_8000_0000_0000;
        let kernel_end:   u64 = 0xFFFF_8000_00FF_FFFF;
        let benign_fn:    u64 = kernel_start + 0x1000;

        // bases page: vectors.0 at offset 0 = listhead_vaddr
        let mut bases_page = [0u8; 4096];
        bases_page[0..8].copy_from_slice(&listhead_vaddr.to_le_bytes());

        // list head sentinel: next → timer entry node
        let timer_entry_node = timer_vaddr + entry_offset;
        let mut listhead_page = [0u8; 4096];
        listhead_page[0..8].copy_from_slice(&timer_entry_node.to_le_bytes());

        // timer_list page
        let mut timer_page = [0u8; 4096];
        // entry.next → listhead_vaddr (terminate walk)
        timer_page[entry_offset as usize..entry_offset as usize + 8]
            .copy_from_slice(&listhead_vaddr.to_le_bytes());
        timer_page[expires_offset as usize..expires_offset as usize + 8]
            .copy_from_slice(&1234u64.to_le_bytes());
        timer_page[function_offset as usize..function_offset as usize + 8]
            .copy_from_slice(&benign_fn.to_le_bytes());
        timer_page[flags_offset as usize..flags_offset as usize + 4]
            .copy_from_slice(&flags_value.to_le_bytes());

        let mut isf_builder = IsfBuilder::new()
            .add_struct("list_head", 0x10)
            .add_field("list_head", "next", 0x00u64, "pointer")
            .add_struct("timer_base", 512)
            .add_struct("timer_list", 64)
            .add_field("timer_list", "entry",    entry_offset,    "pointer")
            .add_field("timer_list", "expires",  expires_offset,  "unsigned long")
            .add_field("timer_list", "function", function_offset, "pointer")
            .add_field("timer_list", "flags",    flags_offset,    "unsigned int")
            .add_symbol("timer_bases", bases_vaddr)
            .add_symbol("_stext",      kernel_start)
            .add_symbol("_etext",      kernel_end);

        for i in 0..TIMER_WHEEL_GROUPS {
            let field_offset: u64 = if i == 0 { 0 } else { 8 + i as u64 * 8 };
            isf_builder = isf_builder.add_field(
                "timer_base",
                &format!("vectors.{i}"),
                field_offset,
                "pointer",
            );
        }
        let isf = isf_builder.build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(bases_vaddr,    bases_paddr,    flags::WRITABLE)
            .write_phys(bases_paddr,    &bases_page)
            .map_4k(listhead_vaddr, listhead_paddr, flags::WRITABLE)
            .write_phys(listhead_paddr, &listhead_page)
            .map_4k(timer_vaddr,    timer_paddr,    flags::WRITABLE)
            .write_phys(timer_paddr,    &timer_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let mut result = walk_kernel_timers(&reader).unwrap();
        assert!(!result.is_empty(), "expected at least one timer");
        result.remove(0)
    }

    #[test]
    fn walk_kernel_timers_is_periodic_true_when_deferrable_bit_set() {
        // TIMER_DEFERRABLE = 0x1 — bit 0 set → is_periodic must be true
        let timer = walk_one_timer_with_flags(0x1);
        assert!(
            timer.is_periodic,
            "flags & 1 != 0 (TIMER_DEFERRABLE) must set is_periodic = true"
        );
    }

    #[test]
    fn walk_kernel_timers_is_periodic_false_when_flags_zero() {
        // flags == 0 → no deferrable bit → is_periodic must be false
        let timer = walk_one_timer_with_flags(0x0);
        assert!(
            !timer.is_periodic,
            "flags == 0 must leave is_periodic = false"
        );
    }

    #[test]
    fn walk_kernel_timers_is_periodic_true_when_other_bits_plus_deferrable() {
        // flags = 0x5 (bit 0 + bit 2) → bit 0 set → is_periodic true
        let timer = walk_one_timer_with_flags(0x5);
        assert!(
            timer.is_periodic,
            "flags = 0x5 has bit 0 set → is_periodic = true"
        );
    }

    #[test]
    fn walk_kernel_timers_is_periodic_false_when_only_non_deferrable_bits_set() {
        // flags = 0x4 (TIMER_PINNED only, bit 0 clear) → is_periodic false
        let timer = walk_one_timer_with_flags(0x4);
        assert!(
            !timer.is_periodic,
            "flags = 0x4 (bit 0 clear) → is_periodic = false"
        );
    }

    #[test]
    fn classify_kernel_timer_just_below_kernel_start_is_suspicious() {
        let kernel_start = 0xFFFF_8000_0000_0000u64;
        let kernel_end = 0xFFFF_8000_00FF_FFFFu64;
        // One below kernel_start but non-zero
        let function = kernel_start - 1;
        assert!(
            classify_kernel_timer(function, kernel_start, kernel_end),
            "function just below kernel_start should be suspicious"
        );
    }

    #[test]
    fn classify_kernel_timer_just_above_kernel_end_is_suspicious() {
        let kernel_start = 0xFFFF_8000_0000_0000u64;
        let kernel_end = 0xFFFF_8000_00FF_FFFFu64;
        let function = kernel_end + 1;
        assert!(
            classify_kernel_timer(function, kernel_start, kernel_end),
            "function just above kernel_end should be suspicious"
        );
    }
}
