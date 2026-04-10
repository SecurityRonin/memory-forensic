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
                is_periodic: false, // Would require tracking re-arm; default to false
                is_suspicious,
            });
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
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
