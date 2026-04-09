//! Linux network protocol handler (`seq_afinfo`) hook detector.
//!
//! Linux rootkits commonly replace the `seq_show` function pointer in
//! `tcp_seq_afinfo`, `udp_seq_afinfo`, and similar protocol handler
//! structures to hide network connections from `/proc/net/tcp` and
//! `/proc/net/udp`. This module reads those structs from memory and
//! compares each `seq_ops` function pointer against the kernel text
//! range (`_stext`..`_etext`) to detect hooks.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Protocol handler symbols to check, paired with human-readable names.
const AFINFO_SYMBOLS: &[(&str, &str)] = &[
    ("tcp_seq_afinfo", "tcp"),
    ("udp_seq_afinfo", "udp"),
    ("tcp6_seq_afinfo", "tcp6"),
    ("udp6_seq_afinfo", "udp6"),
    ("raw_seq_afinfo", "raw"),
];

/// Function pointer field names within the `seq_operations` struct.
const SEQ_OPS_FIELDS: &[&str] = &["show", "start", "next", "stop"];

/// Information about a network protocol handler with potential hooks.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AfInfoHookInfo {
    /// Protocol name, e.g. "tcp", "udp", "tcp6", "udp6", "raw".
    pub protocol: String,
    /// Kernel symbol name, e.g. "tcp_seq_afinfo".
    pub struct_name: String,
    /// Field path that was checked, e.g. "seq_ops.show".
    pub field: String,
    /// Virtual address the function pointer targets.
    pub hook_address: u64,
    /// Expected module (should be kernel text).
    pub expected_module: String,
    /// Where the hook actually points.
    pub actual_module: String,
    /// Whether this function pointer is considered hooked.
    pub is_hooked: bool,
}

/// Classify whether a function pointer in a `seq_afinfo` struct is hooked.
///
/// - Address of `0` is not considered hooked (null/unset pointer).
/// - Address within `[kernel_start, kernel_end]` is benign (kernel text).
/// - Address outside that range is suspicious (hooked).
pub fn classify_afinfo_hook(hook_addr: u64, kernel_start: u64, kernel_end: u64) -> bool {
    if hook_addr == 0 {
        return false;
    }
    !(kernel_start <= hook_addr && hook_addr <= kernel_end)
}

/// Walk network protocol handler structs and check for hooks.
///
/// Looks up `tcp_seq_afinfo`, `udp_seq_afinfo`, `tcp6_seq_afinfo`,
/// `udp6_seq_afinfo`, and `raw_seq_afinfo` symbols. For each, reads
/// the `seq_ops` function pointers (`show`, `start`, `next`, `stop`)
/// and compares against the kernel text range.
///
/// Returns `Ok(Vec::new())` if no afinfo symbols are found (graceful
/// degradation).
pub fn walk_check_afinfo<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<AfInfoHookInfo>> {
    let symbols = reader.symbols();

    // Resolve kernel text boundaries; if missing, we cannot classify anything.
    let Some(kernel_start) = symbols.symbol_address("_stext") else {
        return Ok(Vec::new());
    };
    let Some(kernel_end) = symbols.symbol_address("_etext") else {
        return Ok(Vec::new());
    };

    let mut results = Vec::new();

    for &(sym_name, protocol) in AFINFO_SYMBOLS {
        // Graceful degradation: skip symbols that aren't in this profile.
        let Some(afinfo_addr) = symbols.symbol_address(sym_name) else {
            continue;
        };

        // Read the seq_ops pointer from the seq_afinfo struct.
        let seq_ops_addr: u64 = match reader.read_pointer(afinfo_addr, "seq_afinfo", "seq_ops") {
            Ok(addr) => addr,
            Err(_) => continue, // struct layout unavailable, skip
        };

        if seq_ops_addr == 0 {
            continue; // No seq_ops set for this protocol
        }

        // Read each function pointer from the seq_operations struct.
        for &field_name in SEQ_OPS_FIELDS {
            let ptr: u64 = match reader.read_pointer(seq_ops_addr, "seq_operations", field_name) {
                Ok(p) => p,
                Err(_) => continue,
            };

            let is_hooked = classify_afinfo_hook(ptr, kernel_start, kernel_end);

            let actual_module = if ptr == 0 {
                "null".to_string()
            } else if is_hooked {
                format!("unknown (0x{ptr:016x})")
            } else {
                "kernel".to_string()
            };

            results.push(AfInfoHookInfo {
                protocol: protocol.to_string(),
                struct_name: sym_name.to_string(),
                field: format!("seq_ops.{field_name}"),
                hook_address: ptr,
                expected_module: "kernel".to_string(),
                actual_module,
                is_hooked,
            });
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags as ptflags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // -----------------------------------------------------------------------
    // classify_afinfo_hook unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn hook_outside_kernel_suspicious() {
        let kernel_start = 0xFFFF_8000_0000_0000u64;
        let kernel_end = 0xFFFF_8000_00FF_FFFFu64;

        // Address in module space, well outside kernel text
        assert!(classify_afinfo_hook(0xFFFF_C900_DEAD_BEEF, kernel_start, kernel_end));
        // Address just below kernel start
        assert!(classify_afinfo_hook(kernel_start - 1, kernel_start, kernel_end));
        // Address just above kernel end
        assert!(classify_afinfo_hook(kernel_end + 1, kernel_start, kernel_end));
    }

    #[test]
    fn hook_inside_kernel_benign() {
        let kernel_start = 0xFFFF_8000_0000_0000u64;
        let kernel_end = 0xFFFF_8000_00FF_FFFFu64;

        // Exactly at start
        assert!(!classify_afinfo_hook(kernel_start, kernel_start, kernel_end));
        // In the middle
        assert!(!classify_afinfo_hook(kernel_start + 0x1000, kernel_start, kernel_end));
        // Exactly at end
        assert!(!classify_afinfo_hook(kernel_end, kernel_start, kernel_end));
    }

    #[test]
    fn hook_zero_benign() {
        let kernel_start = 0xFFFF_8000_0000_0000u64;
        let kernel_end = 0xFFFF_8000_00FF_FFFFu64;

        // Null pointer is never considered hooked
        assert!(!classify_afinfo_hook(0, kernel_start, kernel_end));
    }

    #[test]
    fn classify_multiple_protocols() {
        let kernel_start = 0xFFFF_8000_0000_0000u64;
        let kernel_end = 0xFFFF_8000_00FF_FFFFu64;
        let kernel_func = kernel_start + 0x5000;
        let module_func = 0xFFFF_C900_1234_0000u64;

        // Simulate checking several protocol handler pointers:
        // tcp show → kernel (benign)
        assert!(!classify_afinfo_hook(kernel_func, kernel_start, kernel_end));
        // udp show → module space (hooked)
        assert!(classify_afinfo_hook(module_func, kernel_start, kernel_end));
        // tcp6 show → null (benign)
        assert!(!classify_afinfo_hook(0, kernel_start, kernel_end));
        // raw show → just past kernel end (hooked)
        assert!(classify_afinfo_hook(kernel_end + 0x100, kernel_start, kernel_end));
    }

    // -----------------------------------------------------------------------
    // AfInfoHookInfo struct tests
    // -----------------------------------------------------------------------

    #[test]
    fn afinfo_hook_info_serializes() {
        let info = AfInfoHookInfo {
            protocol: "tcp".to_string(),
            struct_name: "tcp_seq_afinfo".to_string(),
            field: "seq_ops.show".to_string(),
            hook_address: 0xFFFF_C900_DEAD_BEEF,
            expected_module: "kernel".to_string(),
            actual_module: "rootkit.ko".to_string(),
            is_hooked: true,
        };

        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["protocol"], "tcp");
        assert_eq!(json["struct_name"], "tcp_seq_afinfo");
        assert_eq!(json["field"], "seq_ops.show");
        assert_eq!(json["is_hooked"], true);
    }

    // -----------------------------------------------------------------------
    // walk_check_afinfo integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn walk_check_afinfo_no_symbols_returns_empty() {
        // Build a reader with _stext/_etext but no afinfo symbols.
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 64)
            .add_field("task_struct", "pid", 0, "int")
            .add_symbol("_stext", 0xFFFF_8000_0000_0000)
            .add_symbol("_etext", 0xFFFF_8000_00FF_FFFF)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_check_afinfo(&reader).unwrap();
        assert!(results.is_empty(), "expected empty results when no afinfo symbols exist");
    }

    #[test]
    fn walk_check_afinfo_detects_hooked_seq_ops() {
        let kernel_start: u64 = 0xFFFF_8000_0000_0000;
        let kernel_end: u64 = 0xFFFF_8000_00FF_FFFF;
        let afinfo_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let afinfo_paddr: u64 = 0x0080_0000;
        let kernel_func: u64 = kernel_start + 0x1000;
        let hooked_func: u64 = 0xFFFF_C900_DEAD_0000; // Outside kernel text

        // Build seq_afinfo struct: contains a pointer to seq_operations.
        // seq_operations contains 4 function pointers (show, start, next, stop).
        // Layout: afinfo has seq_ops at offset 0 (pointer to seq_operations struct).
        // seq_operations: show=0, start=8, next=16, stop=24.
        let seq_ops_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let seq_ops_paddr: u64 = 0x0090_0000;

        // seq_operations data: show is hooked, rest are kernel
        let mut seq_ops_data = vec![0u8; 4096];
        seq_ops_data[0..8].copy_from_slice(&hooked_func.to_le_bytes()); // show → hooked
        seq_ops_data[8..16].copy_from_slice(&kernel_func.to_le_bytes()); // start → kernel
        seq_ops_data[16..24].copy_from_slice(&kernel_func.to_le_bytes()); // next → kernel
        seq_ops_data[24..32].copy_from_slice(&kernel_func.to_le_bytes()); // stop → kernel

        // afinfo data: seq_ops pointer at offset 0
        let mut afinfo_data = vec![0u8; 4096];
        afinfo_data[0..8].copy_from_slice(&seq_ops_vaddr.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("seq_afinfo", 64)
            .add_field("seq_afinfo", "seq_ops", 0, "pointer")
            .add_struct("seq_operations", 32)
            .add_field("seq_operations", "show", 0, "pointer")
            .add_field("seq_operations", "start", 8, "pointer")
            .add_field("seq_operations", "next", 16, "pointer")
            .add_field("seq_operations", "stop", 24, "pointer")
            .add_symbol("_stext", kernel_start)
            .add_symbol("_etext", kernel_end)
            .add_symbol("tcp_seq_afinfo", afinfo_vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(afinfo_vaddr, afinfo_paddr, ptflags::WRITABLE)
            .write_phys(afinfo_paddr, &afinfo_data)
            .map_4k(seq_ops_vaddr, seq_ops_paddr, ptflags::WRITABLE)
            .write_phys(seq_ops_paddr, &seq_ops_data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_check_afinfo(&reader).unwrap();

        // Should find results for tcp protocol
        assert!(!results.is_empty(), "expected non-empty results");

        // Find the hooked entry (show)
        let hooked: Vec<_> = results.iter().filter(|r| r.is_hooked).collect();
        assert_eq!(hooked.len(), 1, "expected exactly one hooked entry");
        assert_eq!(hooked[0].protocol, "tcp");
        assert_eq!(hooked[0].field, "seq_ops.show");
        assert_eq!(hooked[0].hook_address, hooked_func);

        // The other 3 (start, next, stop) should not be hooked
        let benign: Vec<_> = results.iter().filter(|r| !r.is_hooked).collect();
        assert_eq!(benign.len(), 3, "expected 3 benign entries");
    }
}
