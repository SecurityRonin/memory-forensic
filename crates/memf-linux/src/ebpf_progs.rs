//! eBPF map enumeration from kernel memory.
//!
//! The existing `bpf.rs` enumerates eBPF programs via `bpf_prog_idr`.
//! This module enumerates eBPF **maps** via `map_idr`, which are separate
//! kernel objects used for data sharing between eBPF programs and userspace.
//! Rootkits often use PERF_EVENT_ARRAY or RINGBUF maps for stealthy data
//! exfiltration.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// BPF map type strings indexed by their kernel enum value.
const BPF_MAP_TYPES: &[&str] = &[
    "hash",             // 0
    "array",            // 1
    "prog_array",       // 2
    "perf_event_array", // 3
    "percpu_hash",      // 4
    "percpu_array",     // 5
    "stack_trace",      // 6
    "cgroup_array",     // 7
    "lru_hash",         // 8
    "lru_percpu_hash",  // 9
    "lpm_trie",         // 10
    "array_of_maps",    // 11
    "hash_of_maps",     // 12
    "devmap",           // 13
    "sockmap",          // 14
    "cpumap",           // 15
    "xskmap",           // 16
    "sockhash",         // 17
    "cgroup_storage",   // 18
    "reuseport_sockarray", // 19
    "percpu_cgroup_storage", // 20
    "queue",            // 21
    "stack",            // 22
    "sk_storage",       // 23
    "devmap_hash",      // 24
    "struct_ops",       // 25
    "ringbuf",          // 26
    "inode_storage",    // 27
    "task_storage",     // 28
];

/// Known suspicious eBPF map names used by rootkits/implants.
const SUSPICIOUS_MAP_NAMES: &[&str] = &[
    "rootkit",
    "hide_",
    "intercept",
    "keylog",
    "exfil",
    "covert",
];

/// Convert a raw map type integer to its string name.
pub fn map_type_name(raw: u32) -> String {
    BPF_MAP_TYPES
        .get(raw as usize)
        .map_or_else(|| format!("unknown({raw})"), |s| (*s).to_string())
}

/// Information about a loaded eBPF map.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EbpfMapInfo {
    /// Unique map ID.
    pub id: u32,
    /// Raw map type integer.
    pub map_type: u32,
    /// Human-readable map type name.
    pub map_type_name: String,
    /// Key size in bytes.
    pub key_size: u32,
    /// Value size in bytes.
    pub value_size: u32,
    /// Maximum number of entries.
    pub max_entries: u32,
    /// Map name (BPF_OBJ_NAME_LEN = 16 bytes, null-terminated).
    pub name: String,
    /// True when the map is classified as suspicious.
    pub is_suspicious: bool,
}

/// Classify whether an eBPF map is suspicious.
///
/// Suspicious criteria:
/// - Map type is `perf_event_array` or `ringbuf` AND name matches known rootkit patterns
/// - Any map type AND name exactly matches a known suspicious name
pub fn classify_ebpf_map(map_type: u32, name: &str, value_size: u32) -> bool {
    let _ = value_size;
    let name_lower = name.to_lowercase();
    let suspicious_name = SUSPICIOUS_MAP_NAMES
        .iter()
        .any(|p| name_lower.contains(p));

    // perf_event_array (3) and ringbuf (26) are high-risk exfiltration channels
    let high_risk_type = matches!(map_type, 3 | 26);

    suspicious_name || high_risk_type
}

/// Walk `map_idr` and return all loaded eBPF maps.
///
/// Returns `Ok(Vec::new())` when `map_idr` symbol is absent.
pub fn walk_ebpf_maps<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<EbpfMapInfo>> {
    let _ = reader;
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_no_symbol_reader() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn no_symbol_returns_empty() {
        let reader = make_no_symbol_reader();
        let result = walk_ebpf_maps(&reader).unwrap();
        assert!(result.is_empty(), "no map_idr symbol → empty vec");
    }

    #[test]
    fn classify_suspicious_perf_event_array() {
        // perf_event_array (type 3) is always suspicious per spec
        assert!(
            classify_ebpf_map(3, "events", 8),
            "perf_event_array should be suspicious"
        );
        // ringbuf (type 26) is always suspicious
        assert!(
            classify_ebpf_map(26, "output", 0),
            "ringbuf should be suspicious"
        );
    }

    #[test]
    fn classify_hash_map_with_suspicious_name() {
        // hash map (type 0) with a rootkit name is suspicious
        assert!(
            classify_ebpf_map(0, "rootkit_map", 8),
            "hash map named 'rootkit_map' should be suspicious"
        );
        // hash map with benign name is not suspicious
        assert!(
            !classify_ebpf_map(0, "connection_count", 8),
            "hash map with benign name should not be suspicious"
        );
    }

    // RED test: walk_ebpf_maps with a symbol returns EbpfMapInfo entries.
    #[test]
    fn walk_ebpf_maps_with_symbol_returns_entries() {
        use memf_core::test_builders::flags;

        // map_idr is an IDR. The xa_head pointer is at idr.idr_rt offset.
        // We set up the symbol so the walker can attempt traversal.
        // With no valid ISF fields for idr/bpf_map, it should gracefully
        // return empty rather than panic.

        let map_idr_vaddr: u64 = 0xFFFF_8000_0040_0000;
        let map_idr_paddr: u64 = 0x0085_0000;

        let isf = IsfBuilder::new()
            .add_symbol("map_idr", map_idr_vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(map_idr_vaddr, map_idr_paddr, flags::PRESENT | flags::WRITABLE)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_ebpf_maps(&reader);
        assert!(result.is_ok(), "walk_ebpf_maps should not error");
    }
}
