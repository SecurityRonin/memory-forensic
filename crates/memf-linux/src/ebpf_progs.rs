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
    "hash",                  // 0
    "array",                 // 1
    "prog_array",            // 2
    "perf_event_array",      // 3
    "percpu_hash",           // 4
    "percpu_array",          // 5
    "stack_trace",           // 6
    "cgroup_array",          // 7
    "lru_hash",              // 8
    "lru_percpu_hash",       // 9
    "lpm_trie",              // 10
    "array_of_maps",         // 11
    "hash_of_maps",          // 12
    "devmap",                // 13
    "sockmap",               // 14
    "cpumap",                // 15
    "xskmap",                // 16
    "sockhash",              // 17
    "cgroup_storage",        // 18
    "reuseport_sockarray",   // 19
    "percpu_cgroup_storage", // 20
    "queue",                 // 21
    "stack",                 // 22
    "sk_storage",            // 23
    "devmap_hash",           // 24
    "struct_ops",            // 25
    "ringbuf",               // 26
    "inode_storage",         // 27
    "task_storage",          // 28
];

/// Known suspicious eBPF map names used by rootkits/implants.
const SUSPICIOUS_MAP_NAMES: &[&str] =
    &["rootkit", "hide_", "intercept", "keylog", "exfil", "covert"];

/// Convert a raw map type integer to its string name.
pub fn map_type_name(raw: u32) -> String {
        todo!()
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
        todo!()
    }

/// Walk `map_idr` and return all loaded eBPF maps.
///
/// Returns `Ok(Vec::new())` when `map_idr` symbol is absent.
pub fn walk_ebpf_maps<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<EbpfMapInfo>> {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_no_symbol_reader() -> ObjectReader<SyntheticPhysMem> {
        todo!()
    }

    #[test]
    fn no_symbol_returns_empty() {
        todo!()
    }

    #[test]
    fn classify_suspicious_perf_event_array() {
        todo!()
    }

    #[test]
    fn classify_hash_map_with_suspicious_name() {
        todo!()
    }

    #[test]
    fn map_type_name_all_known() {
        todo!()
    }

    #[test]
    fn map_type_name_unknown_index() {
        todo!()
    }

    #[test]
    fn classify_ebpf_map_suspicious_name_patterns() {
        todo!()
    }

    #[test]
    fn classify_ebpf_map_case_insensitive_name() {
        todo!()
    }

    #[test]
    fn classify_ebpf_map_benign_high_risk_type_with_benign_name() {
        todo!()
    }

    // RED test: walk_ebpf_maps with a symbol returns EbpfMapInfo entries.
    #[test]
    fn walk_ebpf_maps_with_symbol_returns_entries() {
        todo!()
    }
}
