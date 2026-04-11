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
    let suspicious_name = SUSPICIOUS_MAP_NAMES.iter().any(|p| name_lower.contains(p));

    // perf_event_array (3) and ringbuf (26) are high-risk exfiltration channels
    let high_risk_type = matches!(map_type, 3 | 26);

    suspicious_name || high_risk_type
}

/// Walk `map_idr` and return all loaded eBPF maps.
///
/// Uses the same xarray/IDR traversal pattern as `bpf.rs` for `bpf_prog_idr`,
/// applied to `map_idr` (the kernel's IDR for `bpf_map` objects).
///
/// Returns `Ok(Vec::new())` when `map_idr` symbol is absent.
pub fn walk_ebpf_maps<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<EbpfMapInfo>> {
    let Some(idr_addr) = reader.symbols().symbol_address("map_idr") else {
        return Ok(Vec::new());
    };

    // Read idr.idr_rt.xa_head (or legacy idr.top) to get the xarray/radix root.
    let xa_head: u64 = reader
        .read_field(idr_addr, "idr", "idr_rt")
        .or_else(|_| reader.read_field::<u64>(idr_addr, "idr", "top"))
        .unwrap_or(0);

    if xa_head == 0 {
        return Ok(Vec::new());
    }

    let mut maps = Vec::new();
    walk_map_idr_entries(reader, xa_head, &mut maps)?;

    Ok(maps)
}

/// Recursively walk xarray/radix-tree nodes to find `bpf_map` leaf pointers.
///
/// Mirrors the logic in `bpf.rs`'s `walk_idr_entries` for `bpf_prog`.
fn walk_map_idr_entries<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    node_ptr: u64,
    maps: &mut Vec<EbpfMapInfo>,
) -> Result<()> {
    const MAX_SLOTS: usize = 64;
    const MAX_MAPS: usize = 10_000;

    let is_node = (node_ptr & 0x3) == 0x2;

    if is_node {
        let real_addr = node_ptr & !0x3;
        let slots_offset = reader
            .symbols()
            .field_offset("xa_node", "slots")
            .unwrap_or(16);

        for i in 0..MAX_SLOTS {
            if maps.len() >= MAX_MAPS {
                break;
            }
            let slot_addr = real_addr + slots_offset + (i as u64) * 8;
            let slot_val = {
                let mut buf = [0u8; 8];
                match reader.vas().read_virt(slot_addr, &mut buf) {
                    Ok(()) => u64::from_le_bytes(buf),
                    Err(_) => 0,
                }
            };
            if slot_val == 0 {
                continue;
            }
            walk_map_idr_entries(reader, slot_val, maps)?;
        }
    } else if node_ptr & 0x3 == 0 && node_ptr > 0x1000 {
        // Leaf pointer — attempt to read a bpf_map struct.
        if let Ok(info) = read_bpf_map(reader, node_ptr) {
            maps.push(info);
        }
    }

    Ok(())
}

/// Read a single `bpf_map` struct and populate `EbpfMapInfo`.
fn read_bpf_map<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    map_addr: u64,
) -> Result<EbpfMapInfo> {
    // bpf_map.map_type (u32)
    let map_type: u32 = reader.read_field(map_addr, "bpf_map", "map_type")?;
    let map_type_name_str = map_type_name(map_type);

    // bpf_map.key_size (u32)
    let key_size: u32 = reader
        .read_field(map_addr, "bpf_map", "key_size")
        .unwrap_or(0);

    // bpf_map.value_size (u32)
    let value_size: u32 = reader
        .read_field(map_addr, "bpf_map", "value_size")
        .unwrap_or(0);

    // bpf_map.max_entries (u32)
    let max_entries: u32 = reader
        .read_field(map_addr, "bpf_map", "max_entries")
        .unwrap_or(0);

    // bpf_map.name (BPF_OBJ_NAME_LEN = 16 bytes, null-terminated)
    let name = reader
        .read_field_string(map_addr, "bpf_map", "name", 16)
        .unwrap_or_default();

    // bpf_map.id — stored in the map's aux or directly; try direct first.
    let id: u32 = reader
        .read_field(map_addr, "bpf_map", "id")
        .unwrap_or(0);

    let is_suspicious = classify_ebpf_map(map_type, &name, value_size);

    Ok(EbpfMapInfo {
        id,
        map_type,
        map_type_name: map_type_name_str,
        key_size,
        value_size,
        max_entries,
        name,
        is_suspicious,
    })
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

    #[test]
    fn map_type_name_all_known() {
        // Verify every known type string for indices 0–28
        assert_eq!(map_type_name(0), "hash");
        assert_eq!(map_type_name(1), "array");
        assert_eq!(map_type_name(2), "prog_array");
        assert_eq!(map_type_name(3), "perf_event_array");
        assert_eq!(map_type_name(4), "percpu_hash");
        assert_eq!(map_type_name(5), "percpu_array");
        assert_eq!(map_type_name(6), "stack_trace");
        assert_eq!(map_type_name(7), "cgroup_array");
        assert_eq!(map_type_name(8), "lru_hash");
        assert_eq!(map_type_name(9), "lru_percpu_hash");
        assert_eq!(map_type_name(10), "lpm_trie");
        assert_eq!(map_type_name(11), "array_of_maps");
        assert_eq!(map_type_name(12), "hash_of_maps");
        assert_eq!(map_type_name(13), "devmap");
        assert_eq!(map_type_name(14), "sockmap");
        assert_eq!(map_type_name(15), "cpumap");
        assert_eq!(map_type_name(16), "xskmap");
        assert_eq!(map_type_name(17), "sockhash");
        assert_eq!(map_type_name(18), "cgroup_storage");
        assert_eq!(map_type_name(19), "reuseport_sockarray");
        assert_eq!(map_type_name(20), "percpu_cgroup_storage");
        assert_eq!(map_type_name(21), "queue");
        assert_eq!(map_type_name(22), "stack");
        assert_eq!(map_type_name(23), "sk_storage");
        assert_eq!(map_type_name(24), "devmap_hash");
        assert_eq!(map_type_name(25), "struct_ops");
        assert_eq!(map_type_name(26), "ringbuf");
        assert_eq!(map_type_name(27), "inode_storage");
        assert_eq!(map_type_name(28), "task_storage");
    }

    #[test]
    fn map_type_name_unknown_index() {
        // Index beyond the known range → "unknown(N)"
        let name = map_type_name(999);
        assert!(
            name.starts_with("unknown("),
            "out-of-range index should produce unknown(...): {name}"
        );
    }

    #[test]
    fn classify_ebpf_map_suspicious_name_patterns() {
        // All SUSPICIOUS_MAP_NAMES patterns should flag any map type
        for pattern in &["rootkit", "hide_", "intercept", "keylog", "exfil", "covert"] {
            let name = format!("{pattern}data");
            assert!(
                classify_ebpf_map(0, &name, 8),
                "pattern '{pattern}' in name should be suspicious"
            );
        }
    }

    #[test]
    fn classify_ebpf_map_case_insensitive_name() {
        // Names are lowercased before matching
        assert!(classify_ebpf_map(0, "ROOTKIT_MAP", 8));
        assert!(classify_ebpf_map(0, "KeyLog_events", 8));
    }

    #[test]
    fn classify_ebpf_map_benign_high_risk_type_with_benign_name() {
        // perf_event_array (3) is always suspicious regardless of name
        assert!(classify_ebpf_map(3, "benign_map", 64));
        // ringbuf (26) is always suspicious
        assert!(classify_ebpf_map(26, "my_output", 0));
    }

    // Walk with a fully-constructed IDR → returns real EbpfMapInfo entries.
    #[test]
    fn walk_ebpf_maps_with_symbol_returns_entries() {
        use memf_core::test_builders::flags;

        // Memory layout:
        //   idr page  @ paddr 0x0085_0000 (vaddr 0xFFFF_8000_0040_0000)
        //   map page  @ paddr 0x0086_0000 (vaddr 0xFFFF_8000_0041_0000)
        //
        // idr.idr_rt at offset 0 = map_vaddr (clean leaf: low bits 0x0, > 0x1000)
        // bpf_map.map_type at offset 0 = 1 (array)

        let idr_vaddr: u64 = 0xFFFF_8000_0040_0000;
        let idr_paddr: u64 = 0x0085_0000;
        let map_vaddr: u64 = 0xFFFF_8000_0041_0000;
        let map_paddr: u64 = 0x0086_0000;

        let map_type_off: u64 = 0x00; // u32
        let key_size_off: u64 = 0x04; // u32
        let value_size_off: u64 = 0x08; // u32
        let max_entries_off: u64 = 0x0C; // u32
        let name_off: u64 = 0x10;     // char[16]
        let id_off: u64 = 0x20;       // u32

        let isf = IsfBuilder::new()
            .add_symbol("map_idr", idr_vaddr)
            .add_struct("idr", 0x20)
            .add_field("idr", "idr_rt", 0x00u64, "pointer")
            .add_struct("bpf_map", 0x100)
            .add_field("bpf_map", "map_type",    map_type_off,    "unsigned int")
            .add_field("bpf_map", "key_size",    key_size_off,    "unsigned int")
            .add_field("bpf_map", "value_size",  value_size_off,  "unsigned int")
            .add_field("bpf_map", "max_entries", max_entries_off, "unsigned int")
            .add_field("bpf_map", "name",        name_off,        "char")
            .add_field("bpf_map", "id",          id_off,          "unsigned int")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();

        // idr page: idr_rt = map_vaddr (leaf pointer)
        let mut idr_page = [0u8; 4096];
        idr_page[0..8].copy_from_slice(&map_vaddr.to_le_bytes());

        // bpf_map page
        let mut map_page = [0u8; 4096];
        map_page[map_type_off as usize..map_type_off as usize + 4]
            .copy_from_slice(&1u32.to_le_bytes()); // array
        map_page[key_size_off as usize..key_size_off as usize + 4]
            .copy_from_slice(&4u32.to_le_bytes());
        map_page[value_size_off as usize..value_size_off as usize + 4]
            .copy_from_slice(&8u32.to_le_bytes());
        map_page[max_entries_off as usize..max_entries_off as usize + 4]
            .copy_from_slice(&1024u32.to_le_bytes());
        map_page[name_off as usize..name_off as usize + 8]
            .copy_from_slice(b"test_map");
        map_page[id_off as usize..id_off as usize + 4]
            .copy_from_slice(&7u32.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(idr_vaddr, idr_paddr, flags::PRESENT | flags::WRITABLE)
            .write_phys(idr_paddr, &idr_page)
            .map_4k(map_vaddr, map_paddr, flags::PRESENT | flags::WRITABLE)
            .write_phys(map_paddr, &map_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_ebpf_maps(&reader);
        assert!(result.is_ok(), "walk_ebpf_maps should not error");
        let maps = result.unwrap();
        assert_eq!(maps.len(), 1, "should return exactly one map entry");
        let m = &maps[0];
        assert_eq!(m.id, 7);
        assert_eq!(m.map_type, 1);
        assert_eq!(m.map_type_name, "array");
        assert_eq!(m.key_size, 4);
        assert_eq!(m.value_size, 8);
        assert_eq!(m.max_entries, 1024);
        assert!(m.name.contains("test_map"), "name should be test_map: {}", m.name);
        assert!(!m.is_suspicious, "benign array map should not be suspicious");
    }
}
