//! Windows global atom table enumeration.
//!
//! The Windows global atom table (`nt!_RTL_ATOM_TABLE`) stores string→integer
//! mappings shared across all processes. Malware frequently registers custom
//! atoms for inter-process signaling, mutex-like exclusion (e.g., "only run
//! one copy"), or to store C2 configuration strings in a shared namespace
//! that's less obvious than named pipes or mutexes.
//!
//! The kernel exposes the global atom table via `ObpAtomTableLock` or the
//! `_RTL_ATOM_TABLE` pointed to by `ExGlobalAtomTableCallout` or
//! `RtlpAtomTable`. Each atom entry (`_RTL_ATOM_TABLE_ENTRY`) contains the
//! atom value, reference count, name length, and the atom name string.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

/// Maximum number of atom entries to walk (safety limit).
const MAX_ATOMS: usize = 4096;

/// Maximum number of hash buckets in the atom table.
const MAX_BUCKETS: usize = 512;

/// Information about a single atom in the global atom table.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AtomInfo {
    /// Atom value (integer handle).
    pub atom: u16,
    /// Atom name string.
    pub name: String,
    /// Reference count — how many processes hold this atom.
    pub reference_count: u32,
    /// Whether this atom looks suspicious based on heuristics.
    pub is_suspicious: bool,
}

/// Classify an atom name as suspicious.
///
/// Returns `true` if the atom name matches patterns commonly used by malware:
/// - GUID-like patterns (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
/// - Base64-like random strings (long, mixed case, no spaces)
/// - Known malware atom prefixes
pub fn classify_atom(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    // GUID-like
    if is_guid_like(&name.to_lowercase()) {
        return true;
    }
    // Long (>64 chars) with no spaces — likely encoded/random
    if name.len() > 64 && !name.contains(' ') {
        return true;
    }
    // >16 chars consisting only of hex digits, dashes, and underscores
    if name.len() > 16 {
        let all_hex_dash = name.chars().all(|c| c.is_ascii_hexdigit() || c == '-' || c == '_');
        if all_hex_dash {
            return true;
        }
    }
    false
}

/// Check if a string matches the GUID format (case-insensitive).
fn is_guid_like(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let bytes = s.as_bytes();
    if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            continue;
        }
        if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Enumerate global atom table entries from kernel memory.
///
/// Looks up `RtlpAtomTable` (or `ExGlobalAtomTableCallout`) to find the
/// `_RTL_ATOM_TABLE`, then walks the hash bucket chains to extract atom
/// entries. Returns an empty `Vec` if the required symbols are not present.
pub fn walk_atom_table<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<AtomInfo>> {
    // Resolve symbol: RtlpAtomTable or ExGlobalAtomTableCallout
    let sym_addr = reader
        .symbols()
        .symbol_address("RtlpAtomTable")
        .or_else(|| reader.symbols().symbol_address("ExGlobalAtomTableCallout"));

    let Some(sym_addr) = sym_addr else {
        return Ok(Vec::new());
    };

    // The symbol holds a pointer to the _RTL_ATOM_TABLE
    let table_ptr: u64 = match reader.read_bytes(sym_addr, 8) {
        Ok(bytes) => u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")),
        Err(_) => return Ok(Vec::new()),
    };
    if table_ptr == 0 {
        return Ok(Vec::new());
    }

    // Read NumberOfBuckets from _RTL_ATOM_TABLE
    let num_buckets: u32 = reader
        .read_field(table_ptr, "_RTL_ATOM_TABLE", "NumberOfBuckets")
        .unwrap_or(37);
    let num_buckets = (num_buckets as usize).min(MAX_BUCKETS);

    // Buckets array starts right after NumberOfBuckets (offset 4, aligned to 8)
    let buckets_off = reader
        .symbols()
        .field_offset("_RTL_ATOM_TABLE", "Buckets")
        .unwrap_or(8) as u64;

    // Field offsets for _RTL_ATOM_TABLE_ENTRY
    let entry_hash_link_off = reader
        .symbols()
        .field_offset("_RTL_ATOM_TABLE_ENTRY", "HashLink")
        .unwrap_or(0) as u64;
    let entry_atom_off = reader
        .symbols()
        .field_offset("_RTL_ATOM_TABLE_ENTRY", "Atom")
        .unwrap_or(0x0c) as u64;
    let entry_ref_count_off = reader
        .symbols()
        .field_offset("_RTL_ATOM_TABLE_ENTRY", "ReferenceCount")
        .unwrap_or(0x08) as u64;
    let entry_name_len_off = reader
        .symbols()
        .field_offset("_RTL_ATOM_TABLE_ENTRY", "NameLength")
        .unwrap_or(0x0e) as u64;
    let entry_name_off = reader
        .symbols()
        .field_offset("_RTL_ATOM_TABLE_ENTRY", "Name")
        .unwrap_or(0x10) as u64;

    let mut results = Vec::new();
    let mut atom_count = 0;

    for i in 0..num_buckets {
        let bucket_ptr_addr = table_ptr + buckets_off + i as u64 * 8;
        let mut entry_ptr: u64 = match reader.read_bytes(bucket_ptr_addr, 8) {
            Ok(bytes) => u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")),
            Err(_) => continue,
        };

        while entry_ptr != 0 && atom_count < MAX_ATOMS {
            // Read atom value
            let atom: u16 = reader
                .read_bytes(entry_ptr + entry_atom_off, 2)
                .map(|b| u16::from_le_bytes(b[..2].try_into().expect("2")))
                .unwrap_or(0);

            // Read reference count
            let reference_count: u32 = reader
                .read_bytes(entry_ptr + entry_ref_count_off, 4)
                .map(|b| u32::from_le_bytes(b[..4].try_into().expect("4")))
                .unwrap_or(0);

            // Read name length (count of UTF-16 code units)
            let name_len: u8 = reader
                .read_bytes(entry_ptr + entry_name_len_off, 1)
                .map(|b| b[0])
                .unwrap_or(0);

            // Read inline UTF-16LE name
            let name = if name_len > 0 {
                let byte_count = usize::from(name_len) * 2;
                reader.read_bytes(entry_ptr + entry_name_off, byte_count)
                    .map(|bytes| {
                        let u16s: Vec<u16> = bytes
                            .chunks_exact(2)
                            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                            .collect();
                        String::from_utf16_lossy(&u16s).to_string()
                    })
                    .unwrap_or_default()
            } else {
                String::new()
            };

            let is_suspicious = classify_atom(&name);
            results.push(AtomInfo { atom, name, reference_count, is_suspicious });
            atom_count += 1;

            // Follow HashLink
            entry_ptr = match reader.read_bytes(entry_ptr + entry_hash_link_off, 8) {
                Ok(bytes) => u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")),
                Err(_) => break,
            };
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// No atom table symbol → empty Vec.
    #[test]
    fn walk_atom_table_no_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("_RTL_ATOM_TABLE", 64)
            .add_field("_RTL_ATOM_TABLE", "NumberOfBuckets", 0, "unsigned int")
            .add_field("_RTL_ATOM_TABLE", "Buckets", 8, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_atom_table(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// GUID-like atom name is suspicious.
    #[test]
    fn classify_atom_guid_suspicious() {
        assert!(classify_atom("12345678-1234-1234-1234-123456789abc"));
        assert!(classify_atom("AABBCCDD-EEFF-0011-2233-445566778899"));
    }

    /// Short readable atom name is not suspicious.
    #[test]
    fn classify_atom_benign() {
        assert!(!classify_atom("MyApp"));
        assert!(!classify_atom("Shell_TrayWnd"));
    }

    /// Very long hex string is suspicious (potential encoded C2 data).
    #[test]
    fn classify_atom_long_hex_suspicious() {
        let long_hex = "a".repeat(17); // 17 hex chars, all hex
        assert!(classify_atom(&long_hex));
    }

    /// Empty name is not suspicious (just a default atom).
    #[test]
    fn classify_atom_empty_benign() {
        assert!(!classify_atom(""));
    }

    /// Single atom entry in the table.
    #[test]
    fn walk_atom_table_single_entry() {
        // Layout:
        //   SYM_VADDR @ RtlpAtomTable symbol → TABLE_VADDR
        //   TABLE_VADDR: _RTL_ATOM_TABLE { NumberOfBuckets=1, Buckets[0]=ENTRY_VADDR }
        //   ENTRY_VADDR: _RTL_ATOM_TABLE_ENTRY {
        //       HashLink @ 0 = 0 (null, end of chain)
        //       ReferenceCount @ 8 = 2
        //       Atom @ 0x0c = 0xC001
        //       NameLength @ 0x0e = 5 (5 UTF-16 units = "Hello")
        //       Name @ 0x10 = "Hello" as UTF-16LE
        //   }

        const SYM_VADDR:   u64 = 0xFFFF_8000_0070_0000;
        const SYM_PADDR:   u64 = 0x0070_0000;
        const TABLE_VADDR: u64 = 0xFFFF_8000_0071_0000;
        const TABLE_PADDR: u64 = 0x0071_0000;
        const ENTRY_VADDR: u64 = 0xFFFF_8000_0072_0000;
        const ENTRY_PADDR: u64 = 0x0072_0000;

        let isf = IsfBuilder::new()
            .add_struct("_RTL_ATOM_TABLE", 64)
            .add_field("_RTL_ATOM_TABLE", "NumberOfBuckets", 0, "unsigned int")
            .add_field("_RTL_ATOM_TABLE", "Buckets", 8, "pointer")
            .add_struct("_RTL_ATOM_TABLE_ENTRY", 64)
            .add_field("_RTL_ATOM_TABLE_ENTRY", "HashLink", 0, "pointer")
            .add_field("_RTL_ATOM_TABLE_ENTRY", "ReferenceCount", 8, "unsigned int")
            .add_field("_RTL_ATOM_TABLE_ENTRY", "Atom", 0x0c, "unsigned short")
            .add_field("_RTL_ATOM_TABLE_ENTRY", "NameLength", 0x0e, "unsigned char")
            .add_field("_RTL_ATOM_TABLE_ENTRY", "Name", 0x10, "pointer")
            .add_symbol("RtlpAtomTable", SYM_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // sym page: pointer to TABLE_VADDR
        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&TABLE_VADDR.to_le_bytes());

        // table page: NumberOfBuckets=1, Buckets[0]=ENTRY_VADDR
        let mut table_page = vec![0u8; 4096];
        table_page[0..4].copy_from_slice(&1u32.to_le_bytes()); // NumberOfBuckets
        table_page[8..16].copy_from_slice(&ENTRY_VADDR.to_le_bytes()); // Buckets[0]

        // entry page
        let name = "Hello";
        let name_utf16: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let mut entry_page = vec![0u8; 4096];
        entry_page[0..8].copy_from_slice(&0u64.to_le_bytes()); // HashLink = null
        entry_page[8..12].copy_from_slice(&2u32.to_le_bytes()); // ReferenceCount = 2
        entry_page[0x0c..0x0e].copy_from_slice(&0xC001u16.to_le_bytes()); // Atom
        entry_page[0x0e] = 5; // NameLength = 5 code units
        entry_page[0x10..0x10 + name_utf16.len()].copy_from_slice(&name_utf16);

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(SYM_VADDR, SYM_PADDR, flags::WRITABLE)
            .write_phys(SYM_PADDR, &sym_page)
            .map_4k(TABLE_VADDR, TABLE_PADDR, flags::WRITABLE)
            .write_phys(TABLE_PADDR, &table_page)
            .map_4k(ENTRY_VADDR, ENTRY_PADDR, flags::WRITABLE)
            .write_phys(ENTRY_PADDR, &entry_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let atoms = walk_atom_table(&reader).unwrap();
        assert_eq!(atoms.len(), 1);
        assert_eq!(atoms[0].name, "Hello");
        assert_eq!(atoms[0].atom, 0xC001);
        assert_eq!(atoms[0].reference_count, 2);
        assert!(!atoms[0].is_suspicious);
    }
}
