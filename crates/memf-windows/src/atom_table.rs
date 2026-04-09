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

    // GUID-like pattern: 8-4-4-4-12 hex chars
    if is_guid_like(name) {
        return true;
    }

    // Very long atom names (>64 chars) with no spaces — likely encoded data
    if name.len() > 64 && !name.contains(' ') {
        return true;
    }

    // High entropy: mostly hex chars, length > 16, no readable words
    if name.len() > 16 && name.chars().all(|c| c.is_ascii_hexdigit() || c == '-' || c == '_') {
        return true;
    }

    false
}

/// Check if a string matches the GUID format (case-insensitive).
fn is_guid_like(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    // Pattern: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    for (i, &b) in bytes.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if b != b'-' {
                    return false;
                }
            }
            _ => {
                if !b.is_ascii_hexdigit() {
                    return false;
                }
            }
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
    todo!()
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
            .add_struct("_RTL_ATOM_TABLE", 0x20)
            .add_field("_RTL_ATOM_TABLE", "NumberOfBuckets", 0x00, "unsigned int")
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
        assert!(classify_atom("12345678-abcd-ef01-2345-67890abcdef0"));
    }

    /// Short readable atom name is not suspicious.
    #[test]
    fn classify_atom_benign() {
        assert!(!classify_atom("OleMainThreadWndClass"));
        assert!(!classify_atom("MSCTFIME UI"));
        assert!(!classify_atom("tooltips_class32"));
    }

    /// Very long hex string is suspicious (potential encoded C2 data).
    #[test]
    fn classify_atom_long_hex_suspicious() {
        assert!(classify_atom("4a3b2c1d5e6f7a8b9c0d1e2f3a4b5c6d7"));
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
        //   RtlpAtomTable (symbol) → pointer → _RTL_ATOM_TABLE @ 0xFFFF_8000_0010_0000
        //     NumberOfBuckets @ 0x00 = 1
        //     Buckets @ 0x10 = [ptr to entry]
        //   _RTL_ATOM_TABLE_ENTRY @ 0xFFFF_8000_0020_0000:
        //     HashLink @ 0x00 = 0 (end of chain)
        //     Atom @ 0x0C = 0xC001
        //     ReferenceCount @ 0x08 = 3
        //     NameLength @ 0x0E = 4 (chars)
        //     Name @ 0x10 = "Test" (UTF-16LE)

        let table_ptr_vaddr: u64 = 0xFFFF_8000_0001_0000;
        let table_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let entry_vaddr: u64 = 0xFFFF_8000_0020_0000;

        let table_ptr_paddr: u64 = 0x0001_0000;
        let table_paddr: u64 = 0x0010_0000;
        let entry_paddr: u64 = 0x0020_0000;

        let isf = IsfBuilder::new()
            .add_struct("_RTL_ATOM_TABLE", 0x20)
            .add_field("_RTL_ATOM_TABLE", "NumberOfBuckets", 0x00, "unsigned int")
            .add_field("_RTL_ATOM_TABLE", "Buckets", 0x10, "pointer")
            .add_struct("_RTL_ATOM_TABLE_ENTRY", 0x30)
            .add_field("_RTL_ATOM_TABLE_ENTRY", "HashLink", 0x00, "pointer")
            .add_field(
                "_RTL_ATOM_TABLE_ENTRY",
                "ReferenceCount",
                0x08,
                "unsigned int",
            )
            .add_field("_RTL_ATOM_TABLE_ENTRY", "Atom", 0x0C, "unsigned short")
            .add_field(
                "_RTL_ATOM_TABLE_ENTRY",
                "NameLength",
                0x0E,
                "unsigned short",
            )
            .add_field("_RTL_ATOM_TABLE_ENTRY", "Name", 0x10, "pointer")
            .add_symbol("RtlpAtomTable", table_ptr_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Table pointer page: points to table
        let mut ptr_data = vec![0u8; 4096];
        ptr_data[0..8].copy_from_slice(&table_vaddr.to_le_bytes());

        // Table page: NumberOfBuckets=1, Buckets[0]=entry_vaddr
        let mut table_data = vec![0u8; 4096];
        table_data[0x00..0x04].copy_from_slice(&1u32.to_le_bytes()); // NumberOfBuckets
        table_data[0x10..0x18].copy_from_slice(&entry_vaddr.to_le_bytes()); // Buckets[0]

        // Entry page: HashLink=0, ReferenceCount=3, Atom=0xC001, NameLength=4, Name="Test"
        let mut entry_data = vec![0u8; 4096];
        entry_data[0x00..0x08].copy_from_slice(&0u64.to_le_bytes()); // HashLink = null
        entry_data[0x08..0x0C].copy_from_slice(&3u32.to_le_bytes()); // ReferenceCount
        entry_data[0x0C..0x0E].copy_from_slice(&0xC001u16.to_le_bytes()); // Atom
        entry_data[0x0E..0x10].copy_from_slice(&4u16.to_le_bytes()); // NameLength (chars)
        // Name as inline UTF-16LE at offset 0x10
        let name_utf16: Vec<u8> = "Test".encode_utf16().flat_map(u16::to_le_bytes).collect();
        entry_data[0x10..0x10 + name_utf16.len()].copy_from_slice(&name_utf16);

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(table_ptr_vaddr, table_ptr_paddr, flags::WRITABLE)
            .write_phys(table_ptr_paddr, &ptr_data)
            .map_4k(table_vaddr, table_paddr, flags::WRITABLE)
            .write_phys(table_paddr, &table_data)
            .map_4k(entry_vaddr, entry_paddr, flags::WRITABLE)
            .write_phys(entry_paddr, &entry_data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let atoms = walk_atom_table(&reader).unwrap();
        assert_eq!(atoms.len(), 1);
        assert_eq!(atoms[0].atom, 0xC001);
        assert_eq!(atoms[0].name, "Test");
        assert_eq!(atoms[0].reference_count, 3);
        assert!(!atoms[0].is_suspicious);
    }
}
