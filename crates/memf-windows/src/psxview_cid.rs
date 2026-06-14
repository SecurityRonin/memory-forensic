//! `PspCidTable` process enumeration — the 5th psxview column.
//!
//! Enumerates processes by walking `PspCidTable`, the kernel handle table that
//! maps process/thread IDs to their `_EPROCESS` / `_ETHREAD` objects.  Because
//! this table is separate from the `ActiveProcessLinks` doubly-linked list,
//! cross-referencing the two views reveals DKOM-hidden processes.
//!
//! `_EX_HANDLE_TABLE.TableCode` encodes the table level in its low 2 bits:
//! - `0` — direct: array of `_EX_HANDLE_TABLE_ENTRY` at 16-byte strides.
//! - `1` — one level of indirection.
//! - `2` — two levels of indirection.
//!
//! For simplicity this walker currently handles only the direct (level 0) case.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// A process entry found by walking `PspCidTable`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CidTableEntry {
    /// Process ID.
    pub pid: u32,
    /// Virtual address of the corresponding `_EPROCESS` structure.
    pub eprocess_addr: u64,
    /// Image name read from `_EPROCESS.ImageFileName`.
    pub image_name: String,
    /// `true` when this PID was also found in `ActiveProcessLinks`.
    pub in_active_list: bool,
    /// `true` when the PID is in `PspCidTable` but absent from `ActiveProcessLinks`
    /// (potential DKOM hiding).
    pub is_hidden: bool,
}

/// Maximum number of CID table entries to scan (safety limit).
pub(crate) const MAX_CID_ENTRIES: u64 = 16384;

/// Walk `PspCidTable` and return one [`CidTableEntry`] per process found.
///
/// Returns an empty `Vec` when the `PspCidTable` symbol is absent
/// (graceful degradation).
pub fn walk_psp_cid_table<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<CidTableEntry>> {
    // Graceful degradation: require PspCidTable symbol.
    let cid_table_ptr = match reader.symbols().symbol_address("PspCidTable") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    // PspCidTable stores a pointer to _HANDLE_TABLE; dereference it.
    let ht_addr: u64 = {
        let bytes = reader.read_bytes(cid_table_ptr, 8)?;
        u64::from_le_bytes(bytes.try_into().map_err(|_| crate::Error::WalkFailed {
            walker: "psxview_cid",
            reason: "failed to read PspCidTable pointer".into(),
        })?)
    };

    if ht_addr == 0 {
        return Ok(Vec::new());
    }

    // Read TableCode from the _HANDLE_TABLE
    let table_code: u64 = reader.read_field(ht_addr, "_HANDLE_TABLE", "TableCode")?;

    // Level = low 2 bits of TableCode
    let level = table_code & 0x3;
    let base_addr = table_code & !0x3;

    if base_addr == 0 {
        return Ok(Vec::new());
    }

    // Only support level-0 (flat) tables for now
    if level != 0 {
        return Err(crate::Error::WalkFailed {
            walker: "psxview_cid",
            reason: format!("PspCidTable level-{level} not yet supported; results incomplete"),
        });
    }

    let entry_size = reader
        .symbols()
        .struct_size("_HANDLE_TABLE_ENTRY")
        .ok_or_else(|| crate::Error::WalkFailed {
            walker: "psxview_cid",
            reason: "missing _HANDLE_TABLE_ENTRY size".into(),
        })?;

    // Read NextHandleNeedingPool to determine entry count
    let next_handle: u32 = reader.read_field(ht_addr, "_HANDLE_TABLE", "NextHandleNeedingPool")?;

    // Number of entries = next_handle / 4 (handle values are index * 4)
    let num_entries = u64::from(next_handle) / 4;
    let num_entries = num_entries.min(MAX_CID_ENTRIES);

    let mut entries = Vec::new();

    // In PspCidTable, handle value = index * 4 = PID for processes.
    // Index 0 is reserved.
    for idx in 1..num_entries {
        let entry_addr = base_addr + idx * entry_size;

        let obj_ptr: u64 =
            match reader.read_field(entry_addr, "_HANDLE_TABLE_ENTRY", "ObjectPointerBits") {
                Ok(v) => v,
                Err(_) => continue,
            };

        if obj_ptr == 0 {
            continue;
        }

        // ObjectPointerBits is shifted right by 4; reconstruct the pointer
        // with kernel canonical high bits set.
        let object_addr = (obj_ptr << 4) | 0xFFFF_0000_0000_0000;

        // object_addr points to _OBJECT_HEADER; the body (_EPROCESS) follows
        // at the Body field offset (typically 0x30).
        let body_offset = reader
            .symbols()
            .field_offset("_OBJECT_HEADER", "Body")
            .unwrap_or(0x30);
        let eprocess_addr = object_addr.wrapping_add(body_offset);

        // Verify this is a process by reading PID and checking it matches
        let pid: u64 = match reader.read_field(eprocess_addr, "_EPROCESS", "UniqueProcessId") {
            Ok(v) => v,
            Err(_) => continue,
        };

        // In PspCidTable, handle value = pid = idx * 4
        let expected_pid = idx * 4;
        if pid != expected_pid {
            // Not a process entry (could be a thread), or corrupted
            continue;
        }

        let image_name = reader
            .read_field_string(eprocess_addr, "_EPROCESS", "ImageFileName", 15)
            .unwrap_or_default();

        entries.push(CidTableEntry {
            pid: pid as u32,
            eprocess_addr,
            image_name,
            in_active_list: false, // caller must cross-reference
            is_hidden: false,      // caller must compute
        });
    }

    Ok(entries)
}

/// Returns `true` when a PID found in `PspCidTable` is absent from
/// the `ActiveProcessLinks` list, indicating potential DKOM hiding.
pub fn classify_hidden_process(in_active_list: bool) -> bool {
    !in_active_list
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_reader_no_symbols() -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;
        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &[0u8; 16]);
        let (cr3, mem) = ptb.build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// When `PspCidTable` symbol is absent the walker returns empty.
    #[test]
    fn walk_psp_cid_table_no_symbol_returns_empty() {
        let reader = make_reader_no_symbols();
        let results = walk_psp_cid_table(&reader).unwrap();
        assert!(results.is_empty());
    }

    /// A PID not found in the active list is classified as hidden.
    #[test]
    fn classify_pid_not_in_active_list_is_hidden() {
        assert!(classify_hidden_process(false));
        assert!(!classify_hidden_process(true));
    }

    // RED: missing _HANDLE_TABLE_ENTRY size → WalkFailed
    #[test]
    fn walk_psp_cid_table_missing_handle_table_entry_size_returns_walk_failed() {
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::test_builders::IsfBuilder;

        // Use windows_kernel_preset (has _HANDLE_TABLE.TableCode etc.) but remove
        // _HANDLE_TABLE_ENTRY so struct_size returns None.
        // Set up: PspCidTable → ht_vaddr; ht.TableCode = entries_vaddr (level 0);
        // ht.NextHandleNeedingPool = 8 so num_entries = 2.
        let psp_cid_paddr: u64 = 0x0010_0000;
        let ht_paddr: u64 = 0x0020_0000;
        let entries_paddr: u64 = 0x0030_0000;
        let psp_cid_vaddr: u64 = 0xFFFFF805_5A500000;
        let ht_vaddr: u64 = 0xFFFFF805_5A600000;
        let entries_vaddr: u64 = 0xFFFFF805_5A700000;

        let ptb = PageTableBuilder::new()
            .map_4k(psp_cid_vaddr, psp_cid_paddr, flags::WRITABLE)
            .map_4k(ht_vaddr, ht_paddr, flags::WRITABLE)
            .map_4k(entries_vaddr, entries_paddr, flags::WRITABLE)
            // PspCidTable pointer → ht_vaddr
            .write_phys_u64(psp_cid_paddr, ht_vaddr)
            // _HANDLE_TABLE.TableCode at preset offset 0x08 = entries_vaddr (level 0)
            .write_phys_u64(ht_paddr + 0x08, entries_vaddr)
            // _HANDLE_TABLE.NextHandleNeedingPool at preset offset 0x3C = 8 (num_entries=2)
            .write_phys(ht_paddr + 0x3C, &8u32.to_le_bytes());

        let mut isf_json = IsfBuilder::windows_kernel_preset()
            .add_symbol("PspCidTable", psp_cid_vaddr)
            .build_json();
        // Remove _HANDLE_TABLE_ENTRY so struct_size returns None
        if let Some(user_types) = isf_json["user_types"].as_object_mut() {
            user_types.remove("_HANDLE_TABLE_ENTRY");
        }
        let resolver = memf_symbols::isf::IsfResolver::from_value(&isf_json).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = memf_core::object_reader::ObjectReader::new(vas, Box::new(resolver));

        let result = walk_psp_cid_table(&reader);
        assert!(
            matches!(
                result,
                Err(crate::Error::WalkFailed { walker, .. }) if walker == "psxview_cid"
            ),
            "expected WalkFailed(psxview_cid), got {result:?}"
        );
    }
}
