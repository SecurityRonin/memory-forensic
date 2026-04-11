//! Windows DKOM (Direct Kernel Object Manipulation) detection via psxview.
//!
//! Cross-references multiple process enumeration sources to detect hidden
//! or unlinked processes. A process visible in one source but absent from
//! another indicates potential DKOM manipulation.
//!
//! Currently implemented sources:
//! 1. **ActiveProcessLinks** — `_EPROCESS` doubly-linked list
//! 2. **PspCidTable** — kernel handle table mapping PIDs to `_EPROCESS`
//!
//! Future sources (not yet implemented):
//! - Pool tag scan (`Proc` tag)
//! - Session list (`_MM_SESSION_SPACE.ProcessList`)
//! - CSRSS handle table

use std::collections::HashMap;

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, Result};

/// Maximum number of CID table entries to scan (safety limit).
const MAX_CID_ENTRIES: u64 = 16384;

/// Cross-view process entry showing visibility across enumeration sources.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PsxViewEntry {
    /// Process ID.
    pub pid: u64,
    /// Image name from `_EPROCESS.ImageFileName`.
    pub image_name: String,
    /// Virtual address of the `_EPROCESS` structure.
    pub eprocess_addr: u64,
    /// Found via `ActiveProcessLinks` doubly-linked list walk.
    pub in_active_list: bool,
    /// Found via pool tag scan (not yet implemented — always `false`).
    pub in_pool_scan: bool,
    /// Found via `PspCidTable` handle table walk.
    pub in_cid_table: bool,
    /// `true` if the process is missing from one or more sources (potentially hidden).
    pub is_hidden: bool,
}

/// Cross-reference process visibility across multiple kernel data structures.
///
/// Walks the `ActiveProcessLinks` list and the `PspCidTable`, then merges
/// results by PID. A process present in one view but missing from the other
/// is flagged as potentially hidden (`is_hidden = true`).
///
/// # Arguments
/// * `reader` — kernel virtual memory reader with symbol resolution
/// * `active_list_head` — virtual address of `PsActiveProcessHead` symbol
///
/// # Errors
/// Returns an error if the active process list walk fails or required
/// symbols are missing.
pub fn psxview<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    active_list_head: u64,
) -> Result<Vec<PsxViewEntry>> {
    // View 1: ActiveProcessLinks
    let active_procs = walk_active_list(reader, active_list_head)?;

    // View 2: PspCidTable
    let cid_procs = walk_cid_table(reader)?;

    // Merge both views by PID
    merge_views(active_procs, cid_procs)
}

/// Process info extracted from a single enumeration source.
struct RawProcInfo {
    pid: u64,
    image_name: String,
    eprocess_addr: u64,
}

/// Walk the `ActiveProcessLinks` doubly-linked list.
fn walk_active_list<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<RawProcInfo>> {
    let eproc_addrs = reader.walk_list_with(
        ps_head_vaddr,
        "_LIST_ENTRY",
        "Flink",
        "_EPROCESS",
        "ActiveProcessLinks",
    )?;

    let mut procs = Vec::with_capacity(eproc_addrs.len());
    for addr in eproc_addrs {
        let pid: u64 = reader.read_field(addr, "_EPROCESS", "UniqueProcessId")?;
        let image_name = reader.read_field_string(addr, "_EPROCESS", "ImageFileName", 15)?;
        procs.push(RawProcInfo {
            pid,
            image_name,
            eprocess_addr: addr,
        });
    }
    Ok(procs)
}

/// Walk the `PspCidTable` kernel handle table to find process objects.
///
/// `PspCidTable` is a pointer to a `_HANDLE_TABLE` whose entries map
/// PIDs (as handle values) to `_EPROCESS` pointers.
fn walk_cid_table<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>) -> Result<Vec<RawProcInfo>> {
    let cid_table_ptr = reader
        .symbols()
        .symbol_address("PspCidTable")
        .ok_or_else(|| Error::Walker("symbol 'PspCidTable' not found".into()))?;

    // PspCidTable stores a pointer to _HANDLE_TABLE; dereference it.
    let ht_addr: u64 = {
        let bytes = reader.read_bytes(cid_table_ptr, 8)?;
        u64::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| Error::Walker("failed to read PspCidTable pointer".into()))?,
        )
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
        return Err(crate::Error::Walker(format!(
            "PspCidTable level-{level} not yet supported; results incomplete"
        )));
    }

    let entry_size = reader
        .symbols()
        .struct_size("_HANDLE_TABLE_ENTRY")
        .ok_or_else(|| Error::Walker("missing _HANDLE_TABLE_ENTRY size".into()))?;

    // Read NextHandleNeedingPool to determine entry count
    let next_handle: u32 = reader.read_field(ht_addr, "_HANDLE_TABLE", "NextHandleNeedingPool")?;

    // Number of entries = next_handle / 4 (handle values are index * 4)
    let num_entries = u64::from(next_handle) / 4;
    let num_entries = num_entries.min(MAX_CID_ENTRIES);

    let mut procs = Vec::new();

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

        procs.push(RawProcInfo {
            pid,
            image_name,
            eprocess_addr,
        });
    }

    Ok(procs)
}

/// Merge process views from ActiveProcessLinks and PspCidTable.
fn merge_views(
    active_list: Vec<RawProcInfo>,
    cid_table: Vec<RawProcInfo>,
) -> Result<Vec<PsxViewEntry>> {
    let mut map: HashMap<u64, PsxViewEntry> = HashMap::new();

    // Insert all processes from the active list
    for proc in active_list {
        map.insert(
            proc.pid,
            PsxViewEntry {
                pid: proc.pid,
                image_name: proc.image_name,
                eprocess_addr: proc.eprocess_addr,
                in_active_list: true,
                in_pool_scan: false,
                in_cid_table: false,
                is_hidden: false, // computed after merge
            },
        );
    }

    // Merge CID table entries
    for proc in cid_table {
        map.entry(proc.pid)
            .and_modify(|e| {
                e.in_cid_table = true;
                if e.eprocess_addr == 0 {
                    e.eprocess_addr = proc.eprocess_addr;
                }
            })
            .or_insert(PsxViewEntry {
                pid: proc.pid,
                image_name: proc.image_name,
                eprocess_addr: proc.eprocess_addr,
                in_active_list: false,
                in_pool_scan: false,
                in_cid_table: true,
                is_hidden: false,
            });
    }

    // Compute is_hidden: missing from active list OR CID table
    let mut results: Vec<PsxViewEntry> = map
        .into_values()
        .map(|mut e| {
            e.is_hidden = !e.in_active_list || !e.in_cid_table;
            e
        })
        .collect();

    results.sort_by_key(|e| e.pid);
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

    // _EPROCESS field offsets (from windows_kernel_preset)
    const EPROCESS_PCB: u64 = 0x0;
    const KPROCESS_DTB: u64 = 0x28;
    const EPROCESS_CREATE_TIME: u64 = 0x430;
    const EPROCESS_EXIT_TIME: u64 = 0x438;
    const EPROCESS_PID: u64 = 0x440;
    const EPROCESS_LINKS: u64 = 0x448;
    const EPROCESS_PPID: u64 = 0x540;
    const EPROCESS_PEB: u64 = 0x550;
    const EPROCESS_IMAGE_NAME: u64 = 0x5A8;

    // _HANDLE_TABLE offsets
    const HANDLE_TABLE_CODE: u64 = 0x08;
    const HANDLE_TABLE_NEXT_HANDLE: u64 = 0x3C;

    // _HANDLE_TABLE_ENTRY: 16 bytes each
    const ENTRY_SIZE: u64 = 16;

    // _OBJECT_HEADER
    const OBJ_HEADER_BODY_OFFSET: u64 = 0x30;

    // PspCidTable symbol virtual address (we pick one that doesn't collide)
    const PSP_CID_TABLE_VADDR: u64 = 0xFFFFF805_5A500000;

    // PsActiveProcessHead from preset
    const PS_ACTIVE_HEAD_VADDR: u64 = 0xFFFFF805_5A400000;

    fn make_reader_with_cid(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset()
            .add_symbol("PspCidTable", PSP_CID_TABLE_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// Write a minimal _EPROCESS at a physical address.
    fn write_eprocess(
        ptb: PageTableBuilder,
        paddr: u64,
        pid: u64,
        image_name: &str,
        flink_vaddr: u64,
        blink_vaddr: u64,
    ) -> PageTableBuilder {
        let name_bytes = image_name.as_bytes();
        let mut ptb = ptb
            .write_phys_u64(paddr + EPROCESS_PCB + KPROCESS_DTB, 0x1000)
            .write_phys_u64(paddr + EPROCESS_CREATE_TIME, 132800000000000000)
            .write_phys_u64(paddr + EPROCESS_EXIT_TIME, 0)
            .write_phys_u64(paddr + EPROCESS_PID, pid)
            .write_phys_u64(paddr + EPROCESS_LINKS, flink_vaddr)
            .write_phys_u64(paddr + EPROCESS_LINKS + 8, blink_vaddr)
            .write_phys_u64(paddr + EPROCESS_PPID, 0)
            .write_phys_u64(paddr + EPROCESS_PEB, 0)
            .write_phys(paddr + EPROCESS_IMAGE_NAME, name_bytes);
        if name_bytes.len() < 15 {
            ptb = ptb.write_phys(paddr + EPROCESS_IMAGE_NAME + name_bytes.len() as u64, &[0]);
        }
        ptb
    }

    /// Build a CID table entry for a process.
    /// In PspCidTable, the handle value for a process with PID `pid` is `pid` itself.
    /// Index in table = pid / 4. The entry stores ObjectPointerBits = (obj_header_vaddr >> 4).
    /// obj_header_vaddr = eprocess_vaddr - OBJ_HEADER_BODY_OFFSET.
    fn write_cid_entry(
        ptb: PageTableBuilder,
        table_base_paddr: u64,
        pid: u64,
        eprocess_vaddr: u64,
    ) -> PageTableBuilder {
        let idx = pid / 4;
        let obj_header_vaddr = eprocess_vaddr.wrapping_sub(OBJ_HEADER_BODY_OFFSET);
        // ObjectPointerBits = obj_header_vaddr >> 4 with high bits stripped
        let obj_ptr_bits = (obj_header_vaddr & 0x0000_FFFF_FFFF_FFFF) >> 4;
        let entry_paddr = table_base_paddr + idx * ENTRY_SIZE;
        ptb.write_phys_u64(entry_paddr, obj_ptr_bits)
    }

    /// Test: process visible in both active list and CID table -> is_hidden = false
    #[test]
    fn psxview_no_hidden() {
        // Layout:
        //   PsActiveProcessHead (sentinel) -> eproc1 -> head (circular)
        //   PspCidTable -> _HANDLE_TABLE -> entry for pid=4 -> eproc1
        //
        // Physical addresses (all below 0x100_0000 = 16MB):
        let head_paddr: u64 = 0x0010_0000; // 1MB - sentinel LIST_ENTRY
        let eproc1_paddr: u64 = 0x0020_0000; // 2MB - _EPROCESS for System (pid=4)
        let cid_ptr_paddr: u64 = 0x0030_0000; // 3MB - PspCidTable pointer
        let ht_paddr: u64 = 0x0040_0000; // 4MB - _HANDLE_TABLE
        let entries_paddr: u64 = 0x0050_0000; // 5MB - handle table entries

        // Virtual addresses
        let head_vaddr: u64 = PS_ACTIVE_HEAD_VADDR;
        let eproc1_vaddr: u64 = 0xFFFF_F805_5B00_0000;
        let ht_vaddr: u64 = 0xFFFF_F805_5B10_0000;
        let entries_vaddr: u64 = 0xFFFF_F805_5B20_0000;

        let eproc1_links = eproc1_vaddr + EPROCESS_LINKS;

        // Build page table with all mappings
        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc1_vaddr, eproc1_paddr, flags::WRITABLE)
            // Map the _EPROCESS upper page too (ImageFileName at 0x5A8 needs second page)
            .map_4k(
                eproc1_vaddr + 0x1000,
                eproc1_paddr + 0x1000,
                flags::WRITABLE,
            )
            .map_4k(PSP_CID_TABLE_VADDR, cid_ptr_paddr, flags::WRITABLE)
            .map_4k(ht_vaddr, ht_paddr, flags::WRITABLE)
            .map_4k(entries_vaddr, entries_paddr, flags::WRITABLE);

        // Sentinel head: Flink -> eproc1.ActiveProcessLinks, Blink -> same
        let ptb = ptb
            .write_phys_u64(head_paddr, eproc1_links)
            .write_phys_u64(head_paddr + 8, eproc1_links);

        // Write _EPROCESS for System (pid=4)
        let ptb = write_eprocess(ptb, eproc1_paddr, 4, "System", head_vaddr, head_vaddr);

        // PspCidTable: pointer to _HANDLE_TABLE
        let ptb = ptb.write_phys_u64(cid_ptr_paddr, ht_vaddr);

        // _HANDLE_TABLE: TableCode = entries_vaddr (level 0, low bits = 0)
        let ptb = ptb.write_phys_u64(ht_paddr + HANDLE_TABLE_CODE, entries_vaddr);
        // NextHandleNeedingPool: we need entries up to index pid/4 + 1 = 2,
        // so next_handle = 2 * 4 = 8
        let ptb = ptb.write_phys(ht_paddr + HANDLE_TABLE_NEXT_HANDLE, &8u32.to_le_bytes());

        // CID table entry for pid=4 (index 1)
        let ptb = write_cid_entry(ptb, entries_paddr, 4, eproc1_vaddr);

        // Also need to map the _OBJECT_HEADER page (eprocess_vaddr - 0x30)
        let obj_hdr_vaddr = eproc1_vaddr - OBJ_HEADER_BODY_OFFSET;
        let obj_hdr_paddr = eproc1_paddr - OBJ_HEADER_BODY_OFFSET;
        // The obj header is on the same page as eproc1 (0x30 < 0x1000), so already mapped

        // The CID walk will reconstruct eprocess_vaddr from the entry and try to
        // read PID from it; since eproc1 is already mapped, this should work.
        let _ = obj_hdr_vaddr; // suppress unused warning
        let _ = obj_hdr_paddr;

        let reader = make_reader_with_cid(ptb);
        let results = psxview(&reader, head_vaddr).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pid, 4);
        assert_eq!(results[0].image_name, "System");
        assert!(results[0].in_active_list);
        assert!(results[0].in_cid_table);
        assert!(!results[0].is_hidden);
    }

    /// Test: process in CID table but NOT in active list -> is_hidden = true (DKOM!)
    #[test]
    fn psxview_hidden_from_active_list() {
        // Two processes: System (pid=4) and a hidden malware process (pid=8).
        // System is in both active list and CID table.
        // Malware is only in CID table (removed from ActiveProcessLinks via DKOM).

        let head_paddr: u64 = 0x0010_0000;
        let eproc1_paddr: u64 = 0x0020_0000; // System, pid=4
        let eproc2_paddr: u64 = 0x0030_0000; // malware.exe, pid=8
        let cid_ptr_paddr: u64 = 0x0040_0000;
        let ht_paddr: u64 = 0x0050_0000;
        let entries_paddr: u64 = 0x0060_0000;

        let head_vaddr: u64 = PS_ACTIVE_HEAD_VADDR;
        let eproc1_vaddr: u64 = 0xFFFF_F805_5B00_0000;
        let eproc2_vaddr: u64 = 0xFFFF_F805_5B40_0000;
        let ht_vaddr: u64 = 0xFFFF_F805_5B10_0000;
        let entries_vaddr: u64 = 0xFFFF_F805_5B20_0000;

        let eproc1_links = eproc1_vaddr + EPROCESS_LINKS;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc1_vaddr, eproc1_paddr, flags::WRITABLE)
            .map_4k(
                eproc1_vaddr + 0x1000,
                eproc1_paddr + 0x1000,
                flags::WRITABLE,
            )
            .map_4k(eproc2_vaddr, eproc2_paddr, flags::WRITABLE)
            .map_4k(
                eproc2_vaddr + 0x1000,
                eproc2_paddr + 0x1000,
                flags::WRITABLE,
            )
            .map_4k(PSP_CID_TABLE_VADDR, cid_ptr_paddr, flags::WRITABLE)
            .map_4k(ht_vaddr, ht_paddr, flags::WRITABLE)
            .map_4k(entries_vaddr, entries_paddr, flags::WRITABLE);

        // Active list: only System (pid=4). Circular: head -> eproc1 -> head
        let ptb = ptb
            .write_phys_u64(head_paddr, eproc1_links)
            .write_phys_u64(head_paddr + 8, eproc1_links);

        let ptb = write_eprocess(ptb, eproc1_paddr, 4, "System", head_vaddr, head_vaddr);

        // Malware process: NOT linked in active list, but we need valid _EPROCESS data
        // Its ActiveProcessLinks point to itself (unlinked process pattern)
        let eproc2_links = eproc2_vaddr + EPROCESS_LINKS;
        let ptb = write_eprocess(
            ptb,
            eproc2_paddr,
            8,
            "malware.exe",
            eproc2_links, // Flink -> self
            eproc2_links, // Blink -> self
        );

        // PspCidTable -> _HANDLE_TABLE
        let ptb = ptb.write_phys_u64(cid_ptr_paddr, ht_vaddr);
        let ptb = ptb.write_phys_u64(ht_paddr + HANDLE_TABLE_CODE, entries_vaddr);
        // Need entries up to index 2 (pid=8 -> index 2), so next_handle = 3 * 4 = 12
        let ptb = ptb.write_phys(ht_paddr + HANDLE_TABLE_NEXT_HANDLE, &12u32.to_le_bytes());

        // CID entries for both processes
        let ptb = write_cid_entry(ptb, entries_paddr, 4, eproc1_vaddr);
        let ptb = write_cid_entry(ptb, entries_paddr, 8, eproc2_vaddr);

        let reader = make_reader_with_cid(ptb);
        let results = psxview(&reader, head_vaddr).unwrap();

        assert_eq!(results.len(), 2);

        // System: visible in both -> not hidden
        let system = results.iter().find(|e| e.pid == 4).unwrap();
        assert!(system.in_active_list);
        assert!(system.in_cid_table);
        assert!(!system.is_hidden);

        // Malware: only in CID table -> hidden!
        let malware = results.iter().find(|e| e.pid == 8).unwrap();
        assert!(!malware.in_active_list);
        assert!(malware.in_cid_table);
        assert!(malware.is_hidden);
        assert_eq!(malware.image_name, "malware.exe");
    }

    /// Test: empty process list and empty CID table -> empty results
    #[test]
    fn psxview_empty() {
        // Head points to itself (empty circular list), CID table has no entries.
        let head_paddr: u64 = 0x0010_0000;
        let cid_ptr_paddr: u64 = 0x0020_0000;
        let ht_paddr: u64 = 0x0030_0000;
        let entries_paddr: u64 = 0x0040_0000;

        let head_vaddr: u64 = PS_ACTIVE_HEAD_VADDR;
        let ht_vaddr: u64 = 0xFFFF_F805_5B10_0000;
        let entries_vaddr: u64 = 0xFFFF_F805_5B20_0000;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(PSP_CID_TABLE_VADDR, cid_ptr_paddr, flags::WRITABLE)
            .map_4k(ht_vaddr, ht_paddr, flags::WRITABLE)
            .map_4k(entries_vaddr, entries_paddr, flags::WRITABLE);

        // Empty circular list: head.Flink = head, head.Blink = head
        let ptb = ptb
            .write_phys_u64(head_paddr, head_vaddr)
            .write_phys_u64(head_paddr + 8, head_vaddr);

        // PspCidTable -> _HANDLE_TABLE
        let ptb = ptb.write_phys_u64(cid_ptr_paddr, ht_vaddr);
        let ptb = ptb.write_phys_u64(ht_paddr + HANDLE_TABLE_CODE, entries_vaddr);
        // NextHandleNeedingPool = 4 (only reserved slot 0, no real entries)
        let ptb = ptb.write_phys(ht_paddr + HANDLE_TABLE_NEXT_HANDLE, &4u32.to_le_bytes());

        let reader = make_reader_with_cid(ptb);
        let results = psxview(&reader, head_vaddr).unwrap();

        assert!(results.is_empty());
    }
}
