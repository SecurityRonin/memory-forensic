//! Windows DKOM (Direct Kernel Object Manipulation) detection via psxview.
//!
//! Cross-references multiple process enumeration sources to detect hidden
//! or unlinked processes. A process visible in one source but absent from
//! another indicates potential DKOM manipulation.
//!
//! Currently implemented sources:
//! 1. **ActiveProcessLinks** — `_EPROCESS` doubly-linked list
//! 2. **PspCidTable** — kernel handle table mapping PIDs to `_EPROCESS`
//! 3. **Pool tag scan** — nonpaged pool scan for `_POOL_HEADER` with tag `Proc`
//! 4. **Session list** — `MmSessionList → _MM_SESSION_SPACE.ProcessList` walk
//! 5. **CSRSS handle table** — `csrss.exe` process `ObjectTable` handle walk
//!
//! Future sources (not yet implemented):
//! - CSRSS heap / LPC port enumeration

use std::collections::HashMap;

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, Result};

/// Cross-view process entry showing visibility across enumeration sources.
#[allow(clippy::struct_excessive_bools)]
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
    /// Found via pool tag scan for `_POOL_HEADER` with tag `Proc`.
    pub in_pool_scan: bool,
    /// Found via `PspCidTable` handle table walk.
    pub in_cid_table: bool,
    /// Found via `_MM_SESSION_SPACE.ProcessList` session list walk.
    pub in_session_list: bool,
    /// Found in a `csrss.exe` process ObjectTable (`_EPROCESS.ObjectTable` handle walk).
    pub in_csrss_handles: bool,
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

    // View 3: Pool tag scan (graceful: empty if MmNonPagedPool symbols absent)
    let pool_procs = walk_pool_scan_procs(reader);

    // View 4: Session list (graceful: empty if MmSessionList symbol absent)
    let session_procs = walk_session_list_procs(reader);

    // View 5: CSRSS handle table (graceful: empty if no csrss.exe or ObjectTable absent)
    let csrss_procs = walk_csrss_handle_procs(reader, &active_procs);

    Ok(merge_views(
        active_procs,
        cid_procs,
        pool_procs,
        session_procs,
        csrss_procs,
    ))
}

/// Process info extracted from a single enumeration source.
#[derive(Debug)]
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
/// Delegates to [`crate::psxview_cid::walk_psp_cid_table`] and maps the
/// results into the local [`RawProcInfo`] type used by the merge step.
fn walk_cid_table<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>) -> Result<Vec<RawProcInfo>> {
    // Require PspCidTable symbol; if absent, treat as error (psxview needs it).
    if reader.symbols().symbol_address("PspCidTable").is_none() {
        return Err(Error::MissingKernelSymbol {
            name: "PspCidTable".into(),
        });
    }

    let entries = crate::psxview_cid::walk_psp_cid_table(reader)?;

    Ok(entries
        .into_iter()
        .map(|e| RawProcInfo {
            pid: u64::from(e.pid),
            image_name: e.image_name,
            eprocess_addr: e.eprocess_addr,
        })
        .collect())
}

/// Walk the nonpaged pool for `_EPROCESS` objects tagged "Proc".
///
/// Reads the pool bounds by dereferencing `MmNonPagedPoolStart` and
/// `MmNonPagedPoolEnd` symbols. Returns an empty `Vec` when either symbol is
/// absent or unreadable (graceful degradation).
fn walk_pool_scan_procs<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>) -> Vec<RawProcInfo> {
    const PROC_TAG: u32 = u32::from_le_bytes(*b"Proc");
    const POOL_HEADER_SIZE: u64 = 0x10;

    let Some(start_ptr_va) = reader.symbols().symbol_address("MmNonPagedPoolStart") else {
        return Vec::new();
    };
    let Some(end_ptr_va) = reader.symbols().symbol_address("MmNonPagedPoolEnd") else {
        return Vec::new();
    };

    let pool_start = {
        let Ok(b) = reader.read_bytes(start_ptr_va, 8) else {
            return Vec::new();
        };
        let Ok(arr) = b.try_into() else {
            return Vec::new();
        };
        u64::from_le_bytes(arr)
    };
    let pool_end = {
        let Ok(b) = reader.read_bytes(end_ptr_va, 8) else {
            return Vec::new();
        };
        let Ok(arr) = b.try_into() else {
            return Vec::new();
        };
        u64::from_le_bytes(arr)
    };

    if pool_end <= pool_start {
        return Vec::new();
    }

    let obj_body_offset = reader
        .symbols()
        .field_offset("_OBJECT_HEADER", "Body")
        .unwrap_or(0x30);

    let hits = crate::pool_scan::scan_pool_for_tag(reader, PROC_TAG, pool_start, pool_end);
    let mut procs = Vec::new();

    for hit_va in hits {
        let eprocess_va = hit_va + POOL_HEADER_SIZE + obj_body_offset;
        let Ok(pid) = reader.read_field::<u64>(eprocess_va, "_EPROCESS", "UniqueProcessId") else {
            continue;
        };
        if pid == 0 {
            continue;
        }
        let Ok(image_name) =
            reader.read_field_string(eprocess_va, "_EPROCESS", "ImageFileName", 15)
        else {
            continue;
        };
        procs.push(RawProcInfo {
            pid,
            image_name,
            eprocess_addr: eprocess_va,
        });
    }

    procs
}

/// Walk `MmSessionList → _MM_SESSION_SPACE.ProcessList → _EPROCESS.SessionProcessLinks`
/// and return one [`RawProcInfo`] per process found across all sessions.
///
/// Returns an empty `Vec` when the `MmSessionList` symbol is absent (graceful degradation).
fn walk_session_list_procs<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Vec<RawProcInfo> {
    let Some(session_list_va) = reader.symbols().symbol_address("MmSessionList") else {
        return Vec::new();
    };

    let mut procs = Vec::new();

    // Walk outer list: MmSessionList ↔ _MM_SESSION_SPACE.ListEntry (at offset 0)
    let outer = reader.walk_list_with(
        session_list_va,
        "_LIST_ENTRY",
        "Flink",
        "_MM_SESSION_SPACE",
        "ListEntry",
    );
    let session_addrs: Vec<u64> = match outer {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    for session_base in session_addrs {
        // Walk inner list: _MM_SESSION_SPACE.ProcessList ↔ _EPROCESS.SessionProcessLinks
        // The ProcessList field IS the list head — pass its exact VA so termination works.
        let proc_list_va = {
            let off = reader
                .symbols()
                .field_offset("_MM_SESSION_SPACE", "ProcessList")
                .unwrap_or(0x10);
            session_base.wrapping_add(off)
        };
        let inner = reader.walk_list_with(
            proc_list_va,
            "_LIST_ENTRY",
            "Flink",
            "_EPROCESS",
            "SessionProcessLinks",
        );
        let eprocess_addrs: Vec<u64> = match inner {
            Ok(v) => v,
            Err(_) => continue,
        };

        for eprocess_va in eprocess_addrs {
            let Ok(pid) = reader.read_field::<u64>(eprocess_va, "_EPROCESS", "UniqueProcessId")
            else {
                continue;
            };
            if pid == 0 {
                continue;
            }
            let Ok(image_name) =
                reader.read_field_string(eprocess_va, "_EPROCESS", "ImageFileName", 15)
            else {
                continue;
            };
            procs.push(RawProcInfo {
                pid,
                image_name,
                eprocess_addr: eprocess_va,
            });
        }
    }

    procs
}

/// Walk the `ObjectTable` handle table of every `csrss.exe` process found in `active_procs`
/// and return one [`RawProcInfo`] for each process object referenced therein.
///
/// This constitutes psxview source #5. A process visible in the CSRSS handle table but
/// absent from `ActiveProcessLinks` or `PspCidTable` is strongly suspicious.
///
/// Returns an empty `Vec` when no `csrss.exe` is present, or when the
/// `_EPROCESS.ObjectTable` field is absent from the ISF (graceful degradation).
fn walk_csrss_handle_procs<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    active_procs: &[RawProcInfo],
) -> Vec<RawProcInfo> {
    // ObjectTable field offset must be known; if absent, skip gracefully.
    if reader
        .symbols()
        .field_offset("_EPROCESS", "ObjectTable")
        .is_none()
    {
        return Vec::new();
    }

    let obj_body_offset = reader
        .symbols()
        .field_offset("_OBJECT_HEADER", "Body")
        .unwrap_or(0x30);

    let entry_size = match reader.symbols().struct_size("_HANDLE_TABLE_ENTRY") {
        Some(s) => s,
        None => return Vec::new(),
    };

    let mut procs = Vec::new();

    for csrss in active_procs
        .iter()
        .filter(|p| p.image_name.eq_ignore_ascii_case("csrss.exe"))
    {
        // Read ObjectTable pointer from this csrss _EPROCESS
        let ot_addr: u64 = match reader.read_field(csrss.eprocess_addr, "_EPROCESS", "ObjectTable")
        {
            Ok(v) => v,
            Err(_) => continue,
        };
        if ot_addr == 0 {
            continue;
        }

        // Read TableCode and NextHandleNeedingPool from the ObjectTable _HANDLE_TABLE
        let table_code: u64 = match reader.read_field(ot_addr, "_HANDLE_TABLE", "TableCode") {
            Ok(v) => v,
            Err(_) => continue,
        };
        let next_handle: u32 =
            match reader.read_field(ot_addr, "_HANDLE_TABLE", "NextHandleNeedingPool") {
                Ok(v) => v,
                Err(_) => continue,
            };

        let level = table_code & 0x3;
        let base_addr = table_code & !0x3;
        if level != 0 || base_addr == 0 {
            continue; // only flat (level-0) tables supported
        }

        let num_entries = (u64::from(next_handle) / 4).min(crate::psxview_cid::MAX_CID_ENTRIES);

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

            let object_addr = (obj_ptr << 4) | 0xFFFF_0000_0000_0000;
            let eprocess_va = object_addr.wrapping_add(obj_body_offset);

            let pid: u64 = match reader.read_field(eprocess_va, "_EPROCESS", "UniqueProcessId") {
                Ok(v) => v,
                Err(_) => continue,
            };
            if pid == 0 {
                continue;
            }
            let image_name = reader
                .read_field_string(eprocess_va, "_EPROCESS", "ImageFileName", 15)
                .unwrap_or_default();
            procs.push(RawProcInfo {
                pid,
                image_name,
                eprocess_addr: eprocess_va,
            });
        }
    }

    procs
}

/// Merge process views from all five enumeration sources.
fn merge_views(
    active_list: Vec<RawProcInfo>,
    cid_table: Vec<RawProcInfo>,
    pool_scan: Vec<RawProcInfo>,
    session_list: Vec<RawProcInfo>,
    csrss_handles: Vec<RawProcInfo>,
) -> Vec<PsxViewEntry> {
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
                in_session_list: false,
                in_csrss_handles: false,
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
                in_session_list: false,
                in_csrss_handles: false,
                is_hidden: false,
            });
    }

    // Merge pool scan entries (no-op when pool scan was skipped)
    for proc in pool_scan {
        map.entry(proc.pid)
            .and_modify(|e| {
                e.in_pool_scan = true;
            })
            .or_insert(PsxViewEntry {
                pid: proc.pid,
                image_name: proc.image_name,
                eprocess_addr: proc.eprocess_addr,
                in_active_list: false,
                in_pool_scan: true,
                in_cid_table: false,
                in_session_list: false,
                in_csrss_handles: false,
                is_hidden: false,
            });
    }

    // Merge session list entries (no-op when MmSessionList symbol absent)
    for proc in session_list {
        map.entry(proc.pid)
            .and_modify(|e| {
                e.in_session_list = true;
            })
            .or_insert(PsxViewEntry {
                pid: proc.pid,
                image_name: proc.image_name,
                eprocess_addr: proc.eprocess_addr,
                in_active_list: false,
                in_pool_scan: false,
                in_cid_table: false,
                in_session_list: true,
                in_csrss_handles: false,
                is_hidden: false,
            });
    }

    // Merge CSRSS handle table entries (no-op when no csrss.exe or ObjectTable absent)
    for proc in csrss_handles {
        map.entry(proc.pid)
            .and_modify(|e| {
                e.in_csrss_handles = true;
            })
            .or_insert(PsxViewEntry {
                pid: proc.pid,
                image_name: proc.image_name,
                eprocess_addr: proc.eprocess_addr,
                in_active_list: false,
                in_pool_scan: false,
                in_cid_table: false,
                in_session_list: false,
                in_csrss_handles: true,
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
    results
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

    // RED: walk_cid_table missing PspCidTable symbol → MissingKernelSymbol
    #[test]
    fn walk_cid_table_missing_psp_cid_table_returns_missing_kernel_symbol() {
        // psxview calls walk_active_list first, then walk_cid_table.
        // To isolate walk_cid_table, call it directly (private fn is accessible in mod tests).
        // Use windows_kernel_preset which has all _EPROCESS fields but no PspCidTable symbol.
        let isf = IsfBuilder::windows_kernel_preset(); // no PspCidTable symbol
        let reader = memf_core::test_builders::make_reader(&isf);
        let result = walk_cid_table(&reader);
        assert!(
            matches!(
                result,
                Err(crate::Error::MissingKernelSymbol { ref name }) if name == "PspCidTable"
            ),
            "expected MissingKernelSymbol(PspCidTable), got {result:?}"
        );
    }

    // Pool scan test virtual addresses (must not collide with existing test constants)
    const POOL_REGION_VADDR: u64 = 0xFFFF_F805_5C00_0000;
    const MM_POOL_START_PTR_VADDR: u64 = 0xFFFF_F805_5D00_0000;
    const MM_POOL_END_PTR_VADDR: u64 = 0xFFFF_F805_5D10_0000;

    /// Build a reader with PspCidTable + MmNonPagedPoolStart/End symbols.
    /// The caller must map and write the pool pointer pages and pool data page.
    fn make_reader_with_pool(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset()
            .add_symbol("PspCidTable", PSP_CID_TABLE_VADDR)
            .add_symbol("MmNonPagedPoolStart", MM_POOL_START_PTR_VADDR)
            .add_symbol("MmNonPagedPoolEnd", MM_POOL_END_PTR_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// Write a 16-byte _POOL_HEADER with pool tag "Proc" at pool_paddr.
    /// _OBJECT_HEADER (0x30 bytes, zeros) follows immediately.
    /// _EPROCESS body starts at pool_paddr + 0x40.
    fn write_pool_header(ptb: PageTableBuilder, pool_paddr: u64) -> PageTableBuilder {
        ptb.write_phys(
            pool_paddr,
            &[
                0x08, 0x00, 0x00, 0x00, b'P', b'r', b'o', b'c', 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        )
    }

    /// Build the standard active list + CID table layout used by pool scan tests.
    ///
    /// Returns a `PageTableBuilder` with System (pid=4) in active list + CID,
    /// plus the pool pointer pages mapping `POOL_REGION_VADDR` as the pool bounds.
    fn build_pool_test_base(
        pool_page_paddr: u64,
        mm_start_ptr_paddr: u64,
        mm_end_ptr_paddr: u64,
    ) -> PageTableBuilder {
        let head_paddr: u64 = 0x0010_0000;
        let eproc1_paddr: u64 = 0x0020_0000;
        let cid_ptr_paddr: u64 = 0x0030_0000;
        let ht_paddr: u64 = 0x0040_0000;
        let entries_paddr: u64 = 0x0050_0000;

        let head_vaddr = PS_ACTIVE_HEAD_VADDR;
        let eproc1_vaddr: u64 = 0xFFFF_F805_5B00_0000;
        let ht_vaddr: u64 = 0xFFFF_F805_5B10_0000;
        let entries_vaddr: u64 = 0xFFFF_F805_5B20_0000;
        let pool_end_vaddr = POOL_REGION_VADDR + 0x1000;

        let eproc1_links = eproc1_vaddr + EPROCESS_LINKS;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc1_vaddr, eproc1_paddr, flags::WRITABLE)
            .map_4k(
                eproc1_vaddr + 0x1000,
                eproc1_paddr + 0x1000,
                flags::WRITABLE,
            )
            .map_4k(PSP_CID_TABLE_VADDR, cid_ptr_paddr, flags::WRITABLE)
            .map_4k(ht_vaddr, ht_paddr, flags::WRITABLE)
            .map_4k(entries_vaddr, entries_paddr, flags::WRITABLE)
            .map_4k(POOL_REGION_VADDR, pool_page_paddr, flags::WRITABLE)
            .map_4k(MM_POOL_START_PTR_VADDR, mm_start_ptr_paddr, flags::WRITABLE)
            .map_4k(MM_POOL_END_PTR_VADDR, mm_end_ptr_paddr, flags::WRITABLE);

        // Active list: head → System → head (circular)
        let ptb = ptb
            .write_phys_u64(head_paddr, eproc1_links)
            .write_phys_u64(head_paddr + 8, eproc1_links);
        let ptb = write_eprocess(ptb, eproc1_paddr, 4, "System", head_vaddr, head_vaddr);

        // CID table for System
        let ptb = ptb
            .write_phys_u64(cid_ptr_paddr, ht_vaddr)
            .write_phys_u64(ht_paddr + HANDLE_TABLE_CODE, entries_vaddr)
            .write_phys(ht_paddr + HANDLE_TABLE_NEXT_HANDLE, &8u32.to_le_bytes());
        let ptb = write_cid_entry(ptb, entries_paddr, 4, eproc1_vaddr);

        // Pool pointer pages: MmNonPagedPoolStart → POOL_REGION_VADDR, End → +0x1000
        ptb.write_phys_u64(mm_start_ptr_paddr, POOL_REGION_VADDR)
            .write_phys_u64(mm_end_ptr_paddr, pool_end_vaddr)
    }

    /// RED: process visible in active list + CID + pool scan → in_pool_scan = true.
    #[test]
    fn psxview_pool_scan_sets_in_pool_scan_true() {
        let pool_page_paddr: u64 = 0x0060_0000;
        let mm_start_ptr_paddr: u64 = 0x0070_0000;
        let mm_end_ptr_paddr: u64 = 0x0080_0000;

        // Standard layout + pool header + _EPROCESS for pid=4 at pool page offset 0x40
        let ptb = build_pool_test_base(pool_page_paddr, mm_start_ptr_paddr, mm_end_ptr_paddr);
        let ptb = write_pool_header(ptb, pool_page_paddr);
        // _EPROCESS body at pool_page_paddr + 0x40 (behind _POOL_HEADER + _OBJECT_HEADER)
        let ptb = write_eprocess(ptb, pool_page_paddr + 0x40, 4, "System", 0, 0);

        let reader = make_reader_with_pool(ptb);
        let results = psxview(&reader, PS_ACTIVE_HEAD_VADDR).unwrap();

        let system = results
            .iter()
            .find(|e| e.pid == 4)
            .expect("System must appear");
        assert!(
            system.in_pool_scan,
            "System visible in pool must have in_pool_scan=true"
        );
        assert!(system.in_active_list);
        assert!(system.in_cid_table);
        assert!(!system.is_hidden);
    }

    /// RED: process visible ONLY in pool scan → in_pool_scan=true, is_hidden=true.
    #[test]
    fn psxview_pool_scan_only_process_is_hidden() {
        let pool_page_paddr: u64 = 0x0060_0000;
        let mm_start_ptr_paddr: u64 = 0x0070_0000;
        let mm_end_ptr_paddr: u64 = 0x0080_0000;

        // Standard layout (System pid=4 in active list + CID)
        let ptb = build_pool_test_base(pool_page_paddr, mm_start_ptr_paddr, mm_end_ptr_paddr);
        // Pool contains malware.exe (pid=100) — NOT in active list, NOT in CID table
        let ptb = write_pool_header(ptb, pool_page_paddr);
        let ptb = write_eprocess(ptb, pool_page_paddr + 0x40, 100, "malware.exe", 0, 0);

        let reader = make_reader_with_pool(ptb);
        let results = psxview(&reader, PS_ACTIVE_HEAD_VADDR).unwrap();

        let malware = results
            .iter()
            .find(|e| e.pid == 100)
            .expect("malware.exe must be discovered via pool scan");
        assert!(
            malware.in_pool_scan,
            "pool-only process must have in_pool_scan=true"
        );
        assert!(
            !malware.in_active_list,
            "pool-only process must not be in active list"
        );
        assert!(
            !malware.in_cid_table,
            "pool-only process must not be in CID table"
        );
        assert!(
            malware.is_hidden,
            "pool-only process must be flagged hidden"
        );
    }

    // Session list (in_session_list) test constants
    const MM_SESSION_LIST_VADDR: u64 = 0xFFFF_F805_5E00_0000;
    const SESSION_SPACE_VADDR: u64 = 0xFFFF_F805_5E10_0000;
    const SESS_LIST_ENTRY_OFFSET: u64 = 0x00; // _MM_SESSION_SPACE.ListEntry
    const SESS_PROC_LIST_OFFSET: u64 = 0x10; // _MM_SESSION_SPACE.ProcessList
    const EPROCESS_SESSION_LINKS: u64 = 0x4E0; // _EPROCESS.SessionProcessLinks (Win10 x64)

    /// Build a reader with PspCidTable + MmSessionList and session-aware ISF structs.
    fn make_reader_with_session(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset()
            .add_struct("_MM_SESSION_SPACE", 4096)
            .add_field(
                "_MM_SESSION_SPACE",
                "ListEntry",
                SESS_LIST_ENTRY_OFFSET,
                "_LIST_ENTRY",
            )
            .add_field(
                "_MM_SESSION_SPACE",
                "ProcessList",
                SESS_PROC_LIST_OFFSET,
                "_LIST_ENTRY",
            )
            .add_field(
                "_EPROCESS",
                "SessionProcessLinks",
                EPROCESS_SESSION_LINKS,
                "_LIST_ENTRY",
            )
            .add_symbol("PspCidTable", PSP_CID_TABLE_VADDR)
            .add_symbol("MmSessionList", MM_SESSION_LIST_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// Build the standard active-list + CID layout for session tests.
    ///
    /// * `session_list_paddr` — physical page backing `MM_SESSION_LIST_VADDR`
    /// * `session_space_paddr` — physical page backing `SESSION_SPACE_VADDR`
    /// * `sess_proc_links_{paddr,vaddr}` — physical/virtual address of the
    ///   `_EPROCESS.SessionProcessLinks` field for the process that is in the session.
    fn build_session_test_base(
        session_list_paddr: u64,
        session_space_paddr: u64,
        sess_proc_links_paddr: u64,
        sess_proc_links_vaddr: u64,
    ) -> PageTableBuilder {
        let head_paddr: u64 = 0x0010_0000;
        let eproc1_paddr: u64 = 0x0020_0000;
        let cid_ptr_paddr: u64 = 0x0030_0000;
        let ht_paddr: u64 = 0x0040_0000;
        let entries_paddr: u64 = 0x0050_0000;

        let head_vaddr = PS_ACTIVE_HEAD_VADDR;
        let eproc1_vaddr: u64 = 0xFFFF_F805_5B00_0000;
        let ht_vaddr: u64 = 0xFFFF_F805_5B10_0000;
        let entries_vaddr: u64 = 0xFFFF_F805_5B20_0000;
        let eproc1_links = eproc1_vaddr + EPROCESS_LINKS;
        let sess_proc_list_head_vaddr = SESSION_SPACE_VADDR + SESS_PROC_LIST_OFFSET;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc1_vaddr, eproc1_paddr, flags::WRITABLE)
            .map_4k(
                eproc1_vaddr + 0x1000,
                eproc1_paddr + 0x1000,
                flags::WRITABLE,
            )
            .map_4k(PSP_CID_TABLE_VADDR, cid_ptr_paddr, flags::WRITABLE)
            .map_4k(ht_vaddr, ht_paddr, flags::WRITABLE)
            .map_4k(entries_vaddr, entries_paddr, flags::WRITABLE)
            .map_4k(MM_SESSION_LIST_VADDR, session_list_paddr, flags::WRITABLE)
            .map_4k(SESSION_SPACE_VADDR, session_space_paddr, flags::WRITABLE);

        // Active list: head → System → head (circular)
        let ptb = ptb
            .write_phys_u64(head_paddr, eproc1_links)
            .write_phys_u64(head_paddr + 8, eproc1_links);
        let ptb = write_eprocess(ptb, eproc1_paddr, 4, "System", head_vaddr, head_vaddr);

        // CID table for System (pid=4)
        let ptb = ptb
            .write_phys_u64(cid_ptr_paddr, ht_vaddr)
            .write_phys_u64(ht_paddr + HANDLE_TABLE_CODE, entries_vaddr)
            .write_phys(ht_paddr + HANDLE_TABLE_NEXT_HANDLE, &8u32.to_le_bytes());
        let ptb = write_cid_entry(ptb, entries_paddr, 4, eproc1_vaddr);

        // Session list: MmSessionList ↔ session_space.ListEntry (one session, circular)
        let ptb = ptb
            .write_phys_u64(session_list_paddr, SESSION_SPACE_VADDR) // MmSessionList.Flink
            .write_phys_u64(session_list_paddr + 8, SESSION_SPACE_VADDR) // MmSessionList.Blink
            .write_phys_u64(
                session_space_paddr + SESS_LIST_ENTRY_OFFSET,
                MM_SESSION_LIST_VADDR,
            )
            .write_phys_u64(
                session_space_paddr + SESS_LIST_ENTRY_OFFSET + 8,
                MM_SESSION_LIST_VADDR,
            );

        // Session process list: ProcessList ↔ target _EPROCESS.SessionProcessLinks
        ptb.write_phys_u64(
            session_space_paddr + SESS_PROC_LIST_OFFSET,
            sess_proc_links_vaddr,
        )
        .write_phys_u64(
            session_space_paddr + SESS_PROC_LIST_OFFSET + 8,
            sess_proc_links_vaddr,
        )
        .write_phys_u64(sess_proc_links_paddr, sess_proc_list_head_vaddr) // Flink → list head
        .write_phys_u64(sess_proc_links_paddr + 8, sess_proc_list_head_vaddr) // Blink
    }

    /// RED: System visible in active list + CID + session list → in_session_list = true.
    #[test]
    fn psxview_session_list_sets_in_session_list_true() {
        let session_list_paddr: u64 = 0x0060_0000;
        let session_space_paddr: u64 = 0x0070_0000;
        // eproc1 internals match build_session_test_base (0x0020_0000, 0xFFFF_F805_5B00_0000)
        let eproc1_links_paddr: u64 = 0x0020_0000 + EPROCESS_SESSION_LINKS;
        let eproc1_links_vaddr: u64 = 0xFFFF_F805_5B00_0000 + EPROCESS_SESSION_LINKS;

        let ptb = build_session_test_base(
            session_list_paddr,
            session_space_paddr,
            eproc1_links_paddr,
            eproc1_links_vaddr,
        );

        let reader = make_reader_with_session(ptb);
        let results = psxview(&reader, PS_ACTIVE_HEAD_VADDR).unwrap();

        let system = results
            .iter()
            .find(|e| e.pid == 4)
            .expect("System must appear");
        assert!(
            system.in_session_list,
            "System visible in session list must have in_session_list=true"
        );
        assert!(system.in_active_list);
        assert!(system.in_cid_table);
        assert!(!system.is_hidden);
    }

    /// RED: process visible ONLY in session list → in_session_list=true, is_hidden=true.
    #[test]
    fn psxview_session_list_only_process_is_hidden() {
        let session_list_paddr: u64 = 0x0060_0000;
        let session_space_paddr: u64 = 0x0070_0000;
        let malware_paddr: u64 = 0x0080_0000;
        let malware_vaddr: u64 = 0xFFFF_F805_5B40_0000;

        // Session process list points to malware.exe (pid=100), NOT System
        let ptb = build_session_test_base(
            session_list_paddr,
            session_space_paddr,
            malware_paddr + EPROCESS_SESSION_LINKS,
            malware_vaddr + EPROCESS_SESSION_LINKS,
        );
        // Map and write malware.exe _EPROCESS (not in active list, not in CID)
        let ptb = ptb
            .map_4k(malware_vaddr, malware_paddr, flags::WRITABLE)
            .map_4k(
                malware_vaddr + 0x1000,
                malware_paddr + 0x1000,
                flags::WRITABLE,
            );
        let ptb = write_eprocess(ptb, malware_paddr, 100, "malware.exe", 0, 0);

        let reader = make_reader_with_session(ptb);
        let results = psxview(&reader, PS_ACTIVE_HEAD_VADDR).unwrap();

        let malware = results
            .iter()
            .find(|e| e.pid == 100)
            .expect("malware.exe must be discovered via session list");
        assert!(
            malware.in_session_list,
            "session-only process must have in_session_list=true"
        );
        assert!(
            !malware.in_active_list,
            "session-only process must not be in active list"
        );
        assert!(
            !malware.in_cid_table,
            "session-only process must not be in CID table"
        );
        assert!(
            malware.is_hidden,
            "session-only process must be flagged hidden"
        );
    }

    // CSRSS handle table (in_csrss_handles) test constants
    const EPROCESS_OBJECT_TABLE: u64 = 0x570; // Win10 x64 _EPROCESS.ObjectTable
    const CSRSS_PID: u64 = 2000;
    const CSRSS_VADDR: u64 = 0xFFFF_F805_5C00_0000;
    const CSRSS_OT_HT_VADDR: u64 = 0xFFFF_F805_5C10_0000;
    const CSRSS_OT_ENTRIES_VADDR: u64 = 0xFFFF_F805_5C20_0000;

    /// Build a reader with PspCidTable + `_EPROCESS.ObjectTable` in ISF.
    fn make_reader_with_csrss(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset()
            .add_symbol("PspCidTable", PSP_CID_TABLE_VADDR)
            .add_field("_EPROCESS", "ObjectTable", EPROCESS_OBJECT_TABLE, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// Build layout: System (pid=4) + csrss.exe (pid=2000) in active list;
    /// System in CID table; csrss.exe.ObjectTable holds a handle to System.
    fn build_csrss_test_base() -> PageTableBuilder {
        let head_paddr: u64 = 0x0010_0000;
        let eproc1_paddr: u64 = 0x0020_0000; // System
        let cid_ptr_paddr: u64 = 0x0030_0000;
        let ht_paddr: u64 = 0x0040_0000;
        let entries_paddr: u64 = 0x0050_0000;
        let csrss_paddr: u64 = 0x0060_0000; // csrss.exe
        let csrss_ot_ht_paddr: u64 = 0x0070_0000; // csrss OT _HANDLE_TABLE
        let csrss_ot_entries_paddr: u64 = 0x0080_0000; // csrss OT entries

        let head_vaddr = PS_ACTIVE_HEAD_VADDR;
        let eproc1_vaddr: u64 = 0xFFFF_F805_5B00_0000;
        let ht_vaddr: u64 = 0xFFFF_F805_5B10_0000;
        let entries_vaddr: u64 = 0xFFFF_F805_5B20_0000;

        let eproc1_links = eproc1_vaddr + EPROCESS_LINKS;
        let csrss_links = CSRSS_VADDR + EPROCESS_LINKS;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc1_vaddr, eproc1_paddr, flags::WRITABLE)
            .map_4k(
                eproc1_vaddr + 0x1000,
                eproc1_paddr + 0x1000,
                flags::WRITABLE,
            )
            .map_4k(PSP_CID_TABLE_VADDR, cid_ptr_paddr, flags::WRITABLE)
            .map_4k(ht_vaddr, ht_paddr, flags::WRITABLE)
            .map_4k(entries_vaddr, entries_paddr, flags::WRITABLE)
            .map_4k(CSRSS_VADDR, csrss_paddr, flags::WRITABLE)
            .map_4k(CSRSS_VADDR + 0x1000, csrss_paddr + 0x1000, flags::WRITABLE)
            .map_4k(CSRSS_OT_HT_VADDR, csrss_ot_ht_paddr, flags::WRITABLE)
            .map_4k(
                CSRSS_OT_ENTRIES_VADDR,
                csrss_ot_entries_paddr,
                flags::WRITABLE,
            );

        // Active list: head ↔ System ↔ csrss ↔ head
        let ptb = ptb
            .write_phys_u64(head_paddr, eproc1_links)
            .write_phys_u64(head_paddr + 8, csrss_links);

        let ptb = write_eprocess(ptb, eproc1_paddr, 4, "System", csrss_links, head_vaddr);
        let ptb = write_eprocess(
            ptb,
            csrss_paddr,
            CSRSS_PID,
            "csrss.exe",
            head_vaddr,
            eproc1_links,
        );

        // csrss.exe ObjectTable → csrss OT _HANDLE_TABLE
        let ptb = ptb.write_phys_u64(csrss_paddr + EPROCESS_OBJECT_TABLE, CSRSS_OT_HT_VADDR);

        // CID table: System only (csrss not in CID for this test)
        let ptb = ptb.write_phys_u64(cid_ptr_paddr, ht_vaddr);
        let ptb = ptb.write_phys_u64(ht_paddr + HANDLE_TABLE_CODE, entries_vaddr);
        let ptb = ptb.write_phys(ht_paddr + HANDLE_TABLE_NEXT_HANDLE, &8u32.to_le_bytes());
        let ptb = write_cid_entry(ptb, entries_paddr, 4, eproc1_vaddr);

        // csrss OT _HANDLE_TABLE: one entry (idx=1) pointing to System's _EPROCESS
        let ptb = ptb.write_phys_u64(
            csrss_ot_ht_paddr + HANDLE_TABLE_CODE,
            CSRSS_OT_ENTRIES_VADDR,
        );
        let ptb = ptb.write_phys(
            csrss_ot_ht_paddr + HANDLE_TABLE_NEXT_HANDLE,
            &8u32.to_le_bytes(),
        );

        let obj_header_vaddr = eproc1_vaddr.wrapping_sub(OBJ_HEADER_BODY_OFFSET);
        let obj_ptr_bits = (obj_header_vaddr & 0x0000_FFFF_FFFF_FFFF) >> 4;
        ptb.write_phys_u64(csrss_ot_entries_paddr + ENTRY_SIZE, obj_ptr_bits)
    }

    /// RED: System visible in active + CID + csrss OT → in_csrss_handles = true.
    #[test]
    fn psxview_csrss_handles_sets_in_csrss_handles_true() {
        let ptb = build_csrss_test_base();
        let reader = make_reader_with_csrss(ptb);
        let results = psxview(&reader, PS_ACTIVE_HEAD_VADDR).unwrap();

        let system = results
            .iter()
            .find(|e| e.pid == 4)
            .expect("System must appear");
        assert!(
            system.in_csrss_handles,
            "System visible in csrss OT must have in_csrss_handles=true"
        );
        assert!(system.in_active_list);
        assert!(system.in_cid_table);
        assert!(!system.is_hidden);
    }

    /// RED: no csrss.exe in active list → OT walk skipped, in_csrss_handles = false.
    #[test]
    fn psxview_csrss_handles_graceful_if_no_csrss() {
        let head_paddr: u64 = 0x0010_0000;
        let eproc1_paddr: u64 = 0x0020_0000;
        let cid_ptr_paddr: u64 = 0x0030_0000;
        let ht_paddr: u64 = 0x0040_0000;
        let entries_paddr: u64 = 0x0050_0000;

        let head_vaddr = PS_ACTIVE_HEAD_VADDR;
        let eproc1_vaddr: u64 = 0xFFFF_F805_5B00_0000;
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
            .map_4k(PSP_CID_TABLE_VADDR, cid_ptr_paddr, flags::WRITABLE)
            .map_4k(ht_vaddr, ht_paddr, flags::WRITABLE)
            .map_4k(entries_vaddr, entries_paddr, flags::WRITABLE)
            .write_phys_u64(head_paddr, eproc1_links)
            .write_phys_u64(head_paddr + 8, eproc1_links)
            .write_phys_u64(cid_ptr_paddr, ht_vaddr)
            .write_phys_u64(ht_paddr + HANDLE_TABLE_CODE, entries_vaddr)
            .write_phys(ht_paddr + HANDLE_TABLE_NEXT_HANDLE, &8u32.to_le_bytes());

        let ptb = write_eprocess(ptb, eproc1_paddr, 4, "System", head_vaddr, head_vaddr);
        let ptb = write_cid_entry(ptb, entries_paddr, 4, eproc1_vaddr);

        let reader = make_reader_with_cid(ptb);
        let results = psxview(&reader, PS_ACTIVE_HEAD_VADDR).unwrap();

        let system = results
            .iter()
            .find(|e| e.pid == 4)
            .expect("System must appear");
        assert!(
            !system.in_csrss_handles,
            "no csrss.exe in active list → in_csrss_handles must be false"
        );
        assert!(!system.is_hidden, "System in active+CID is not hidden");
    }
}
