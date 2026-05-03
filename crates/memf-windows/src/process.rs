//! Windows process walker.
//!
//! Enumerates processes by walking the `_EPROCESS` linked list via
//! `ActiveProcessLinks`. Each `_EPROCESS` is connected via `_LIST_ENTRY`
//! to form a circular doubly-linked list starting from `PsActiveProcessHead`.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;
use crate::{Error, Result, WinPebMasqueradeInfo, WinProcessInfo, WinPsTreeEntry};

/// Walk the Windows process list starting from `PsActiveProcessHead`.
///
/// `ps_head_vaddr` is the virtual address of the `PsActiveProcessHead` symbol.
/// This can come from dump metadata or symbol resolution.
pub fn walk_processes<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<WinProcessInfo>> {
    let eproc_addrs = reader.walk_list_with(
        ps_head_vaddr,
        "_LIST_ENTRY",
        "Flink",
        "_EPROCESS",
        "ActiveProcessLinks",
    )?;

    let mut procs = Vec::with_capacity(eproc_addrs.len());
    for addr in eproc_addrs {
        procs.push(read_process_info(reader, addr)?);
    }

    procs.sort_by_key(|p| p.pid);
    Ok(procs)
}

fn read_process_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    eproc_addr: u64,
) -> Result<WinProcessInfo> {
    let pid: u64 = reader.read_field(eproc_addr, "_EPROCESS", "UniqueProcessId")?;
    let ppid: u64 = reader.read_field(eproc_addr, "_EPROCESS", "InheritedFromUniqueProcessId")?;
    let image_name = reader.read_field_string(eproc_addr, "_EPROCESS", "ImageFileName", 15)?;
    let create_time: u64 = reader.read_field(eproc_addr, "_EPROCESS", "CreateTime")?;
    let exit_time: u64 = reader.read_field(eproc_addr, "_EPROCESS", "ExitTime")?;
    let peb_addr: u64 = reader.read_field(eproc_addr, "_EPROCESS", "Peb")?;

    // Pcb is at offset 0 within _EPROCESS, which IS the _KPROCESS.
    // We need the offset of Pcb within _EPROCESS to compute the _KPROCESS base.
    let pcb_offset = reader.required_field_offset("_EPROCESS", "Pcb")?;
    let kproc_addr = eproc_addr.wrapping_add(pcb_offset);
    let cr3: u64 = reader.read_field(kproc_addr, "_KPROCESS", "DirectoryTableBase")?;

    let thread_count: u32 = reader
        .read_field::<u32>(eproc_addr, "_EPROCESS", "ActiveThreads")
        .unwrap_or(0);

    let is_wow64: bool = reader
        .read_field::<u64>(eproc_addr, "_EPROCESS", "Wow64Process")
        .map(|v| v != 0)
        .unwrap_or(false);

    Ok(WinProcessInfo {
        pid,
        ppid,
        image_name,
        create_time,
        exit_time,
        cr3,
        peb_addr,
        vaddr: eproc_addr,
        thread_count,
        is_wow64,
    })
}

/// Build a process tree from a flat process list.
///
/// Returns a depth-first-ordered list of `WinPsTreeEntry` with each
/// entry annotated with its tree depth. Processes whose parent is
/// not found in the list are treated as roots (depth 0).
pub fn build_pstree(procs: &[WinProcessInfo]) -> Vec<WinPsTreeEntry> {
    use std::collections::{HashMap, HashSet};

    // Build PID → index map and children map
    let pid_set: HashSet<u64> = procs.iter().map(|p| p.pid).collect();
    let mut children: HashMap<u64, Vec<usize>> = HashMap::new();
    let mut roots = Vec::new();

    for (i, proc) in procs.iter().enumerate() {
        if proc.ppid == 0 || !pid_set.contains(&proc.ppid) {
            roots.push(i);
        } else {
            children.entry(proc.ppid).or_default().push(i);
        }
    }

    // Sort roots and children by PID for deterministic output
    roots.sort_by_key(|&i| procs[i].pid);
    for kids in children.values_mut() {
        kids.sort_by_key(|&i| procs[i].pid);
    }

    // DFS walk
    let mut result = Vec::with_capacity(procs.len());
    let mut stack: Vec<(usize, u32)> = roots.into_iter().rev().map(|i| (i, 0)).collect();

    while let Some((idx, depth)) = stack.pop() {
        result.push(WinPsTreeEntry {
            process: procs[idx].clone(),
            depth,
        });
        if let Some(kids) = children.get(&procs[idx].pid) {
            // Push in reverse so first child is processed first
            for &kid_idx in kids.iter().rev() {
                stack.push((kid_idx, depth + 1));
            }
        }
    }

    result
}

/// Check for PEB masquerade across all processes.
///
/// For each process with a non-null PEB, reads
/// `PEB.ProcessParameters.ImagePathName` and compares the basename
/// against `_EPROCESS.ImageFileName`. Mismatches may indicate
/// process masquerading (e.g., malware pretending to be svchost.exe).
pub fn check_peb_masquerade<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<WinPebMasqueradeInfo>> {
    let eproc_addrs = reader.walk_list_with(
        ps_head_vaddr,
        "_LIST_ENTRY",
        "Flink",
        "_EPROCESS",
        "ActiveProcessLinks",
    )?;

    let mut results = Vec::new();

    for eproc_addr in eproc_addrs {
        let pid: u64 = reader.read_field(eproc_addr, "_EPROCESS", "UniqueProcessId")?;
        let peb_addr: u64 = reader.read_field(eproc_addr, "_EPROCESS", "Peb")?;
        let eprocess_name =
            reader.read_field_string(eproc_addr, "_EPROCESS", "ImageFileName", 15)?;

        // Skip kernel processes (no PEB)
        if peb_addr == 0 {
            continue;
        }

        // PEB.ProcessParameters
        let params_ptr: u64 = reader.read_field(peb_addr, "_PEB", "ProcessParameters")?;
        if params_ptr == 0 {
            continue;
        }

        // ProcessParameters.ImagePathName is a _UNICODE_STRING
        let image_path_offset = reader
            .symbols()
            .field_offset("_RTL_USER_PROCESS_PARAMETERS", "ImagePathName")
            .ok_or_else(|| {
                Error::Walker("missing _RTL_USER_PROCESS_PARAMETERS.ImagePathName offset".into())
            })?;
        let image_ustr_addr = params_ptr.wrapping_add(image_path_offset);
        let peb_image_path = read_unicode_string(reader, image_ustr_addr)?;

        // Extract basename from path (after last backslash)
        let peb_basename = peb_image_path
            .rsplit('\\')
            .next()
            .unwrap_or(&peb_image_path);

        // Case-insensitive comparison
        let suspicious = !eprocess_name.eq_ignore_ascii_case(peb_basename);

        results.push(WinPebMasqueradeInfo {
            pid,
            eprocess_name,
            peb_image_path,
            suspicious,
        });
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::make_reader;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_symbols::test_builders::IsfBuilder;

    // Offsets from windows_kernel_preset:
    // _EPROCESS:
    //   Pcb (= _KPROCESS): 0x0
    //   CreateTime: 0x430
    //   ExitTime: 0x438
    //   UniqueProcessId: 0x440
    //   ActiveProcessLinks: 0x448 (_LIST_ENTRY, Flink@0, Blink@8)
    //   Token: 0x4B8
    //   InheritedFromUniqueProcessId: 0x540
    //   Peb: 0x550
    //   ImageFileName: 0x5A8  (char, 15 bytes max)
    // _KPROCESS:
    //   DirectoryTableBase: 0x28
    // _LIST_ENTRY:
    //   Flink: 0
    //   Blink: 8

    const EPROCESS_PCB: u64 = 0x0;
    const KPROCESS_DTB: u64 = 0x28;
    const EPROCESS_CREATE_TIME: u64 = 0x430;
    const EPROCESS_EXIT_TIME: u64 = 0x438;
    const EPROCESS_PID: u64 = 0x440;
    const EPROCESS_LINKS: u64 = 0x448;
    const EPROCESS_PPID: u64 = 0x540;
    const EPROCESS_PEB: u64 = 0x550;
    const EPROCESS_IMAGE_NAME: u64 = 0x5A8;

    /// Build an ObjectReader with the windows_kernel_preset symbols and a
    /// configured page table mapping.
    fn make_win_reader(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset();
        make_reader(&isf, ptb)
    }

    /// Write an _EPROCESS structure at the given physical address.
    fn write_eprocess(
        ptb: PageTableBuilder,
        paddr: u64,
        _eproc_vaddr: u64,
        pid: u64,
        ppid: u64,
        image_name: &str,
        create_time: u64,
        exit_time: u64,
        cr3: u64,
        peb: u64,
        flink_vaddr: u64,
        blink_vaddr: u64,
    ) -> PageTableBuilder {
        let name_bytes = image_name.as_bytes();
        let mut ptb = ptb
            // _KPROCESS.DirectoryTableBase at eproc + Pcb(0) + DTB(0x28)
            .write_phys_u64(paddr + EPROCESS_PCB + KPROCESS_DTB, cr3)
            // CreateTime
            .write_phys_u64(paddr + EPROCESS_CREATE_TIME, create_time)
            // ExitTime
            .write_phys_u64(paddr + EPROCESS_EXIT_TIME, exit_time)
            // UniqueProcessId
            .write_phys_u64(paddr + EPROCESS_PID, pid)
            // ActiveProcessLinks.Flink
            .write_phys_u64(paddr + EPROCESS_LINKS, flink_vaddr)
            // ActiveProcessLinks.Blink
            .write_phys_u64(paddr + EPROCESS_LINKS + 8, blink_vaddr)
            // InheritedFromUniqueProcessId
            .write_phys_u64(paddr + EPROCESS_PPID, ppid)
            // Peb
            .write_phys_u64(paddr + EPROCESS_PEB, peb)
            // ImageFileName (write bytes)
            .write_phys(paddr + EPROCESS_IMAGE_NAME, name_bytes);
        // Null-terminate the image name if shorter than 15 bytes
        if name_bytes.len() < 15 {
            ptb = ptb.write_phys(paddr + EPROCESS_IMAGE_NAME + name_bytes.len() as u64, &[0]);
        }
        ptb
    }

    #[test]
    fn walk_single_process() {
        // One _EPROCESS (System, pid=4) in the process list.
        // PsActiveProcessHead is a sentinel _LIST_ENTRY.
        // Circular: head.Flink → eproc.ActiveProcessLinks
        //           eproc.ActiveProcessLinks.Flink → head

        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0080_1000;

        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_1000;

        // head.Flink → eproc.ActiveProcessLinks (eproc_vaddr + EPROCESS_LINKS)
        // head.Blink → eproc.ActiveProcessLinks (circular, single entry)
        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            // Sentinel head: Flink → eproc.ActiveProcessLinks
            .write_phys_u64(head_paddr, eproc_vaddr + EPROCESS_LINKS)
            // Sentinel head: Blink → eproc.ActiveProcessLinks
            .write_phys_u64(head_paddr + 8, eproc_vaddr + EPROCESS_LINKS);

        let ptb = write_eprocess(
            ptb,
            eproc_paddr,
            eproc_vaddr,
            4, // pid = 4 (System)
            0, // ppid = 0
            "System",
            132800000000000000, // create_time
            0,                  // exit_time (still running)
            0x1ab000,           // CR3
            0,                  // PEB = 0 (System has no PEB)
            head_vaddr,         // Flink → back to head
            head_vaddr,         // Blink → back to head
        );

        let reader = make_win_reader(ptb);
        let procs = walk_processes(&reader, head_vaddr).unwrap();

        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].pid, 4);
        assert_eq!(procs[0].ppid, 0);
        assert_eq!(procs[0].image_name, "System");
        assert_eq!(procs[0].cr3, 0x1ab000);
        assert_eq!(procs[0].create_time, 132800000000000000);
        assert_eq!(procs[0].exit_time, 0);
        assert_eq!(procs[0].peb_addr, 0);
        assert_eq!(procs[0].vaddr, eproc_vaddr);
    }

    #[test]
    fn walk_three_processes() {
        // Three processes: System(4), csrss.exe(528), svchost.exe(700)
        // Circular list: head → A → B → C → head

        let head_paddr: u64 = 0x0080_0000;
        let a_paddr: u64 = 0x0080_1000;
        let b_paddr: u64 = 0x0080_2000;
        let c_paddr: u64 = 0x0080_3000;

        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let a_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let b_vaddr: u64 = 0xFFFF_8000_0010_2000;
        let c_vaddr: u64 = 0xFFFF_8000_0010_3000;

        let a_links = a_vaddr + EPROCESS_LINKS;
        let b_links = b_vaddr + EPROCESS_LINKS;
        let c_links = c_vaddr + EPROCESS_LINKS;

        // Sentinel head
        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(a_vaddr, a_paddr, flags::WRITABLE)
            .map_4k(b_vaddr, b_paddr, flags::WRITABLE)
            .map_4k(c_vaddr, c_paddr, flags::WRITABLE)
            // head.Flink → A.ActiveProcessLinks
            .write_phys_u64(head_paddr, a_links)
            // head.Blink → C.ActiveProcessLinks
            .write_phys_u64(head_paddr + 8, c_links);

        // Process A: System, pid=4
        let ptb = write_eprocess(
            ptb,
            a_paddr,
            a_vaddr,
            4,
            0,
            "System",
            132800000000000000,
            0,
            0x1ab000,
            0,
            b_links,    // Flink → B
            head_vaddr, // Blink → head
        );

        // Process B: csrss.exe, pid=528
        let ptb = write_eprocess(
            ptb,
            b_paddr,
            b_vaddr,
            528,
            4,
            "csrss.exe",
            132800000100000000,
            0,
            0x2cd000,
            0x0000_0040_0000_0000,
            c_links, // Flink → C
            a_links, // Blink → A
        );

        // Process C: svchost.exe, pid=700
        let ptb = write_eprocess(
            ptb,
            c_paddr,
            c_vaddr,
            700,
            528,
            "svchost.exe",
            132800000200000000,
            0,
            0x3ef000,
            0x0000_0050_0000_0000,
            head_vaddr, // Flink → head (loop back)
            b_links,    // Blink → B
        );

        let reader = make_win_reader(ptb);
        let procs = walk_processes(&reader, head_vaddr).unwrap();

        // Should be sorted by PID
        assert_eq!(procs.len(), 3);

        assert_eq!(procs[0].pid, 4);
        assert_eq!(procs[0].image_name, "System");
        assert_eq!(procs[0].ppid, 0);
        assert_eq!(procs[0].cr3, 0x1ab000);

        assert_eq!(procs[1].pid, 528);
        assert_eq!(procs[1].image_name, "csrss.exe");
        assert_eq!(procs[1].ppid, 4);
        assert_eq!(procs[1].cr3, 0x2cd000);

        assert_eq!(procs[2].pid, 700);
        assert_eq!(procs[2].image_name, "svchost.exe");
        assert_eq!(procs[2].ppid, 528);
        assert_eq!(procs[2].cr3, 0x3ef000);
    }

    #[test]
    fn walk_empty_list() {
        // PsActiveProcessHead.Flink points to itself → empty list.
        let head_paddr: u64 = 0x0080_0000;
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            // head.Flink → head (self-referential = empty)
            .write_phys_u64(head_paddr, head_vaddr)
            // head.Blink → head
            .write_phys_u64(head_paddr + 8, head_vaddr);

        let reader = make_win_reader(ptb);
        let procs = walk_processes(&reader, head_vaddr).unwrap();

        assert!(procs.is_empty());
    }

    #[test]
    fn read_process_creates_correct_info() {
        // Verify all fields are read correctly from a single _EPROCESS.
        let eproc_paddr: u64 = 0x0080_1000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let head_paddr: u64 = 0x0080_0000;
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;

        let specific_create_time: u64 = 132_900_000_000_000_000;
        let specific_exit_time: u64 = 132_900_001_000_000_000;
        let specific_cr3: u64 = 0x00AB_C000;
        let specific_peb: u64 = 0x0000_0070_0000_0000;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            // head → eproc → head (single process)
            .write_phys_u64(head_paddr, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(head_paddr + 8, eproc_vaddr + EPROCESS_LINKS);

        let ptb = write_eprocess(
            ptb,
            eproc_paddr,
            eproc_vaddr,
            1234, // pid
            567,  // ppid
            "notepad.exe",
            specific_create_time,
            specific_exit_time,
            specific_cr3,
            specific_peb,
            head_vaddr, // Flink → head
            head_vaddr, // Blink → head
        );

        let reader = make_win_reader(ptb);
        let procs = walk_processes(&reader, head_vaddr).unwrap();

        assert_eq!(procs.len(), 1);
        let p = &procs[0];
        assert_eq!(p.pid, 1234);
        assert_eq!(p.ppid, 567);
        assert_eq!(p.image_name, "notepad.exe");
        assert_eq!(p.create_time, specific_create_time);
        assert_eq!(p.exit_time, specific_exit_time);
        assert_eq!(p.cr3, specific_cr3);
        assert_eq!(p.peb_addr, specific_peb);
        assert_eq!(p.vaddr, eproc_vaddr);
        assert_eq!(p.thread_count, 0);
        assert!(!p.is_wow64);
    }

    // -------------------------------------------------------------------
    // pstree tests (pure function, no memory access)
    // -------------------------------------------------------------------

    fn make_proc(pid: u64, ppid: u64, name: &str) -> WinProcessInfo {
        WinProcessInfo {
            pid,
            ppid,
            image_name: name.to_string(),
            create_time: 0,
            exit_time: 0,
            cr3: 0,
            peb_addr: 0,
            vaddr: 0,
            thread_count: 0,
            is_wow64: false,
        }
    }

    #[test]
    fn build_pstree_single_root() {
        let procs = vec![make_proc(4, 0, "System")];
        let tree = build_pstree(&procs);

        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].process.pid, 4);
        assert_eq!(tree[0].depth, 0);
    }

    #[test]
    fn build_pstree_nested() {
        // System(4) → csrss(528) → conhost(700)
        let procs = vec![
            make_proc(700, 528, "conhost.exe"),
            make_proc(4, 0, "System"),
            make_proc(528, 4, "csrss.exe"),
        ];
        let tree = build_pstree(&procs);

        assert_eq!(tree.len(), 3);
        // DFS order: System, csrss, conhost
        assert_eq!(tree[0].process.pid, 4);
        assert_eq!(tree[0].depth, 0);
        assert_eq!(tree[1].process.pid, 528);
        assert_eq!(tree[1].depth, 1);
        assert_eq!(tree[2].process.pid, 700);
        assert_eq!(tree[2].depth, 2);
    }

    #[test]
    fn build_pstree_orphan_processes() {
        // Orphan process (ppid points to non-existent process)
        // should appear as a root at depth 0.
        let procs = vec![
            make_proc(4, 0, "System"),
            make_proc(999, 12345, "orphan.exe"),
        ];
        let tree = build_pstree(&procs);

        assert_eq!(tree.len(), 2);
        // Both should be roots (depth 0), sorted by PID
        assert_eq!(tree[0].process.pid, 4);
        assert_eq!(tree[0].depth, 0);
        assert_eq!(tree[1].process.pid, 999);
        assert_eq!(tree[1].depth, 0);
    }

    // -------------------------------------------------------------------
    // PEB masquerade tests
    // -------------------------------------------------------------------

    /// Encode a Rust &str as UTF-16LE bytes.
    fn utf16le_bytes(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn build_unicode_string_at(buf: &mut [u8], offset: usize, length: u16, buffer_ptr: u64) {
        buf[offset..offset + 2].copy_from_slice(&length.to_le_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&length.to_le_bytes());
        buf[offset + 8..offset + 16].copy_from_slice(&buffer_ptr.to_le_bytes());
    }

    const PEB_PROCESS_PARAMETERS: u64 = 0x20;
    const PARAMS_IMAGE_PATH_NAME: u64 = 0x60;

    #[test]
    fn detects_peb_masquerade() {
        // EPROCESS says "malware.exe" but PEB ImagePathName says "svchost.exe"
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let peb_vaddr: u64 = 0xFFFF_8000_0010_2000;
        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0080_1000;
        let peb_paddr: u64 = 0x0080_2000;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(peb_vaddr, peb_paddr, flags::WRITABLE)
            .write_phys_u64(head_paddr, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(head_paddr + 8, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(eproc_paddr + KPROCESS_DTB, 0x1AB000)
            .write_phys_u64(eproc_paddr + EPROCESS_CREATE_TIME, 132800000000000000)
            .write_phys_u64(eproc_paddr + EPROCESS_EXIT_TIME, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_PID, 666)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS + 8, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_PPID, 4)
            .write_phys_u64(eproc_paddr + EPROCESS_PEB, peb_vaddr)
            .write_phys(eproc_paddr + EPROCESS_IMAGE_NAME, b"malware.exe\0");

        // PEB → ProcessParameters → ImagePathName = "C:\Windows\System32\svchost.exe"
        let params_vaddr = peb_vaddr + 0x200;
        let mut peb_data = vec![0u8; 4096];
        peb_data[PEB_PROCESS_PARAMETERS as usize..PEB_PROCESS_PARAMETERS as usize + 8]
            .copy_from_slice(&params_vaddr.to_le_bytes());

        let image_path = r"C:\Windows\System32\svchost.exe";
        let image_utf16 = utf16le_bytes(image_path);
        let image_len = image_utf16.len() as u16;
        let image_buf_vaddr = peb_vaddr + 0x400;
        let params_off = 0x200usize;
        build_unicode_string_at(
            &mut peb_data,
            params_off + PARAMS_IMAGE_PATH_NAME as usize,
            image_len,
            image_buf_vaddr,
        );
        let str_off = 0x400usize;
        peb_data[str_off..str_off + image_utf16.len()].copy_from_slice(&image_utf16);

        let ptb = ptb.write_phys(peb_paddr, &peb_data);

        let reader = make_win_reader(ptb);
        let results = check_peb_masquerade(&reader, head_vaddr).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pid, 666);
        assert_eq!(results[0].eprocess_name, "malware.exe");
        assert!(results[0].peb_image_path.contains("svchost.exe"));
        assert!(results[0].suspicious);
    }

    // -------------------------------------------------------------------
    // thread_count and is_wow64 tests
    // -------------------------------------------------------------------

    /// Build an ObjectReader using a custom ISF that extends the preset with
    /// `ActiveThreads` and `Wow64Process` fields on `_EPROCESS`.
    fn make_win_reader_with_thread_wow64(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset()
            .add_field("_EPROCESS", "ActiveThreads", 0x4B4, "unsigned int")
            .add_field("_EPROCESS", "Wow64Process", 0x548, "pointer");
        make_reader(&isf, ptb)
    }

    const EPROCESS_ACTIVE_THREADS: u64 = 0x4B4;
    const EPROCESS_WOW64_PROCESS: u64 = 0x548;

    #[test]
    fn thread_count_is_read_from_active_threads() {
        // A process with 7 threads: ActiveThreads = 7, Wow64Process = 0
        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0080_1000;
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_1000;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys_u64(head_paddr, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(head_paddr + 8, eproc_vaddr + EPROCESS_LINKS);

        let ptb = write_eprocess(
            ptb,
            eproc_paddr,
            eproc_vaddr,
            4,
            0,
            "System",
            132800000000000000,
            0,
            0x1ab000,
            0,
            head_vaddr,
            head_vaddr,
        );
        // Write ActiveThreads = 7 (u32 at offset 0x4B4)
        let ptb = ptb.write_phys(eproc_paddr + EPROCESS_ACTIVE_THREADS, &7u32.to_le_bytes());
        // Wow64Process = 0 (not a WoW64 process)
        let ptb = ptb.write_phys_u64(eproc_paddr + EPROCESS_WOW64_PROCESS, 0);

        let reader = make_win_reader_with_thread_wow64(ptb);
        let procs = walk_processes(&reader, head_vaddr).unwrap();

        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].thread_count, 7, "thread_count should be 7");
        assert!(
            !procs[0].is_wow64,
            "is_wow64 should be false when Wow64Process == 0"
        );
    }

    #[test]
    fn is_wow64_true_when_wow64process_nonzero() {
        // A WoW64 process: Wow64Process pointer is non-zero
        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0080_1000;
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_1000;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys_u64(head_paddr, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(head_paddr + 8, eproc_vaddr + EPROCESS_LINKS);

        let ptb = write_eprocess(
            ptb,
            eproc_paddr,
            eproc_vaddr,
            1024,
            4,
            "wow64app.exe",
            132800000100000000,
            0,
            0x2cd000,
            0x0000_0040_0000_0000,
            head_vaddr,
            head_vaddr,
        );
        // ActiveThreads = 3
        let ptb = ptb.write_phys(eproc_paddr + EPROCESS_ACTIVE_THREADS, &3u32.to_le_bytes());
        // Wow64Process = non-zero pointer (WoW64 thunk page VA, typical value)
        let ptb = ptb.write_phys_u64(eproc_paddr + EPROCESS_WOW64_PROCESS, 0x0000_0000_7FFD_E000);

        let reader = make_win_reader_with_thread_wow64(ptb);
        let procs = walk_processes(&reader, head_vaddr).unwrap();

        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].thread_count, 3, "thread_count should be 3");
        assert!(
            procs[0].is_wow64,
            "is_wow64 should be true when Wow64Process != 0"
        );
    }

    #[test]
    fn is_wow64_false_when_wow64process_zero() {
        // A native 64-bit process: Wow64Process = 0
        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0080_1000;
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_1000;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys_u64(head_paddr, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(head_paddr + 8, eproc_vaddr + EPROCESS_LINKS);

        let ptb = write_eprocess(
            ptb,
            eproc_paddr,
            eproc_vaddr,
            2048,
            4,
            "native64.exe",
            132800000200000000,
            0,
            0x3ef000,
            0x0000_0050_0000_0000,
            head_vaddr,
            head_vaddr,
        );
        // ActiveThreads = 1
        let ptb = ptb.write_phys(eproc_paddr + EPROCESS_ACTIVE_THREADS, &1u32.to_le_bytes());
        // Wow64Process = 0 (native 64-bit)
        let ptb = ptb.write_phys_u64(eproc_paddr + EPROCESS_WOW64_PROCESS, 0);

        let reader = make_win_reader_with_thread_wow64(ptb);
        let procs = walk_processes(&reader, head_vaddr).unwrap();

        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].thread_count, 1, "thread_count should be 1");
        assert!(
            !procs[0].is_wow64,
            "is_wow64 should be false when Wow64Process == 0"
        );
    }

    #[test]
    fn clean_process_no_masquerade() {
        // EPROCESS says "svchost.exe" and PEB ImagePathName also says "svchost.exe"
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let peb_vaddr: u64 = 0xFFFF_8000_0010_2000;
        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0080_1000;
        let peb_paddr: u64 = 0x0080_2000;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(peb_vaddr, peb_paddr, flags::WRITABLE)
            .write_phys_u64(head_paddr, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(head_paddr + 8, eproc_vaddr + EPROCESS_LINKS)
            .write_phys_u64(eproc_paddr + KPROCESS_DTB, 0x1AB000)
            .write_phys_u64(eproc_paddr + EPROCESS_CREATE_TIME, 132800000000000000)
            .write_phys_u64(eproc_paddr + EPROCESS_EXIT_TIME, 0)
            .write_phys_u64(eproc_paddr + EPROCESS_PID, 800)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_LINKS + 8, head_vaddr)
            .write_phys_u64(eproc_paddr + EPROCESS_PPID, 4)
            .write_phys_u64(eproc_paddr + EPROCESS_PEB, peb_vaddr)
            .write_phys(eproc_paddr + EPROCESS_IMAGE_NAME, b"svchost.exe\0");

        // PEB → ProcessParameters → ImagePathName matches
        let params_vaddr = peb_vaddr + 0x200;
        let mut peb_data = vec![0u8; 4096];
        peb_data[PEB_PROCESS_PARAMETERS as usize..PEB_PROCESS_PARAMETERS as usize + 8]
            .copy_from_slice(&params_vaddr.to_le_bytes());

        let image_path = r"C:\Windows\System32\svchost.exe";
        let image_utf16 = utf16le_bytes(image_path);
        let image_len = image_utf16.len() as u16;
        let image_buf_vaddr = peb_vaddr + 0x400;
        let params_off = 0x200usize;
        build_unicode_string_at(
            &mut peb_data,
            params_off + PARAMS_IMAGE_PATH_NAME as usize,
            image_len,
            image_buf_vaddr,
        );
        let str_off = 0x400usize;
        peb_data[str_off..str_off + image_utf16.len()].copy_from_slice(&image_utf16);

        let ptb = ptb.write_phys(peb_paddr, &peb_data);

        let reader = make_win_reader(ptb);
        let results = check_peb_masquerade(&reader, head_vaddr).unwrap();

        assert_eq!(results.len(), 1);
        assert!(!results[0].suspicious);
    }
}
