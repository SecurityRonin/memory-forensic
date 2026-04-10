//! Detect processes holding raw (`AF_PACKET` or `SOCK_RAW`) sockets.
//!
//! Raw sockets give user-space full access to Ethernet frames or raw IP packets,
//! enabling packet sniffing, ARP poisoning, and covert C2 channels. Legitimate
//! use is limited to well-known diagnostic tools (`tcpdump`, `ping`, etc.).
//!
//! MITRE ATT&CK: T1040 — Network Sniffing.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use serde::Serialize;

use crate::Result;

/// Linux address family: raw Ethernet frames.
const AF_PACKET: u16 = 17;
/// Socket type: raw IP.
const SOCK_RAW: u16 = 3;
/// Interface flag: promiscuous mode.
const IFF_PROMISC: u32 = 0x100;

/// Known-benign process names that legitimately use `AF_PACKET` sockets.
const BENIGN_AF_PACKET: &[&str] = &[
    "tcpdump",
    "wireshark",
    "dumpcap",
    "dhclient",
    "dhcpcd",
    "arping",
    "ping",
    "ping6",
];

/// Known-benign process names that legitimately use `SOCK_RAW` sockets.
const BENIGN_SOCK_RAW: &[&str] = &["ping", "ping6", "traceroute", "traceroute6", "arping"];

/// Information about a raw socket held by a process.
#[derive(Debug, Clone, Serialize)]
pub struct RawSocketInfo {
    /// Process ID.
    pub pid: u32,
    /// Process command name (`task_struct.comm`, max 16 chars).
    pub comm: String,
    /// Socket type: `"AF_PACKET"` or `"SOCK_RAW"`.
    pub socket_type: String,
    /// Protocol number (e.g. `0x0300` = ETH_P_ALL, `255` = IPPROTO_RAW).
    pub protocol: u16,
    /// Whether the interface has `IFF_PROMISC` set.
    pub is_promiscuous: bool,
    /// Whether this raw socket is considered suspicious.
    pub is_suspicious: bool,
}

/// Classify whether a raw socket is suspicious.
///
/// Suspicious if any of:
/// - `is_promiscuous` — captures all traffic on the interface.
/// - `socket_type == "AF_PACKET"` and `comm` is not a known diagnostic tool.
/// - `socket_type == "SOCK_RAW"` and `comm` is not a known diagnostic tool.
pub fn classify_raw_socket(comm: &str, socket_type: &str, is_promiscuous: bool) -> bool {
    if is_promiscuous {
        return true;
    }

    let comm_lower = comm.to_lowercase();

    if socket_type == "AF_PACKET" {
        return !BENIGN_AF_PACKET.iter().any(|&b| comm_lower == b);
    }

    if socket_type == "SOCK_RAW" {
        return !BENIGN_SOCK_RAW.iter().any(|&b| comm_lower == b);
    }

    false
}

/// Walk the task list and enumerate all open raw sockets.
///
/// Walks `task_struct.files -> files_struct.fdt -> fdtable.fd[]`, then for
/// each open file checks whether it is a raw socket by probing the kernel
/// `socket` struct fields.
///
/// Gracefully returns `Ok(vec![])` if any required symbol is absent so that
/// callers on unexpected kernel versions are not broken.
pub fn walk_raw_sockets<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<RawSocketInfo>> {
    // --- symbol resolution (graceful degradation) ---
    let init_task_addr = match reader.symbols().symbol_address("init_task") {
        Some(a) => a,
        None => return Ok(vec![]),
    };
    let tasks_offset = match reader.symbols().field_offset("task_struct", "tasks") {
        Some(o) => o,
        None => return Ok(vec![]),
    };
    // Ensure the critical fd-table field exists before walking.
    if reader
        .symbols()
        .field_offset("task_struct", "files")
        .is_none()
    {
        return Ok(vec![]);
    }

    let head_vaddr = init_task_addr + tasks_offset;
    let task_addrs = reader.walk_list(head_vaddr, "task_struct", "tasks")?;

    let mut results: Vec<RawSocketInfo> = Vec::new();

    collect_raw_sockets_for_task(reader, init_task_addr, &mut results);
    for &task_addr in &task_addrs {
        collect_raw_sockets_for_task(reader, task_addr, &mut results);
    }

    results.sort_by_key(|r| r.pid);
    Ok(results)
}

/// Collect raw sockets for a single task by walking its fd table.
fn collect_raw_sockets_for_task<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
    out: &mut Vec<RawSocketInfo>,
) {
    let pid: u32 = match reader.read_field(task_addr, "task_struct", "pid") {
        Ok(v) => v,
        Err(_) => return,
    };
    let comm = reader
        .read_field_string(task_addr, "task_struct", "comm", 16)
        .unwrap_or_default();

    // files_struct pointer.
    let files_ptr: u64 = match reader.read_field(task_addr, "task_struct", "files") {
        Ok(v) => v,
        Err(_) => return,
    };
    if files_ptr == 0 {
        return;
    }

    // files_struct.fdt → fdtable pointer.
    let fdt_ptr: u64 = match reader.read_field(files_ptr, "files_struct", "fdt") {
        Ok(v) => v,
        Err(_) => return,
    };
    if fdt_ptr == 0 {
        return;
    }

    // fdtable.fd → pointer to array of file pointers.
    let fd_array_ptr: u64 = match reader.read_field(fdt_ptr, "fdtable", "fd") {
        Ok(v) => v,
        Err(_) => return,
    };
    if fd_array_ptr == 0 {
        return;
    }

    // Read up to 256 file descriptors.
    for fd_index in 0u64..256 {
        let file_slot_addr = fd_array_ptr + fd_index * 8;
        let file_ptr_raw = match reader.read_bytes(file_slot_addr, 8) {
            Ok(b) => b,
            Err(_) => break,
        };
        let file_ptr = u64::from_le_bytes(match file_ptr_raw.try_into() {
            Ok(b) => b,
            Err(_) => break,
        });
        if file_ptr == 0 {
            continue;
        }

        if let Some(info) = try_read_raw_socket(reader, pid, &comm, file_ptr) {
            out.push(info);
        }
    }
}

/// Attempt to interpret an open file as a raw socket.
///
/// Reads `file.private_data` as a `struct socket*`, then inspects
/// `socket.sk -> sock.sk_family` / `sock.sk_type`. Returns `None` if the
/// file is not a (raw) socket or fields cannot be read.
fn try_read_raw_socket<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    pid: u32,
    comm: &str,
    file_ptr: u64,
) -> Option<RawSocketInfo> {
    // file.private_data holds the socket* for socket files.
    let sock_ptr: u64 = reader.read_field(file_ptr, "file", "private_data").ok()?;
    if sock_ptr == 0 {
        return None;
    }

    // socket.type: SOCK_RAW == 3.
    let sock_type: u16 = reader.read_field(sock_ptr, "socket", "type").ok()?;

    // socket.sk → struct sock*.
    let sk_ptr: u64 = reader.read_field(sock_ptr, "socket", "sk").ok()?;
    if sk_ptr == 0 {
        return None;
    }

    // sock.sk_family: AF_PACKET == 17.
    let sk_family: u16 = reader.read_field(sk_ptr, "sock", "sk_family").ok()?;
    // sock.sk_protocol (u16 in network byte order, stored LE in memory).
    let protocol: u16 = reader
        .read_field::<u16>(sk_ptr, "sock", "sk_protocol")
        .unwrap_or(0);

    let socket_type_str = if sk_family == AF_PACKET {
        "AF_PACKET"
    } else if sock_type == SOCK_RAW {
        "SOCK_RAW"
    } else {
        return None; // not a raw socket
    };

    // For AF_PACKET, try to read promiscuous flag via packet_sock.prot_hook.
    // If the field is absent, default to false — graceful degradation.
    let is_promiscuous = try_read_promisc(reader, sk_ptr);

    let is_suspicious = classify_raw_socket(comm, socket_type_str, is_promiscuous);

    Some(RawSocketInfo {
        pid,
        comm: comm.to_string(),
        socket_type: socket_type_str.to_string(),
        protocol,
        is_promiscuous,
        is_suspicious,
    })
}

/// Attempt to read `IFF_PROMISC` from `packet_sock.prot_hook.dev->flags`.
///
/// Returns `false` on any read failure (graceful degradation).
fn try_read_promisc<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, sk_ptr: u64) -> bool {
    // packet_sock starts at the same address as the embedded sock.
    let prot_hook_offset = match reader.symbols().field_offset("packet_sock", "prot_hook") {
        Some(o) => o,
        None => return false,
    };
    let dev_in_hook = match reader.symbols().field_offset("packet_type", "dev") {
        Some(o) => o,
        None => return false,
    };

    let dev_ptr_addr = sk_ptr + prot_hook_offset + dev_in_hook;
    let dev_raw = match reader.read_bytes(dev_ptr_addr, 8) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let dev_ptr = u64::from_le_bytes(match dev_raw.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    });
    if dev_ptr == 0 {
        return false;
    }

    let flags: u32 = match reader.read_field(dev_ptr, "net_device", "flags") {
        Ok(v) => v,
        Err(_) => return false,
    };

    (flags & IFF_PROMISC) != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // -----------------------------------------------------------------------
    // classify_raw_socket unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn classify_raw_socket_promiscuous_is_suspicious() {
        assert!(
            classify_raw_socket("tcpdump", "AF_PACKET", true),
            "promiscuous mode must always be suspicious regardless of comm"
        );
    }

    #[test]
    fn classify_raw_socket_af_packet_unknown_comm_suspicious() {
        assert!(
            classify_raw_socket("malware", "AF_PACKET", false),
            "AF_PACKET socket held by unknown process must be suspicious"
        );
    }

    #[test]
    fn classify_raw_socket_tcpdump_benign() {
        assert!(
            !classify_raw_socket("tcpdump", "AF_PACKET", false),
            "non-promiscuous AF_PACKET socket by tcpdump must not be suspicious"
        );
    }

    #[test]
    fn classify_raw_socket_ping_benign() {
        assert!(
            !classify_raw_socket("ping", "SOCK_RAW", false),
            "SOCK_RAW socket by ping must not be suspicious"
        );
    }

    #[test]
    fn classify_raw_socket_sock_raw_unknown_comm_suspicious() {
        assert!(
            classify_raw_socket("implant", "SOCK_RAW", false),
            "SOCK_RAW socket held by unknown process must be suspicious"
        );
    }

    // -----------------------------------------------------------------------
    // walk_raw_sockets integration tests
    // -----------------------------------------------------------------------

    fn make_reader_no_init_task() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn walk_raw_sockets_missing_init_task_returns_empty() {
        let reader = make_reader_no_init_task();
        let result = walk_raw_sockets(&reader).expect("should not error");
        assert!(
            result.is_empty(),
            "missing init_task must yield empty results (graceful degradation)"
        );
    }

    // --- classify_raw_socket exhaustive branch coverage ---

    #[test]
    fn classify_raw_socket_unknown_type_benign() {
        // socket_type is neither "AF_PACKET" nor "SOCK_RAW" and not promiscuous
        assert!(
            !classify_raw_socket("someproc", "UNKNOWN_TYPE", false),
            "unknown socket type, not promiscuous must not be suspicious"
        );
    }

    #[test]
    fn classify_raw_socket_wireshark_af_packet_benign() {
        assert!(
            !classify_raw_socket("wireshark", "AF_PACKET", false),
            "wireshark AF_PACKET must not be suspicious"
        );
    }

    #[test]
    fn classify_raw_socket_dumpcap_af_packet_benign() {
        assert!(
            !classify_raw_socket("dumpcap", "AF_PACKET", false),
            "dumpcap AF_PACKET must not be suspicious"
        );
    }

    #[test]
    fn classify_raw_socket_dhclient_af_packet_benign() {
        assert!(
            !classify_raw_socket("dhclient", "AF_PACKET", false),
            "dhclient AF_PACKET must not be suspicious"
        );
    }

    #[test]
    fn classify_raw_socket_dhcpcd_af_packet_benign() {
        assert!(
            !classify_raw_socket("dhcpcd", "AF_PACKET", false),
            "dhcpcd AF_PACKET must not be suspicious"
        );
    }

    #[test]
    fn classify_raw_socket_arping_af_packet_benign() {
        assert!(
            !classify_raw_socket("arping", "AF_PACKET", false),
            "arping AF_PACKET must not be suspicious"
        );
    }

    #[test]
    fn classify_raw_socket_ping_af_packet_benign() {
        assert!(
            !classify_raw_socket("ping", "AF_PACKET", false),
            "ping AF_PACKET must not be suspicious"
        );
    }

    #[test]
    fn classify_raw_socket_ping6_af_packet_benign() {
        assert!(
            !classify_raw_socket("ping6", "AF_PACKET", false),
            "ping6 AF_PACKET must not be suspicious"
        );
    }

    #[test]
    fn classify_raw_socket_traceroute_sock_raw_benign() {
        assert!(
            !classify_raw_socket("traceroute", "SOCK_RAW", false),
            "traceroute SOCK_RAW must not be suspicious"
        );
    }

    #[test]
    fn classify_raw_socket_traceroute6_sock_raw_benign() {
        assert!(
            !classify_raw_socket("traceroute6", "SOCK_RAW", false),
            "traceroute6 SOCK_RAW must not be suspicious"
        );
    }

    #[test]
    fn classify_raw_socket_arping_sock_raw_benign() {
        assert!(
            !classify_raw_socket("arping", "SOCK_RAW", false),
            "arping SOCK_RAW must not be suspicious"
        );
    }

    #[test]
    fn classify_raw_socket_ping6_sock_raw_benign() {
        assert!(
            !classify_raw_socket("ping6", "SOCK_RAW", false),
            "ping6 SOCK_RAW must not be suspicious"
        );
    }

    #[test]
    fn classify_raw_socket_uppercase_comm_not_benign() {
        // comm is lowercased before comparison; "TCPDUMP" → "tcpdump" should match
        assert!(
            !classify_raw_socket("TCPDUMP", "AF_PACKET", false),
            "TCPDUMP (uppercase) AF_PACKET must not be suspicious (case-folded)"
        );
    }

    #[test]
    fn classify_raw_socket_promisc_overrides_benign_comm() {
        // promiscuous always wins even for known-benign tools
        assert!(
            classify_raw_socket("wireshark", "AF_PACKET", true),
            "promiscuous wireshark must still be suspicious"
        );
    }

    // --- walk_raw_sockets: has init_task but missing tasks offset ---

    fn make_reader_with_init_task_no_tasks() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_symbol("init_task", 0xFFFF_FFFF_8260_0000)
            .add_struct("task_struct", 512)
            .add_field("task_struct", "pid", 0, "int")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn walk_raw_sockets_missing_tasks_offset_returns_empty() {
        let reader = make_reader_with_init_task_no_tasks();
        let result = walk_raw_sockets(&reader).expect("should not error");
        assert!(
            result.is_empty(),
            "missing task_struct.tasks offset must yield empty results"
        );
    }

    // --- walk_raw_sockets: has init_task + tasks but missing files field ---

    fn make_reader_with_tasks_no_files() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_symbol("init_task", 0xFFFF_FFFF_8260_0000)
            .add_struct("task_struct", 512)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 8, "pointer")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn walk_raw_sockets_missing_files_field_returns_empty() {
        let reader = make_reader_with_tasks_no_files();
        let result = walk_raw_sockets(&reader).expect("should not error");
        assert!(
            result.is_empty(),
            "missing task_struct.files field must yield empty results"
        );
    }

    // --- walk_raw_sockets: all symbols present, self-pointing list, files=0 → exercises body ---
    // Exercises collect_raw_sockets_for_task: files ptr is 0 → early return → no raw sockets.
    #[test]
    fn walk_raw_sockets_symbol_present_files_null_returns_empty() {
        use memf_core::test_builders::flags as ptf;
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};

        // tasks at offset 0x10; pid at 0x00; comm at 0x20; files at 0x30.
        let tasks_offset: u64 = 0x10;
        let sym_vaddr: u64 = 0xFFFF_8800_0090_0000;
        let sym_paddr: u64 = 0x0090_0000; // unique, < 16 MB

        let isf = IsfBuilder::new()
            .add_symbol("init_task", sym_vaddr)
            .add_struct("list_head", 0x10)
            .add_field("list_head", "next", 0x00, "pointer")
            .add_struct("task_struct", 0x400)
            .add_field("task_struct", "tasks", tasks_offset, "pointer")
            .add_field("task_struct", "pid", 0x00, "unsigned int")
            .add_field("task_struct", "comm", 0x20, "char")
            .add_field("task_struct", "files", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Build init_task page: tasks.next self-pointing, files=0 → no fd table.
        let mut page = [0u8; 4096];
        let self_ptr = sym_vaddr + tasks_offset;
        page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&self_ptr.to_le_bytes());
        // files at 0x30 remains 0.

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_raw_sockets(&reader).expect("should not error");
        assert!(
            result.is_empty(),
            "null files ptr → no fd table → no raw sockets"
        );
    }

    // --- collect_raw_sockets_for_task: files != 0 but fdt_ptr == 0 ---
    // Exercises the `if fdt_ptr == 0 { return }` branch.
    #[test]
    fn walk_raw_sockets_fdt_ptr_null_returns_empty() {
        use memf_core::test_builders::flags as ptf;

        let tasks_offset: u64 = 0x10;
        let files_offset: u64 = 0x30;

        let sym_vaddr: u64 = 0xFFFF_8800_0091_0000;
        let sym_paddr: u64 = 0x0091_0000;

        // files_struct at a separate mapped page; fdt at offset 0 = 0 (null).
        let files_vaddr: u64 = 0xFFFF_8800_0092_0000;
        let files_paddr: u64 = 0x0092_0000;

        let isf = IsfBuilder::new()
            .add_symbol("init_task", sym_vaddr)
            .add_struct("list_head", 0x10)
            .add_field("list_head", "next", 0x00, "pointer")
            .add_struct("task_struct", 0x400)
            .add_field("task_struct", "tasks", tasks_offset, "pointer")
            .add_field("task_struct", "pid", 0x00, "unsigned int")
            .add_field("task_struct", "comm", 0x20, "char")
            .add_field("task_struct", "files", files_offset, "pointer")
            .add_struct("files_struct", 0x100)
            .add_field("files_struct", "fdt", 0x00, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // init_task page: tasks self-pointing; files = files_vaddr.
        let mut task_page = [0u8; 4096];
        let self_ptr = sym_vaddr + tasks_offset;
        task_page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&self_ptr.to_le_bytes());
        task_page[files_offset as usize..files_offset as usize + 8]
            .copy_from_slice(&files_vaddr.to_le_bytes());

        // files_struct page: fdt at offset 0 = 0.
        let files_page = [0u8; 4096]; // all zeros → fdt_ptr = 0

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &task_page)
            .map_4k(files_vaddr, files_paddr, ptf::WRITABLE)
            .write_phys(files_paddr, &files_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_raw_sockets(&reader).expect("should not error");
        assert!(result.is_empty(), "fdt_ptr == 0 → early return → no raw sockets");
    }

    // --- collect_raw_sockets_for_task: fdt != 0, fd_array_ptr == 0 ---
    // Exercises the `if fd_array_ptr == 0 { return }` branch.
    #[test]
    fn walk_raw_sockets_fd_array_null_returns_empty() {
        use memf_core::test_builders::flags as ptf;

        let tasks_offset: u64 = 0x10;
        let files_offset: u64 = 0x30;

        let sym_vaddr: u64 = 0xFFFF_8800_0093_0000;
        let sym_paddr: u64 = 0x0093_0000;

        let files_vaddr: u64 = 0xFFFF_8800_0094_0000;
        let files_paddr: u64 = 0x0094_0000;

        let fdt_vaddr: u64 = 0xFFFF_8800_0095_0000;
        let fdt_paddr: u64 = 0x0095_0000;

        let isf = IsfBuilder::new()
            .add_symbol("init_task", sym_vaddr)
            .add_struct("list_head", 0x10)
            .add_field("list_head", "next", 0x00, "pointer")
            .add_struct("task_struct", 0x400)
            .add_field("task_struct", "tasks", tasks_offset, "pointer")
            .add_field("task_struct", "pid", 0x00, "unsigned int")
            .add_field("task_struct", "comm", 0x20, "char")
            .add_field("task_struct", "files", files_offset, "pointer")
            .add_struct("files_struct", 0x100)
            .add_field("files_struct", "fdt", 0x00, "pointer")
            .add_struct("fdtable", 0x40)
            .add_field("fdtable", "fd", 0x00, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut task_page = [0u8; 4096];
        let self_ptr = sym_vaddr + tasks_offset;
        task_page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&self_ptr.to_le_bytes());
        task_page[files_offset as usize..files_offset as usize + 8]
            .copy_from_slice(&files_vaddr.to_le_bytes());

        // files_struct: fdt = fdt_vaddr.
        let mut files_page = [0u8; 4096];
        files_page[0..8].copy_from_slice(&fdt_vaddr.to_le_bytes());

        // fdtable: fd (offset 0) = 0 → fd_array_ptr = 0.
        let fdt_page = [0u8; 4096];

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &task_page)
            .map_4k(files_vaddr, files_paddr, ptf::WRITABLE)
            .write_phys(files_paddr, &files_page)
            .map_4k(fdt_vaddr, fdt_paddr, ptf::WRITABLE)
            .write_phys(fdt_paddr, &fdt_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_raw_sockets(&reader).expect("should not error");
        assert!(result.is_empty(), "fd_array_ptr == 0 → early return → no raw sockets");
    }

    // --- RawSocketInfo struct coverage ---
    #[test]
    fn raw_socket_info_serializes() {
        let info = RawSocketInfo {
            pid: 99,
            comm: "sniffer".to_string(),
            socket_type: "AF_PACKET".to_string(),
            protocol: 0x0300,
            is_promiscuous: false,
            is_suspicious: true,
        };
        let cloned = info.clone();
        let json = serde_json::to_string(&cloned).unwrap();
        assert!(json.contains("\"pid\":99"));
        assert!(json.contains("AF_PACKET"));
        let dbg = format!("{:?}", cloned);
        assert!(dbg.contains("sniffer"));
    }

    // --- collect_raw_sockets_for_task: fd_array has all-zero entries → no file ptrs ---
    // Exercises the fd-slot loop: all file_ptr == 0 → continue → no try_read_raw_socket calls.
    #[test]
    fn walk_raw_sockets_all_fd_slots_null_returns_empty() {
        use memf_core::test_builders::flags as ptf;

        let tasks_offset: u64 = 0x10;
        let files_offset: u64 = 0x30;

        let sym_vaddr: u64 = 0xFFFF_8800_0096_0000;
        let sym_paddr: u64 = 0x0096_0000;

        let files_vaddr: u64 = 0xFFFF_8800_0097_0000;
        let files_paddr: u64 = 0x0097_0000;

        let fdt_vaddr: u64 = 0xFFFF_8800_0098_0000;
        let fdt_paddr: u64 = 0x0098_0000;

        let fd_array_vaddr: u64 = 0xFFFF_8800_0099_0000;
        let fd_array_paddr: u64 = 0x0099_0000;

        let isf = IsfBuilder::new()
            .add_symbol("init_task", sym_vaddr)
            .add_struct("list_head", 0x10)
            .add_field("list_head", "next", 0x00, "pointer")
            .add_struct("task_struct", 0x400)
            .add_field("task_struct", "tasks", tasks_offset, "pointer")
            .add_field("task_struct", "pid", 0x00, "unsigned int")
            .add_field("task_struct", "comm", 0x20, "char")
            .add_field("task_struct", "files", files_offset, "pointer")
            .add_struct("files_struct", 0x100)
            .add_field("files_struct", "fdt", 0x00, "pointer")
            .add_struct("fdtable", 0x40)
            .add_field("fdtable", "fd", 0x00, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut task_page = [0u8; 4096];
        let self_ptr = sym_vaddr + tasks_offset;
        task_page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&self_ptr.to_le_bytes());
        task_page[files_offset as usize..files_offset as usize + 8]
            .copy_from_slice(&files_vaddr.to_le_bytes());

        let mut files_page = [0u8; 4096];
        files_page[0..8].copy_from_slice(&fdt_vaddr.to_le_bytes());

        let mut fdt_page = [0u8; 4096];
        fdt_page[0..8].copy_from_slice(&fd_array_vaddr.to_le_bytes());

        // fd_array page: all zeros → every file_ptr == 0 → all slots skipped.
        let fd_array_page = [0u8; 4096];

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &task_page)
            .map_4k(files_vaddr, files_paddr, ptf::WRITABLE)
            .write_phys(files_paddr, &files_page)
            .map_4k(fdt_vaddr, fdt_paddr, ptf::WRITABLE)
            .write_phys(fdt_paddr, &fdt_page)
            .map_4k(fd_array_vaddr, fd_array_paddr, ptf::WRITABLE)
            .write_phys(fd_array_paddr, &fd_array_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_raw_sockets(&reader).expect("should not error");
        assert!(result.is_empty(), "all-zero fd slots → no raw sockets");
    }

    // --- try_read_raw_socket: file_ptr readable, private_data != 0, sk_family == AF_PACKET ---
    // Exercises try_read_raw_socket (lines 188-238) and try_read_promisc (lines 243-273).
    // private_data (sock_ptr) → socket.type=SOCK_RAW, socket.sk → sock.sk_family=AF_PACKET.
    // prot_hook field missing from ISF → try_read_promisc returns false (graceful).
    #[test]
    fn walk_raw_sockets_af_packet_sock_detected() {
        use memf_core::test_builders::flags as ptf;

        let tasks_offset: u64   = 0x10;
        let files_offset: u64   = 0x30;

        let sym_vaddr: u64      = 0xFFFF_8800_009A_0000;
        let sym_paddr: u64      = 0x009A_0000;

        let files_vaddr: u64    = 0xFFFF_8800_009B_0000;
        let files_paddr: u64    = 0x009B_0000;

        let fdt_vaddr: u64      = 0xFFFF_8800_009C_0000;
        let fdt_paddr: u64      = 0x009C_0000;

        let fd_array_vaddr: u64 = 0xFFFF_8800_009D_0000;
        let fd_array_paddr: u64 = 0x009D_0000;

        // file struct: private_data at offset 0 → sock_vaddr
        let file_vaddr: u64     = 0xFFFF_8800_009E_0000;
        let file_paddr: u64     = 0x009E_0000;

        // socket struct: type at 0, sk at 8
        let sock_vaddr: u64     = 0xFFFF_8800_009F_0000;
        let sock_paddr: u64     = 0x009F_0000;

        // struct sock: sk_family at 0, sk_protocol at 2
        let sk_vaddr: u64       = 0xFFFF_8800_00C0_0000;
        let sk_paddr: u64       = 0x00C0_0000;

        let isf = IsfBuilder::new()
            .add_symbol("init_task", sym_vaddr)
            .add_struct("list_head", 0x10)
            .add_field("list_head", "next", 0x00, "pointer")
            .add_struct("task_struct", 0x400)
            .add_field("task_struct", "tasks", tasks_offset, "pointer")
            .add_field("task_struct", "pid", 0x00, "unsigned int")
            .add_field("task_struct", "comm", 0x20, "char")
            .add_field("task_struct", "files", files_offset, "pointer")
            .add_struct("files_struct", 0x100)
            .add_field("files_struct", "fdt", 0x00, "pointer")
            .add_struct("fdtable", 0x40)
            .add_field("fdtable", "fd", 0x00, "pointer")
            .add_struct("file", 0x100)
            .add_field("file", "private_data", 0x00, "pointer")
            .add_struct("socket", 0x80)
            .add_field("socket", "type", 0x00, "unsigned short")
            .add_field("socket", "sk", 0x08, "pointer")
            .add_struct("sock", 0x100)
            .add_field("sock", "sk_family", 0x00, "unsigned short")
            .add_field("sock", "sk_protocol", 0x02, "unsigned short")
            // packet_sock intentionally omitted → try_read_promisc returns false
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Task page
        let mut task_page = [0u8; 4096];
        let self_ptr = sym_vaddr + tasks_offset;
        task_page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&self_ptr.to_le_bytes());
        task_page[0x20..0x28].copy_from_slice(b"sniffer\0");
        task_page[0x00..0x04].copy_from_slice(&200u32.to_le_bytes()); // pid=200
        task_page[files_offset as usize..files_offset as usize + 8]
            .copy_from_slice(&files_vaddr.to_le_bytes());

        // files_struct: fdt at 0
        let mut files_page = [0u8; 4096];
        files_page[0..8].copy_from_slice(&fdt_vaddr.to_le_bytes());

        // fdtable: fd array at 0
        let mut fdt_page = [0u8; 4096];
        fdt_page[0..8].copy_from_slice(&fd_array_vaddr.to_le_bytes());

        // fd array: slot 0 → file_vaddr, rest zero
        let mut fd_array_page = [0u8; 4096];
        fd_array_page[0..8].copy_from_slice(&file_vaddr.to_le_bytes());
        // slot 1 = 0 → loop will continue (already covered), then eventually breaks
        // when reading beyond the mapped page fails.

        // file struct: private_data at 0 → sock_vaddr
        let mut file_page = [0u8; 4096];
        file_page[0..8].copy_from_slice(&sock_vaddr.to_le_bytes());

        // socket struct: type=SOCK_RAW(3) at byte 0, sk at 8
        let mut socket_page = [0u8; 4096];
        socket_page[0..2].copy_from_slice(&3u16.to_le_bytes()); // type=SOCK_RAW
        socket_page[8..16].copy_from_slice(&sk_vaddr.to_le_bytes());

        // sock struct: sk_family=AF_PACKET(17) at 0, sk_protocol=0x0300 at 2
        let mut sk_page = [0u8; 4096];
        sk_page[0..2].copy_from_slice(&17u16.to_le_bytes()); // sk_family=AF_PACKET
        sk_page[2..4].copy_from_slice(&0x0300u16.to_le_bytes()); // sk_protocol

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &task_page)
            .map_4k(files_vaddr, files_paddr, ptf::WRITABLE)
            .write_phys(files_paddr, &files_page)
            .map_4k(fdt_vaddr, fdt_paddr, ptf::WRITABLE)
            .write_phys(fdt_paddr, &fdt_page)
            .map_4k(fd_array_vaddr, fd_array_paddr, ptf::WRITABLE)
            .write_phys(fd_array_paddr, &fd_array_page)
            .map_4k(file_vaddr, file_paddr, ptf::WRITABLE)
            .write_phys(file_paddr, &file_page)
            .map_4k(sock_vaddr, sock_paddr, ptf::WRITABLE)
            .write_phys(sock_paddr, &socket_page)
            .map_4k(sk_vaddr, sk_paddr, ptf::WRITABLE)
            .write_phys(sk_paddr, &sk_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_raw_sockets(&reader).expect("should not error");
        assert_eq!(result.len(), 1, "one AF_PACKET socket should be detected");
        assert_eq!(result[0].socket_type, "AF_PACKET");
        assert_eq!(result[0].pid, 200);
        assert!(!result[0].is_promiscuous, "promisc false when packet_sock missing");
    }

    // --- try_read_raw_socket: sk_ptr == 0 → returns None (exercises line 205-206) ---
    #[test]
    fn walk_raw_sockets_sk_ptr_null_no_entry() {
        use memf_core::test_builders::flags as ptf;

        let tasks_offset: u64   = 0x10;
        let files_offset: u64   = 0x30;
        let sym_vaddr: u64      = 0xFFFF_8800_00D0_0000;
        let sym_paddr: u64      = 0x00D0_0000;
        let files_vaddr: u64    = 0xFFFF_8800_00D1_0000;
        let files_paddr: u64    = 0x00D1_0000;
        let fdt_vaddr: u64      = 0xFFFF_8800_00D2_0000;
        let fdt_paddr: u64      = 0x00D2_0000;
        let fd_array_vaddr: u64 = 0xFFFF_8800_00D3_0000;
        let fd_array_paddr: u64 = 0x00D3_0000;
        let file_vaddr: u64     = 0xFFFF_8800_00D4_0000;
        let file_paddr: u64     = 0x00D4_0000;
        // socket struct: sock_ptr = private_data, sk = 0
        let sock_vaddr: u64     = 0xFFFF_8800_00D5_0000;
        let sock_paddr: u64     = 0x00D5_0000;

        let isf = IsfBuilder::new()
            .add_symbol("init_task", sym_vaddr)
            .add_struct("list_head", 0x10)
            .add_field("list_head", "next", 0x00, "pointer")
            .add_struct("task_struct", 0x400)
            .add_field("task_struct", "tasks", tasks_offset, "pointer")
            .add_field("task_struct", "pid", 0x00, "unsigned int")
            .add_field("task_struct", "comm", 0x20, "char")
            .add_field("task_struct", "files", files_offset, "pointer")
            .add_struct("files_struct", 0x100)
            .add_field("files_struct", "fdt", 0x00, "pointer")
            .add_struct("fdtable", 0x40)
            .add_field("fdtable", "fd", 0x00, "pointer")
            .add_struct("file", 0x100)
            .add_field("file", "private_data", 0x00, "pointer")
            .add_struct("socket", 0x80)
            .add_field("socket", "type", 0x00, "unsigned short")
            .add_field("socket", "sk", 0x08, "pointer")
            .add_struct("sock", 0x100)
            .add_field("sock", "sk_family", 0x00, "unsigned short")
            .add_field("sock", "sk_protocol", 0x02, "unsigned short")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut task_page = [0u8; 4096];
        let self_ptr = sym_vaddr + tasks_offset;
        task_page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&self_ptr.to_le_bytes());
        task_page[files_offset as usize..files_offset as usize + 8]
            .copy_from_slice(&files_vaddr.to_le_bytes());

        let mut files_page = [0u8; 4096];
        files_page[0..8].copy_from_slice(&fdt_vaddr.to_le_bytes());

        let mut fdt_page = [0u8; 4096];
        fdt_page[0..8].copy_from_slice(&fd_array_vaddr.to_le_bytes());

        let mut fd_array_page = [0u8; 4096];
        fd_array_page[0..8].copy_from_slice(&file_vaddr.to_le_bytes());

        let mut file_page = [0u8; 4096];
        file_page[0..8].copy_from_slice(&sock_vaddr.to_le_bytes()); // private_data = sock_vaddr

        // socket: type = SOCK_RAW (3), sk = 0 (null)
        let mut socket_page = [0u8; 4096];
        socket_page[0..2].copy_from_slice(&3u16.to_le_bytes()); // type = SOCK_RAW
        socket_page[8..16].copy_from_slice(&0u64.to_le_bytes()); // sk = NULL

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &task_page)
            .map_4k(files_vaddr, files_paddr, ptf::WRITABLE)
            .write_phys(files_paddr, &files_page)
            .map_4k(fdt_vaddr, fdt_paddr, ptf::WRITABLE)
            .write_phys(fdt_paddr, &fdt_page)
            .map_4k(fd_array_vaddr, fd_array_paddr, ptf::WRITABLE)
            .write_phys(fd_array_paddr, &fd_array_page)
            .map_4k(file_vaddr, file_paddr, ptf::WRITABLE)
            .write_phys(file_paddr, &file_page)
            .map_4k(sock_vaddr, sock_paddr, ptf::WRITABLE)
            .write_phys(sock_paddr, &socket_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_raw_sockets(&reader).expect("should not error");
        assert!(result.is_empty(), "sk_ptr == 0 → returns None → no raw socket entry");
    }

    // --- try_read_raw_socket: SOCK_RAW branch (sk_family != AF_PACKET, sock_type == SOCK_RAW) ---
    // Exercises lines 218-219: the `else if sock_type == SOCK_RAW` branch.
    #[test]
    fn walk_raw_sockets_sock_raw_family_detected() {
        use memf_core::test_builders::flags as ptf;

        let tasks_offset: u64   = 0x10;
        let files_offset: u64   = 0x30;
        let sym_vaddr: u64      = 0xFFFF_8800_00E0_0000;
        let sym_paddr: u64      = 0x00E0_0000;
        let files_vaddr: u64    = 0xFFFF_8800_00E1_0000;
        let files_paddr: u64    = 0x00E1_0000;
        let fdt_vaddr: u64      = 0xFFFF_8800_00E2_0000;
        let fdt_paddr: u64      = 0x00E2_0000;
        let fd_array_vaddr: u64 = 0xFFFF_8800_00E3_0000;
        let fd_array_paddr: u64 = 0x00E3_0000;
        let file_vaddr: u64     = 0xFFFF_8800_00E4_0000;
        let file_paddr: u64     = 0x00E4_0000;
        let sock_vaddr: u64     = 0xFFFF_8800_00E5_0000;
        let sock_paddr: u64     = 0x00E5_0000;
        let sk_vaddr: u64       = 0xFFFF_8800_00E6_0000;
        let sk_paddr: u64       = 0x00E6_0000;

        let isf = IsfBuilder::new()
            .add_symbol("init_task", sym_vaddr)
            .add_struct("list_head", 0x10)
            .add_field("list_head", "next", 0x00, "pointer")
            .add_struct("task_struct", 0x400)
            .add_field("task_struct", "tasks", tasks_offset, "pointer")
            .add_field("task_struct", "pid", 0x00, "unsigned int")
            .add_field("task_struct", "comm", 0x20, "char")
            .add_field("task_struct", "files", files_offset, "pointer")
            .add_struct("files_struct", 0x100)
            .add_field("files_struct", "fdt", 0x00, "pointer")
            .add_struct("fdtable", 0x40)
            .add_field("fdtable", "fd", 0x00, "pointer")
            .add_struct("file", 0x100)
            .add_field("file", "private_data", 0x00, "pointer")
            .add_struct("socket", 0x80)
            .add_field("socket", "type", 0x00, "unsigned short")
            .add_field("socket", "sk", 0x08, "pointer")
            .add_struct("sock", 0x100)
            .add_field("sock", "sk_family", 0x00, "unsigned short")
            .add_field("sock", "sk_protocol", 0x02, "unsigned short")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut task_page = [0u8; 4096];
        let self_ptr = sym_vaddr + tasks_offset;
        task_page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&self_ptr.to_le_bytes());
        task_page[0x20..0x28].copy_from_slice(b"implant\0");
        task_page[0x00..0x04].copy_from_slice(&300u32.to_le_bytes());
        task_page[files_offset as usize..files_offset as usize + 8]
            .copy_from_slice(&files_vaddr.to_le_bytes());

        let mut files_page = [0u8; 4096];
        files_page[0..8].copy_from_slice(&fdt_vaddr.to_le_bytes());

        let mut fdt_page = [0u8; 4096];
        fdt_page[0..8].copy_from_slice(&fd_array_vaddr.to_le_bytes());

        let mut fd_array_page = [0u8; 4096];
        fd_array_page[0..8].copy_from_slice(&file_vaddr.to_le_bytes());

        let mut file_page = [0u8; 4096];
        file_page[0..8].copy_from_slice(&sock_vaddr.to_le_bytes());

        // socket: type=SOCK_RAW(3), sk=sk_vaddr
        let mut socket_page = [0u8; 4096];
        socket_page[0..2].copy_from_slice(&3u16.to_le_bytes()); // type=SOCK_RAW
        socket_page[8..16].copy_from_slice(&sk_vaddr.to_le_bytes());

        // sock: sk_family=AF_INET(2) (not AF_PACKET), sk_protocol=255
        let mut sk_page = [0u8; 4096];
        sk_page[0..2].copy_from_slice(&2u16.to_le_bytes()); // sk_family = AF_INET (not AF_PACKET)
        sk_page[2..4].copy_from_slice(&255u16.to_le_bytes()); // sk_protocol

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &task_page)
            .map_4k(files_vaddr, files_paddr, ptf::WRITABLE)
            .write_phys(files_paddr, &files_page)
            .map_4k(fdt_vaddr, fdt_paddr, ptf::WRITABLE)
            .write_phys(fdt_paddr, &fdt_page)
            .map_4k(fd_array_vaddr, fd_array_paddr, ptf::WRITABLE)
            .write_phys(fd_array_paddr, &fd_array_page)
            .map_4k(file_vaddr, file_paddr, ptf::WRITABLE)
            .write_phys(file_paddr, &file_page)
            .map_4k(sock_vaddr, sock_paddr, ptf::WRITABLE)
            .write_phys(sock_paddr, &socket_page)
            .map_4k(sk_vaddr, sk_paddr, ptf::WRITABLE)
            .write_phys(sk_paddr, &sk_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_raw_sockets(&reader).expect("should not error");
        assert_eq!(result.len(), 1, "SOCK_RAW socket should be detected");
        assert_eq!(result[0].socket_type, "SOCK_RAW");
        assert_eq!(result[0].pid, 300);
        assert!(result[0].is_suspicious, "unknown comm + SOCK_RAW → suspicious");
    }

    // --- try_read_raw_socket: sk_family != AF_PACKET AND sock_type != SOCK_RAW → None ---
    // Exercises the final `return None` (not a raw socket) branch (line 221).
    #[test]
    fn walk_raw_sockets_not_raw_socket_returns_none() {
        use memf_core::test_builders::flags as ptf;

        let tasks_offset: u64   = 0x10;
        let files_offset: u64   = 0x30;
        let sym_vaddr: u64      = 0xFFFF_8800_00F0_0000;
        let sym_paddr: u64      = 0x00F0_0000;
        let files_vaddr: u64    = 0xFFFF_8800_00F1_0000;
        let files_paddr: u64    = 0x00F1_0000;
        let fdt_vaddr: u64      = 0xFFFF_8800_00F2_0000;
        let fdt_paddr: u64      = 0x00F2_0000;
        let fd_array_vaddr: u64 = 0xFFFF_8800_00F3_0000;
        let fd_array_paddr: u64 = 0x00F3_0000;
        let file_vaddr: u64     = 0xFFFF_8800_00F4_0000;
        let file_paddr: u64     = 0x00F4_0000;
        let sock_vaddr: u64     = 0xFFFF_8800_00F5_0000;
        let sock_paddr: u64     = 0x00F5_0000;
        let sk_vaddr: u64       = 0xFFFF_8800_00F6_0000;
        let sk_paddr: u64       = 0x00F6_0000;

        let isf = IsfBuilder::new()
            .add_symbol("init_task", sym_vaddr)
            .add_struct("list_head", 0x10)
            .add_field("list_head", "next", 0x00, "pointer")
            .add_struct("task_struct", 0x400)
            .add_field("task_struct", "tasks", tasks_offset, "pointer")
            .add_field("task_struct", "pid", 0x00, "unsigned int")
            .add_field("task_struct", "comm", 0x20, "char")
            .add_field("task_struct", "files", files_offset, "pointer")
            .add_struct("files_struct", 0x100)
            .add_field("files_struct", "fdt", 0x00, "pointer")
            .add_struct("fdtable", 0x40)
            .add_field("fdtable", "fd", 0x00, "pointer")
            .add_struct("file", 0x100)
            .add_field("file", "private_data", 0x00, "pointer")
            .add_struct("socket", 0x80)
            .add_field("socket", "type", 0x00, "unsigned short")
            .add_field("socket", "sk", 0x08, "pointer")
            .add_struct("sock", 0x100)
            .add_field("sock", "sk_family", 0x00, "unsigned short")
            .add_field("sock", "sk_protocol", 0x02, "unsigned short")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut task_page = [0u8; 4096];
        let self_ptr = sym_vaddr + tasks_offset;
        task_page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&self_ptr.to_le_bytes());
        task_page[files_offset as usize..files_offset as usize + 8]
            .copy_from_slice(&files_vaddr.to_le_bytes());

        let mut files_page = [0u8; 4096];
        files_page[0..8].copy_from_slice(&fdt_vaddr.to_le_bytes());

        let mut fdt_page = [0u8; 4096];
        fdt_page[0..8].copy_from_slice(&fd_array_vaddr.to_le_bytes());

        let mut fd_array_page = [0u8; 4096];
        fd_array_page[0..8].copy_from_slice(&file_vaddr.to_le_bytes());

        let mut file_page = [0u8; 4096];
        file_page[0..8].copy_from_slice(&sock_vaddr.to_le_bytes());

        // socket: type = SOCK_STREAM (1, not SOCK_RAW), sk = sk_vaddr
        let mut socket_page = [0u8; 4096];
        socket_page[0..2].copy_from_slice(&1u16.to_le_bytes()); // type = SOCK_STREAM
        socket_page[8..16].copy_from_slice(&sk_vaddr.to_le_bytes());

        // sock: sk_family = AF_INET (2, not AF_PACKET)
        let mut sk_page = [0u8; 4096];
        sk_page[0..2].copy_from_slice(&2u16.to_le_bytes()); // sk_family = AF_INET

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &task_page)
            .map_4k(files_vaddr, files_paddr, ptf::WRITABLE)
            .write_phys(files_paddr, &files_page)
            .map_4k(fdt_vaddr, fdt_paddr, ptf::WRITABLE)
            .write_phys(fdt_paddr, &fdt_page)
            .map_4k(fd_array_vaddr, fd_array_paddr, ptf::WRITABLE)
            .write_phys(fd_array_paddr, &fd_array_page)
            .map_4k(file_vaddr, file_paddr, ptf::WRITABLE)
            .write_phys(file_paddr, &file_page)
            .map_4k(sock_vaddr, sock_paddr, ptf::WRITABLE)
            .write_phys(sock_paddr, &socket_page)
            .map_4k(sk_vaddr, sk_paddr, ptf::WRITABLE)
            .write_phys(sk_paddr, &sk_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_raw_sockets(&reader).expect("should not error");
        assert!(result.is_empty(), "SOCK_STREAM is not a raw socket → None → empty");
    }

    // --- try_read_raw_socket: private_data == 0 → returns None → no entry ---
    #[test]
    fn walk_raw_sockets_private_data_null_no_entry() {
        use memf_core::test_builders::flags as ptf;

        let tasks_offset: u64   = 0x10;
        let files_offset: u64   = 0x30;
        let sym_vaddr: u64      = 0xFFFF_8800_00C1_0000;
        let sym_paddr: u64      = 0x00C1_0000;
        let files_vaddr: u64    = 0xFFFF_8800_00C2_0000;
        let files_paddr: u64    = 0x00C2_0000;
        let fdt_vaddr: u64      = 0xFFFF_8800_00C3_0000;
        let fdt_paddr: u64      = 0x00C3_0000;
        let fd_array_vaddr: u64 = 0xFFFF_8800_00C4_0000;
        let fd_array_paddr: u64 = 0x00C4_0000;
        let file_vaddr: u64     = 0xFFFF_8800_00C5_0000;
        let file_paddr: u64     = 0x00C5_0000;

        let isf = IsfBuilder::new()
            .add_symbol("init_task", sym_vaddr)
            .add_struct("list_head", 0x10)
            .add_field("list_head", "next", 0x00, "pointer")
            .add_struct("task_struct", 0x400)
            .add_field("task_struct", "tasks", tasks_offset, "pointer")
            .add_field("task_struct", "pid", 0x00, "unsigned int")
            .add_field("task_struct", "comm", 0x20, "char")
            .add_field("task_struct", "files", files_offset, "pointer")
            .add_struct("files_struct", 0x100)
            .add_field("files_struct", "fdt", 0x00, "pointer")
            .add_struct("fdtable", 0x40)
            .add_field("fdtable", "fd", 0x00, "pointer")
            .add_struct("file", 0x100)
            .add_field("file", "private_data", 0x00, "pointer")
            .add_struct("socket", 0x80)
            .add_field("socket", "type", 0x00, "unsigned short")
            .add_field("socket", "sk", 0x08, "pointer")
            .add_struct("sock", 0x100)
            .add_field("sock", "sk_family", 0x00, "unsigned short")
            .add_field("sock", "sk_protocol", 0x02, "unsigned short")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut task_page = [0u8; 4096];
        let self_ptr = sym_vaddr + tasks_offset;
        task_page[tasks_offset as usize..tasks_offset as usize + 8]
            .copy_from_slice(&self_ptr.to_le_bytes());
        task_page[files_offset as usize..files_offset as usize + 8]
            .copy_from_slice(&files_vaddr.to_le_bytes());

        let mut files_page = [0u8; 4096];
        files_page[0..8].copy_from_slice(&fdt_vaddr.to_le_bytes());

        let mut fdt_page = [0u8; 4096];
        fdt_page[0..8].copy_from_slice(&fd_array_vaddr.to_le_bytes());

        let mut fd_array_page = [0u8; 4096];
        fd_array_page[0..8].copy_from_slice(&file_vaddr.to_le_bytes());

        // file page: private_data at 0 = 0 → try_read_raw_socket returns None
        let file_page = [0u8; 4096];

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, ptf::WRITABLE)
            .write_phys(sym_paddr, &task_page)
            .map_4k(files_vaddr, files_paddr, ptf::WRITABLE)
            .write_phys(files_paddr, &files_page)
            .map_4k(fdt_vaddr, fdt_paddr, ptf::WRITABLE)
            .write_phys(fdt_paddr, &fdt_page)
            .map_4k(fd_array_vaddr, fd_array_paddr, ptf::WRITABLE)
            .write_phys(fd_array_paddr, &fd_array_page)
            .map_4k(file_vaddr, file_paddr, ptf::WRITABLE)
            .write_phys(file_paddr, &file_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_raw_sockets(&reader).expect("should not error");
        assert!(result.is_empty(), "private_data=0 → no raw socket entry");
    }
}
