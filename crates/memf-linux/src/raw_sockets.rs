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
}
