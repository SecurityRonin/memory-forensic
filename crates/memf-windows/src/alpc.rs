//! Windows ALPC (Advanced Local Procedure Call) port enumeration.
//!
//! ALPC is the modern IPC mechanism in Windows, replacing the older LPC.
//! Every RPC, COM, and many system services communicate via ALPC ports.
//! Enumerating ALPC ports from memory reveals inter-process communication
//! patterns — useful for detecting:
//!
//! - Malware using custom ALPC ports for C2 communication
//! - Privilege escalation via ALPC port impersonation
//! - Process injection through ALPC message handlers
//!
//! ALPC ports are kernel objects of type `_ALPC_PORT`. Each port has a
//! name, owner process, and connection state.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;

/// Maximum number of ALPC ports to enumerate (safety limit).
const MAX_PORTS: usize = 8192;

/// Information about an ALPC port recovered from kernel memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AlpcPortInfo {
    /// Virtual address of the port object.
    pub address: u64,
    /// Port name (from the object name in the object directory).
    pub name: String,
    /// Owner process ID.
    pub owner_pid: u32,
    /// Whether this is a connection port (server-side, listening).
    pub is_server_port: bool,
    /// Number of connected client ports.
    pub connection_count: u32,
    /// Whether this port looks suspicious.
    pub is_suspicious: bool,
}

/// Classify an ALPC port name as suspicious.
///
/// Returns `true` for ports that don't match known Windows system patterns.
pub fn classify_alpc_port(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let lower = name.to_lowercase();
    // Known benign prefixes
    let benign_prefixes = [
        "\\rpc control\\",
        "\\windows\\",
        "\\sessions\\",
        "\\basenamedobjects\\",
        "\\knownlls\\",
        "\\registry\\",
        "\\device\\",
    ];
    for prefix in &benign_prefixes {
        if lower.starts_with(prefix) {
            return false;
        }
    }
    // Long names in unusual namespaces are suspicious
    name.len() > 40
}

/// Enumerate ALPC ports from kernel memory.
///
/// Walks the `AlpcpPortList` linked list to find `_ALPC_PORT` structures.
/// Returns an empty `Vec` if the required symbols are not present.
pub fn walk_alpc_ports<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<AlpcPortInfo>> {
    let list_head_vaddr = match reader.symbols().symbol_address("AlpcpPortList") {
        Some(v) => v,
        None => return Ok(Vec::new()),
    };

    // Read the Flink of the list head
    let flink: u64 = match reader.read_bytes(list_head_vaddr, 8) {
        Ok(bytes) => u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")),
        Err(_) => return Ok(Vec::new()),
    };

    if flink == 0 || flink == list_head_vaddr {
        return Ok(Vec::new());
    }

    // Default field offsets when ISF does not define _ALPC_PORT
    let port_list_entry_off: u64 = reader
        .symbols()
        .field_offset("_ALPC_PORT", "PortListEntry")
        .unwrap_or(0x00) as u64;
    let owner_process_off: u64 = reader
        .symbols()
        .field_offset("_ALPC_PORT", "OwnerProcess")
        .unwrap_or(0x08) as u64;
    let connection_port_off: u64 = reader
        .symbols()
        .field_offset("_ALPC_PORT", "ConnectionPort")
        .unwrap_or(0x10) as u64;
    let port_name_off: u64 = reader
        .symbols()
        .field_offset("_ALPC_PORT", "PortName")
        .unwrap_or(0x18) as u64;
    let connection_count_off: u64 = reader
        .symbols()
        .field_offset("_ALPC_PORT", "ConnectionCount")
        .unwrap_or(0x28) as u64;
    let pid_off: u64 = reader
        .symbols()
        .field_offset("_EPROCESS", "UniqueProcessId")
        .unwrap_or(0x440) as u64;

    let mut results = Vec::new();
    let mut current = flink;
    let mut count = 0;

    while current != list_head_vaddr && count < MAX_PORTS {
        let port_addr = current.wrapping_sub(port_list_entry_off);

        // Read port name (_UNICODE_STRING at port_name_off)
        let name = read_unicode_string(reader, port_addr + port_name_off)
            .unwrap_or_default();

        // Read owner PID
        let owner_pid = {
            let owner_ptr_bytes = reader.read_bytes(port_addr + owner_process_off, 8).ok();
            owner_ptr_bytes
                .and_then(|b| {
                    let ptr = u64::from_le_bytes(b[..8].try_into().ok()?);
                    if ptr == 0 { return None; }
                    reader.read_bytes(ptr + pid_off, 8).ok().map(|pid_bytes| {
                        u64::from_le_bytes(pid_bytes[..8].try_into().expect("8")) as u32
                    })
                })
                .unwrap_or(0)
        };

        // is_server_port: ConnectionPort field points back to self
        let is_server_port = {
            reader.read_bytes(port_addr + connection_port_off, 8)
                .ok()
                .map(|b| {
                    let ptr = u64::from_le_bytes(b[..8].try_into().expect("8"));
                    ptr == port_addr || ptr == 0
                })
                .unwrap_or(false)
        };

        // Read connection count (u32)
        let connection_count = reader.read_bytes(port_addr + connection_count_off, 4)
            .ok()
            .map(|b| u32::from_le_bytes(b[..4].try_into().expect("4")))
            .unwrap_or(0);

        let is_suspicious = classify_alpc_port(&name);

        results.push(AlpcPortInfo {
            address: port_addr,
            name,
            owner_pid,
            is_server_port,
            connection_count,
            is_suspicious,
        });

        // Follow Flink
        current = match reader.read_bytes(current, 8) {
            Ok(bytes) => u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")),
            Err(_) => break,
        };
        count += 1;
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

    fn make_empty_reader() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// No ALPC symbol → empty Vec.
    #[test]
    fn walk_alpc_ports_no_symbol() {
        let reader = make_empty_reader();
        let result = walk_alpc_ports(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// Known Windows RPC Control ports are benign.
    #[test]
    fn classify_alpc_benign_rpc() {
        assert!(!classify_alpc_port("\\RPC Control\\lsasspirpc"));
        assert!(!classify_alpc_port("\\RPC Control\\samss lpc"));
    }

    /// Very long port names in unusual paths are suspicious.
    #[test]
    fn classify_alpc_suspicious_long_name() {
        let long_name = "\\CustomNamespace\\".to_string() + &"x".repeat(40);
        assert!(classify_alpc_port(&long_name));
    }

    /// Empty name is not suspicious.
    #[test]
    fn classify_alpc_empty_benign() {
        assert!(!classify_alpc_port(""));
    }

    /// Short port names in unusual namespaces are benign (< 40 chars).
    #[test]
    fn classify_alpc_short_unusual_name_benign() {
        assert!(!classify_alpc_port("\\CustomNS\\short"));
    }

    /// Known benign prefixes are all correctly classified.
    #[test]
    fn classify_alpc_all_benign_prefixes() {
        assert!(!classify_alpc_port("\\Windows\\ApiPort"));
        assert!(!classify_alpc_port("\\Sessions\\1\\BaseNamedObjects\\test"));
        assert!(!classify_alpc_port("\\BaseNamedObjects\\SomePort"));
        assert!(!classify_alpc_port("\\KnownDlls\\ntdll.dll"));
        assert!(!classify_alpc_port("\\Registry\\Machine\\System"));
        assert!(!classify_alpc_port("\\Device\\NamedPipe\\somepipe"));
    }

    /// AlpcPortInfo serializes to JSON.
    #[test]
    fn alpc_port_info_serializes() {
        let info = AlpcPortInfo {
            address: 0xFFFF_8000_0001_0000,
            name: "\\RPC Control\\test".to_string(),
            owner_pid: 1234,
            is_server_port: true,
            connection_count: 5,
            is_suspicious: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("test"));
        assert!(json.contains("1234"));
    }

    /// Walker with AlpcpPortList symbol but unreadable head returns empty.
    #[test]
    fn walk_alpc_ports_unreadable_list_head() {
        // Symbol present but vaddr not mapped → read_bytes fails → empty
        let isf = IsfBuilder::new()
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            .add_symbol("AlpcpPortList", 0xFFFF_8000_DEAD_0000)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_alpc_ports(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// Walker with AlpcpPortList symbol whose head Flink is zero returns empty.
    #[test]
    fn walk_alpc_ports_zero_flink() {
        const LIST_VADDR: u64 = 0xFFFF_8000_0010_0000;
        const LIST_PADDR: u64 = 0x0010_0000;
        let isf = IsfBuilder::new()
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            .add_symbol("AlpcpPortList", LIST_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let mut page = vec![0u8; 4096];
        // Flink = 0
        page[0..8].copy_from_slice(&0u64.to_le_bytes());
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(LIST_VADDR, LIST_PADDR, flags::WRITABLE)
            .write_phys(LIST_PADDR, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_alpc_ports(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// Walker with AlpcpPortList pointing to itself (empty circular list) returns empty.
    #[test]
    fn walk_alpc_ports_self_referential_head() {
        const LIST_VADDR: u64 = 0xFFFF_8000_0011_0000;
        const LIST_PADDR: u64 = 0x0011_0000;
        let isf = IsfBuilder::new()
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            .add_symbol("AlpcpPortList", LIST_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let mut page = vec![0u8; 4096];
        // Flink = self (empty list)
        page[0..8].copy_from_slice(&LIST_VADDR.to_le_bytes());
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(LIST_VADDR, LIST_PADDR, flags::WRITABLE)
            .write_phys(LIST_PADDR, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_alpc_ports(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// Walker falls back to empty when AlpcpPortList absent (no ObpRootDirectoryObject fallback in impl).
    #[test]
    fn walk_alpc_ports_fallback_to_obp_root() {
        let reader = make_empty_reader();
        let result = walk_alpc_ports(&reader).unwrap();
        assert!(result.is_empty());
    }

    // ── walk body: one port entry ─────────────────────────────────────

    /// Walk body: AlpcpPortList → one port → list_head (terminates).
    #[test]
    fn walk_alpc_ports_one_entry_in_loop() {
        // Layout:
        //   list_head  @ 0xFFFF_8000_0012_0000 (LIST_VADDR)
        //   port_entry @ 0xFFFF_8000_0012_1000 (PORT_VADDR)
        //     +0x00: Flink → LIST_VADDR (terminates)
        //     +0x08: OwnerProcess ptr → EPROC_VADDR
        //     +0x10: ConnectionPort ptr → PORT_VADDR (self = server port)
        //     +0x18: _UNICODE_STRING { Length=10, MaxLen=10, Buffer=NAME_VADDR }
        //     +0x28: ConnectionCount (u32) = 3
        //   eproc @ 0xFFFF_8000_0012_2000 (EPROC_VADDR)
        //     +0x440: UniqueProcessId = 888
        //   name string @ 0xFFFF_8000_0012_3000 (NAME_VADDR): "Port1\0" in UTF-16LE

        const LIST_VADDR:  u64 = 0xFFFF_8000_0012_0000;
        const PORT_VADDR:  u64 = 0xFFFF_8000_0012_1000;
        const EPROC_VADDR: u64 = 0xFFFF_8000_0012_2000;
        const NAME_VADDR:  u64 = 0xFFFF_8000_0012_3000;
        const LIST_PADDR:  u64 = 0x0012_0000;
        const PORT_PADDR:  u64 = 0x0012_1000;
        const EPROC_PADDR: u64 = 0x0012_2000;
        const NAME_PADDR:  u64 = 0x0012_3000;

        let name_str = "Port1";
        let name_utf16: Vec<u8> = name_str.encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let name_len = name_utf16.len() as u16;

        let isf = IsfBuilder::new()
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            .add_symbol("AlpcpPortList", LIST_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // list_head: Flink → PORT_VADDR
        let mut list_page = vec![0u8; 4096];
        list_page[0..8].copy_from_slice(&PORT_VADDR.to_le_bytes());

        // port entry page
        let mut port_page = vec![0u8; 4096];
        port_page[0x00..0x08].copy_from_slice(&LIST_VADDR.to_le_bytes()); // Flink = list_head
        port_page[0x08..0x10].copy_from_slice(&EPROC_VADDR.to_le_bytes()); // OwnerProcess
        port_page[0x10..0x18].copy_from_slice(&PORT_VADDR.to_le_bytes()); // ConnectionPort = self
        port_page[0x18..0x1a].copy_from_slice(&name_len.to_le_bytes()); // Length
        port_page[0x1a..0x1c].copy_from_slice(&name_len.to_le_bytes()); // MaximumLength
        port_page[0x20..0x28].copy_from_slice(&NAME_VADDR.to_le_bytes()); // Buffer
        port_page[0x28..0x2c].copy_from_slice(&3u32.to_le_bytes()); // ConnectionCount

        // eprocess page: PID at +0x440
        let mut eproc_page = vec![0u8; 0x500];
        eproc_page[0x440..0x448].copy_from_slice(&888u64.to_le_bytes());

        // name page
        let mut name_page = vec![0u8; 4096];
        name_page[..name_utf16.len()].copy_from_slice(&name_utf16);

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(LIST_VADDR, LIST_PADDR, flags::WRITABLE)
            .write_phys(LIST_PADDR, &list_page)
            .map_4k(PORT_VADDR, PORT_PADDR, flags::WRITABLE)
            .write_phys(PORT_PADDR, &port_page)
            .map_4k(EPROC_VADDR, EPROC_PADDR, flags::WRITABLE)
            .write_phys(EPROC_PADDR, &eproc_page)
            .map_4k(NAME_VADDR, NAME_PADDR, flags::WRITABLE)
            .write_phys(NAME_PADDR, &name_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let ports = walk_alpc_ports(&reader).unwrap();
        assert_eq!(ports.len(), 1);
        let p = &ports[0];
        assert_eq!(p.name, name_str);
        assert_eq!(p.owner_pid, 888);
        assert!(p.is_server_port);
        assert_eq!(p.connection_count, 3);
    }
}
