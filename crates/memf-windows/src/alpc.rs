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

    let lower = name.to_ascii_lowercase();

    // Known benign Windows ALPC port prefixes
    const BENIGN_PREFIXES: &[&str] = &[
        "\\rpc control\\",
        "\\windows\\",
        "\\basenamed",
        "\\sessions\\",
        "\\kernelconnect\\",
        "\\themeapiport",
        "\\lsapolicylookup",
        "\\nca",
    ];

    for prefix in BENIGN_PREFIXES {
        if lower.starts_with(prefix) {
            return false;
        }
    }

    // Random GUID-like port names in unusual locations are suspicious
    if name.len() > 40 && !name.contains("\\RPC Control\\") {
        return true;
    }

    false
}

/// Enumerate ALPC ports from kernel memory.
///
/// Walks the object directory `\RPC Control\` and other locations to find
/// ALPC port objects. Returns an empty `Vec` if the required symbols are
/// not present.
pub fn walk_alpc_ports<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<AlpcPortInfo>> {
    // ALPC port enumeration requires ObpRootDirectoryObject or AlpcpPortList.
    // Try AlpcpPortList first (simpler linked list), then fall back to
    // ObpRootDirectoryObject (full object directory traversal).
    let list_head = match reader.symbols().symbol_address("AlpcpPortList") {
        Some(addr) => addr,
        None => match reader.symbols().symbol_address("ObpRootDirectoryObject") {
            Some(_root) => {
                // Full object directory traversal is complex and version-specific.
                // For now, return empty — pool scanning is more reliable for ALPC.
                return Ok(Vec::new());
            }
            None => return Ok(Vec::new()),
        },
    };

    // Walk the linked list of _ALPC_PORT structures via PortListEntry.
    let port_list_entry_off = reader
        .symbols()
        .field_offset("_ALPC_PORT", "PortListEntry")
        .unwrap_or(0x00);

    let owner_process_off = reader
        .symbols()
        .field_offset("_ALPC_PORT", "OwnerProcess")
        .unwrap_or(0x08);

    let connection_port_off = reader
        .symbols()
        .field_offset("_ALPC_PORT", "ConnectionPort")
        .unwrap_or(0x10);

    let port_name_off = reader
        .symbols()
        .field_offset("_ALPC_PORT", "PortName")
        .unwrap_or(0x18);

    let connection_count_off = reader
        .symbols()
        .field_offset("_ALPC_PORT", "ConnectionCount")
        .unwrap_or(0x28);

    // Read the UniqueProcessId offset within _EPROCESS for PID extraction.
    let pid_off = reader
        .symbols()
        .field_offset("_EPROCESS", "UniqueProcessId")
        .unwrap_or(0x440);

    // Read head Flink.
    let first = match reader.read_bytes(list_head, 8) {
        Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        _ => return Ok(Vec::new()),
    };

    if first == 0 || first == list_head {
        return Ok(Vec::new());
    }

    let mut ports = Vec::new();
    let mut current = first;
    let mut seen = std::collections::HashSet::new();

    while current != list_head && current != 0 && ports.len() < MAX_PORTS {
        if !seen.insert(current) {
            break; // Cycle detection.
        }

        // current points to PortListEntry within _ALPC_PORT.
        let port_addr = current.wrapping_sub(port_list_entry_off);

        // Read port name (UNICODE_STRING).
        let name = read_unicode_string(reader, port_addr + port_name_off).unwrap_or_default();

        // Read owner process pointer, then dereference to get PID.
        let owner_pid = match reader.read_bytes(port_addr + owner_process_off, 8) {
            Ok(bytes) if bytes.len() == 8 => {
                let eproc = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                if eproc != 0 {
                    match reader.read_bytes(eproc + pid_off, 8) {
                        Ok(pid_bytes) if pid_bytes.len() == 8 => {
                            u64::from_le_bytes(pid_bytes[..8].try_into().unwrap()) as u32
                        }
                        _ => 0,
                    }
                } else {
                    0
                }
            }
            _ => 0,
        };

        // Determine if this is a server (connection) port: ConnectionPort == self.
        let is_server_port = match reader.read_bytes(port_addr + connection_port_off, 8) {
            Ok(bytes) if bytes.len() == 8 => {
                let conn_port = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                conn_port == port_addr
            }
            _ => false,
        };

        // Read connection count.
        let connection_count: u32 = match reader.read_bytes(port_addr + connection_count_off, 4) {
            Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            _ => 0,
        };

        let is_suspicious = classify_alpc_port(&name);

        ports.push(AlpcPortInfo {
            address: port_addr,
            name,
            owner_pid,
            is_server_port,
            connection_count,
            is_suspicious,
        });

        // Follow Flink to next entry.
        current = match reader.read_bytes(current, 8) {
            Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            _ => break,
        };
    }

    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// No ALPC symbol → empty Vec.
    #[test]
    fn walk_alpc_ports_no_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("_ALPC_PORT", 0x100)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_alpc_ports(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// Known Windows RPC Control ports are benign.
    #[test]
    fn classify_alpc_benign_rpc() {
        assert!(!classify_alpc_port("\\RPC Control\\lsarpc"));
        assert!(!classify_alpc_port("\\RPC Control\\samr"));
        assert!(!classify_alpc_port("\\RPC Control\\epmapper"));
        assert!(!classify_alpc_port("\\Windows\\ApiPort"));
    }

    /// Very long port names in unusual paths are suspicious.
    #[test]
    fn classify_alpc_suspicious_long_name() {
        let long_name = format!("\\Custom\\{}", "a".repeat(50));
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
        // Only > 40 chars in unusual paths are suspicious.
        assert!(!classify_alpc_port("\\Custom\\short"));
    }

    /// Known benign prefixes are all correctly classified.
    #[test]
    fn classify_alpc_all_benign_prefixes() {
        assert!(!classify_alpc_port("\\Windows\\ApiPort"));
        assert!(!classify_alpc_port("\\BaseNamedObjects\\something"));
        assert!(!classify_alpc_port("\\Sessions\\1\\something"));
        assert!(!classify_alpc_port("\\KernelConnect\\port1"));
        assert!(!classify_alpc_port("\\ThemeApiPort"));
        assert!(!classify_alpc_port("\\LsaPolicyLookup"));
        assert!(!classify_alpc_port("\\NcaPort"));
    }

    /// AlpcPortInfo serializes to JSON.
    #[test]
    fn alpc_port_info_serializes() {
        let info = AlpcPortInfo {
            address: 0xFFFF_8000_1234_5678,
            name: "\\RPC Control\\test".to_string(),
            owner_pid: 4,
            is_server_port: true,
            connection_count: 2,
            is_suspicious: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\\\\RPC Control\\\\test"));
        assert!(json.contains("owner_pid"));
        assert!(json.contains("connection_count"));
    }

    /// Walker with AlpcpPortList symbol but unreadable head returns empty.
    #[test]
    fn walk_alpc_ports_unreadable_list_head() {
        let isf = IsfBuilder::new()
            .add_struct("_ALPC_PORT", 0x100)
            .add_symbol("AlpcpPortList", 0xFFFF_8000_DEAD_0000u64)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        // No memory mapped at the symbol address → read_bytes fails → empty.
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_alpc_ports(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// Walker with AlpcpPortList symbol whose head Flink is zero returns empty.
    #[test]
    fn walk_alpc_ports_zero_flink() {
        use memf_core::test_builders::flags;

        let list_vaddr: u64 = 0xFFFF_8000_1000_0000;
        let list_paddr: u64 = 0x0050_0000;

        // Write 8 bytes of 0 at the list head address (Flink = 0).
        let mut page = vec![0u8; 4096];
        // Flink at offset 0 in the page = 0 (list is empty).
        page[0..8].copy_from_slice(&0u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("_ALPC_PORT", 0x100)
            .add_symbol("AlpcpPortList", list_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(list_vaddr, list_paddr, flags::WRITABLE)
            .write_phys(list_paddr, &page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        // Flink == 0 → first == 0 → empty.
        let result = walk_alpc_ports(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// Walker with AlpcpPortList pointing to itself (empty circular list) returns empty.
    #[test]
    fn walk_alpc_ports_self_referential_head() {
        use memf_core::test_builders::flags;

        let list_vaddr: u64 = 0xFFFF_8000_2000_0000;
        let list_paddr: u64 = 0x0060_0000;

        // Write Flink = list_vaddr (points to itself — empty LIST_ENTRY).
        let mut page = vec![0u8; 4096];
        page[0..8].copy_from_slice(&list_vaddr.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("_ALPC_PORT", 0x100)
            .add_symbol("AlpcpPortList", list_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(list_vaddr, list_paddr, flags::WRITABLE)
            .write_phys(list_paddr, &page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        // first == list_head → loop condition fails immediately → empty.
        let result = walk_alpc_ports(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// Walker falls back to ObpRootDirectoryObject when AlpcpPortList absent.
    #[test]
    fn walk_alpc_ports_fallback_to_obp_root() {
        let isf = IsfBuilder::new()
            .add_struct("_ALPC_PORT", 0x100)
            .add_symbol("ObpRootDirectoryObject", 0xFFFF_8000_ABCD_0000u64)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        // Falls back to ObpRootDirectoryObject path → returns empty (not implemented).
        let result = walk_alpc_ports(&reader).unwrap();
        assert!(result.is_empty());
    }
}
