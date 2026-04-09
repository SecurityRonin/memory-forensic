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
}
