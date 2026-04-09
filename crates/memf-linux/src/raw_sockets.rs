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
pub fn classify_raw_socket(_comm: &str, _socket_type: &str, _is_promiscuous: bool) -> bool {
    todo!("RED: implement classify_raw_socket")
}

/// Walk the task list and enumerate all open raw sockets.
pub fn walk_raw_sockets<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
) -> Result<Vec<RawSocketInfo>> {
    todo!("RED: implement walk_raw_sockets")
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
}
