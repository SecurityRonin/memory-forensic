//! Linux network connection walker.
//!
//! Enumerates TCP connections by scanning the kernel's `tcp_hashinfo.ehash`
//! hash table. Each bucket contains a `hlist_nulls` chain of `sock` structs.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{ConnectionInfo, ConnectionState, Error, Protocol, Result};

/// Walk Linux TCP connections via `tcp_hashinfo.ehash`.
pub fn walk_connections<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<ConnectionInfo>> {
    let tcp_hashinfo_addr = reader
        .symbols()
        .symbol_address("tcp_hashinfo")
        .ok_or_else(|| Error::Walker("symbol 'tcp_hashinfo' not found".into()))?;

    let ehash_ptr: u64 = reader.read_field(tcp_hashinfo_addr, "inet_hashinfo", "ehash")?;
    let ehash_mask: u32 = reader.read_field(tcp_hashinfo_addr, "inet_hashinfo", "ehash_mask")?;

    if ehash_ptr == 0 {
        return Ok(Vec::new());
    }

    let mut connections = Vec::new();
    let bucket_count = u64::from(ehash_mask) + 1;

    for i in 0..bucket_count {
        let bucket_size = reader
            .symbols()
            .struct_size("inet_ehash_bucket")
            .unwrap_or(8);
        let bucket_addr = ehash_ptr + i * bucket_size;

        let chain_first: u64 = match reader.read_field(bucket_addr, "inet_ehash_bucket", "chain") {
            Ok(v) => v,
            Err(_) => continue,
        };

        // hlist_nulls terminates with low bit set
        if chain_first == 0 || chain_first & 1 != 0 {
            continue;
        }

        let mut sk_addr = chain_first;
        let mut chain_len = 0;
        while sk_addr != 0 && sk_addr & 1 == 0 && chain_len < 1000 {
            if let Ok(conn) = read_inet_sock(reader, sk_addr) {
                connections.push(conn);
            }

            sk_addr = match reader.read_pointer(sk_addr, "sock_common", "skc_nulls_node") {
                Ok(v) => v,
                Err(_) => break,
            };
            chain_len += 1;
        }
    }

    Ok(connections)
}

fn read_inet_sock<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    sk_addr: u64,
) -> Result<ConnectionInfo> {
    let sk_common_off = reader
        .symbols()
        .field_offset("sock", "__sk_common")
        .unwrap_or(0);
    let common_addr = sk_addr + sk_common_off;

    let daddr: u32 = reader.read_field(common_addr, "sock_common", "skc_daddr")?;
    let saddr: u32 = reader.read_field(common_addr, "sock_common", "skc_rcv_saddr")?;
    let dport: u16 = reader.read_field(common_addr, "sock_common", "skc_dport")?;
    let sport: u16 = reader.read_field(common_addr, "sock_common", "skc_num")?;
    let state: u8 = reader.read_field(common_addr, "sock_common", "skc_state")?;

    // dport is in network byte order (big-endian)
    let dport = u16::from_be(dport);

    Ok(ConnectionInfo {
        protocol: Protocol::Tcp,
        local_addr: ipv4_to_string(saddr),
        local_port: sport,
        remote_addr: ipv4_to_string(daddr),
        remote_port: dport,
        state: ConnectionState::from_raw(state),
        pid: None,
    })
}

fn ipv4_to_string(addr: u32) -> String {
    let bytes = addr.to_le_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_net_reader(data: &[u8], vaddr: u64, paddr: u64) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("inet_hashinfo", 64)
            .add_field("inet_hashinfo", "ehash", 0, "pointer")
            .add_field("inet_hashinfo", "ehash_mask", 8, "unsigned int")
            .add_struct("inet_ehash_bucket", 8)
            .add_field("inet_ehash_bucket", "chain", 0, "pointer")
            .add_struct("sock_common", 64)
            .add_field("sock_common", "skc_nulls_node", 0, "pointer")
            .add_field("sock_common", "skc_daddr", 8, "unsigned int")
            .add_field("sock_common", "skc_rcv_saddr", 12, "unsigned int")
            .add_field("sock_common", "skc_dport", 16, "unsigned short")
            .add_field("sock_common", "skc_num", 18, "unsigned short")
            .add_field("sock_common", "skc_state", 20, "unsigned char")
            .add_struct("sock", 256)
            .add_field("sock", "__sk_common", 0, "sock_common")
            .add_symbol("tcp_hashinfo", vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn walk_single_connection() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        let ehash_addr = vaddr + 0x100;
        data[0..8].copy_from_slice(&ehash_addr.to_le_bytes());
        data[8..12].copy_from_slice(&0u32.to_le_bytes());

        let sock_addr = vaddr + 0x200;
        data[0x100..0x108].copy_from_slice(&sock_addr.to_le_bytes());

        // sock_common at vaddr + 0x200
        data[0x200..0x208].copy_from_slice(&1u64.to_le_bytes()); // null terminator
        let daddr: u32 = u32::from_le_bytes([192, 168, 1, 100]);
        data[0x208..0x20C].copy_from_slice(&daddr.to_le_bytes());
        let saddr: u32 = u32::from_le_bytes([10, 0, 0, 1]);
        data[0x20C..0x210].copy_from_slice(&saddr.to_le_bytes());
        data[0x210..0x212].copy_from_slice(&443u16.to_be_bytes());
        data[0x212..0x214].copy_from_slice(&54321u16.to_le_bytes());
        data[0x214] = 1; // ESTABLISHED

        let reader = make_net_reader(&data, vaddr, paddr);
        let conns = walk_connections(&reader).unwrap();

        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].protocol, Protocol::Tcp);
        assert_eq!(conns[0].local_addr, "10.0.0.1");
        assert_eq!(conns[0].local_port, 54321);
        assert_eq!(conns[0].remote_addr, "192.168.1.100");
        assert_eq!(conns[0].remote_port, 443);
        assert_eq!(conns[0].state, ConnectionState::Established);
    }

    #[test]
    fn empty_hash_table() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];
        data[0..8].copy_from_slice(&0u64.to_le_bytes());
        data[8..12].copy_from_slice(&0u32.to_le_bytes());

        let reader = make_net_reader(&data, vaddr, paddr);
        let conns = walk_connections(&reader).unwrap();
        assert!(conns.is_empty());
    }

    #[test]
    fn ipv4_formatting() {
        assert_eq!(
            ipv4_to_string(u32::from_le_bytes([127, 0, 0, 1])),
            "127.0.0.1"
        );
        assert_eq!(
            ipv4_to_string(u32::from_le_bytes([192, 168, 1, 1])),
            "192.168.1.1"
        );
    }
}
