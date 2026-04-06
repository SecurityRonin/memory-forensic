//! Windows network connection enumeration.
//!
//! Walks TCP endpoint hash tables from `tcpip.sys` to enumerate
//! active network connections. Each hash bucket contains a
//! doubly-linked list of `_TCP_ENDPOINT` structures linked via
//! their `HashEntry` field.
//!
//! The local and remote IP addresses are resolved through the
//! `AddrInfo` pointer chain: `_TCP_ENDPOINT.AddrInfo` ->
//! `_ADDR_INFO.Local` -> `_LOCAL_ADDRESS.pData` -> raw IPv4.
//! Remote address is stored directly in `_ADDR_INFO.Remote`.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Result, WinConnectionInfo, WinTcpState};

/// Maximum entries per bucket chain to prevent infinite loops.
const MAX_CHAIN_LENGTH: usize = 4096;

/// Walk a TCP endpoint hash table and return connection information.
///
/// `table_vaddr` is the base address of the hash table (an array of
/// `_LIST_ENTRY` bucket heads). `bucket_count` is the number of buckets.
///
/// For each non-empty bucket, walks the doubly-linked chain of
/// `_TCP_ENDPOINT` structures. Each endpoint's local/remote addresses
/// are resolved through `AddrInfo` pointer chains, and the owning
/// process is identified via the `Owner` pointer to `_EPROCESS`.
pub fn walk_tcp_endpoints<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    table_vaddr: u64,
    bucket_count: u32,
) -> Result<Vec<WinConnectionInfo>> {
    let hash_entry_off = reader
        .symbols()
        .field_offset("_TCP_ENDPOINT", "HashEntry")
        .ok_or_else(|| crate::Error::Walker("missing _TCP_ENDPOINT.HashEntry offset".into()))?;

    let mut results = Vec::new();

    for i in 0..u64::from(bucket_count) {
        let bucket_addr = table_vaddr + i * 16; // each _LIST_ENTRY is 16 bytes

        // Read Flink from this bucket head
        let flink: u64 = reader.read_field(bucket_addr, "_LIST_ENTRY", "Flink")?;

        // Empty bucket: Flink points back to self
        if flink == bucket_addr {
            continue;
        }

        let mut current = flink;
        let mut chain_len = 0;

        while current != bucket_addr && chain_len < MAX_CHAIN_LENGTH {
            // CONTAINING_RECORD: endpoint base = HashEntry addr - HashEntry offset
            let ep_addr = current.wrapping_sub(hash_entry_off);

            if let Ok(conn) = read_tcp_endpoint(reader, ep_addr) {
                results.push(conn);
            }

            // Follow Flink to next entry in chain
            current = match reader.read_field(current, "_LIST_ENTRY", "Flink") {
                Ok(v) => v,
                Err(_) => break,
            };
            chain_len += 1;
        }
    }

    Ok(results)
}

/// Read a single `_TCP_ENDPOINT` and resolve its addresses and owner.
fn read_tcp_endpoint<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ep_addr: u64,
) -> Result<WinConnectionInfo> {
    let state_raw: u32 = reader.read_field(ep_addr, "_TCP_ENDPOINT", "State")?;
    let state = WinTcpState::from_raw(state_raw);

    // Ports are stored in network byte order (big-endian)
    let local_port_raw: u16 = reader.read_field(ep_addr, "_TCP_ENDPOINT", "LocalPort")?;
    let local_port = u16::from_be(local_port_raw);

    let remote_port_raw: u16 = reader.read_field(ep_addr, "_TCP_ENDPOINT", "RemotePort")?;
    let remote_port = u16::from_be(remote_port_raw);

    let create_time: u64 = reader.read_field(ep_addr, "_TCP_ENDPOINT", "CreateTime")?;

    // Resolve addresses through AddrInfo pointer chain
    let (local_addr, remote_addr) = read_addresses(reader, ep_addr)?;

    // Resolve owning process
    let (pid, process_name) = read_owner(reader, ep_addr)?;

    Ok(WinConnectionInfo {
        protocol: "TCPv4".to_string(),
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        state,
        pid,
        process_name,
        create_time,
    })
}

/// Resolve local and remote IPv4 addresses from the `AddrInfo` pointer chain.
///
/// Chain: `_TCP_ENDPOINT.AddrInfo` -> `_ADDR_INFO.Local` ->
/// `_LOCAL_ADDRESS.pData` -> raw IPv4. Remote is at `_ADDR_INFO.Remote`.
fn read_addresses<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ep_addr: u64,
) -> Result<(String, String)> {
    let addr_info: u64 = reader.read_field(ep_addr, "_TCP_ENDPOINT", "AddrInfo")?;
    if addr_info == 0 {
        return Ok(("0.0.0.0".to_string(), "0.0.0.0".to_string()));
    }

    // Remote address: direct u32 in _ADDR_INFO
    let remote_raw: u32 = reader.read_field(addr_info, "_ADDR_INFO", "Remote")?;
    let remote_addr = ipv4_to_string(remote_raw);

    // Local address: pointer chain _ADDR_INFO.Local -> _LOCAL_ADDRESS.pData -> u32
    let local_addr_ptr: u64 = reader.read_field(addr_info, "_ADDR_INFO", "Local")?;
    let local_addr = if local_addr_ptr != 0 {
        let pdata: u64 = reader.read_field(local_addr_ptr, "_LOCAL_ADDRESS", "pData")?;
        if pdata != 0 {
            let bytes = reader.read_bytes(pdata, 4)?;
            let raw = u32::from_le_bytes(bytes.try_into().expect("4 bytes"));
            ipv4_to_string(raw)
        } else {
            "0.0.0.0".to_string()
        }
    } else {
        "0.0.0.0".to_string()
    };

    Ok((local_addr, remote_addr))
}

/// Read the owning process PID and image name from `_TCP_ENDPOINT.Owner`.
fn read_owner<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ep_addr: u64,
) -> Result<(u64, String)> {
    let owner: u64 = reader.read_field(ep_addr, "_TCP_ENDPOINT", "Owner")?;
    if owner == 0 {
        return Ok((0, "<unknown>".to_string()));
    }

    let pid: u64 = reader.read_field(owner, "_EPROCESS", "UniqueProcessId")?;

    let name_off = reader
        .symbols()
        .field_offset("_EPROCESS", "ImageFileName")
        .unwrap_or(0);
    let name_bytes = reader.read_bytes(owner + name_off, 15)?;
    let process_name = String::from_utf8_lossy(&name_bytes)
        .trim_end_matches('\0')
        .to_string();

    Ok((pid, process_name))
}

/// Convert a raw IPv4 address (stored in network byte order, read as LE u32)
/// to a dotted-decimal string.
fn ipv4_to_string(addr: u32) -> String {
    let bytes = addr.to_le_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // _TCP_ENDPOINT field offsets (match ISF definitions in make_net_reader)
    const EP_ADDR_INFO: usize = 0x10;
    const EP_OWNER: usize = 0x28;
    const EP_CREATE_TIME: usize = 0x40;
    const EP_HASH_ENTRY: usize = 0x50;
    const EP_STATE: usize = 0x6C;
    const EP_LOCAL_PORT: usize = 0x72;
    const EP_REMOTE_PORT: usize = 0x74;

    // _ADDR_INFO field offsets
    const AI_LOCAL: usize = 0x0;
    const AI_REMOTE: usize = 0x10;

    // _LOCAL_ADDRESS field offsets
    const LA_PDATA: usize = 0x10;

    // _EPROCESS field offsets
    const EPROC_PID: usize = 0x440;
    const EPROC_IMAGE_NAME: usize = 0x5A8;

    fn make_net_reader(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("_TCP_ENDPOINT", 0x100)
            .add_field("_TCP_ENDPOINT", "AddrInfo", EP_ADDR_INFO as u64, "pointer")
            .add_field("_TCP_ENDPOINT", "Owner", EP_OWNER as u64, "pointer")
            .add_field(
                "_TCP_ENDPOINT",
                "CreateTime",
                EP_CREATE_TIME as u64,
                "unsigned long",
            )
            .add_field(
                "_TCP_ENDPOINT",
                "HashEntry",
                EP_HASH_ENTRY as u64,
                "_LIST_ENTRY",
            )
            .add_field("_TCP_ENDPOINT", "State", EP_STATE as u64, "unsigned int")
            .add_field(
                "_TCP_ENDPOINT",
                "LocalPort",
                EP_LOCAL_PORT as u64,
                "unsigned short",
            )
            .add_field(
                "_TCP_ENDPOINT",
                "RemotePort",
                EP_REMOTE_PORT as u64,
                "unsigned short",
            )
            .add_struct("_ADDR_INFO", 0x60)
            .add_field("_ADDR_INFO", "Local", AI_LOCAL as u64, "pointer")
            .add_field("_ADDR_INFO", "Remote", AI_REMOTE as u64, "unsigned int")
            .add_struct("_LOCAL_ADDRESS", 0x18)
            .add_field("_LOCAL_ADDRESS", "pData", LA_PDATA as u64, "pointer")
            .add_struct("_EPROCESS", 2048)
            .add_field("_EPROCESS", "UniqueProcessId", EPROC_PID as u64, "pointer")
            .add_field("_EPROCESS", "ImageFileName", EPROC_IMAGE_NAME as u64, "char")
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// Write a _TCP_ENDPOINT into a byte buffer at the given offset.
    fn write_endpoint(
        buf: &mut [u8],
        off: usize,
        hash_flink: u64,
        hash_blink: u64,
        state: u32,
        local_port: u16,
        remote_port: u16,
        addr_info_vaddr: u64,
        owner_vaddr: u64,
        create_time: u64,
    ) {
        buf[off + EP_ADDR_INFO..off + EP_ADDR_INFO + 8]
            .copy_from_slice(&addr_info_vaddr.to_le_bytes());
        buf[off + EP_OWNER..off + EP_OWNER + 8].copy_from_slice(&owner_vaddr.to_le_bytes());
        buf[off + EP_CREATE_TIME..off + EP_CREATE_TIME + 8]
            .copy_from_slice(&create_time.to_le_bytes());
        // HashEntry: Flink + Blink
        buf[off + EP_HASH_ENTRY..off + EP_HASH_ENTRY + 8]
            .copy_from_slice(&hash_flink.to_le_bytes());
        buf[off + EP_HASH_ENTRY + 8..off + EP_HASH_ENTRY + 16]
            .copy_from_slice(&hash_blink.to_le_bytes());
        buf[off + EP_STATE..off + EP_STATE + 4].copy_from_slice(&state.to_le_bytes());
        // Ports stored in network byte order (big-endian)
        buf[off + EP_LOCAL_PORT..off + EP_LOCAL_PORT + 2]
            .copy_from_slice(&local_port.to_be_bytes());
        buf[off + EP_REMOTE_PORT..off + EP_REMOTE_PORT + 2]
            .copy_from_slice(&remote_port.to_be_bytes());
    }

    /// Write _ADDR_INFO + _LOCAL_ADDRESS + IPv4 data into a byte buffer.
    /// Returns nothing; caller provides the offsets.
    fn write_addr_info(
        buf: &mut [u8],
        ai_off: usize,
        local_addr_vaddr: u64,
        remote_ipv4: [u8; 4],
        la_off: usize,
        ipv4_data_vaddr: u64,
        ipv4_off: usize,
        local_ipv4: [u8; 4],
    ) {
        // _ADDR_INFO
        buf[ai_off + AI_LOCAL..ai_off + AI_LOCAL + 8]
            .copy_from_slice(&local_addr_vaddr.to_le_bytes());
        let remote = u32::from_le_bytes(remote_ipv4);
        buf[ai_off + AI_REMOTE..ai_off + AI_REMOTE + 4].copy_from_slice(&remote.to_le_bytes());

        // _LOCAL_ADDRESS
        buf[la_off + LA_PDATA..la_off + LA_PDATA + 8]
            .copy_from_slice(&ipv4_data_vaddr.to_le_bytes());

        // Raw IPv4 data
        let local = u32::from_le_bytes(local_ipv4);
        buf[ipv4_off..ipv4_off + 4].copy_from_slice(&local.to_le_bytes());
    }

    #[test]
    fn walk_single_endpoint() {
        let table_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let table_paddr: u64 = 0x0080_0000;
        let ep_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let ep_paddr: u64 = 0x0080_1000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_2000;
        let eproc_paddr: u64 = 0x0080_2000;

        let mut table_page = vec![0u8; 4096];
        let mut ep_page = vec![0u8; 4096];
        let mut eproc_page = vec![0u8; 4096];

        // Sub-structure addresses within the table page
        let ai_vaddr = table_vaddr + 0x100;
        let la_vaddr = table_vaddr + 0x200;
        let ipv4_vaddr = table_vaddr + 0x300;

        let bucket0 = table_vaddr;
        let ep_hash = ep_vaddr + EP_HASH_ENTRY as u64;

        // Bucket[0]: single entry, Flink/Blink -> ep.HashEntry
        table_page[0..8].copy_from_slice(&ep_hash.to_le_bytes());
        table_page[8..16].copy_from_slice(&ep_hash.to_le_bytes());

        // Address chain: remote 192.168.1.100, local 10.0.0.1
        write_addr_info(
            &mut table_page,
            0x100,
            la_vaddr,
            [192, 168, 1, 100],
            0x200,
            ipv4_vaddr,
            0x300,
            [10, 0, 0, 1],
        );

        // TCP endpoint: ESTABLISHED, port 54321 -> 443
        write_endpoint(
            &mut ep_page,
            0,
            bucket0,
            bucket0,
            5, // ESTABLISHED
            54321,
            443,
            ai_vaddr,
            eproc_vaddr,
            132_800_000_000_000_000,
        );

        // Owner _EPROCESS: PID 1234, name "firefox.exe"
        eproc_page[EPROC_PID..EPROC_PID + 8].copy_from_slice(&1234u64.to_le_bytes());
        eproc_page[EPROC_IMAGE_NAME..EPROC_IMAGE_NAME + 11].copy_from_slice(b"firefox.exe");

        let ptb = PageTableBuilder::new()
            .map_4k(table_vaddr, table_paddr, flags::WRITABLE)
            .map_4k(ep_vaddr, ep_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys(table_paddr, &table_page)
            .write_phys(ep_paddr, &ep_page)
            .write_phys(eproc_paddr, &eproc_page);

        let reader = make_net_reader(ptb);
        let results = walk_tcp_endpoints(&reader, table_vaddr, 1).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].protocol, "TCPv4");
        assert_eq!(results[0].local_addr, "10.0.0.1");
        assert_eq!(results[0].local_port, 54321);
        assert_eq!(results[0].remote_addr, "192.168.1.100");
        assert_eq!(results[0].remote_port, 443);
        assert_eq!(results[0].state, WinTcpState::Established);
        assert_eq!(results[0].pid, 1234);
        assert_eq!(results[0].process_name, "firefox.exe");
        assert_eq!(results[0].create_time, 132_800_000_000_000_000);
    }

    #[test]
    fn walk_empty_table() {
        let table_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let table_paddr: u64 = 0x0080_0000;

        let mut table_page = vec![0u8; 4096];

        // Two empty buckets: each Flink/Blink points to self
        let bucket0 = table_vaddr;
        let bucket1 = table_vaddr + 16;
        table_page[0..8].copy_from_slice(&bucket0.to_le_bytes());
        table_page[8..16].copy_from_slice(&bucket0.to_le_bytes());
        table_page[16..24].copy_from_slice(&bucket1.to_le_bytes());
        table_page[24..32].copy_from_slice(&bucket1.to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(table_vaddr, table_paddr, flags::WRITABLE)
            .write_phys(table_paddr, &table_page);

        let reader = make_net_reader(ptb);
        let results = walk_tcp_endpoints(&reader, table_vaddr, 2).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn walk_chain_within_bucket() {
        // Two endpoints in the same hash bucket chain
        let table_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let table_paddr: u64 = 0x0080_0000;
        let ep1_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let ep1_paddr: u64 = 0x0080_1000;
        let ep2_vaddr: u64 = 0xFFFF_8000_0010_2000;
        let ep2_paddr: u64 = 0x0080_2000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_3000;
        let eproc_paddr: u64 = 0x0080_3000;

        let mut table_page = vec![0u8; 4096];
        let mut ep1_page = vec![0u8; 4096];
        let mut ep2_page = vec![0u8; 4096];
        let mut eproc_page = vec![0u8; 4096];

        // Address info for EP1 and EP2 (packed onto table page)
        let ai1_vaddr = table_vaddr + 0x100;
        let la1_vaddr = table_vaddr + 0x200;
        let ip1_vaddr = table_vaddr + 0x300;
        let ai2_vaddr = table_vaddr + 0x400;
        let la2_vaddr = table_vaddr + 0x500;
        let ip2_vaddr = table_vaddr + 0x600;

        let bucket0 = table_vaddr;
        let ep1_hash = ep1_vaddr + EP_HASH_ENTRY as u64;
        let ep2_hash = ep2_vaddr + EP_HASH_ENTRY as u64;

        // Bucket[0]: Flink -> ep1.HashEntry, Blink -> ep2.HashEntry
        table_page[0..8].copy_from_slice(&ep1_hash.to_le_bytes());
        table_page[8..16].copy_from_slice(&ep2_hash.to_le_bytes());

        // EP1 addr info: remote 192.168.1.100, local 10.0.0.1
        write_addr_info(
            &mut table_page,
            0x100,
            la1_vaddr,
            [192, 168, 1, 100],
            0x200,
            ip1_vaddr,
            0x300,
            [10, 0, 0, 1],
        );

        // EP2 addr info: remote 10.20.30.40, local 172.16.0.1
        write_addr_info(
            &mut table_page,
            0x400,
            la2_vaddr,
            [10, 20, 30, 40],
            0x500,
            ip2_vaddr,
            0x600,
            [172, 16, 0, 1],
        );

        // EP1: chain -> ep2 -> bucket0
        write_endpoint(
            &mut ep1_page,
            0,
            ep2_hash,  // Flink -> ep2.HashEntry
            bucket0,   // Blink -> bucket head
            5,         // ESTABLISHED
            8080,
            443,
            ai1_vaddr,
            eproc_vaddr,
            132_800_000_000_000_000,
        );

        // EP2: chain -> bucket0 (end)
        write_endpoint(
            &mut ep2_page,
            0,
            bucket0,   // Flink -> bucket head (end of chain)
            ep1_hash,  // Blink -> ep1.HashEntry
            2,         // LISTEN
            3389,
            0,
            ai2_vaddr,
            eproc_vaddr,
            132_800_000_000_000_000,
        );

        // Owner _EPROCESS
        eproc_page[EPROC_PID..EPROC_PID + 8].copy_from_slice(&4u64.to_le_bytes());
        eproc_page[EPROC_IMAGE_NAME..EPROC_IMAGE_NAME + 6].copy_from_slice(b"System");

        let ptb = PageTableBuilder::new()
            .map_4k(table_vaddr, table_paddr, flags::WRITABLE)
            .map_4k(ep1_vaddr, ep1_paddr, flags::WRITABLE)
            .map_4k(ep2_vaddr, ep2_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys(table_paddr, &table_page)
            .write_phys(ep1_paddr, &ep1_page)
            .write_phys(ep2_paddr, &ep2_page)
            .write_phys(eproc_paddr, &eproc_page);

        let reader = make_net_reader(ptb);
        let results = walk_tcp_endpoints(&reader, table_vaddr, 1).unwrap();

        assert_eq!(results.len(), 2);

        // EP1: ESTABLISHED, 10.0.0.1:8080 -> 192.168.1.100:443
        assert_eq!(results[0].local_addr, "10.0.0.1");
        assert_eq!(results[0].local_port, 8080);
        assert_eq!(results[0].remote_addr, "192.168.1.100");
        assert_eq!(results[0].remote_port, 443);
        assert_eq!(results[0].state, WinTcpState::Established);

        // EP2: LISTEN on 172.16.0.1:3389
        assert_eq!(results[1].local_addr, "172.16.0.1");
        assert_eq!(results[1].local_port, 3389);
        assert_eq!(results[1].state, WinTcpState::Listen);
        assert_eq!(results[1].pid, 4);
        assert_eq!(results[1].process_name, "System");
    }

    #[test]
    fn walk_multiple_buckets() {
        // One endpoint in each of two buckets
        let table_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let table_paddr: u64 = 0x0080_0000;
        let ep1_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let ep1_paddr: u64 = 0x0080_1000;
        let ep2_vaddr: u64 = 0xFFFF_8000_0010_2000;
        let ep2_paddr: u64 = 0x0080_2000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0010_3000;
        let eproc_paddr: u64 = 0x0080_3000;

        let mut table_page = vec![0u8; 4096];
        let mut ep1_page = vec![0u8; 4096];
        let mut ep2_page = vec![0u8; 4096];
        let mut eproc_page = vec![0u8; 4096];

        let ai1_vaddr = table_vaddr + 0x100;
        let la1_vaddr = table_vaddr + 0x200;
        let ip1_vaddr = table_vaddr + 0x280;
        let ai2_vaddr = table_vaddr + 0x300;
        let la2_vaddr = table_vaddr + 0x400;
        let ip2_vaddr = table_vaddr + 0x480;

        let bucket0 = table_vaddr;
        let bucket1 = table_vaddr + 16;
        let ep1_hash = ep1_vaddr + EP_HASH_ENTRY as u64;
        let ep2_hash = ep2_vaddr + EP_HASH_ENTRY as u64;

        // Bucket[0] -> ep1, Bucket[1] -> ep2
        table_page[0..8].copy_from_slice(&ep1_hash.to_le_bytes());
        table_page[8..16].copy_from_slice(&ep1_hash.to_le_bytes());
        table_page[16..24].copy_from_slice(&ep2_hash.to_le_bytes());
        table_page[24..32].copy_from_slice(&ep2_hash.to_le_bytes());

        // Addr info for EP1
        write_addr_info(
            &mut table_page,
            0x100,
            la1_vaddr,
            [8, 8, 8, 8],
            0x200,
            ip1_vaddr,
            0x280,
            [127, 0, 0, 1],
        );

        // Addr info for EP2
        write_addr_info(
            &mut table_page,
            0x300,
            la2_vaddr,
            [1, 1, 1, 1],
            0x400,
            ip2_vaddr,
            0x480,
            [0, 0, 0, 0],
        );

        // EP1 in bucket 0
        write_endpoint(
            &mut ep1_page,
            0,
            bucket0,
            bucket0,
            5,    // ESTABLISHED
            12345,
            53,
            ai1_vaddr,
            eproc_vaddr,
            132_800_000_000_000_000,
        );

        // EP2 in bucket 1
        write_endpoint(
            &mut ep2_page,
            0,
            bucket1,
            bucket1,
            2, // LISTEN
            80,
            0,
            ai2_vaddr,
            eproc_vaddr,
            132_800_000_000_000_000,
        );

        // _EPROCESS
        eproc_page[EPROC_PID..EPROC_PID + 8].copy_from_slice(&7777u64.to_le_bytes());
        eproc_page[EPROC_IMAGE_NAME..EPROC_IMAGE_NAME + 8].copy_from_slice(b"nginx.ex");

        let ptb = PageTableBuilder::new()
            .map_4k(table_vaddr, table_paddr, flags::WRITABLE)
            .map_4k(ep1_vaddr, ep1_paddr, flags::WRITABLE)
            .map_4k(ep2_vaddr, ep2_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .write_phys(table_paddr, &table_page)
            .write_phys(ep1_paddr, &ep1_page)
            .write_phys(ep2_paddr, &ep2_page)
            .write_phys(eproc_paddr, &eproc_page);

        let reader = make_net_reader(ptb);
        let results = walk_tcp_endpoints(&reader, table_vaddr, 2).unwrap();

        assert_eq!(results.len(), 2);
        // EP1 from bucket 0
        assert_eq!(results[0].local_addr, "127.0.0.1");
        assert_eq!(results[0].remote_addr, "8.8.8.8");
        assert_eq!(results[0].local_port, 12345);
        assert_eq!(results[0].remote_port, 53);
        // EP2 from bucket 1
        assert_eq!(results[1].local_addr, "0.0.0.0");
        assert_eq!(results[1].local_port, 80);
        assert_eq!(results[1].state, WinTcpState::Listen);
    }
}
