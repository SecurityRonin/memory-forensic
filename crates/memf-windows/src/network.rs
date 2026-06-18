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
        .ok_or_else(|| crate::Error::MissingField {
            struct_name: "_TCP_ENDPOINT".into(),
            field_name: "HashEntry".into(),
        })?;

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
        offset: ep_addr,
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
    addresses_from_addr_info(reader, addr_info)
}

/// Resolve (local, remote) IPv4 from an `_ADDR_INFO` virtual address.
fn addresses_from_addr_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    addr_info: u64,
) -> Result<(String, String)> {
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
            let raw = bytes.try_into().map_or(0, u32::from_le_bytes);
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
    owner_info(reader, owner)
}

/// Resolve (pid, process name) from an owning `_EPROCESS` virtual address.
fn owner_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    owner: u64,
) -> Result<(u64, String)> {
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

/// `_TCP_ENDPOINT` pool tag.
const TCPE_TAG: &[u8; 4] = b"TcpE";
/// Candidate `_TCP_ENDPOINT` start offsets relative to the pool block base.
const TCPE_DELTAS: &[u64] = &[0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x80];
/// Physical scan chunk.
const SCAN_CHUNK: usize = 1 << 20;

/// True for a canonical x64 kernel-half virtual address.
fn is_kernel_va(x: u64) -> bool {
    (x >> 48) == 0xFFFF && ((x >> 40) & 0xFF) >= 0xF8
}

/// Enumerate active TCP connections by **physically pool-tag scanning** for
/// `_TCP_ENDPOINT` objects (`TcpE`), independent of the tcpip partition/hash
/// table layout (which is version-specific). Each object's own fields are read
/// from its physical location; the `AddrInfo` and `Owner` pointers are followed
/// through the address space.
///
/// Returns an empty vec when the tcpip `_TCP_ENDPOINT` schema is unavailable.
///
/// # Errors
/// Propagates address-space read failures encountered while following pointers.
pub fn scan_tcp_endpoints<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<WinConnectionInfo>> {
    let syms = reader.symbols();
    let off = |s: &str| syms.field_offset("_TCP_ENDPOINT", s);
    let (Some(state_o), Some(lp_o), Some(rp_o), Some(ai_o), Some(ow_o)) = (
        off("State"),
        off("LocalPort"),
        off("RemotePort"),
        off("AddrInfo"),
        off("Owner"),
    ) else {
        return Ok(Vec::new());
    };
    let ct_o = off("CreateTime").unwrap_or(0);
    let prov = reader.vas().physical();

    let ranges: Vec<(u64, u64)> = {
        let r = prov.ranges();
        if r.is_empty() {
            vec![(0, prov.total_size())]
        } else {
            r.iter().map(|x| (x.start, x.end)).collect()
        }
    };

    let read_phys_u = |pa: u64, n: usize| -> Option<u64> {
        let mut b = [0u8; 8];
        if prov.read_phys(pa, &mut b[..n]).unwrap_or(0) < n {
            return None;
        }
        Some(u64::from_le_bytes(b))
    };

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut buf = vec![0u8; SCAN_CHUNK + 4];
    for (start, end) in ranges {
        let mut addr = start;
        while addr < end {
            let n = prov.read_phys(addr, &mut buf).unwrap_or(0);
            if n < 4 {
                addr = addr.saturating_add(SCAN_CHUNK as u64);
                continue;
            }
            let mut i = 0usize;
            while i + 4 <= n {
                if &buf[i..i + 4] != TCPE_TAG {
                    i += 1;
                    continue;
                }
                let pool_base = (addr + i as u64).saturating_sub(4);
                i += 1;
                for &delta in TCPE_DELTAS {
                    let ep = pool_base + delta;
                    // State gate: a real endpoint has a small MIB_TCP_STATE value.
                    let Some(state_raw) = read_phys_u(ep + state_o, 4) else {
                        continue;
                    };
                    if state_raw == 0 || state_raw > 12 {
                        continue;
                    }
                    // AddrInfo / Owner must be kernel pointers for a live endpoint.
                    let (Some(ai), Some(owner)) =
                        (read_phys_u(ep + ai_o, 8), read_phys_u(ep + ow_o, 8))
                    else {
                        continue;
                    };
                    if !is_kernel_va(ai) || !is_kernel_va(owner) {
                        continue;
                    }
                    let local_port =
                        read_phys_u(ep + lp_o, 2).map_or(0, |v| u16::from_be(v as u16));
                    let remote_port =
                        read_phys_u(ep + rp_o, 2).map_or(0, |v| u16::from_be(v as u16));
                    let Ok((local_addr, remote_addr)) = addresses_from_addr_info(reader, ai) else {
                        continue;
                    };
                    let (pid, process_name) =
                        owner_info(reader, owner).unwrap_or((0, "<unknown>".to_string()));
                    let create_time = read_phys_u(ep + ct_o, 8).unwrap_or(0);
                    // Dedup on the 4-tuple.
                    let key = (
                        local_addr.clone(),
                        local_port,
                        remote_addr.clone(),
                        remote_port,
                    );
                    if !seen.insert(key) {
                        continue;
                    }
                    out.push(WinConnectionInfo {
                        protocol: "TCPv4".to_string(),
                        local_addr,
                        local_port,
                        remote_addr,
                        remote_port,
                        state: WinTcpState::from_raw(state_raw as u32),
                        pid,
                        process_name,
                        create_time,
                        offset: ep,
                    });
                    break;
                }
            }
            addr = addr.saturating_add(SCAN_CHUNK as u64 - 4);
        }
    }
    Ok(out)
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
        let isf = net_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    fn net_isf() -> serde_json::Value {
        IsfBuilder::new()
            // _LIST_ENTRY
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer")
            // _TCP_ENDPOINT
            .add_struct("_TCP_ENDPOINT", 128)
            .add_field("_TCP_ENDPOINT", "AddrInfo", EP_ADDR_INFO as u64, "pointer")
            .add_field("_TCP_ENDPOINT", "Owner", EP_OWNER as u64, "pointer")
            .add_field(
                "_TCP_ENDPOINT",
                "CreateTime",
                EP_CREATE_TIME as u64,
                "unsigned long long",
            )
            .add_field(
                "_TCP_ENDPOINT",
                "HashEntry",
                EP_HASH_ENTRY as u64,
                "_LIST_ENTRY",
            )
            .add_field("_TCP_ENDPOINT", "State", EP_STATE as u64, "unsigned long")
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
            // _ADDR_INFO
            .add_struct("_ADDR_INFO", 32)
            .add_field("_ADDR_INFO", "Local", AI_LOCAL as u64, "pointer")
            .add_field("_ADDR_INFO", "Remote", AI_REMOTE as u64, "unsigned long")
            // _LOCAL_ADDRESS
            .add_struct("_LOCAL_ADDRESS", 32)
            .add_field("_LOCAL_ADDRESS", "pData", LA_PDATA as u64, "pointer")
            // _EPROCESS
            .add_struct("_EPROCESS", 1536)
            .add_field(
                "_EPROCESS",
                "UniqueProcessId",
                EPROC_PID as u64,
                "unsigned long long",
            )
            .add_field(
                "_EPROCESS",
                "ImageFileName",
                EPROC_IMAGE_NAME as u64,
                "array",
            )
            .build_json()
    }

    /// Write a _TCP_ENDPOINT into a byte buffer at the given offset.
    // Test builder mirroring the _TCP_ENDPOINT fields; arity matches the struct.
    #[allow(clippy::too_many_arguments)]
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
        // AddrInfo
        buf[off + EP_ADDR_INFO..off + EP_ADDR_INFO + 8]
            .copy_from_slice(&addr_info_vaddr.to_le_bytes());
        // Owner
        buf[off + EP_OWNER..off + EP_OWNER + 8].copy_from_slice(&owner_vaddr.to_le_bytes());
        // CreateTime
        buf[off + EP_CREATE_TIME..off + EP_CREATE_TIME + 8]
            .copy_from_slice(&create_time.to_le_bytes());
        // HashEntry (LIST_ENTRY: Flink at +0, Blink at +8)
        buf[off + EP_HASH_ENTRY..off + EP_HASH_ENTRY + 8]
            .copy_from_slice(&hash_flink.to_le_bytes());
        buf[off + EP_HASH_ENTRY + 8..off + EP_HASH_ENTRY + 16]
            .copy_from_slice(&hash_blink.to_le_bytes());
        // State
        buf[off + EP_STATE..off + EP_STATE + 4].copy_from_slice(&state.to_le_bytes());
        // LocalPort (big-endian on wire, stored as BE u16)
        buf[off + EP_LOCAL_PORT..off + EP_LOCAL_PORT + 2]
            .copy_from_slice(&local_port.to_be_bytes());
        // RemotePort
        buf[off + EP_REMOTE_PORT..off + EP_REMOTE_PORT + 2]
            .copy_from_slice(&remote_port.to_be_bytes());
    }

    /// Write _ADDR_INFO + _LOCAL_ADDRESS + IPv4 data into a byte buffer.
    /// Returns nothing; caller provides the offsets.
    // Test builder mirroring the _ADDR_INFO/_LOCAL_ADDRESS layout; arity matches the structs.
    #[allow(clippy::too_many_arguments)]
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

    /// Single bucket with one endpoint — verifies the basic happy path.
    #[test]
    fn walk_single_endpoint() {
        // Layout:
        //   TABLE_VADDR: bucket[0] _LIST_ENTRY { Flink=HASH_ENTRY_VADDR, Blink=HASH_ENTRY_VADDR }
        //   EP_PAGE_VADDR: _TCP_ENDPOINT (HASH_ENTRY at EP_HASH_ENTRY offset)
        //   AI_PAGE_VADDR: _ADDR_INFO { Local=LA_VADDR, Remote=10.0.0.2 }
        //   LA_PAGE_VADDR: _LOCAL_ADDRESS { pData=IPV4_VADDR }
        //   IPV4_PAGE_VADDR: raw 4 bytes of 10.0.0.1
        //   EPROC_PAGE_VADDR: _EPROCESS { pid=1234, name="svchost.exe" }

        const TABLE_VADDR: u64 = 0xFFFF_8000_0001_0000;
        const TABLE_PADDR: u64 = 0x0001_0000;
        const EP_PAGE_VADDR: u64 = 0xFFFF_8000_0002_0000;
        const EP_PAGE_PADDR: u64 = 0x0002_0000;
        const AI_PAGE_VADDR: u64 = 0xFFFF_8000_0003_0000;
        const AI_PAGE_PADDR: u64 = 0x0003_0000;
        const LA_PAGE_VADDR: u64 = 0xFFFF_8000_0004_0000;
        const LA_PAGE_PADDR: u64 = 0x0004_0000;
        const IPV4_VADDR: u64 = 0xFFFF_8000_0005_0000;
        const IPV4_PADDR: u64 = 0x0005_0000;
        const EPROC_VADDR: u64 = 0xFFFF_8000_0006_0000;
        const EPROC_PADDR: u64 = 0x0006_0000;

        // The endpoint's HashEntry lives at EP_PAGE_VADDR + EP_HASH_ENTRY.
        // The bucket Flink points to that HashEntry address.
        let hash_entry_vaddr = EP_PAGE_VADDR + EP_HASH_ENTRY as u64;

        let mut table_page = vec![0u8; 4096];
        // bucket[0]: Flink = hash_entry_vaddr, Blink = hash_entry_vaddr
        table_page[0..8].copy_from_slice(&hash_entry_vaddr.to_le_bytes());
        table_page[8..16].copy_from_slice(&hash_entry_vaddr.to_le_bytes());

        let mut ep_page = vec![0u8; 4096];
        // HashEntry.Flink = TABLE_VADDR (terminates), Blink = TABLE_VADDR
        write_endpoint(
            &mut ep_page,
            0,
            TABLE_VADDR,   // hash_flink  (points back to bucket head → terminates)
            TABLE_VADDR,   // hash_blink
            2,             // state = ESTABLISHED
            80,            // local_port
            54321,         // remote_port
            AI_PAGE_VADDR, // addr_info
            EPROC_VADDR,   // owner
            0xABCD_1234,   // create_time
        );

        let mut ai_page = vec![0u8; 4096];
        write_addr_info(
            &mut ai_page,
            0,             // ai_off
            LA_PAGE_VADDR, // local_addr_vaddr
            [10, 0, 0, 2], // remote IPv4
            0,             // la_off (same page, offset 0 is repurposed — use LA_PAGE)
            IPV4_VADDR,    // ipv4_data_vaddr
            0,             // ipv4_off (relative to IPV4_VADDR page)
            [10, 0, 0, 1], // local IPv4
        );
        // Fix la_off: _LOCAL_ADDRESS is in LA_PAGE, write pData there
        // write_addr_info already writes to la_off=0 within ai_page, which is wrong for LA.
        // We need to write LA_PAGE separately:
        let mut la_page = vec![0u8; 4096];
        la_page[LA_PDATA..LA_PDATA + 8].copy_from_slice(&IPV4_VADDR.to_le_bytes());

        let mut ipv4_page = vec![0u8; 4096];
        ipv4_page[0..4].copy_from_slice(&[10, 0, 0, 1]); // local IP raw bytes

        let mut eproc_page = vec![0u8; 4096];
        eproc_page[EPROC_PID..EPROC_PID + 8].copy_from_slice(&1234u64.to_le_bytes());
        let name = b"svchost.exe\0\0\0\0";
        eproc_page[EPROC_IMAGE_NAME..EPROC_IMAGE_NAME + name.len()].copy_from_slice(name);

        // Fix ai_page: write _ADDR_INFO correctly
        // AI_LOCAL=0x0: local_addr_ptr = LA_PAGE_VADDR
        let mut ai_page2 = vec![0u8; 4096];
        ai_page2[AI_LOCAL..AI_LOCAL + 8].copy_from_slice(&LA_PAGE_VADDR.to_le_bytes());
        // AI_REMOTE=0x10: remote IPv4 as u32 LE
        ai_page2[AI_REMOTE..AI_REMOTE + 4]
            .copy_from_slice(&u32::from_le_bytes([10, 0, 0, 2]).to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(TABLE_VADDR, TABLE_PADDR, flags::WRITABLE)
            .write_phys(TABLE_PADDR, &table_page)
            .map_4k(EP_PAGE_VADDR, EP_PAGE_PADDR, flags::WRITABLE)
            .write_phys(EP_PAGE_PADDR, &ep_page)
            .map_4k(AI_PAGE_VADDR, AI_PAGE_PADDR, flags::WRITABLE)
            .write_phys(AI_PAGE_PADDR, &ai_page2)
            .map_4k(LA_PAGE_VADDR, LA_PAGE_PADDR, flags::WRITABLE)
            .write_phys(LA_PAGE_PADDR, &la_page)
            .map_4k(IPV4_VADDR, IPV4_PADDR, flags::WRITABLE)
            .write_phys(IPV4_PADDR, &ipv4_page)
            .map_4k(EPROC_VADDR, EPROC_PADDR, flags::WRITABLE)
            .write_phys(EPROC_PADDR, &eproc_page);

        let reader = make_net_reader(ptb);
        let conns = walk_tcp_endpoints(&reader, TABLE_VADDR, 1).unwrap();
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].local_addr, "10.0.0.1");
        assert_eq!(conns[0].remote_addr, "10.0.0.2");
        assert_eq!(conns[0].local_port, 80);
        assert_eq!(conns[0].remote_port, 54321);
        assert_eq!(conns[0].pid, 1234);
        assert_eq!(conns[0].process_name, "svchost.exe");
    }

    /// Empty bucket (Flink == bucket_addr) returns no connections.
    #[test]
    fn walk_empty_table() {
        const TABLE_VADDR: u64 = 0xFFFF_8000_0010_0000;
        const TABLE_PADDR: u64 = 0x0010_0000;

        let mut table_page = vec![0u8; 4096];
        // bucket[0]: Flink = TABLE_VADDR (self-referential → empty)
        table_page[0..8].copy_from_slice(&TABLE_VADDR.to_le_bytes());
        table_page[8..16].copy_from_slice(&TABLE_VADDR.to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(TABLE_VADDR, TABLE_PADDR, flags::WRITABLE)
            .write_phys(TABLE_PADDR, &table_page);
        let reader = make_net_reader(ptb);
        let conns = walk_tcp_endpoints(&reader, TABLE_VADDR, 1).unwrap();
        assert!(conns.is_empty());
    }

    /// Two endpoints chained in the same bucket — verifies chain walking.
    #[test]
    fn walk_chain_within_bucket() {
        const TABLE_VADDR: u64 = 0xFFFF_8000_0020_0000;
        const TABLE_PADDR: u64 = 0x0020_0000;
        const EP1_VADDR: u64 = 0xFFFF_8000_0021_0000;
        const EP1_PADDR: u64 = 0x0021_0000;
        const EP2_VADDR: u64 = 0xFFFF_8000_0022_0000;
        const EP2_PADDR: u64 = 0x0022_0000;

        let ep1_hash = EP1_VADDR + EP_HASH_ENTRY as u64;
        let ep2_hash = EP2_VADDR + EP_HASH_ENTRY as u64;

        let mut table_page = vec![0u8; 4096];
        // bucket[0]: Flink = ep1_hash
        table_page[0..8].copy_from_slice(&ep1_hash.to_le_bytes());
        table_page[8..16].copy_from_slice(&ep2_hash.to_le_bytes());

        let mut ep1_page = vec![0u8; 4096];
        // HashEntry.Flink = ep2_hash (points to ep2), Blink = TABLE_VADDR
        write_endpoint(
            &mut ep1_page,
            0,
            ep2_hash,
            TABLE_VADDR,
            2,
            443,
            12345,
            0,
            0,
            0,
        );

        let mut ep2_page = vec![0u8; 4096];
        // HashEntry.Flink = TABLE_VADDR (terminates), Blink = ep1_hash
        write_endpoint(
            &mut ep2_page,
            0,
            TABLE_VADDR,
            ep1_hash,
            2,
            80,
            54321,
            0,
            0,
            0,
        );

        let ptb = PageTableBuilder::new()
            .map_4k(TABLE_VADDR, TABLE_PADDR, flags::WRITABLE)
            .write_phys(TABLE_PADDR, &table_page)
            .map_4k(EP1_VADDR, EP1_PADDR, flags::WRITABLE)
            .write_phys(EP1_PADDR, &ep1_page)
            .map_4k(EP2_VADDR, EP2_PADDR, flags::WRITABLE)
            .write_phys(EP2_PADDR, &ep2_page);
        let reader = make_net_reader(ptb);
        let conns = walk_tcp_endpoints(&reader, TABLE_VADDR, 1).unwrap();
        assert_eq!(conns.len(), 2);
        // Ports are returned in the order endpoints appear in the chain
        let ports: std::collections::HashSet<u16> = conns.iter().map(|c| c.local_port).collect();
        assert!(ports.contains(&443));
        assert!(ports.contains(&80));
    }

    /// Two buckets each with one endpoint — verifies multi-bucket iteration.
    #[test]
    fn walk_multiple_buckets() {
        const TABLE_VADDR: u64 = 0xFFFF_8000_0030_0000;
        const TABLE_PADDR: u64 = 0x0030_0000;
        const EP1_VADDR: u64 = 0xFFFF_8000_0031_0000;
        const EP1_PADDR: u64 = 0x0031_0000;
        const EP2_VADDR: u64 = 0xFFFF_8000_0032_0000;
        const EP2_PADDR: u64 = 0x0032_0000;

        let ep1_hash = EP1_VADDR + EP_HASH_ENTRY as u64;
        let ep2_hash = EP2_VADDR + EP_HASH_ENTRY as u64;

        let bucket0_addr = TABLE_VADDR;
        let bucket1_addr = TABLE_VADDR + 16;

        let mut table_page = vec![0u8; 4096];
        // bucket[0]: Flink = ep1_hash
        table_page[0..8].copy_from_slice(&ep1_hash.to_le_bytes());
        table_page[8..16].copy_from_slice(&ep1_hash.to_le_bytes());
        // bucket[1]: Flink = ep2_hash
        table_page[16..24].copy_from_slice(&ep2_hash.to_le_bytes());
        table_page[24..32].copy_from_slice(&ep2_hash.to_le_bytes());

        let mut ep1_page = vec![0u8; 4096];
        write_endpoint(
            &mut ep1_page,
            0,
            bucket0_addr,
            bucket0_addr,
            2,
            8080,
            0,
            0,
            0,
            0,
        );

        let mut ep2_page = vec![0u8; 4096];
        write_endpoint(
            &mut ep2_page,
            0,
            bucket1_addr,
            bucket1_addr,
            2,
            443,
            0,
            0,
            0,
            0,
        );

        let ptb = PageTableBuilder::new()
            .map_4k(TABLE_VADDR, TABLE_PADDR, flags::WRITABLE)
            .write_phys(TABLE_PADDR, &table_page)
            .map_4k(EP1_VADDR, EP1_PADDR, flags::WRITABLE)
            .write_phys(EP1_PADDR, &ep1_page)
            .map_4k(EP2_VADDR, EP2_PADDR, flags::WRITABLE)
            .write_phys(EP2_PADDR, &ep2_page);
        let reader = make_net_reader(ptb);
        let conns = walk_tcp_endpoints(&reader, TABLE_VADDR, 2).unwrap();
        assert_eq!(conns.len(), 2);
        let ports: std::collections::HashSet<u16> = conns.iter().map(|c| c.local_port).collect();
        assert!(ports.contains(&8080));
        assert!(ports.contains(&443));
    }

    // RED: missing _TCP_ENDPOINT.HashEntry field → MissingField
    #[test]
    fn walk_tcp_endpoints_missing_hash_entry_returns_missing_field() {
        let isf = IsfBuilder::new();
        let reader = memf_core::test_builders::make_reader(&isf);
        let result = walk_tcp_endpoints(&reader, 0, 1);
        assert!(
            matches!(
                result,
                Err(crate::Error::MissingField { ref struct_name, ref field_name })
                if struct_name == "_TCP_ENDPOINT" && field_name == "HashEntry"
            ),
            "expected MissingField(_TCP_ENDPOINT.HashEntry), got {result:?}"
        );
    }

    /// Wrap `SyntheticPhysMem` so it advertises a physical range (needed for the
    /// physical pool-tag scan; the builder's mem reports none).
    struct RangedMem {
        inner: SyntheticPhysMem,
        ranges: Vec<memf_format::PhysicalRange>,
    }
    impl PhysicalMemoryProvider for RangedMem {
        fn read_phys(&self, addr: u64, buf: &mut [u8]) -> memf_format::Result<usize> {
            self.inner.read_phys(addr, buf)
        }
        fn ranges(&self) -> &[memf_format::PhysicalRange] {
            &self.ranges
        }
        fn format_name(&self) -> &str {
            "RangedSynthetic"
        }
    }

    #[test]
    fn scan_tcp_endpoints_recovers_a_connection_from_a_tcpe_pool_object() {
        // VA-mapped pointer targets (kernel half so the is_kernel_va gate passes).
        let ai_va = 0xFFFF_F800_0200_0000u64;
        let la_va = 0xFFFF_F800_0200_1000u64;
        let pdata_va = 0xFFFF_F800_0200_2000u64;
        let ep_va = 0xFFFF_F800_0200_3000u64;
        let (pa_ai, pa_la, pa_pdata, pa_ep) = (0x60_000u64, 0x61_000, 0x62_000, 0x63_000);

        let mut ai = vec![0u8; 0x1000];
        ai[AI_REMOTE..AI_REMOTE + 4].copy_from_slice(&[1, 2, 3, 4]); // remote 1.2.3.4
        ai[AI_LOCAL..AI_LOCAL + 8].copy_from_slice(&la_va.to_le_bytes());
        let mut la = vec![0u8; 0x1000];
        la[LA_PDATA..LA_PDATA + 8].copy_from_slice(&pdata_va.to_le_bytes());
        let mut pdata = vec![0u8; 0x1000];
        pdata[0..4].copy_from_slice(&[10, 0, 0, 5]); // local 10.0.0.5
        let mut ep = vec![0u8; 0x1000];
        ep[EPROC_PID..EPROC_PID + 8].copy_from_slice(&1337u64.to_le_bytes());
        ep[EPROC_IMAGE_NAME..EPROC_IMAGE_NAME + 11].copy_from_slice(b"coreupdater");

        // The _TCP_ENDPOINT pool object, read PHYSICALLY by the scan.
        let tag_phys = 0x50_004u64;
        let ep_obj = 0x50_010u64; // pool_base(0x50000) + delta 0x10
        let mut obj = vec![0u8; 0x100];
        obj[(EP_STATE)..(EP_STATE + 4)].copy_from_slice(&5u32.to_le_bytes()); // ESTABLISHED
        obj[(EP_LOCAL_PORT)..(EP_LOCAL_PORT + 2)].copy_from_slice(&1234u16.to_be_bytes());
        obj[(EP_REMOTE_PORT)..(EP_REMOTE_PORT + 2)].copy_from_slice(&443u16.to_be_bytes());
        obj[(EP_ADDR_INFO)..(EP_ADDR_INFO + 8)].copy_from_slice(&ai_va.to_le_bytes());
        obj[(EP_OWNER)..(EP_OWNER + 8)].copy_from_slice(&ep_va.to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(ai_va, pa_ai, flags::WRITABLE)
            .map_4k(la_va, pa_la, flags::WRITABLE)
            .map_4k(pdata_va, pa_pdata, flags::WRITABLE)
            .map_4k(ep_va, pa_ep, flags::WRITABLE)
            .write_phys(pa_ai, &ai)
            .write_phys(pa_la, &la)
            .write_phys(pa_pdata, &pdata)
            .write_phys(pa_ep, &ep)
            .write_phys(tag_phys, b"TcpE")
            .write_phys(ep_obj, &obj);

        let resolver = IsfResolver::from_value(&net_isf()).unwrap();
        let (cr3, mem) = ptb.build();
        let ranged = RangedMem {
            inner: mem,
            ranges: vec![memf_format::PhysicalRange {
                start: 0,
                end: 16 * 1024 * 1024,
            }],
        };
        let reader = ObjectReader::new(
            VirtualAddressSpace::new(ranged, cr3, TranslationMode::X86_64FourLevel),
            Box::new(resolver),
        );

        let conns = scan_tcp_endpoints(&reader).expect("scan ok");
        assert_eq!(conns.len(), 1, "exactly one endpoint, got {conns:?}");
        let c = &conns[0];
        assert_eq!(c.remote_addr, "1.2.3.4");
        assert_eq!(c.remote_port, 443);
        assert_eq!(c.local_addr, "10.0.0.5");
        assert_eq!(c.local_port, 1234);
        assert_eq!(c.pid, 1337);
        assert_eq!(c.process_name, "coreupdater");
        assert_eq!(c.state, WinTcpState::Established);
    }
}
