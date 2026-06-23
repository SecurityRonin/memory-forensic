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

/// `_UDP_ENDPOINT` pool tag (Volatility netscan `UdpA`).
const UDPA_TAG: &[u8; 4] = b"UdpA";
/// Candidate `_UDP_ENDPOINT` start offsets relative to the pool block base.
const UDPA_DELTAS: &[u64] = &[0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x80];
/// Physical scan chunk.
const SCAN_CHUNK: usize = 1 << 20;

/// x64 `_TCP_ENDPOINT` / `_ADDRINFO` / `_LOCAL_ADDRESS` / `_INETAF` field offsets
/// for one Windows build. The public tcpip.pdb ships symbols but no struct
/// *types*, so these come from the Volatility 3 maintained overlays
/// `volatility3/framework/symbols/windows/netscan/netscan-*-x64.json`. The
/// Win8/8.1/10 family shares most offsets and differs only in `Owner`/`CreateTime`
/// (the struct grew over time); Win7 differs throughout, so every field is carried
/// explicitly. `create_time == 0` means the build has no `CreateTime` field.
#[derive(Clone, Copy)]
pub struct TcpEndpointLayout {
    /// Offset of `InetAF` (pointer to the address-family `_INETAF`) in `_TCP_ENDPOINT`.
    pub inet_af: u64,
    /// Offset of `AddrInfo` (pointer to `_ADDRINFO`) in `_TCP_ENDPOINT`.
    pub addr_info: u64,
    /// Offset of the connection `State` field in `_TCP_ENDPOINT`.
    pub state: u64,
    /// Offset of the local port in `_TCP_ENDPOINT`.
    pub local_port: u64,
    /// Offset of the remote port in `_TCP_ENDPOINT`.
    pub remote_port: u64,
    /// Offset of the owning-process pointer in `_TCP_ENDPOINT`.
    pub owner: u64,
    /// Offset of `CreateTime` in `_TCP_ENDPOINT`; `0` if the build has no such field.
    pub create_time: u64,
    /// Offset of `Local` (pointer to `_LOCAL_ADDRESS`) in `_ADDRINFO`.
    pub ai_local: u64,
    /// Offset of `Remote` (pointer to the remote address) in `_ADDRINFO`.
    pub ai_remote: u64,
    /// Offset of `pData` (pointer to the address bytes) in `_LOCAL_ADDRESS`.
    pub la_pdata: u64,
    /// Offset of the address family in `_INETAF`.
    pub inetaf_af: u64,
}

impl TcpEndpointLayout {
    /// Win8/8.1/10 family base: only `owner`/`create_time` move between builds.
    const fn modern(owner: u64, create_time: u64) -> Self {
        Self {
            inet_af: 0x10,
            addr_info: 0x18,
            state: 0x6C,
            local_port: 0x70,
            remote_port: 0x72,
            owner,
            create_time,
            ai_local: 0x0,
            ai_remote: 0x10,
            la_pdata: 0x10,
            inetaf_af: 0x18,
        }
    }
}

/// Select the `_TCP_ENDPOINT` layout for an NT `build` number (x64), mirroring
/// Volatility 3's `netscan` build→symbol-file table
/// (`volatility3/framework/plugins/windows/netscan.py`). Returns `None` for
/// builds with no maintained overlay — the caller then reports the build as
/// unsupported rather than reading at guessed offsets. Extend this table (a data
/// update, not an algorithm change) when a new build's overlay is published.
fn tcp_endpoint_layout_x64(build: u32) -> Option<TcpEndpointLayout> {
    Some(match build {
        // Win7: _TCP_ENDPOINT differs throughout (netscan-win7-x64).
        7600 | 7601 | 8400 => TcpEndpointLayout {
            inet_af: 0x18,
            addr_info: 0x20,
            state: 0x68,
            local_port: 0x6C,
            remote_port: 0x6E,
            owner: 0x238,
            create_time: 0x0,
            ai_local: 0x0,
            ai_remote: 0x10,
            la_pdata: 0x10,
            inetaf_af: 0x14,
        },
        9200 => TcpEndpointLayout::modern(0x250, 0x0), // Win8 / Server 2012
        9600 => TcpEndpointLayout::modern(0x258, 0x0), // Win8.1 / Server 2012 R2
        10240 | 10586 | 14393 => TcpEndpointLayout::modern(0x258, 0x268), // Win10 / Server 2016
        15063 => TcpEndpointLayout::modern(0x270, 0x268),
        16299 => TcpEndpointLayout::modern(0x270, 0x280),
        17134 => TcpEndpointLayout::modern(0x278, 0x288),
        17763 => TcpEndpointLayout::modern(0x2C8, 0x2D8),
        18362 | 18363 => TcpEndpointLayout::modern(0x290, 0x2A0),
        19041 => TcpEndpointLayout::modern(0x2D8, 0x2E8),
        20348 => TcpEndpointLayout::modern(0x2F0, 0x308), // Server 2022
        _ => return None,
    })
}

/// `AF_INET`.
const AF_INET: u16 = 2;

/// Read the OS build number from the `NtBuildNumber` kernel global (its low 16
/// bits hold the build; the high bits are checked/free-build flags). Validated
/// on citadeldc01.mem: reads `0xF0002580` -> build `9600` (Server 2012 R2),
/// cross-checked against the kernel `NtBuildLab` string (`9600.winblue_gdr…`).
///
/// (The fixed-VA `_KUSER_SHARED_DATA.NtBuildNumber` field was found unreliable —
/// it read 0 on that dump — so the kernel symbol is the source of truth.)
pub(crate) fn nt_build_number<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>) -> Option<u32> {
    // Exact when the kernel symbol resolves.
    if let Some(va) = reader.symbols().symbol_address("NtBuildNumber") {
        if let Some(raw) = read_phys_u_via(reader, va, 4) {
            let build = (raw as u32) & 0xFFFF;
            if build >= 2600 {
                return Some(build);
            }
        }
    }
    // Symbol-free fallback: scan for the NtBuildLab string. Un-gates overlay
    // selection on dumps where kernel-symbol resolution failed (e.g. the
    // Szechuan workstation, build 19041).
    scan_build_from_buildlab(reader.vas().physical())
}

/// Architecture tokens that anchor an `NtBuildLab` string in raw memory.
const BUILDLAB_ANCHORS: [&[u8]; 3] = [b"amd64fre", b"x86fre", b"arm64fre"];

/// Parse the NT build number from an `NtBuildLab` fragment whose leading dotted
/// field is the build (e.g. "19041.1.amd64fre.vb_release.191206-1406", or just
/// the "19041.1." prefix). Tolerates a non-digit prefix picked up by a raw scan;
/// rejects values below the NT build floor (2600) as noise.
fn build_from_buildlab(lab: &str) -> Option<u32> {
    let first = lab.split('.').next()?;
    let start = first.find(|c: char| c.is_ascii_digit())?;
    let digits: String = first[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    let build: u32 = digits.parse().ok()?;
    (build >= 2600).then_some(build)
}

/// Overlap the scan read window so an anchor straddling a chunk boundary — plus
/// the short "<build>.<rev>." prefix in front of it — stays within one buffer.
const BUILDLAB_OVERLAP: usize = 32;

/// Symbol-free OS build detection: physically scan for an `NtBuildLab`-style
/// string (anchored on its architecture token) and parse the build number. The
/// fallback used when `NtBuildNumber` symbol resolution is unavailable on a dump.
fn scan_build_from_buildlab<P: PhysicalMemoryProvider>(prov: &P) -> Option<u32> {
    let ranges: Vec<(u64, u64)> = {
        let r = prov.ranges();
        if r.is_empty() {
            vec![(0, prov.total_size())]
        } else {
            r.iter().map(|x| (x.start, x.end)).collect()
        }
    };
    let mut buf = vec![0u8; SCAN_CHUNK + BUILDLAB_OVERLAP];
    for (start, end) in ranges {
        let mut addr = start;
        while addr < end {
            let n = prov.read_phys(addr, &mut buf).unwrap_or(0);
            if n == 0 {
                addr = addr.saturating_add(SCAN_CHUNK as u64);
                continue;
            }
            for anchor in BUILDLAB_ANCHORS {
                let mut from = 0usize;
                while from + anchor.len() <= n {
                    let Some(rel) = buf[from..n].windows(anchor.len()).position(|w| w == anchor)
                    else {
                        break;
                    };
                    let i = from + rel;
                    // Backtrack over the graphic-ASCII "<build>.<rev>." prefix.
                    let lo = i.saturating_sub(24);
                    let mut s = i;
                    while s > lo && buf[s - 1].is_ascii_graphic() {
                        s -= 1;
                    }
                    let frag = String::from_utf8_lossy(&buf[s..i]);
                    if let Some(build) = build_from_buildlab(&frag) {
                        return Some(build);
                    }
                    from = i + 1;
                }
            }
            addr = addr.saturating_add(SCAN_CHUNK as u64);
        }
    }
    None
}

/// `_EPROCESS` (`UniqueProcessId`, `ImageFileName`) byte offsets, preferring the
/// typed kernel ISF (which covers every build) and falling back to a per-build
/// table only for symbol-free dumps. Extend the table per build validated
/// against a real image; the legacy default is kept solely so pre-existing
/// symbol-free flows do not regress.
fn eprocess_offsets<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, build: u32) -> (u64, u64) {
    let syms = reader.symbols();
    // Per-build fallback used only when the ISF lacks the field (symbol-free
    // dumps); the typed ISF, when present, covers every build.
    let (fb_pid, fb_name) = match build {
        // Win10 2004/20H1 — validated against the Szechuan workstation dump.
        19041 => (0x440, 0x5A8),
        // Legacy default, kept so pre-existing symbol-free flows don't regress.
        _ => (0x2E0, 0x450),
    };
    (
        syms.field_offset("_EPROCESS", "UniqueProcessId")
            .unwrap_or(fb_pid),
        syms.field_offset("_EPROCESS", "ImageFileName")
            .unwrap_or(fb_name),
    )
}

/// True for a canonical x64 kernel-half virtual address (bits 47..63 all set,
/// i.e. `>= 0xFFFF_8000_0000_0000`). Pool pointers live across the whole kernel
/// half, not only the `0xFFFF_F8…` ntoskrnl band.
fn is_kernel_va(x: u64) -> bool {
    (x >> 47) == 0x1_FFFF
}

/// Map the in-memory `_TCP_ENDPOINT.State` (`TCPStateEnum`, 0-based) to
/// [`WinTcpState`]. This is NOT the 1-based `MIB_TCP_STATE` that
/// [`WinTcpState::from_raw`] decodes.
fn tcp_state_from_enum(v: u32) -> WinTcpState {
    match v {
        0 => WinTcpState::Closed,
        1 => WinTcpState::Listen,
        2 => WinTcpState::SynSent,
        3 => WinTcpState::SynReceived,
        4 => WinTcpState::Established,
        5 => WinTcpState::FinWait1,
        6 => WinTcpState::FinWait2,
        7 => WinTcpState::CloseWait,
        8 => WinTcpState::Closing,
        9 => WinTcpState::LastAck,
        12 => WinTcpState::TimeWait,
        other => WinTcpState::Unknown(other),
    }
}

/// Enumerate active TCP connections by **physically pool-tag scanning** for
/// `_TCP_ENDPOINT` objects (`TcpE`), independent of the tcpip partition/hash
/// table layout (which is version-specific). Each object's own fields are read
/// from its physical location; `AddrInfo`/`Owner`/`InetAF` pointers are followed
/// through the address space. The `_TCP_ENDPOINT` overlay is selected from the
/// dump's `NtBuildNumber`; an unrecognized build yields an empty result (no
/// guessed offsets).
///
/// # Errors
/// Propagates address-space read failures encountered while following pointers.
pub fn scan_tcp_endpoints<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<WinConnectionInfo>> {
    let Some(build) = nt_build_number(reader) else {
        return Ok(Vec::new());
    };
    let Some(t) = tcp_endpoint_layout_x64(build) else {
        return Ok(Vec::new());
    };
    // `_EPROCESS` offsets: typed ISF when present, else a per-build fallback.
    let (pid_off, name_off) = eprocess_offsets(reader, build);
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
    // Read a pointer-sized value from a virtual address (follows transition PTEs).
    let read_virt_u64 = |va: u64| -> Option<u64> {
        reader
            .read_bytes(va, 8)
            .ok()
            .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8])))
    };
    let read_ipv4 = |va: u64| -> Option<String> {
        reader
            .read_bytes(va, 4)
            .ok()
            .map(|b| format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
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
                    // State gate: a valid TCPStateEnum value (0..=12).
                    let Some(state_raw) = read_phys_u(ep + t.state, 4) else {
                        continue;
                    };
                    if state_raw > 12 {
                        continue;
                    }
                    // AddrInfo / Owner / InetAF must be kernel pointers.
                    let (Some(ai), Some(owner), Some(inetaf)) = (
                        read_phys_u(ep + t.addr_info, 8),
                        read_phys_u(ep + t.owner, 8),
                        read_phys_u(ep + t.inet_af, 8),
                    ) else {
                        continue;
                    };
                    if !is_kernel_va(ai) || !is_kernel_va(inetaf) {
                        continue;
                    }
                    // Address family must be AF_INET (this walker emits IPv4).
                    let Some(af) = read_phys_u_via(reader, inetaf + t.inetaf_af, 2) else {
                        continue;
                    };
                    if af as u16 != AF_INET {
                        continue;
                    }
                    // Owner is OPTIONAL: ownerless endpoints (system / transient,
                    // e.g. an established socket with no live owning process) carry
                    // Owner == 0 and are valid connections. A non-zero Owner that
                    // isn't a kernel pointer is a false-positive candidate; a
                    // kernel-pointer Owner must yield a plausible PID.
                    let (pid, process_name) = if owner == 0 {
                        (0, String::new())
                    } else if is_kernel_va(owner) {
                        let Some(p) = read_virt_u64(owner + pid_off) else {
                            continue;
                        };
                        if p > 0xFFFF {
                            continue;
                        }
                        let name = reader
                            .read_bytes(owner + name_off, 15)
                            .map(|b| {
                                String::from_utf8_lossy(&b)
                                    .trim_end_matches('\0')
                                    .to_string()
                            })
                            .unwrap_or_default();
                        (p, name)
                    } else {
                        continue;
                    };

                    // Remote: _ADDRINFO.Remote (ptr) -> _IN_ADDR(addr4).
                    let remote_addr = read_virt_u64(ai + t.ai_remote)
                        .filter(|&p| is_kernel_va(p))
                        .and_then(read_ipv4)
                        .unwrap_or_else(|| "0.0.0.0".to_string());
                    // Local: _ADDRINFO.Local -> _LOCAL_ADDRESS.pData -> ptr -> _IN_ADDR.
                    let local_addr = read_virt_u64(ai + t.ai_local)
                        .filter(|&p| is_kernel_va(p))
                        .and_then(|la| read_virt_u64(la + t.la_pdata))
                        .and_then(&read_virt_u64)
                        .and_then(read_ipv4)
                        .unwrap_or_else(|| "0.0.0.0".to_string());

                    let local_port =
                        read_phys_u(ep + t.local_port, 2).map_or(0, |v| u16::from_be(v as u16));
                    let remote_port =
                        read_phys_u(ep + t.remote_port, 2).map_or(0, |v| u16::from_be(v as u16));
                    // create_time == 0 means the build has no CreateTime field.
                    let create_time = if t.create_time != 0 {
                        read_phys_u(ep + t.create_time, 8).unwrap_or(0)
                    } else {
                        0
                    };

                    let key = (
                        local_addr.clone(),
                        local_port,
                        remote_addr.clone(),
                        remote_port,
                        pid,
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
                        state: tcp_state_from_enum(state_raw as u32),
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

/// Read `n` bytes (<= 8) at virtual address `va` as a little-endian integer.
fn read_phys_u_via<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    va: u64,
    n: usize,
) -> Option<u64> {
    let b = reader.read_bytes(va, n).ok()?;
    let mut buf = [0u8; 8];
    buf[..n].copy_from_slice(&b[..n]);
    Some(u64::from_le_bytes(buf))
}

/// x64 `_UDP_ENDPOINT` field offsets. `InetAF`/`Owner`/`CreateTime` are constant
/// across the supported builds; only `LocalAddr`/`Port` move. `_INETAF.AddressFamily`
/// (0x18) and `_LOCAL_ADDRESS.pData` (0x10) are constant. Source: Volatility3
/// netscan ISFs (`netscan-*-x64.json`).
pub struct UdpEndpointLayout {
    /// Offset of `InetAF` (pointer to `_INETAF`) in `_UDP_ENDPOINT`.
    pub inet_af: u64,
    /// Offset of the owning-process pointer in `_UDP_ENDPOINT`.
    pub owner: u64,
    /// Offset of `CreateTime` in `_UDP_ENDPOINT`.
    pub create_time: u64,
    /// Offset of `LocalAddr` (pointer to `_LOCAL_ADDRESS`) in `_UDP_ENDPOINT`.
    pub local_addr: u64,
    /// Offset of the local port (big-endian u16) in `_UDP_ENDPOINT`.
    pub port: u64,
    /// Offset of the address family in `_INETAF`.
    pub inetaf_af: u64,
    /// Offset of `pData` (pointer to `_IN_ADDR`) in `_LOCAL_ADDRESS`.
    pub la_pdata: u64,
}

impl UdpEndpointLayout {
    /// Only `LocalAddr`/`Port` vary between supported builds.
    const fn at(local_addr: u64, port: u64) -> Self {
        Self {
            inet_af: 0x20,
            owner: 0x28,
            create_time: 0x58,
            local_addr,
            port,
            inetaf_af: 0x18,
            la_pdata: 0x10,
        }
    }
}

/// Select the `_UDP_ENDPOINT` layout for an NT `build` number (x64), from the
/// Volatility3 netscan ISFs. Early Win10 x64 builds (10240/10586/14393) have no
/// dedicated x64 netscan ISF and are intentionally omitted (None) rather than
/// guessed — extend per build validated against a real image.
fn udp_endpoint_layout_x64(build: u32) -> Option<UdpEndpointLayout> {
    Some(match build {
        7600 | 7601 | 8400 | 9200 => UdpEndpointLayout::at(0x60, 0x80), // Win7 / Win8
        9600 => UdpEndpointLayout::at(0x60, 0x78),                      // Win8.1 / Server 2012 R2
        15063 | 16299 | 17134 | 17763 | 18362 => UdpEndpointLayout::at(0x80, 0x78),
        18363 => UdpEndpointLayout::at(0x88, 0x80),
        19041 | 20348 => UdpEndpointLayout::at(0xA8, 0xA0),
        _ => return None,
    })
}

/// Enumerate UDP endpoints by **physically pool-tag scanning** for `_UDP_ENDPOINT`
/// objects (`UdpA`), mirroring Volatility3 netscan. Each object's `InetAF`/`Owner`/
/// `LocalAddr` pointers are followed through the address space; the `_UDP_ENDPOINT`
/// overlay is selected from the dump's `NtBuildNumber`. IPv4 only for now (the
/// IPv6 increment lifts the `AF_INET` gate). Unrecognized build ⇒ empty.
///
/// Address chain (vol3 `_TCP_LISTENER.get_in_addr`): `LocalAddr` → `_LOCAL_ADDRESS`
/// → `pData` → `_IN_ADDR` (a *single* `pData` deref, unlike the `_ADDRINFO` chain
/// `scan_tcp_endpoints` uses — confirm against the citadel oracle when wiring the
/// issen tier-2 test).
///
/// # Errors
/// Propagates address-space read failures encountered while following pointers.
pub fn scan_udp_endpoints<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<WinConnectionInfo>> {
    let Some(build) = nt_build_number(reader) else {
        return Ok(Vec::new());
    };
    let Some(u) = udp_endpoint_layout_x64(build) else {
        return Ok(Vec::new());
    };
    let (pid_off, name_off) = eprocess_offsets(reader, build);
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
    let read_virt_u64 = |va: u64| -> Option<u64> {
        reader
            .read_bytes(va, 8)
            .ok()
            .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8])))
    };
    let read_ipv4 = |va: u64| -> Option<String> {
        reader
            .read_bytes(va, 4)
            .ok()
            .map(|b| format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
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
                if &buf[i..i + 4] != UDPA_TAG {
                    i += 1;
                    continue;
                }
                let pool_base = (addr + i as u64).saturating_sub(4);
                i += 1;
                for &delta in UDPA_DELTAS {
                    let ep = pool_base + delta;
                    let (Some(inetaf), Some(owner)) =
                        (read_phys_u(ep + u.inet_af, 8), read_phys_u(ep + u.owner, 8))
                    else {
                        continue;
                    };
                    if !is_kernel_va(inetaf) {
                        continue;
                    }
                    // Address family must be AF_INET (this path emits IPv4).
                    let Some(af) = read_phys_u_via(reader, inetaf + u.inetaf_af, 2) else {
                        continue;
                    };
                    if af as u16 != AF_INET {
                        continue;
                    }
                    // Owner is OPTIONAL (ownerless system/transient endpoints carry 0).
                    let (pid, process_name) = if owner == 0 {
                        (0, String::new())
                    } else if is_kernel_va(owner) {
                        let Some(p) = read_virt_u64(owner + pid_off) else {
                            continue;
                        };
                        if p > 0xFFFF {
                            continue;
                        }
                        let name = reader
                            .read_bytes(owner + name_off, 15)
                            .map(|b| {
                                String::from_utf8_lossy(&b)
                                    .trim_end_matches('\0')
                                    .to_string()
                            })
                            .unwrap_or_default();
                        (p, name)
                    } else {
                        continue;
                    };

                    // Local: LocalAddr -> _LOCAL_ADDRESS.pData -> _IN_ADDR (single deref).
                    let local_addr = read_phys_u(ep + u.local_addr, 8)
                        .filter(|&p| is_kernel_va(p))
                        .and_then(|la| read_virt_u64(la + u.la_pdata))
                        .filter(|&p| is_kernel_va(p))
                        .and_then(read_ipv4)
                        .unwrap_or_else(|| "0.0.0.0".to_string());
                    let local_port =
                        read_phys_u(ep + u.port, 2).map_or(0, |v| u16::from_be(v as u16));
                    let create_time = read_phys_u(ep + u.create_time, 8).unwrap_or(0);

                    let key = (local_addr.clone(), local_port, pid);
                    if !seen.insert(key) {
                        continue;
                    }
                    out.push(WinConnectionInfo {
                        protocol: "UDPv4".to_string(),
                        local_addr,
                        local_port,
                        remote_addr: "*".to_string(),
                        remote_port: 0,
                        state: WinTcpState::None,
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
            // Kernel NtBuildNumber global (the scan reads its low 16 bits).
            .add_symbol("NtBuildNumber", NT_BUILD_NUMBER_VA)
            .build_json()
    }

    /// VA the synthetic `NtBuildNumber` symbol resolves to (mapped by the test).
    const NT_BUILD_NUMBER_VA: u64 = 0xFFFF_C000_0002_0000;

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
    fn tcp_endpoint_layout_selected_per_build() {
        // Win7: distinct layout throughout.
        let w7 = tcp_endpoint_layout_x64(7601).unwrap();
        assert_eq!((w7.inet_af, w7.addr_info, w7.state), (0x18, 0x20, 0x68));
        assert_eq!(
            (w7.local_port, w7.remote_port, w7.owner),
            (0x6C, 0x6E, 0x238)
        );
        assert_eq!((w7.inetaf_af, w7.create_time), (0x14, 0x0));

        // Win8.1 / Server 2012 R2 (the DC): modern base, Owner 0x258, no CreateTime.
        let w81 = tcp_endpoint_layout_x64(9600).unwrap();
        assert_eq!((w81.addr_info, w81.state, w81.owner), (0x18, 0x6C, 0x258));
        assert_eq!(w81.create_time, 0x0);

        // Win10 1607 (Server 2016) and 2004 differ only in Owner/CreateTime.
        assert_eq!(tcp_endpoint_layout_x64(14393).unwrap().owner, 0x258);
        assert_eq!(tcp_endpoint_layout_x64(14393).unwrap().create_time, 0x268);
        assert_eq!(tcp_endpoint_layout_x64(19041).unwrap().owner, 0x2D8);
        assert_eq!(tcp_endpoint_layout_x64(19041).unwrap().create_time, 0x2E8);

        // Unknown build: no overlay (caller must not read at guessed offsets).
        assert!(tcp_endpoint_layout_x64(12345).is_none());
    }

    #[test]
    fn scan_tcp_endpoints_recovers_a_connection_from_a_tcpe_pool_object() {
        // Build 9600 (Server 2012 R2 — the real CITADEL-DC01 build); the scan
        // selects this layout from the NtBuildNumber symbol at runtime.
        let t = tcp_endpoint_layout_x64(9600).unwrap();
        // VA-mapped pointer targets — use 0xFFFFC0.. to exercise the full
        // kernel-half is_kernel_va range (pool lives outside the 0xFFFFF8.. band).
        let inetaf_va = 0xFFFF_C000_0001_0000u64;
        let ai_va = 0xFFFF_C000_0001_1000u64;
        let remote_in_va = 0xFFFF_C000_0001_2000u64;
        let la_va = 0xFFFF_C000_0001_3000u64;
        let pdata_va = 0xFFFF_C000_0001_4000u64;
        let local_in_va = 0xFFFF_C000_0001_5000u64;
        let ep_va = 0xFFFF_C000_0001_6000u64;
        let (pa_inetaf, pa_ai, pa_rin, pa_la, pa_pdata, pa_lin, pa_ep) = (
            0x70_000u64,
            0x71_000,
            0x72_000,
            0x73_000,
            0x74_000,
            0x75_000,
            0x76_000,
        );

        let mut inetaf = vec![0u8; 0x1000];
        inetaf[t.inetaf_af as usize..t.inetaf_af as usize + 2].copy_from_slice(&2u16.to_le_bytes());
        let mut ai = vec![0u8; 0x1000];
        ai[t.ai_local as usize..t.ai_local as usize + 8].copy_from_slice(&la_va.to_le_bytes());
        ai[t.ai_remote as usize..t.ai_remote as usize + 8]
            .copy_from_slice(&remote_in_va.to_le_bytes());
        let mut rin = vec![0u8; 0x1000];
        rin[0..4].copy_from_slice(&[203, 78, 103, 109]); // remote (C2)
                                                         // Local chain: _ADDRINFO.Local -> _LOCAL_ADDRESS.pData -> (deref) ptr ->
                                                         // (deref) _IN_ADDR. la.pData = pdata_va; *pdata_va = local_in_va; *local_in_va = IP.
        let mut la = vec![0u8; 0x1000];
        la[t.la_pdata as usize..t.la_pdata as usize + 8].copy_from_slice(&pdata_va.to_le_bytes());
        let mut pdata = vec![0u8; 0x1000];
        pdata[0..8].copy_from_slice(&local_in_va.to_le_bytes());
        let mut lin = vec![0u8; 0x1000];
        lin[0..4].copy_from_slice(&[10, 42, 85, 10]); // local
        let mut ep = vec![0u8; 0x1000];
        ep[EPROC_PID..EPROC_PID + 8].copy_from_slice(&3644u64.to_le_bytes());
        ep[EPROC_IMAGE_NAME..EPROC_IMAGE_NAME + 15].copy_from_slice(b"coreupdater.exe");

        // The _TCP_ENDPOINT pool object, read PHYSICALLY by the scan (14393 layout).
        let tag_phys = 0x50_004u64;
        let ep_obj = 0x50_010u64; // pool_base(0x50000) + delta 0x10
        let mut obj = vec![0u8; 0x300];
        obj[t.state as usize..t.state as usize + 4].copy_from_slice(&4u32.to_le_bytes()); // ESTABLISHED
        obj[t.local_port as usize..t.local_port as usize + 2]
            .copy_from_slice(&62613u16.to_be_bytes());
        obj[t.remote_port as usize..t.remote_port as usize + 2]
            .copy_from_slice(&443u16.to_be_bytes());
        obj[t.inet_af as usize..t.inet_af as usize + 8].copy_from_slice(&inetaf_va.to_le_bytes());
        obj[t.addr_info as usize..t.addr_info as usize + 8].copy_from_slice(&ai_va.to_le_bytes());
        obj[t.owner as usize..t.owner as usize + 8].copy_from_slice(&ep_va.to_le_bytes());

        // NtBuildNumber global = 0xF0002580 (free-build flags | build 9600), so
        // the scan selects the build-9600 overlay from the dump itself.
        let pa_build = 0x77_000u64;
        let mut build_page = vec![0u8; 0x1000];
        build_page[0..4].copy_from_slice(&0xF000_2580u32.to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(NT_BUILD_NUMBER_VA, pa_build, flags::WRITABLE)
            .map_4k(inetaf_va, pa_inetaf, flags::WRITABLE)
            .map_4k(ai_va, pa_ai, flags::WRITABLE)
            .map_4k(remote_in_va, pa_rin, flags::WRITABLE)
            .map_4k(la_va, pa_la, flags::WRITABLE)
            .map_4k(pdata_va, pa_pdata, flags::WRITABLE)
            .map_4k(local_in_va, pa_lin, flags::WRITABLE)
            .map_4k(ep_va, pa_ep, flags::WRITABLE)
            .write_phys(pa_build, &build_page)
            .write_phys(pa_inetaf, &inetaf)
            .write_phys(pa_ai, &ai)
            .write_phys(pa_rin, &rin)
            .write_phys(pa_la, &la)
            .write_phys(pa_pdata, &pdata)
            .write_phys(pa_lin, &lin)
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
        assert_eq!(c.remote_addr, "203.78.103.109");
        assert_eq!(c.remote_port, 443);
        assert_eq!(c.local_addr, "10.42.85.10");
        assert_eq!(c.local_port, 62613);
        assert_eq!(c.pid, 3644);
        assert_eq!(c.process_name, "coreupdater.exe");
        assert_eq!(c.state, WinTcpState::Established);
    }

    // RED: an established _TCP_ENDPOINT with Owner == 0 (an ownerless system /
    // transient socket — exactly the Szechuan workstation's 13.78.149.173:443
    // connection) must still be recovered, just with pid 0 / empty process name.
    // The old gate rejected it because `is_kernel_va(owner)` is false for 0.
    #[test]
    fn scan_tcp_endpoints_recovers_an_ownerless_endpoint() {
        let t = tcp_endpoint_layout_x64(9600).unwrap();
        let inetaf_va = 0xFFFF_C000_0001_0000u64;
        let ai_va = 0xFFFF_C000_0001_1000u64;
        let remote_in_va = 0xFFFF_C000_0001_2000u64;
        let la_va = 0xFFFF_C000_0001_3000u64;
        let pdata_va = 0xFFFF_C000_0001_4000u64;
        let local_in_va = 0xFFFF_C000_0001_5000u64;
        let (pa_inetaf, pa_ai, pa_rin, pa_la, pa_pdata, pa_lin) = (
            0x70_000u64,
            0x71_000,
            0x72_000,
            0x73_000,
            0x74_000,
            0x75_000,
        );

        let mut inetaf = vec![0u8; 0x1000];
        inetaf[t.inetaf_af as usize..t.inetaf_af as usize + 2].copy_from_slice(&2u16.to_le_bytes());
        let mut ai = vec![0u8; 0x1000];
        ai[t.ai_local as usize..t.ai_local as usize + 8].copy_from_slice(&la_va.to_le_bytes());
        ai[t.ai_remote as usize..t.ai_remote as usize + 8]
            .copy_from_slice(&remote_in_va.to_le_bytes());
        let mut rin = vec![0u8; 0x1000];
        rin[0..4].copy_from_slice(&[13, 78, 149, 173]); // remote (Azure C2)
        let mut la = vec![0u8; 0x1000];
        la[t.la_pdata as usize..t.la_pdata as usize + 8].copy_from_slice(&pdata_va.to_le_bytes());
        let mut pdata = vec![0u8; 0x1000];
        pdata[0..8].copy_from_slice(&local_in_va.to_le_bytes());
        let mut lin = vec![0u8; 0x1000];
        lin[0..4].copy_from_slice(&[10, 42, 85, 115]); // local

        let mut obj = vec![0u8; 0x300];
        obj[t.state as usize..t.state as usize + 4].copy_from_slice(&4u32.to_le_bytes()); // ESTABLISHED
        obj[t.local_port as usize..t.local_port as usize + 2]
            .copy_from_slice(&50979u16.to_be_bytes());
        obj[t.remote_port as usize..t.remote_port as usize + 2]
            .copy_from_slice(&443u16.to_be_bytes());
        obj[t.inet_af as usize..t.inet_af as usize + 8].copy_from_slice(&inetaf_va.to_le_bytes());
        obj[t.addr_info as usize..t.addr_info as usize + 8].copy_from_slice(&ai_va.to_le_bytes());
        // Owner left as 0 — no owning process.

        let tag_phys = 0x50_004u64;
        let ep_obj = 0x50_010u64; // pool_base(0x50000) + delta 0x10
        let pa_build = 0x77_000u64;
        let mut build_page = vec![0u8; 0x1000];
        build_page[0..4].copy_from_slice(&0xF000_2580u32.to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(NT_BUILD_NUMBER_VA, pa_build, flags::WRITABLE)
            .map_4k(inetaf_va, pa_inetaf, flags::WRITABLE)
            .map_4k(ai_va, pa_ai, flags::WRITABLE)
            .map_4k(remote_in_va, pa_rin, flags::WRITABLE)
            .map_4k(la_va, pa_la, flags::WRITABLE)
            .map_4k(pdata_va, pa_pdata, flags::WRITABLE)
            .map_4k(local_in_va, pa_lin, flags::WRITABLE)
            .write_phys(pa_build, &build_page)
            .write_phys(pa_inetaf, &inetaf)
            .write_phys(pa_ai, &ai)
            .write_phys(pa_rin, &rin)
            .write_phys(pa_la, &la)
            .write_phys(pa_pdata, &pdata)
            .write_phys(pa_lin, &lin)
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
        assert_eq!(
            conns.len(),
            1,
            "ownerless endpoint must be recovered, got {conns:?}"
        );
        let c = &conns[0];
        assert_eq!(c.remote_addr, "13.78.149.173");
        assert_eq!(c.remote_port, 443);
        assert_eq!(c.local_addr, "10.42.85.115");
        assert_eq!(c.local_port, 50979);
        assert_eq!(c.pid, 0, "ownerless -> pid 0");
        assert_eq!(c.process_name, "");
        assert_eq!(c.state, WinTcpState::Established);
    }

    // --- Symbol-free OS build detection (NtBuildLab scan) -------------------

    #[test]
    fn build_from_buildlab_parses_leading_field() {
        assert_eq!(
            build_from_buildlab("19041.1.amd64fre.vb_release.191206-1406"),
            Some(19041)
        );
        assert_eq!(
            build_from_buildlab("9600.17415.amd64fre.winblue_r4.141028-1500"),
            Some(9600)
        );
        // Just the build.rev prefix (what the scanner backtracks to) also parses.
        assert_eq!(build_from_buildlab("19041.1."), Some(19041));
        assert_eq!(build_from_buildlab("not-a-buildlab"), None);
        assert_eq!(build_from_buildlab(""), None);
        // Below the NT build floor (>= 2600): reject as scan noise.
        assert_eq!(build_from_buildlab("12.1.amd64fre"), None);
    }

    /// Build a `RangedMem` whose physical memory contains `bytes` at `pa`.
    fn ranged_mem_with(pa: u64, bytes: &[u8]) -> (u64, RangedMem) {
        let mut page = vec![0u8; 0x1000];
        page[..bytes.len()].copy_from_slice(bytes);
        let (cr3, mem) = PageTableBuilder::new().write_phys(pa, &page).build();
        let ranged = RangedMem {
            inner: mem,
            ranges: vec![memf_format::PhysicalRange {
                start: 0,
                end: 1024 * 1024,
            }],
        };
        (cr3, ranged)
    }

    #[test]
    fn scan_build_from_buildlab_recovers_build_symbol_free() {
        let (_cr3, ranged) =
            ranged_mem_with(0x40_000, b"19041.1.amd64fre.vb_release.191206-1406\0");
        assert_eq!(scan_build_from_buildlab(&ranged), Some(19041));
    }

    #[test]
    fn nt_build_number_falls_back_to_buildlab_scan_without_symbol() {
        // Mirrors the Szechuan workstation dump: the NtBuildNumber symbol does
        // not resolve, but the NtBuildLab string is physically present.
        // Detection must still recover build 19041 so the overlay is reachable.
        let (cr3, ranged) = ranged_mem_with(0x40_000, b"19041.1.amd64fre.vb_release.191206-1406\0");
        // ISF with NO NtBuildNumber symbol.
        let resolver = IsfResolver::from_value(&IsfBuilder::new().build_json()).unwrap();
        let reader = ObjectReader::new(
            VirtualAddressSpace::new(ranged, cr3, TranslationMode::X86_64FourLevel),
            Box::new(resolver),
        );
        assert_eq!(nt_build_number(&reader), Some(19041));
    }

    /// A reader whose ISF defines no `_EPROCESS` field offsets (symbol-free).
    fn empty_symbol_reader() -> ObjectReader<SyntheticPhysMem> {
        let resolver = IsfResolver::from_value(&IsfBuilder::new().build_json()).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        ObjectReader::new(
            VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel),
            Box::new(resolver),
        )
    }

    #[test]
    fn eprocess_offsets_prefer_symbols_then_build_aware_fallback() {
        // Symbols present (net_isf defines 0x440/0x5A8) → used regardless of build.
        let with = make_net_reader(PageTableBuilder::new());
        assert_eq!(eprocess_offsets(&with, 9600), (0x440, 0x5A8));

        // Symbols absent + build 19041 → validated Win10-2004 fallback, NOT the
        // 9600-era 0x2E0/0x450 default (the workstation-netstat bug).
        let empty = empty_symbol_reader();
        assert_eq!(eprocess_offsets(&empty, 19041), (0x440, 0x5A8));

        // Symbols absent + unrecognized build → legacy default (no regression).
        assert_eq!(eprocess_offsets(&empty, 7601), (0x2E0, 0x450));
    }

    #[test]
    fn scan_udp_endpoints_recovers_a_udp_endpoint_from_a_udpa_pool_object() {
        // Build 9600 (Server 2012 R2 — CITADEL-DC01) _UDP_ENDPOINT offsets
        // (vol3 netscan-win81-x64): InetAF 0x20, Owner 0x28, LocalAddr 0x60,
        // Port 0x78; _INETAF.AddressFamily 0x18; _LOCAL_ADDRESS.pData 0x10.
        const U_INETAF: usize = 0x20;
        const U_OWNER: usize = 0x28;
        const U_LOCALADDR: usize = 0x60;
        const U_PORT: usize = 0x78;
        const INETAF_AF: usize = 0x18;
        const LA_PDATA: usize = 0x10;

        let inetaf_va = 0xFFFF_C000_0001_0000u64;
        let la_va = 0xFFFF_C000_0001_3000u64;
        let in_addr_va = 0xFFFF_C000_0001_5000u64;
        let ep_va = 0xFFFF_C000_0001_6000u64;
        let (pa_inetaf, pa_la, pa_in, pa_ep) = (0x70_000u64, 0x73_000, 0x75_000, 0x76_000);

        let mut inetaf = vec![0u8; 0x1000];
        inetaf[INETAF_AF..INETAF_AF + 2].copy_from_slice(&2u16.to_le_bytes()); // AF_INET
                                                                               // Local: LocalAddr -> _LOCAL_ADDRESS.pData -> _IN_ADDR (vol3 single deref).
        let mut la = vec![0u8; 0x1000];
        la[LA_PDATA..LA_PDATA + 8].copy_from_slice(&in_addr_va.to_le_bytes());
        let mut inb = vec![0u8; 0x1000];
        inb[0..4].copy_from_slice(&[10, 42, 85, 10]); // local 10.42.85.10
        let mut ep = vec![0u8; 0x1000];
        ep[EPROC_PID..EPROC_PID + 8].copy_from_slice(&1368u64.to_le_bytes());
        ep[EPROC_IMAGE_NAME..EPROC_IMAGE_NAME + 7].copy_from_slice(b"dns.exe");

        // _UDP_ENDPOINT pool object (read PHYSICALLY by the scan).
        let pool_base = 0x50_000u64;
        let tag_phys = pool_base + 4; // "UdpA"
        let obj_off = pool_base + 0x10; // delta 0x10
        let mut obj = vec![0u8; 0x200];
        obj[U_INETAF..U_INETAF + 8].copy_from_slice(&inetaf_va.to_le_bytes());
        obj[U_OWNER..U_OWNER + 8].copy_from_slice(&ep_va.to_le_bytes());
        obj[U_LOCALADDR..U_LOCALADDR + 8].copy_from_slice(&la_va.to_le_bytes());
        obj[U_PORT..U_PORT + 2].copy_from_slice(&53u16.to_be_bytes());

        let pa_build = 0x77_000u64;
        let mut build_page = vec![0u8; 0x1000];
        build_page[0..4].copy_from_slice(&0xF000_2580u32.to_le_bytes()); // build 9600

        let ptb = PageTableBuilder::new()
            .map_4k(NT_BUILD_NUMBER_VA, pa_build, flags::WRITABLE)
            .map_4k(inetaf_va, pa_inetaf, flags::WRITABLE)
            .map_4k(la_va, pa_la, flags::WRITABLE)
            .map_4k(in_addr_va, pa_in, flags::WRITABLE)
            .map_4k(ep_va, pa_ep, flags::WRITABLE)
            .write_phys(pa_build, &build_page)
            .write_phys(pa_inetaf, &inetaf)
            .write_phys(pa_la, &la)
            .write_phys(pa_in, &inb)
            .write_phys(pa_ep, &ep)
            .write_phys(tag_phys, b"UdpA")
            .write_phys(obj_off, &obj);

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

        let conns = scan_udp_endpoints(&reader).expect("scan ok");
        assert_eq!(conns.len(), 1, "exactly one udp endpoint, got {conns:?}");
        let c = &conns[0];
        assert_eq!(c.protocol, "UDPv4");
        assert_eq!(c.local_addr, "10.42.85.10");
        assert_eq!(c.local_port, 53);
        assert_eq!(c.pid, 1368);
        assert_eq!(c.process_name, "dns.exe");
    }
}
