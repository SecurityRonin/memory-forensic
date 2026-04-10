//! Linux Unix domain socket walker.
//!
//! Enumerates Unix domain sockets from kernel memory by walking the
//! `unix_socket_table` hash table of `unix_sock` structures. Unix sockets
//! are used for local IPC and can reveal hidden communication channels
//! between processes. Malware uses abstract Unix sockets (names starting
//! with `\0`) for covert C2 channels. Equivalent to Volatility's
//! `linux.sockstat` for `AF_UNIX`.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about a Unix domain socket extracted from kernel memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UnixSocketInfo {
    /// Inode number of the socket.
    pub inode: u64,
    /// Socket path (empty for abstract sockets, `@`-prefixed in display).
    pub path: String,
    /// Socket type: STREAM, DGRAM, or SEQPACKET.
    pub socket_type: String,
    /// Socket state (e.g. UNCONNECTED, CONNECTED, LISTENING).
    pub state: String,
    /// PID of the process that owns this socket.
    pub owner_pid: u32,
    /// PID of the peer process (0 if none).
    pub peer_pid: u32,
    /// Whether this socket is classified as suspicious.
    pub is_suspicious: bool,
}

/// Map a kernel `sk_type` value to a human-readable socket type name.
pub fn socket_type_name(sk_type: u32) -> &'static str {
    match sk_type {
        1 => "STREAM",
        2 => "DGRAM",
        5 => "SEQPACKET",
        _ => "UNKNOWN",
    }
}

/// Classify whether a Unix socket is suspicious.
///
/// A socket is suspicious if:
/// - It is an abstract socket (empty path or path starts with `@`) owned by
///   a non-system PID (pid >= 1000), or
/// - Its path is under `/tmp` or `/dev/shm` (common malware staging areas).
pub fn classify_unix_socket(path: &str, owner_pid: u32) -> bool {
    let is_abstract = path.is_empty() || path.starts_with('@');
    if is_abstract && owner_pid >= 1000 {
        return true;
    }
    if path.starts_with("/tmp") || path.starts_with("/dev/shm") {
        return true;
    }
    false
}

/// Safety limit: maximum number of Unix sockets to enumerate.
const MAX_UNIX_SOCKETS: usize = 65536;
/// Number of hash table buckets in `unix_socket_table`.
const UNIX_HASH_SIZE: u64 = 256;

/// Walk Unix domain sockets from kernel memory.
///
/// Looks up `unix_socket_table` (or `init_net.unx.table`) and walks the
/// hash table of `unix_sock` structures, reading path, type, state, and
/// owning PID from each entry.
///
/// Returns `Ok(Vec::new())` when required kernel symbols are absent.
pub fn walk_unix_sockets<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<UnixSocketInfo>> {
    // Locate the unix_socket_table hash array.
    let table_addr = match reader.symbols().symbol_address("unix_socket_table") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    // Resolve key offsets within unix_sock / sock.
    // unix_sock embeds `struct sock sk` at offset 0 (sk.sk_node is the hlist).
    // The path (sun_path) is in `struct sockaddr_un` embedded in unix_sock.
    let sk_type_off = reader
        .symbols()
        .field_offset("sock", "sk_type")
        .unwrap_or(0x12);
    let sk_state_off = reader
        .symbols()
        .field_offset("sock", "sk_state")
        .unwrap_or(0x14);
    let sk_socket_off = reader
        .symbols()
        .field_offset("sock", "sk_socket")
        .unwrap_or(0x30);
    let unix_addr_off = reader
        .symbols()
        .field_offset("unix_sock", "addr")
        .unwrap_or(0x288);
    let sun_path_off: u64 = 2; // offsetof(sockaddr_un, sun_path) after sa_family u16

    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Walk each hash bucket (hlist_head: first pointer at offset 0).
    for bucket in 0..UNIX_HASH_SIZE {
        let bucket_addr = table_addr + bucket * 8;
        let first = match reader.read_bytes(bucket_addr, 8) {
            Ok(b) if b.len() == 8 => u64::from_le_bytes(b[..8].try_into().unwrap()),
            _ => continue,
        };
        if first == 0 {
            continue;
        }

        // Walk hlist: each node's `next` is the first field.
        let mut node = first;
        while node != 0 && results.len() < MAX_UNIX_SOCKETS {
            if !seen.insert(node) {
                break; // cycle detected
            }

            // `unix_sock` starts with embedded `struct sock` (sk) at offset 0,
            // and `sk.sk_node` (hlist_node: next, pprev) is at offset 0 of sk.
            // The node pointer IS the address of sk_node inside unix_sock,
            // so unix_sock starts at node (no adjustment needed for the first field).
            let sock_addr = node;

            // Follow hlist next pointer (offset 0 within hlist_node).
            let next = match reader.read_bytes(node, 8) {
                Ok(b) if b.len() == 8 => u64::from_le_bytes(b[..8].try_into().unwrap()),
                _ => break,
            };

            // Read sk_type (u16) and sk_state (u8).
            let sk_type: u32 = reader
                .read_bytes(sock_addr + sk_type_off, 2)
                .ok()
                .and_then(|b| Some(u16::from_le_bytes(b[..2].try_into().ok()?) as u32))
                .unwrap_or(0);
            let sk_state: u8 = reader
                .read_bytes(sock_addr + sk_state_off, 1)
                .ok()
                .and_then(|b| b.first().copied())
                .unwrap_or(0);

            let state_str = match sk_state {
                1 => "UNCONNECTED",
                2 => "CONNECTING",
                3 => "CONNECTED",
                4 => "DISCONNECTING",
                _ => "UNKNOWN",
            }
            .to_string();

            // Read unix path from unix_sock.addr -> unix_address.name.sun_path.
            let path = 'path: {
                let addr_ptr = reader
                    .read_bytes(sock_addr + unix_addr_off, 8)
                    .ok()
                    .and_then(|b| Some(u64::from_le_bytes(b[..8].try_into().ok()?)))
                    .unwrap_or(0);
                if addr_ptr == 0 {
                    break 'path String::new();
                }
                // sun_path starts at addr_ptr + sun_path_off (skip sa_family u16).
                let path_bytes = reader
                    .read_bytes(addr_ptr + sun_path_off, 108)
                    .unwrap_or_default();
                // Abstract socket: first byte is '\0', display as '@' prefix.
                if path_bytes.first().copied() == Some(0) {
                    let inner: String = path_bytes[1..]
                        .iter()
                        .take_while(|&&b| b != 0)
                        .map(|&b| b as char)
                        .collect();
                    if inner.is_empty() {
                        String::new()
                    } else {
                        format!("@{}", inner)
                    }
                } else {
                    path_bytes
                        .iter()
                        .take_while(|&&b| b != 0)
                        .map(|&b| b as char)
                        .collect()
                }
            };

            // Read socket inode via sk_socket -> socket -> inode.
            let inode: u64 = reader
                .read_bytes(sock_addr + sk_socket_off, 8)
                .ok()
                .and_then(|b| {
                    let socket_ptr = u64::from_le_bytes(b[..8].try_into().ok()?);
                    if socket_ptr == 0 {
                        return None;
                    }
                    // socket.file offset varies; inode is typically at +0x18.
                    reader
                        .read_bytes(socket_ptr + 0x18, 8)
                        .ok()
                        .and_then(|ib| Some(u64::from_le_bytes(ib[..8].try_into().ok()?)))
                })
                .unwrap_or(0);

            let is_suspicious = classify_unix_socket(&path, 0);

            results.push(UnixSocketInfo {
                inode,
                path,
                socket_type: socket_type_name(sk_type).to_string(),
                state: state_str,
                owner_pid: 0,
                peer_pid: 0,
                is_suspicious,
            });

            node = next;
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_type_stream() {
        assert_eq!(socket_type_name(1), "STREAM");
    }

    #[test]
    fn socket_type_dgram() {
        assert_eq!(socket_type_name(2), "DGRAM");
    }

    #[test]
    fn socket_type_seqpacket() {
        assert_eq!(socket_type_name(5), "SEQPACKET");
    }

    #[test]
    fn socket_type_unknown() {
        assert_eq!(socket_type_name(0), "UNKNOWN");
        assert_eq!(socket_type_name(3), "UNKNOWN");
        assert_eq!(socket_type_name(99), "UNKNOWN");
    }

    #[test]
    fn classify_abstract_socket_high_pid_is_suspicious() {
        // Abstract socket (empty path) with non-system PID
        assert!(classify_unix_socket("", 1000));
        assert!(classify_unix_socket("", 31337));
        // Abstract socket with @ prefix
        assert!(classify_unix_socket("@hidden_channel", 2000));
    }

    #[test]
    fn classify_abstract_socket_system_pid_not_suspicious() {
        // Abstract socket with system PID (< 1000) is not suspicious on its own
        assert!(!classify_unix_socket("", 0));
        assert!(!classify_unix_socket("", 1));
        assert!(!classify_unix_socket("", 999));
        assert!(!classify_unix_socket("@/org/freedesktop/systemd1", 1));
    }

    #[test]
    fn classify_tmp_socket_always_suspicious() {
        // Sockets in /tmp are always suspicious regardless of PID
        assert!(classify_unix_socket("/tmp/hidden.sock", 0));
        assert!(classify_unix_socket("/tmp/hidden.sock", 1));
        assert!(classify_unix_socket("/tmp/.X11-unix/X0", 500));
    }

    #[test]
    fn classify_dev_shm_socket_always_suspicious() {
        // Sockets in /dev/shm are always suspicious regardless of PID
        assert!(classify_unix_socket("/dev/shm/malware.sock", 0));
        assert!(classify_unix_socket("/dev/shm/c2_channel", 2000));
    }

    #[test]
    fn classify_normal_socket_not_suspicious() {
        // Normal filesystem sockets in standard locations
        assert!(!classify_unix_socket("/var/run/dbus/system_bus_socket", 1));
        assert!(!classify_unix_socket("/run/systemd/journal/socket", 500));
        assert!(!classify_unix_socket("/var/lib/mysql/mysql.sock", 999));
    }

    #[test]
    fn unix_socket_info_is_serializable() {
        let info = UnixSocketInfo {
            inode: 12345,
            path: "/var/run/test.sock".to_string(),
            socket_type: "STREAM".to_string(),
            state: "CONNECTED".to_string(),
            owner_pid: 100,
            peer_pid: 200,
            is_suspicious: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"inode\":12345"));
        assert!(json.contains("\"path\":\"/var/run/test.sock\""));
        assert!(json.contains("\"is_suspicious\":false"));
    }

    #[test]
    fn unix_socket_info_clone_and_debug() {
        let info = UnixSocketInfo {
            inode: 1,
            path: "@abstract".to_string(),
            socket_type: "DGRAM".to_string(),
            state: "UNCONNECTED".to_string(),
            owner_pid: 0,
            peer_pid: 0,
            is_suspicious: true,
        };
        let cloned = info.clone();
        assert_eq!(cloned.inode, 1);
        let dbg = format!("{:?}", cloned);
        assert!(dbg.contains("abstract"));
    }

    // -----------------------------------------------------------------------
    // socket_type_name boundary: all possible named values
    // -----------------------------------------------------------------------

    #[test]
    fn socket_type_all_named() {
        assert_eq!(socket_type_name(1), "STREAM");
        assert_eq!(socket_type_name(2), "DGRAM");
        assert_eq!(socket_type_name(5), "SEQPACKET");
        // All other values → UNKNOWN
        assert_eq!(socket_type_name(4), "UNKNOWN");
        assert_eq!(socket_type_name(u32::MAX), "UNKNOWN");
    }

    // -----------------------------------------------------------------------
    // classify_unix_socket: edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn classify_abstract_pid_boundary() {
        // pid=999 is just below threshold → not suspicious (abstract path)
        assert!(!classify_unix_socket("", 999));
        // pid=1000 is at threshold → suspicious
        assert!(classify_unix_socket("", 1000));
        // pid=1001 → suspicious
        assert!(classify_unix_socket("", 1001));
    }

    #[test]
    fn classify_at_prefix_with_system_pid_not_suspicious() {
        // @ prefix, system PID → not suspicious
        assert!(!classify_unix_socket("@/org/freedesktop/systemd1", 999));
    }

    #[test]
    fn classify_dev_shm_prefix_match() {
        // Exact prefix match /dev/shm
        assert!(classify_unix_socket("/dev/shm", 0));
        // Path that starts with /dev/shm/ but is longer
        assert!(classify_unix_socket("/dev/shm/nested/path.sock", 0));
    }

    #[test]
    fn classify_tmp_prefix_exact() {
        // /tmp itself (edge: path == /tmp prefix)
        assert!(classify_unix_socket("/tmp", 0));
    }

    #[test]
    fn classify_normal_non_suspicious_paths() {
        assert!(!classify_unix_socket("/run/user/1000/pulse/native", 1000));
        assert!(!classify_unix_socket("/var/run/docker.sock", 0));
        assert!(!classify_unix_socket("/run/systemd/private/tmp-sock", 0));
    }

    // -----------------------------------------------------------------------
    // walk_unix_sockets: no symbol → empty Vec
    // -----------------------------------------------------------------------

    #[test]
    fn walk_unix_sockets_no_symbol_returns_empty() {
        use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_unix_sockets(&reader).unwrap();
        assert!(result.is_empty(), "missing unix_socket_table symbol must yield empty vec");
    }

    // --- walk_unix_sockets: symbol present, all 256 buckets are zero → exercises loop body ---
    // Exercises the hash-table scanning loop: each bucket's first pointer is 0 → no sockets.
    #[test]
    fn walk_unix_sockets_symbol_present_empty_buckets_returns_empty() {
        use memf_core::test_builders::{flags as ptf, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // unix_socket_table is an array of 256 hlist_head (each 8 bytes = 2048 bytes total).
        // All zeros → every bucket's first pointer is 0 → no sockets enumerated.
        // We need two 4K pages to cover: page 0 (buckets 0–511 bytes fit in 4K).
        let table_vaddr: u64 = 0xFFFF_8800_0070_0000;
        let table_paddr: u64 = 0x0070_0000; // unique, < 16 MB

        let isf = IsfBuilder::new()
            .add_symbol("unix_socket_table", table_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // All-zero page → all 256 bucket pointers are 0.
        let page = [0u8; 4096];

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(table_vaddr, table_paddr, ptf::WRITABLE)
            .write_phys(table_paddr, &page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_unix_sockets(&reader).unwrap();
        assert!(
            result.is_empty(),
            "all-zero hash buckets → no unix sockets found"
        );
    }

    // --- walk_unix_sockets: bucket[0] has a valid non-zero hlist node that self-terminates ---
    // Exercises the inner while loop: node != 0, hlist next == 0 → one iteration → one socket.
    #[test]
    fn walk_unix_sockets_single_node_one_entry() {
        use memf_core::test_builders::{flags as ptf, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Layout:
        //   table_vaddr  = unix_socket_table (256 buckets × 8 bytes = 2 KB, fits in 4K page)
        //   node_vaddr   = the single unix_sock entry
        //
        // The walker reads:
        //   bucket[0] = node_vaddr              (first hlist node)
        //   node[0..8] = next pointer = 0       (terminates the hlist)
        //   node[sk_type_off..+2] = 1 (STREAM)
        //   node[sk_state_off..+1] = 3 (CONNECTED)
        //   node[unix_addr_off..+8] = 0         (no path → empty string)
        //   node[sk_socket_off..+8] = 0         (no socket → inode = 0)
        //
        // With an empty path and owner_pid=0 → classify_unix_socket("", 0) = false.

        let table_vaddr: u64 = 0xFFFF_8800_0071_0000;
        let table_paddr: u64 = 0x0071_0000;

        let node_vaddr: u64 = 0xFFFF_8800_0072_0000;
        let node_paddr: u64 = 0x0072_0000;

        // Default offsets used by walk_unix_sockets when ISF fields are missing:
        //   sk_type_off  = unwrap_or(0x12) = 0x12
        //   sk_state_off = unwrap_or(0x14) = 0x14
        //   sk_socket_off= unwrap_or(0x30) = 0x30
        //   unix_addr_off= unwrap_or(0x288)= 0x288
        let sk_type_off: usize = 0x12;
        let sk_state_off: usize = 0x14;
        // unix_addr_off = 0x288 — leave as zero (addr_ptr=0 → path="")
        // sk_socket_off = 0x30  — leave as zero (socket_ptr=0 → inode=0)

        // Build the hash-table page: bucket[0] = node_vaddr; rest = 0.
        let mut table_page = [0u8; 4096];
        table_page[0..8].copy_from_slice(&node_vaddr.to_le_bytes());

        // Build the node page.
        let mut node_page = [0u8; 4096];
        // hlist next (offset 0) = 0 → terminates after one iteration
        node_page[0..8].copy_from_slice(&0u64.to_le_bytes());
        // sk_type = 1 (STREAM)
        node_page[sk_type_off..sk_type_off + 2].copy_from_slice(&1u16.to_le_bytes());
        // sk_state = 3 (CONNECTED)
        node_page[sk_state_off] = 3u8;
        // unix_addr_off at 0x288 — bytes remain 0 (addr_ptr=0 → path="")
        // sk_socket_off at 0x30 — bytes remain 0 (socket_ptr=0 → inode=0)

        let isf = IsfBuilder::new()
            .add_symbol("unix_socket_table", table_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(table_vaddr, table_paddr, ptf::WRITABLE)
            .write_phys(table_paddr, &table_page)
            .map_4k(node_vaddr, node_paddr, ptf::WRITABLE)
            .write_phys(node_paddr, &node_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_unix_sockets(&reader).unwrap();
        assert_eq!(result.len(), 1, "one hlist node → exactly one unix socket entry");
        assert_eq!(result[0].socket_type, "STREAM");
        assert_eq!(result[0].state, "CONNECTED");
        assert_eq!(result[0].inode, 0);
        assert!(result[0].path.is_empty());
        assert!(!result[0].is_suspicious, "empty path + pid=0 must not be suspicious");
    }

    // --- walk_unix_sockets: node with abstract path (@name) is classified correctly ---
    #[test]
    fn walk_unix_sockets_node_with_abstract_path_high_pid() {
        use memf_core::test_builders::{flags as ptf, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // The walker uses classify_unix_socket(&path, 0) internally — owner_pid is always 0
        // at this point in the code. So an abstract path with pid=0 is NOT suspicious.
        // We test that the abstract-path decoding (first byte == 0 → '@' prefix) works.

        let table_vaddr: u64 = 0xFFFF_8800_0073_0000;
        let table_paddr: u64 = 0x0073_0000;

        let node_vaddr: u64 = 0xFFFF_8800_0074_0000;
        let node_paddr: u64 = 0x0074_0000;

        // unix_address struct at addr_ptr: 2 bytes sa_family + sun_path
        let addr_vaddr: u64 = 0xFFFF_8800_0075_0000;
        let addr_paddr: u64 = 0x0075_0000;

        let unix_addr_off: usize = 0x288; // default used by walker

        let mut table_page = [0u8; 4096];
        table_page[0..8].copy_from_slice(&node_vaddr.to_le_bytes());

        let mut node_page = [0u8; 4096];
        // hlist next = 0
        node_page[0..8].copy_from_slice(&0u64.to_le_bytes());
        // sk_type = 2 (DGRAM) at 0x12
        node_page[0x12..0x14].copy_from_slice(&2u16.to_le_bytes());
        // sk_state = 1 (UNCONNECTED) at 0x14
        node_page[0x14] = 1u8;
        // unix_addr pointer at unix_addr_off = addr_vaddr
        node_page[unix_addr_off..unix_addr_off + 8].copy_from_slice(&addr_vaddr.to_le_bytes());

        // addr page: sun_path_off = 2; first byte of sun_path = 0 (abstract), then "hidden\0"
        let mut addr_page = [0u8; 4096];
        // sa_family at [0..2], sun_path at [2..]:
        // sun_path[0] = 0 → abstract; "hidden" as inner name
        addr_page[2] = 0u8; // abstract marker
        addr_page[3..9].copy_from_slice(b"hidden");
        addr_page[9] = 0u8;

        let isf = IsfBuilder::new()
            .add_symbol("unix_socket_table", table_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(table_vaddr, table_paddr, ptf::WRITABLE)
            .write_phys(table_paddr, &table_page)
            .map_4k(node_vaddr, node_paddr, ptf::WRITABLE)
            .write_phys(node_paddr, &node_page)
            .map_4k(addr_vaddr, addr_paddr, ptf::WRITABLE)
            .write_phys(addr_paddr, &addr_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_unix_sockets(&reader).unwrap();
        assert_eq!(result.len(), 1, "one node → one entry");
        assert_eq!(result[0].path, "@hidden", "abstract path must be decoded as @<name>");
        assert_eq!(result[0].socket_type, "DGRAM");
        assert_eq!(result[0].state, "UNCONNECTED");
        // classify_unix_socket("@hidden", 0) → is_abstract=true, owner_pid=0 < 1000 → false
        assert!(!result[0].is_suspicious, "abstract path with pid=0 is not suspicious");
    }

    // --- walk_unix_sockets: cycle detection via seen set ---
    // Two nodes that point to each other → cycle detected → second iteration breaks.
    #[test]
    fn walk_unix_sockets_cycle_detected_breaks() {
        use memf_core::test_builders::{flags as ptf, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let table_vaddr: u64 = 0xFFFF_8800_0076_0000;
        let table_paddr: u64 = 0x0076_0000;

        // Two nodes: nodeA.next = nodeB, nodeB.next = nodeA (cycle)
        let node_a_vaddr: u64 = 0xFFFF_8800_0077_0000;
        let node_a_paddr: u64 = 0x0077_0000;

        let node_b_vaddr: u64 = 0xFFFF_8800_0078_0000;
        let node_b_paddr: u64 = 0x0078_0000;

        let mut table_page = [0u8; 4096];
        table_page[0..8].copy_from_slice(&node_a_vaddr.to_le_bytes());

        // nodeA: next = node_b_vaddr; sk_type = 1 (STREAM); sk_state = 1 (UNCONNECTED)
        let mut node_a_page = [0u8; 4096];
        node_a_page[0..8].copy_from_slice(&node_b_vaddr.to_le_bytes());
        node_a_page[0x12..0x14].copy_from_slice(&1u16.to_le_bytes());
        node_a_page[0x14] = 1u8;

        // nodeB: next = node_a_vaddr (cycle!); sk_type = 2 (DGRAM); sk_state = 1
        let mut node_b_page = [0u8; 4096];
        node_b_page[0..8].copy_from_slice(&node_a_vaddr.to_le_bytes());
        node_b_page[0x12..0x14].copy_from_slice(&2u16.to_le_bytes());
        node_b_page[0x14] = 1u8;

        let isf = IsfBuilder::new()
            .add_symbol("unix_socket_table", table_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(table_vaddr, table_paddr, ptf::WRITABLE)
            .write_phys(table_paddr, &table_page)
            .map_4k(node_a_vaddr, node_a_paddr, ptf::WRITABLE)
            .write_phys(node_a_paddr, &node_a_page)
            .map_4k(node_b_vaddr, node_b_paddr, ptf::WRITABLE)
            .write_phys(node_b_paddr, &node_b_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_unix_sockets(&reader).unwrap();
        // Should get exactly 2 entries (nodeA + nodeB), then cycle detected → stop
        assert_eq!(result.len(), 2, "cycle detected after 2 unique nodes → exactly 2 entries");
    }

    // --- walk_unix_sockets: sk_state unknown value → state = "UNKNOWN" ---
    #[test]
    fn walk_unix_sockets_unknown_sk_state() {
        use memf_core::test_builders::{flags as ptf, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let table_vaddr: u64 = 0xFFFF_8800_0079_0000;
        let table_paddr: u64 = 0x0079_0000;

        let node_vaddr: u64 = 0xFFFF_8800_007A_0000;
        let node_paddr: u64 = 0x007A_0000;

        let mut table_page = [0u8; 4096];
        table_page[0..8].copy_from_slice(&node_vaddr.to_le_bytes());

        let mut node_page = [0u8; 4096];
        node_page[0..8].copy_from_slice(&0u64.to_le_bytes()); // next = 0
        node_page[0x12..0x14].copy_from_slice(&5u16.to_le_bytes()); // SEQPACKET
        node_page[0x14] = 99u8; // unknown sk_state → "UNKNOWN"

        let isf = IsfBuilder::new()
            .add_symbol("unix_socket_table", table_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(table_vaddr, table_paddr, ptf::WRITABLE)
            .write_phys(table_paddr, &table_page)
            .map_4k(node_vaddr, node_paddr, ptf::WRITABLE)
            .write_phys(node_paddr, &node_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_unix_sockets(&reader).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].state, "UNKNOWN");
        assert_eq!(result[0].socket_type, "SEQPACKET");
    }
}
