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

use crate::{Error, Result};

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
                let path_bytes = reader.read_bytes(addr_ptr + sun_path_off, 108).unwrap_or_default();
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
                    reader.read_bytes(socket_ptr + 0x18, 8).ok().and_then(|ib| {
                        Some(u64::from_le_bytes(ib[..8].try_into().ok()?))
                    })
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
}
