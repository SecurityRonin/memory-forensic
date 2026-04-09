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

/// Walk Unix domain sockets from kernel memory.
///
/// Looks up `unix_socket_table` (or `init_net.unx.table`) and walks the
/// hash table of `unix_sock` structures, reading path, type, state, and
/// owning PID from each entry.
pub fn walk_unix_sockets<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
) -> Result<Vec<UnixSocketInfo>> {
    todo!()
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
