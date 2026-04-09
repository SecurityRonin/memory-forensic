//! Linux cgroup membership enumeration for container forensics.
//!
//! Enumerates cgroup memberships for processes to identify container isolation
//! (Docker, LXC, Kubernetes pods) and resource limits. Forensically significant
//! for detecting containerized malware or container escapes.
//!
//! MITRE ATT&CK T1610 — Deploy Container.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{ProcessInfo, Result};

/// Cgroup membership information extracted from a process's `task_struct`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CgroupInfo {
    /// Process ID.
    pub pid: u32,
    /// Process command name (from `task_struct.comm`).
    pub comm: String,
    /// Full cgroup path (e.g., "/docker/abc123.../").
    pub cgroup_path: String,
    /// Cgroup controller names (e.g., "cpu,memory,blkio").
    pub controllers: String,
    /// Whether this process is running inside a container.
    pub is_containerized: bool,
    /// Extracted container ID (64-char hex for Docker, or shorter slug).
    pub container_id: String,
    /// Whether the cgroup membership is suspicious (container escape indicator).
    pub is_suspicious: bool,
}

/// Classify a cgroup path to detect container membership and extract container ID.
///
/// Returns `(is_containerized, container_id)`.
///
/// A process is classified as containerized if its cgroup path contains any of:
/// - `/docker/`   — Docker container
/// - `/lxc/`      — LXC container
/// - `/kubepods/` — Kubernetes pod
/// - `/containerd/` — containerd-managed container
///
/// For Docker containers, the container ID is the 64-character hex string
/// following `/docker/`. For other runtimes, the segment after the runtime
/// prefix is extracted as the container ID.
pub fn classify_cgroup(path: &str) -> (bool, String) {
    const RUNTIME_PREFIXES: &[&str] = &["/docker/", "/lxc/", "/kubepods/", "/containerd/"];

    for prefix in RUNTIME_PREFIXES {
        if let Some(idx) = path.find(prefix) {
            let after_prefix = &path[idx + prefix.len()..];
            // Extract the container ID: take everything up to the next '/' or end.
            let id = after_prefix
                .split('/')
                .next()
                .unwrap_or("")
                .to_string();
            return (true, id);
        }
    }

    (false, String::new())
}

/// Classify whether a cgroup path is suspicious (potential container escape).
///
/// Suspicious conditions:
/// - Cgroup path is root `"/"` for a non-init process (PID != 1): suggests
///   the process escaped its cgroup namespace.
/// - Cgroup path contains `"privileged"`: indicates a privileged container
///   which weakens isolation boundaries.
fn is_suspicious_cgroup(path: &str, pid: u32) -> bool {
    // Root cgroup for non-init process suggests escape.
    if path == "/" && pid != 1 {
        return true;
    }

    // Privileged containers weaken isolation.
    if path.contains("privileged") {
        return true;
    }

    false
}

/// Walk cgroup membership information for each process in the provided list.
///
/// Reads `task_struct.cgroups` (pointer to `css_set`) for each process,
/// then traverses `css_set.cg_links` to find `cgroup_subsys_state` entries.
/// Reads the cgroup path from the `cgroup.kn.name` chain. Classifies each
/// process for containerization and suspicious indicators.
///
/// Processes whose cgroup information is unreadable are silently skipped
/// (graceful degradation).
pub fn walk_cgroups<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    processes: &[ProcessInfo],
) -> Result<Vec<CgroupInfo>> {
    // Resolve required field offsets; graceful degradation if missing.
    let cgroups_offset = match reader.symbols().field_offset("task_struct", "cgroups") {
        Some(off) => off,
        None => return Ok(Vec::new()),
    };

    // css_set.subsys is an array of pointers to cgroup_subsys_state.
    // We need css_set to get a cgroup_subsys_state pointer, then follow
    // cgroup_subsys_state.cgroup -> cgroup.kn -> kernfs_node.name.
    // If offsets are missing we fall back to an empty path.
    let subsys_offset = reader
        .symbols()
        .field_offset("css_set", "subsys")
        .unwrap_or(0x10);

    let css_cgroup_offset = reader
        .symbols()
        .field_offset("cgroup_subsys_state", "cgroup")
        .unwrap_or(0x08);

    let cgroup_kn_offset = reader
        .symbols()
        .field_offset("cgroup", "kn")
        .unwrap_or(0x48);

    let kn_name_offset = reader
        .symbols()
        .field_offset("kernfs_node", "name")
        .unwrap_or(0x48);

    let kn_parent_offset = reader
        .symbols()
        .field_offset("kernfs_node", "parent")
        .unwrap_or(0x10);

    let mut results = Vec::new();

    for proc in processes {
        let task_addr = proc.vaddr;

        // Read task_struct.cgroups pointer -> css_set.
        let css_set_ptr: u64 = match reader.read_bytes(task_addr + cgroups_offset, 8) {
            Ok(b) if b.len() == 8 => u64::from_le_bytes(b[..8].try_into().unwrap()),
            _ => continue,
        };
        if css_set_ptr == 0 {
            continue;
        }

        // Read first subsys pointer from css_set.subsys[0].
        let css_ptr: u64 = match reader.read_bytes(css_set_ptr + subsys_offset, 8) {
            Ok(b) if b.len() == 8 => u64::from_le_bytes(b[..8].try_into().unwrap()),
            _ => continue,
        };
        if css_ptr == 0 {
            continue;
        }

        // Follow cgroup_subsys_state -> cgroup.
        let cgroup_ptr: u64 = match reader.read_bytes(css_ptr + css_cgroup_offset, 8) {
            Ok(b) if b.len() == 8 => u64::from_le_bytes(b[..8].try_into().unwrap()),
            _ => continue,
        };
        if cgroup_ptr == 0 {
            continue;
        }

        // Read kernfs_node pointer from cgroup.kn.
        let kn_ptr: u64 = match reader.read_bytes(cgroup_ptr + cgroup_kn_offset, 8) {
            Ok(b) if b.len() == 8 => u64::from_le_bytes(b[..8].try_into().unwrap()),
            _ => continue,
        };

        // Walk the kernfs_node parent chain to reconstruct the path.
        let cgroup_path = if kn_ptr == 0 {
            "/".to_string()
        } else {
            build_kernfs_path(reader, kn_ptr, kn_name_offset, kn_parent_offset)
        };

        let (is_containerized, container_id) = classify_cgroup(&cgroup_path);
        let is_suspicious = is_suspicious_cgroup(&cgroup_path, proc.pid as u32);

        // Controllers: use empty string — would require walking cgroup_subsys array.
        let controllers = String::new();

        results.push(CgroupInfo {
            pid: proc.pid as u32,
            comm: proc.comm.clone(),
            cgroup_path,
            controllers,
            is_containerized,
            container_id,
            is_suspicious,
        });
    }

    Ok(results)
}

/// Walk a `kernfs_node` parent chain and reconstruct a path string.
///
/// Reads the `name` pointer at each node, then follows `parent` until
/// the pointer is null or cycles back. Returns `"/"` on failure.
fn build_kernfs_path<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    kn_ptr: u64,
    name_offset: u64,
    parent_offset: u64,
) -> String {
    let mut segments: Vec<String> = Vec::new();
    let mut current = kn_ptr;
    let mut seen = std::collections::HashSet::new();

    for _ in 0..32 {
        if current == 0 || !seen.insert(current) {
            break;
        }

        // Read name pointer (char *).
        let name_ptr: u64 = match reader.read_bytes(current + name_offset, 8) {
            Ok(b) if b.len() == 8 => u64::from_le_bytes(b[..8].try_into().unwrap()),
            _ => break,
        };

        // Read up to 256 bytes from the name pointer.
        let name = if name_ptr != 0 {
            match reader.read_bytes(name_ptr, 256) {
                Ok(bytes) => {
                    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                    String::from_utf8_lossy(&bytes[..end]).into_owned()
                }
                Err(_) => break,
            }
        } else {
            break;
        };

        if name.is_empty() || name == "/" {
            break;
        }

        segments.push(name);

        // Follow parent pointer.
        current = match reader.read_bytes(current + parent_offset, 8) {
            Ok(b) if b.len() == 8 => u64::from_le_bytes(b[..8].try_into().unwrap()),
            _ => break,
        };
    }

    if segments.is_empty() {
        return "/".to_string();
    }

    // Segments are leaf-to-root; reverse and join.
    segments.reverse();
    format!("/{}", segments.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // classify_cgroup tests
    // -----------------------------------------------------------------------

    #[test]
    fn classify_docker_container() {
        let path = "/system.slice/docker/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2/init.scope";
        let (is_container, id) = classify_cgroup(path);
        assert!(is_container, "Docker path should be classified as containerized");
        assert_eq!(
            id,
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        );
    }

    #[test]
    fn classify_lxc_container() {
        let path = "/lxc/my-container/init.scope";
        let (is_container, id) = classify_cgroup(path);
        assert!(is_container, "LXC path should be classified as containerized");
        assert_eq!(id, "my-container");
    }

    #[test]
    fn classify_kubepods_container() {
        let path = "/kubepods/burstable/pod1234abcd-ef56-7890/container-id-here";
        let (is_container, id) = classify_cgroup(path);
        assert!(is_container, "Kubepods path should be classified as containerized");
        assert_eq!(id, "burstable");
    }

    #[test]
    fn classify_containerd_container() {
        let path = "/system.slice/containerd/abc123def456";
        let (is_container, id) = classify_cgroup(path);
        assert!(is_container, "containerd path should be classified as containerized");
        assert_eq!(id, "abc123def456");
    }

    #[test]
    fn classify_host_process_not_containerized() {
        let path = "/system.slice/sshd.service";
        let (is_container, id) = classify_cgroup(path);
        assert!(!is_container, "Host sshd should NOT be classified as containerized");
        assert!(id.is_empty(), "Non-container should have empty container ID");
    }

    #[test]
    fn classify_root_path_not_containerized() {
        let path = "/";
        let (is_container, id) = classify_cgroup(path);
        assert!(!is_container, "Root path should NOT be classified as containerized");
        assert!(id.is_empty());
    }

    // -----------------------------------------------------------------------
    // is_suspicious_cgroup tests
    // -----------------------------------------------------------------------

    #[test]
    fn suspicious_root_cgroup_non_init() {
        // PID 42 in root cgroup "/" is suspicious (potential escape).
        assert!(
            is_suspicious_cgroup("/", 42),
            "Non-init process in root cgroup should be suspicious"
        );
    }

    #[test]
    fn not_suspicious_root_cgroup_init() {
        // PID 1 (init) in root cgroup "/" is expected.
        assert!(
            !is_suspicious_cgroup("/", 1),
            "Init process in root cgroup should NOT be suspicious"
        );
    }

    #[test]
    fn suspicious_privileged_container() {
        let path = "/docker/abc123/privileged";
        assert!(
            is_suspicious_cgroup(path, 100),
            "Privileged container cgroup should be suspicious"
        );
    }

    #[test]
    fn not_suspicious_normal_container() {
        let path = "/docker/abc123def456/init.scope";
        assert!(
            !is_suspicious_cgroup(path, 100),
            "Normal Docker container cgroup should NOT be suspicious"
        );
    }

    #[test]
    fn not_suspicious_normal_host_service() {
        let path = "/system.slice/sshd.service";
        assert!(
            !is_suspicious_cgroup(path, 500),
            "Normal host service should NOT be suspicious"
        );
    }

    // -----------------------------------------------------------------------
    // CgroupInfo struct tests
    // -----------------------------------------------------------------------

    #[test]
    fn cgroup_info_serializes_to_json() {
        let info = CgroupInfo {
            pid: 42,
            comm: "nginx".to_string(),
            cgroup_path: "/docker/abc123/init.scope".to_string(),
            controllers: "cpu,memory".to_string(),
            is_containerized: true,
            container_id: "abc123".to_string(),
            is_suspicious: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":42"));
        assert!(json.contains("\"is_containerized\":true"));
        assert!(json.contains("\"container_id\":\"abc123\""));
    }

    #[test]
    fn classify_and_suspicious_combined() {
        // Docker path that is also privileged.
        let path = "/docker/deadbeef01234567/privileged";
        let (is_container, id) = classify_cgroup(path);
        let suspicious = is_suspicious_cgroup(path, 99);
        assert!(is_container);
        assert_eq!(id, "deadbeef01234567");
        assert!(suspicious, "Privileged Docker container should be suspicious");
    }
}
