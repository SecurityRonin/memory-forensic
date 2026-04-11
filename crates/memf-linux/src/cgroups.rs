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
    pub pid: u64,
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
            let id = after_prefix.split('/').next().unwrap_or("").to_string();
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
fn is_suspicious_cgroup(path: &str, pid: u64) -> bool {
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
        let is_suspicious = is_suspicious_cgroup(&cgroup_path, proc.pid);

        // Controllers: use empty string — would require walking cgroup_subsys array.
        let controllers = String::new();

        results.push(CgroupInfo {
            pid: proc.pid,
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
        assert!(
            is_container,
            "Docker path should be classified as containerized"
        );
        assert_eq!(
            id,
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        );
    }

    #[test]
    fn classify_lxc_container() {
        let path = "/lxc/my-container/init.scope";
        let (is_container, id) = classify_cgroup(path);
        assert!(
            is_container,
            "LXC path should be classified as containerized"
        );
        assert_eq!(id, "my-container");
    }

    #[test]
    fn classify_kubepods_container() {
        let path = "/kubepods/burstable/pod1234abcd-ef56-7890/container-id-here";
        let (is_container, id) = classify_cgroup(path);
        assert!(
            is_container,
            "Kubepods path should be classified as containerized"
        );
        assert_eq!(id, "burstable");
    }

    #[test]
    fn classify_containerd_container() {
        let path = "/system.slice/containerd/abc123def456";
        let (is_container, id) = classify_cgroup(path);
        assert!(
            is_container,
            "containerd path should be classified as containerized"
        );
        assert_eq!(id, "abc123def456");
    }

    #[test]
    fn classify_host_process_not_containerized() {
        let path = "/system.slice/sshd.service";
        let (is_container, id) = classify_cgroup(path);
        assert!(
            !is_container,
            "Host sshd should NOT be classified as containerized"
        );
        assert!(
            id.is_empty(),
            "Non-container should have empty container ID"
        );
    }

    #[test]
    fn classify_root_path_not_containerized() {
        let path = "/";
        let (is_container, id) = classify_cgroup(path);
        assert!(
            !is_container,
            "Root path should NOT be classified as containerized"
        );
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
        assert!(
            suspicious,
            "Privileged Docker container should be suspicious"
        );
    }

    // -----------------------------------------------------------------------
    // classify_cgroup: additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn classify_empty_path_not_containerized() {
        let (is_container, id) = classify_cgroup("");
        assert!(!is_container);
        assert!(id.is_empty());
    }

    #[test]
    fn classify_docker_at_root_level() {
        // Docker cgroup directly at /docker/<id>
        let path = "/docker/abc123";
        let (is_container, id) = classify_cgroup(path);
        assert!(is_container);
        assert_eq!(id, "abc123");
    }

    #[test]
    fn classify_docker_id_no_trailing_slash() {
        // Path ends right after container ID
        let path = "/docker/feedcafe1234";
        let (is_container, id) = classify_cgroup(path);
        assert!(is_container);
        assert_eq!(id, "feedcafe1234");
    }

    #[test]
    fn classify_kubepods_nested_id() {
        // kubepods with nested path: first segment after /kubepods/ is "besteffort"
        let path = "/kubepods/besteffort/podXYZ/container123";
        let (is_container, id) = classify_cgroup(path);
        assert!(is_container);
        assert_eq!(id, "besteffort");
    }

    #[test]
    fn classify_containerd_empty_after_prefix() {
        // Unusual: /containerd/ with nothing after
        let path = "/containerd/";
        let (is_container, id) = classify_cgroup(path);
        assert!(is_container);
        // After /containerd/ and split('/'), first element is ""
        assert_eq!(id, "");
    }

    // -----------------------------------------------------------------------
    // is_suspicious_cgroup: boundary tests
    // -----------------------------------------------------------------------

    #[test]
    fn not_suspicious_non_root_path_pid_1() {
        // PID 1 in a non-root path is NOT suspicious
        assert!(!is_suspicious_cgroup("/system.slice/init.scope", 1));
    }

    #[test]
    fn not_suspicious_root_cgroup_pid_0() {
        // PID 0 (idle thread) in root cgroup — unusual but pid != 1 check matters
        // pid=0 IS != 1, so it IS suspicious
        assert!(is_suspicious_cgroup("/", 0));
    }

    #[test]
    fn suspicious_privileged_in_any_path() {
        // The word "privileged" anywhere in path is suspicious regardless of PID
        assert!(is_suspicious_cgroup("/kubepods/privileged/pod1", 1));
    }

    // -----------------------------------------------------------------------
    // walk_cgroups: missing field offset → empty Vec
    // -----------------------------------------------------------------------

    #[test]
    fn walk_cgroups_no_cgroups_field_returns_empty() {
        use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;
        use crate::ProcessInfo;

        // task_struct without a "cgroups" field → walk_cgroups returns Ok(empty)
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            // deliberately no "cgroups" field
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let processes: Vec<ProcessInfo> = vec![];
        let result = walk_cgroups(&reader, &processes).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn walk_cgroups_empty_process_list_returns_empty() {
        use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;
        use crate::ProcessInfo;

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "cgroups", 64, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        // Empty process list → empty results regardless of offsets
        let processes: Vec<ProcessInfo> = vec![];
        let result = walk_cgroups(&reader, &processes).unwrap();
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // walk_cgroups: cgroups field present, process list non-empty,
    // css_set pointer == 0 → body runs but skips the process
    // -----------------------------------------------------------------------

    #[test]
    fn walk_cgroups_css_set_null_produces_no_output() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags as ptflags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;
        use crate::ProcessInfo;

        let task_vaddr: u64 = 0xFFFF_8800_0050_0000;
        let task_paddr: u64 = 0x0060_0000;
        let cgroups_offset = 64u64;

        let mut page = [0u8; 4096];
        // cgroups pointer at offset 64 = 0 (NULL → skip)
        page[cgroups_offset as usize..cgroups_offset as usize + 8]
            .copy_from_slice(&0u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "cgroups", 64, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(task_vaddr, task_paddr, ptflags::WRITABLE)
            .write_phys(task_paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let processes = vec![ProcessInfo {
            pid: 42,
            ppid: 1,
            comm: "bash".to_string(),
            state: crate::ProcessState::Running,
            vaddr: task_vaddr,
            cr3: None,
            start_time: 0,
        }];

        let result = walk_cgroups(&reader, &processes).unwrap();
        assert!(result.is_empty(), "process with css_set==NULL should produce no cgroup output");
    }

    // -----------------------------------------------------------------------
    // walk_cgroups: css_set non-null, subsys_ptr (css_ptr) == 0 → skips process
    // Exercises lines after the css_set_ptr != 0 check.
    // -----------------------------------------------------------------------

    #[test]
    fn walk_cgroups_css_ptr_null_skips_process() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags as ptflags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // task_addr holds:  cgroups_offset(64) → css_set_vaddr (non-zero)
        // css_set_vaddr holds: subsys_offset(0x10) → 0  (null css_ptr → skip)
        let task_vaddr: u64   = 0xFFFF_8800_0070_0000;
        let task_paddr: u64   = 0x0070_0000;
        let cssset_vaddr: u64 = 0xFFFF_8800_0071_0000;
        let cssset_paddr: u64 = 0x0071_0000;
        let cgroups_offset: u64 = 64;
        let subsys_offset: u64  = 0x10;

        let mut task_page = [0u8; 4096];
        task_page[cgroups_offset as usize..cgroups_offset as usize + 8]
            .copy_from_slice(&cssset_vaddr.to_le_bytes());

        let mut cssset_page = [0u8; 4096];
        // subsys[0] at subsys_offset = 0 → css_ptr is null → process skipped
        cssset_page[subsys_offset as usize..subsys_offset as usize + 8]
            .copy_from_slice(&0u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 256)
            .add_field("task_struct", "cgroups", 64, "pointer")
            .add_struct("css_set", 256)
            .add_field("css_set", "subsys", 0x10, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(task_vaddr,   task_paddr,   ptflags::WRITABLE)
            .write_phys(task_paddr,   &task_page)
            .map_4k(cssset_vaddr, cssset_paddr, ptflags::WRITABLE)
            .write_phys(cssset_paddr, &cssset_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let processes = vec![ProcessInfo {
            pid: 55,
            ppid: 1,
            comm: "bash".to_string(),
            state: crate::ProcessState::Running,
            vaddr: task_vaddr,
            cr3: None,
            start_time: 0,
        }];

        let result = walk_cgroups(&reader, &processes).unwrap();
        assert!(result.is_empty(), "null css_ptr should skip the process");
    }

    // -----------------------------------------------------------------------
    // walk_cgroups: css_set and css_ptr non-null, cgroup_ptr == 0 → skips process
    // Exercises the cgroup_ptr == 0 guard.
    // -----------------------------------------------------------------------

    #[test]
    fn walk_cgroups_cgroup_ptr_null_skips_process() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags as ptflags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let task_vaddr: u64   = 0xFFFF_8800_0072_0000;
        let task_paddr: u64   = 0x0072_0000;
        let cssset_vaddr: u64 = 0xFFFF_8800_0073_0000;
        let cssset_paddr: u64 = 0x0073_0000;
        let css_vaddr: u64    = 0xFFFF_8800_0074_0000;
        let css_paddr: u64    = 0x0074_0000;
        let cgroups_offset: u64 = 64;
        let subsys_offset: u64  = 0x10;
        let css_cgroup_offset: u64 = 0x08;

        let mut task_page = [0u8; 4096];
        task_page[cgroups_offset as usize..cgroups_offset as usize + 8]
            .copy_from_slice(&cssset_vaddr.to_le_bytes());

        let mut cssset_page = [0u8; 4096];
        cssset_page[subsys_offset as usize..subsys_offset as usize + 8]
            .copy_from_slice(&css_vaddr.to_le_bytes());

        let mut css_page = [0u8; 4096];
        // cgroup_subsys_state.cgroup at offset 0x08 = 0 (null → skip)
        css_page[css_cgroup_offset as usize..css_cgroup_offset as usize + 8]
            .copy_from_slice(&0u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 256)
            .add_field("task_struct", "cgroups", 64, "pointer")
            .add_struct("css_set", 256)
            .add_field("css_set", "subsys", 0x10, "pointer")
            .add_struct("cgroup_subsys_state", 256)
            .add_field("cgroup_subsys_state", "cgroup", 0x08, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(task_vaddr,   task_paddr,   ptflags::WRITABLE)
            .write_phys(task_paddr,   &task_page)
            .map_4k(cssset_vaddr, cssset_paddr, ptflags::WRITABLE)
            .write_phys(cssset_paddr, &cssset_page)
            .map_4k(css_vaddr,    css_paddr,    ptflags::WRITABLE)
            .write_phys(css_paddr,    &css_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let processes = vec![ProcessInfo {
            pid: 66,
            ppid: 1,
            comm: "bash".to_string(),
            state: crate::ProcessState::Running,
            vaddr: task_vaddr,
            cr3: None,
            start_time: 0,
        }];

        let result = walk_cgroups(&reader, &processes).unwrap();
        assert!(result.is_empty(), "null cgroup_ptr should skip the process");
    }

    // -----------------------------------------------------------------------
    // walk_cgroups: full path to kn_ptr == 0 → cgroup_path = "/" → result pushed
    // Exercises kn_ptr==0 branch → build_kernfs_path not called → "/" path.
    // -----------------------------------------------------------------------

    #[test]
    fn walk_cgroups_kn_ptr_zero_produces_root_path_result() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags as ptflags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let task_vaddr: u64   = 0xFFFF_8800_0075_0000;
        let task_paddr: u64   = 0x0075_0000;
        let cssset_vaddr: u64 = 0xFFFF_8800_0076_0000;
        let cssset_paddr: u64 = 0x0076_0000;
        let css_vaddr: u64    = 0xFFFF_8800_0077_0000;
        let css_paddr: u64    = 0x0077_0000;
        let cgroup_vaddr: u64 = 0xFFFF_8800_0078_0000;
        let cgroup_paddr: u64 = 0x0078_0000;

        let cgroups_offset: u64      = 64;
        let subsys_offset: u64       = 0x10;
        let css_cgroup_offset: u64   = 0x08;
        let cgroup_kn_offset: u64    = 0x48;

        let mut task_page = [0u8; 4096];
        task_page[cgroups_offset as usize..cgroups_offset as usize + 8]
            .copy_from_slice(&cssset_vaddr.to_le_bytes());

        let mut cssset_page = [0u8; 4096];
        cssset_page[subsys_offset as usize..subsys_offset as usize + 8]
            .copy_from_slice(&css_vaddr.to_le_bytes());

        let mut css_page = [0u8; 4096];
        css_page[css_cgroup_offset as usize..css_cgroup_offset as usize + 8]
            .copy_from_slice(&cgroup_vaddr.to_le_bytes());

        let mut cgroup_page = [0u8; 4096];
        // kn at offset 0x48 = 0 → kn_ptr == 0 → cgroup_path = "/"
        cgroup_page[cgroup_kn_offset as usize..cgroup_kn_offset as usize + 8]
            .copy_from_slice(&0u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 256)
            .add_field("task_struct", "cgroups", 64, "pointer")
            .add_struct("css_set", 256)
            .add_field("css_set", "subsys", 0x10, "pointer")
            .add_struct("cgroup_subsys_state", 256)
            .add_field("cgroup_subsys_state", "cgroup", 0x08, "pointer")
            .add_struct("cgroup", 512)
            .add_field("cgroup", "kn", 0x48, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(task_vaddr,    task_paddr,    ptflags::WRITABLE)
            .write_phys(task_paddr,    &task_page)
            .map_4k(cssset_vaddr,  cssset_paddr,  ptflags::WRITABLE)
            .write_phys(cssset_paddr,  &cssset_page)
            .map_4k(css_vaddr,     css_paddr,     ptflags::WRITABLE)
            .write_phys(css_paddr,     &css_page)
            .map_4k(cgroup_vaddr,  cgroup_paddr,  ptflags::WRITABLE)
            .write_phys(cgroup_paddr,  &cgroup_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let processes = vec![ProcessInfo {
            pid: 77,
            ppid: 1,
            comm: "bash".to_string(),
            state: crate::ProcessState::Running,
            vaddr: task_vaddr,
            cr3: None,
            start_time: 0,
        }];

        let result = walk_cgroups(&reader, &processes).unwrap();
        // kn_ptr==0 → cgroup_path = "/" → is_suspicious_cgroup("/", 77) = true (pid≠1)
        assert_eq!(result.len(), 1, "full chain resolved → one result pushed");
        assert_eq!(result[0].cgroup_path, "/");
        assert_eq!(result[0].pid, 77);
        assert!(result[0].is_suspicious, "root cgroup for non-init pid is suspicious");
    }

    // -----------------------------------------------------------------------
    // walk_cgroups: full chain with non-zero kn_ptr → build_kernfs_path called
    // Exercises build_kernfs_path body (lines 205-253): name pointer readable,
    // parent pointer readable, loop walks one node then hits a null parent.
    // -----------------------------------------------------------------------

    #[test]
    fn walk_cgroups_kn_ptr_nonzero_builds_path() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags as ptflags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Memory layout (all physical addrs < 16 MB):
        //   task        @ task_vaddr  / task_paddr
        //   css_set     @ cssset_vaddr / cssset_paddr
        //   css         @ css_vaddr   / css_paddr
        //   cgroup_node @ cgroup_vaddr / cgroup_paddr
        //   kn_node     @ kn_vaddr    / kn_paddr        (kernfs_node)
        //   name_str    @ name_vaddr  / name_paddr       ("docker\0")
        //
        // Offsets (all using defaults / ISF-specified):
        //   task.cgroups       @ 64
        //   css_set.subsys     @ 0x10
        //   cgroup_ss.cgroup   @ 0x08
        //   cgroup.kn          @ 0x48
        //   kernfs_node.name   @ 0x48  (pointer to name string)
        //   kernfs_node.parent @ 0x10  (pointer to parent node, null = root)

        let task_vaddr:   u64 = 0xFFFF_8800_0079_0000;
        let task_paddr:   u64 = 0x0079_0000;
        let cssset_vaddr: u64 = 0xFFFF_8800_007A_0000;
        let cssset_paddr: u64 = 0x007A_0000;
        let css_vaddr:    u64 = 0xFFFF_8800_007B_0000;
        let css_paddr:    u64 = 0x007B_0000;
        let cgroup_vaddr: u64 = 0xFFFF_8800_007C_0000;
        let cgroup_paddr: u64 = 0x007C_0000;
        let kn_vaddr:     u64 = 0xFFFF_8800_007D_0000;
        let kn_paddr:     u64 = 0x007D_0000;
        let name_vaddr:   u64 = 0xFFFF_8800_007E_0000;
        let name_paddr:   u64 = 0x007E_0000;

        let cgroups_offset:    u64 = 64;
        let subsys_offset:     u64 = 0x10;
        let css_cgroup_offset: u64 = 0x08;
        let cgroup_kn_offset:  u64 = 0x48;
        let kn_name_offset:    u64 = 0x48;
        let kn_parent_offset:  u64 = 0x10;

        // task page
        let mut task_page = [0u8; 4096];
        task_page[cgroups_offset as usize..cgroups_offset as usize + 8]
            .copy_from_slice(&cssset_vaddr.to_le_bytes());

        // css_set page
        let mut cssset_page = [0u8; 4096];
        cssset_page[subsys_offset as usize..subsys_offset as usize + 8]
            .copy_from_slice(&css_vaddr.to_le_bytes());

        // css (cgroup_subsys_state) page
        let mut css_page = [0u8; 4096];
        css_page[css_cgroup_offset as usize..css_cgroup_offset as usize + 8]
            .copy_from_slice(&cgroup_vaddr.to_le_bytes());

        // cgroup page: kn @ 0x48 = kn_vaddr (non-zero)
        let mut cgroup_page = [0u8; 4096];
        cgroup_page[cgroup_kn_offset as usize..cgroup_kn_offset as usize + 8]
            .copy_from_slice(&kn_vaddr.to_le_bytes());

        // kernfs_node page:
        //   name   @ kn_name_offset   = name_vaddr (pointer to name string)
        //   parent @ kn_parent_offset = 0          (null = root, stops walk)
        let mut kn_page = [0u8; 4096];
        kn_page[kn_name_offset as usize..kn_name_offset as usize + 8]
            .copy_from_slice(&name_vaddr.to_le_bytes());
        // parent already 0

        // name string page: "docker\0"
        let mut name_page = [0u8; 4096];
        name_page[..7].copy_from_slice(b"docker\0");

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 256)
            .add_field("task_struct", "cgroups", 64u64, "pointer")
            .add_struct("css_set", 256)
            .add_field("css_set", "subsys", 0x10u64, "pointer")
            .add_struct("cgroup_subsys_state", 256)
            .add_field("cgroup_subsys_state", "cgroup", 0x08u64, "pointer")
            .add_struct("cgroup", 512)
            .add_field("cgroup", "kn", 0x48u64, "pointer")
            .add_struct("kernfs_node", 512)
            .add_field("kernfs_node", "name", 0x48u64, "pointer")
            .add_field("kernfs_node", "parent", 0x10u64, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(task_vaddr,   task_paddr,   ptflags::WRITABLE)
            .write_phys(task_paddr,   &task_page)
            .map_4k(cssset_vaddr, cssset_paddr, ptflags::WRITABLE)
            .write_phys(cssset_paddr, &cssset_page)
            .map_4k(css_vaddr,    css_paddr,    ptflags::WRITABLE)
            .write_phys(css_paddr,    &css_page)
            .map_4k(cgroup_vaddr, cgroup_paddr, ptflags::WRITABLE)
            .write_phys(cgroup_paddr, &cgroup_page)
            .map_4k(kn_vaddr,     kn_paddr,     ptflags::WRITABLE)
            .write_phys(kn_paddr,     &kn_page)
            .map_4k(name_vaddr,   name_paddr,   ptflags::WRITABLE)
            .write_phys(name_paddr,   &name_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let processes = vec![crate::ProcessInfo {
            pid: 99,
            ppid: 1,
            comm: "nginx".to_string(),
            state: crate::ProcessState::Running,
            vaddr: task_vaddr,
            cr3: None,
            start_time: 0,
        }];

        let result = walk_cgroups(&reader, &processes).unwrap();
        assert_eq!(result.len(), 1, "full chain should produce one CgroupInfo");
        // build_kernfs_path reads "docker" as the leaf segment, parent=null → stops
        // segments = ["docker"], reversed = ["docker"] → path = "/docker"
        assert_eq!(result[0].cgroup_path, "/docker");
        assert_eq!(result[0].pid, 99);
        // /docker is not containerized (no container ID extracted this way) but
        // classify_cgroup("/docker") → matches /docker/ prefix only if there's more after,
        // actually "/docker" does not match "/docker/" since there's no trailing /id
        // so is_containerized = false, is_suspicious = false (path != "/" and no "privileged")
        assert!(!result[0].is_suspicious);
    }

    // -----------------------------------------------------------------------
    // CgroupInfo: Debug + Clone
    // -----------------------------------------------------------------------

    #[test]
    fn cgroup_info_clone_and_debug() {
        let info = CgroupInfo {
            pid: 1,
            comm: "init".to_string(),
            cgroup_path: "/".to_string(),
            controllers: String::new(),
            is_containerized: false,
            container_id: String::new(),
            is_suspicious: false,
        };
        let cloned = info.clone();
        assert_eq!(cloned.pid, 1);
        let dbg = format!("{:?}", cloned);
        assert!(dbg.contains("init"));
    }
}
