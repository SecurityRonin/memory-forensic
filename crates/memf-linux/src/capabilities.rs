//! Linux process capabilities analysis for privilege escalation detection.
//!
//! Linux capabilities split root privileges into granular units
//! (CAP_SYS_ADMIN, CAP_NET_RAW, CAP_SYS_PTRACE, etc.). Each process has
//! effective, permitted, and inheritable capability sets stored in
//! `task_struct.cred->cap_effective/cap_permitted/cap_inheritable`.
//!
//! Processes with unusual capabilities -- especially non-root with elevated
//! caps -- indicate privilege escalation and are flagged as suspicious.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, ProcessInfo, Result};

// ---------------------------------------------------------------------------
// Capability bit constants (from include/uapi/linux/capability.h)
// ---------------------------------------------------------------------------

/// Override DAC access restrictions.
const CAP_DAC_OVERRIDE: u64 = 1 << 1;
/// Allow network administration (e.g., interface config, firewall rules).
const CAP_NET_ADMIN: u64 = 1 << 12;
/// Allow raw socket access (packet sniffing, crafting).
const CAP_NET_RAW: u64 = 1 << 13;
/// Allow loading/unloading kernel modules.
const CAP_SYS_MODULE: u64 = 1 << 16;
/// Allow ptrace of any process (process injection, debugging).
const CAP_SYS_PTRACE: u64 = 1 << 19;
/// Catch-all admin capability (mount, sethostname, reboot, etc.).
const CAP_SYS_ADMIN: u64 = 1 << 21;

/// Process capability information extracted from `task_struct.cred`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProcessCapabilities {
    /// Process ID.
    pub pid: u64,
    /// Process command name.
    pub name: String,
    /// Bitmask of effective capabilities.
    pub effective: u64,
    /// Bitmask of permitted capabilities.
    pub permitted: u64,
    /// Bitmask of inheritable capabilities.
    pub inheritable: u64,
    /// True if the process is non-root with elevated capabilities.
    pub is_suspicious: bool,
    /// Names of the suspicious capabilities held by a non-root process.
    pub suspicious_caps: Vec<String>,
}

/// All known capabilities for name lookup.
/// `(bit_value, name)` pairs used by [`cap_name`].
const ALL_CAPS: &[(u64, &str)] = &[
    (CAP_DAC_OVERRIDE, "CAP_DAC_OVERRIDE"),
    (CAP_NET_ADMIN, "CAP_NET_ADMIN"),
    (CAP_NET_RAW, "CAP_NET_RAW"),
    (CAP_SYS_MODULE, "CAP_SYS_MODULE"),
    (CAP_SYS_PTRACE, "CAP_SYS_PTRACE"),
    (CAP_SYS_ADMIN, "CAP_SYS_ADMIN"),
];

/// Map a single capability bit to its human-readable name.
///
/// Returns `"UNKNOWN"` for unrecognized bits.
pub fn cap_name(bit: u64) -> &'static str {
    for &(cap_bit, name) in ALL_CAPS {
        if bit == cap_bit {
            return name;
        }
    }
    "UNKNOWN"
}

/// Classify whether a process's effective capabilities are suspicious.
///
/// A process is suspicious if it is **non-root** (uid != 0) and holds any
/// dangerous capability (e.g. `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_RAW`).
///
/// Returns `(is_suspicious, list_of_suspicious_cap_names)`.
pub use crate::heuristics::classify_capabilities;

/// Walk capability information for each process in the provided list.
///
/// For each process, reads `task_struct.cred` (a pointer to the `cred`
/// struct), then reads `cap_effective`, `cap_permitted`, `cap_inheritable`
/// (each a `kernel_cap_t`, typically a pair of u32s or a single u64
/// depending on kernel version) and `uid` from the `cred` struct.
///
/// Applies [`classify_capabilities`] to flag privilege escalation.
pub fn walk_capabilities<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    processes: &[ProcessInfo],
) -> Result<Vec<ProcessCapabilities>> {
    if processes.is_empty() {
        return Ok(Vec::new());
    }

    let mut results = Vec::with_capacity(processes.len());

    for proc in processes {
        match read_process_caps(reader, proc) {
            Ok(caps) => results.push(caps),
            // Skip processes whose cred is unreadable (e.g., zombie/dead).
            Err(_) => continue,
        }
    }

    Ok(results)
}

/// Read capability information from a single process's `task_struct.cred`.
fn read_process_caps<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    proc: &ProcessInfo,
) -> Result<ProcessCapabilities> {
    // task_struct.cred -> pointer to cred struct
    let cred_ptr: u64 = reader.read_field(proc.vaddr, "task_struct", "cred")?;
    if cred_ptr == 0 {
        return Err(Error::Walker("cred pointer is NULL".into()));
    }

    // cred.uid (kuid_t, effectively u32)
    let uid: u32 = reader.read_field(cred_ptr, "cred", "uid")?;

    // Read capability bitmasks from cred struct.
    // kernel_cap_t is typically { u32 cap[_KERNEL_CAPABILITY_U32S] }.
    // On 64-bit kernels with VFS caps v3 this is a single u64;
    // on older kernels it may be two u32s. We read as u64 which covers
    // both layouts when the field is declared as unsigned long.
    let effective: u64 = reader.read_field(cred_ptr, "cred", "cap_effective")?;
    let permitted: u64 = reader.read_field(cred_ptr, "cred", "cap_permitted")?;
    let inheritable: u64 = reader.read_field(cred_ptr, "cred", "cap_inheritable")?;

    let (is_suspicious, suspicious_caps) = classify_capabilities(effective, uid);

    Ok(ProcessCapabilities {
        pid: proc.pid,
        name: proc.comm.clone(),
        effective,
        permitted,
        inheritable,
        is_suspicious,
        suspicious_caps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Helper: create an ObjectReader from ISF and page table builders.
    fn make_reader(
        isf: &IsfBuilder,
        builder: PageTableBuilder,
    ) -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let json = isf.build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();
        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// Helper: build a minimal ProcessInfo for testing.
    fn fake_process(pid: u64, comm: &str, vaddr: u64) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: 1,
            comm: comm.to_string(),
            state: crate::types::ProcessState::Running,
            vaddr,
            cr3: None,
            start_time: 0,
        }
    }

    #[test]
    fn cap_name_known() {
        assert_eq!(cap_name(CAP_SYS_ADMIN), "CAP_SYS_ADMIN");
        assert_eq!(cap_name(CAP_SYS_PTRACE), "CAP_SYS_PTRACE");
        assert_eq!(cap_name(CAP_NET_RAW), "CAP_NET_RAW");
        assert_eq!(cap_name(CAP_NET_ADMIN), "CAP_NET_ADMIN");
        assert_eq!(cap_name(CAP_SYS_MODULE), "CAP_SYS_MODULE");
        assert_eq!(cap_name(CAP_DAC_OVERRIDE), "CAP_DAC_OVERRIDE");
    }

    #[test]
    fn cap_name_unknown() {
        // A bit that doesn't match any known capability.
        assert_eq!(cap_name(1 << 30), "UNKNOWN");
    }

    #[test]
    fn classify_root_not_suspicious() {
        // Root (uid=0) with all caps set should NOT be flagged.
        let (suspicious, caps) = classify_capabilities(u64::MAX, 0);
        assert!(!suspicious, "root should never be flagged as suspicious");
        assert!(caps.is_empty(), "root should have no suspicious cap names");
    }

    #[test]
    fn classify_nonroot_elevated_suspicious() {
        // Non-root (uid=1000) with CAP_SYS_ADMIN should be flagged.
        let effective = CAP_SYS_ADMIN | CAP_NET_RAW;
        let (suspicious, caps) = classify_capabilities(effective, 1000);
        assert!(
            suspicious,
            "non-root with CAP_SYS_ADMIN should be suspicious"
        );
        assert!(caps.contains(&"CAP_SYS_ADMIN".to_string()));
        assert!(caps.contains(&"CAP_NET_RAW".to_string()));
    }

    #[test]
    fn classify_nonroot_normal_benign() {
        // Non-root (uid=1000) with no special caps should NOT be flagged.
        let effective = CAP_DAC_OVERRIDE | CAP_NET_ADMIN;
        let (suspicious, caps) = classify_capabilities(effective, 1000);
        assert!(
            !suspicious,
            "non-root without critical caps should not be suspicious"
        );
        assert!(caps.is_empty());
    }

    #[test]
    fn walk_capabilities_empty() {
        // Empty process list should return empty Vec.
        let isf = IsfBuilder::new();
        let ptb = PageTableBuilder::new();
        let reader = make_reader(&isf, ptb);

        let result = walk_capabilities(&reader, &[]).unwrap();
        assert!(
            result.is_empty(),
            "expected empty vec for empty process list"
        );
    }

    #[test]
    fn walk_capabilities_reads_cred() {
        // Integration test: set up a synthetic task_struct -> cred -> caps.
        let task_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let task_paddr: u64 = 0x0080_0000;
        let cred_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let cred_paddr: u64 = 0x0090_0000;

        // Offsets within task_struct
        let cred_offset: u64 = 1608; // task_struct.cred

        // Offsets within cred struct
        let uid_offset: u64 = 4; // cred.uid
        let cap_effective_offset: u64 = 40; // cred.cap_effective
        let cap_permitted_offset: u64 = 48; // cred.cap_permitted
        let cap_inheritable_offset: u64 = 56; // cred.cap_inheritable

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 9024)
            .add_field("task_struct", "cred", cred_offset, "pointer")
            .add_struct("cred", 176)
            .add_field("cred", "uid", uid_offset, "unsigned int")
            .add_field(
                "cred",
                "cap_effective",
                cap_effective_offset,
                "unsigned long",
            )
            .add_field(
                "cred",
                "cap_permitted",
                cap_permitted_offset,
                "unsigned long",
            )
            .add_field(
                "cred",
                "cap_inheritable",
                cap_inheritable_offset,
                "unsigned long",
            );

        // uid=1000 (non-root), effective has CAP_SYS_ADMIN
        let effective_caps: u64 = CAP_SYS_ADMIN | CAP_DAC_OVERRIDE;
        let permitted_caps: u64 = CAP_SYS_ADMIN | CAP_DAC_OVERRIDE | CAP_NET_RAW;
        let inheritable_caps: u64 = 0;

        let ptb = PageTableBuilder::new()
            .map_4k(task_vaddr, task_paddr, flags::WRITABLE)
            .map_4k(cred_vaddr, cred_paddr, flags::WRITABLE)
            // Write cred pointer in task_struct
            .write_phys_u64(task_paddr + cred_offset, cred_vaddr)
            // Write uid in cred
            .write_phys_u64(cred_paddr + uid_offset, 1000u64)
            // Write capability bitmasks in cred
            .write_phys_u64(cred_paddr + cap_effective_offset, effective_caps)
            .write_phys_u64(cred_paddr + cap_permitted_offset, permitted_caps)
            .write_phys_u64(cred_paddr + cap_inheritable_offset, inheritable_caps);

        let reader = make_reader(&isf, ptb);
        let procs = vec![fake_process(42, "evil_proc", task_vaddr)];

        let result = walk_capabilities(&reader, &procs).unwrap();
        assert_eq!(result.len(), 1);

        let cap = &result[0];
        assert_eq!(cap.pid, 42);
        assert_eq!(cap.name, "evil_proc");
        assert_eq!(cap.effective, effective_caps);
        assert_eq!(cap.permitted, permitted_caps);
        assert_eq!(cap.inheritable, inheritable_caps);
        assert!(
            cap.is_suspicious,
            "non-root with CAP_SYS_ADMIN should be suspicious"
        );
        assert!(cap.suspicious_caps.contains(&"CAP_SYS_ADMIN".to_string()));
    }

    #[test]
    fn walk_capabilities_root_not_flagged() {
        // Root process with all caps should not be flagged.
        let task_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let task_paddr: u64 = 0x0080_0000;
        let cred_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let cred_paddr: u64 = 0x0090_0000;

        let cred_offset: u64 = 1608;
        let uid_offset: u64 = 4;
        let cap_effective_offset: u64 = 40;
        let cap_permitted_offset: u64 = 48;
        let cap_inheritable_offset: u64 = 56;

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 9024)
            .add_field("task_struct", "cred", cred_offset, "pointer")
            .add_struct("cred", 176)
            .add_field("cred", "uid", uid_offset, "unsigned int")
            .add_field(
                "cred",
                "cap_effective",
                cap_effective_offset,
                "unsigned long",
            )
            .add_field(
                "cred",
                "cap_permitted",
                cap_permitted_offset,
                "unsigned long",
            )
            .add_field(
                "cred",
                "cap_inheritable",
                cap_inheritable_offset,
                "unsigned long",
            );

        let ptb = PageTableBuilder::new()
            .map_4k(task_vaddr, task_paddr, flags::WRITABLE)
            .map_4k(cred_vaddr, cred_paddr, flags::WRITABLE)
            .write_phys_u64(task_paddr + cred_offset, cred_vaddr)
            // uid=0 (root)
            .write_phys_u64(cred_paddr + uid_offset, 0u64)
            .write_phys_u64(cred_paddr + cap_effective_offset, u64::MAX)
            .write_phys_u64(cred_paddr + cap_permitted_offset, u64::MAX)
            .write_phys_u64(cred_paddr + cap_inheritable_offset, 0u64);

        let reader = make_reader(&isf, ptb);
        let procs = vec![fake_process(1, "init", task_vaddr)];

        let result = walk_capabilities(&reader, &procs).unwrap();
        assert_eq!(result.len(), 1);
        assert!(
            !result[0].is_suspicious,
            "root process should not be flagged"
        );
        assert!(result[0].suspicious_caps.is_empty());
    }
}
