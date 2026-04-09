//! Linux namespace enumeration for container forensics.
//!
//! Enumerates PID/NET/MNT/USER/IPC/UTS/cgroup namespaces from
//! `task_struct.nsproxy`. Critical for detecting Docker/K8s container
//! boundaries and identifying processes that escaped their namespace.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{ProcessInfo, Result};

/// Namespace information extracted from a process's `task_struct.nsproxy`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NamespaceInfo {
    /// Process ID.
    pub pid: u64,
    /// Process command name (from `task_struct.comm`).
    pub image_name: String,
    /// Virtual address of the `uts_namespace` (hostname/domainname isolation).
    pub uts_ns_addr: u64,
    /// Virtual address of the `pid_namespace` (PID isolation).
    pub pid_ns_addr: u64,
    /// Virtual address of the `net` namespace (network isolation).
    pub net_ns_addr: u64,
    /// Virtual address of the `mnt_namespace` (mount isolation).
    pub mnt_ns_addr: u64,
    /// Virtual address of the `ipc_namespace` (IPC isolation).
    pub ipc_ns_addr: u64,
    /// Virtual address of the `cgroup_namespace` (cgroup isolation).
    pub cgroup_ns_addr: u64,
    /// True if this process is in the init (root) namespace.
    ///
    /// Determined by comparing all namespace pointers against PID 1's
    /// namespaces. A process in a container will have at least one
    /// namespace pointer that differs from init's.
    pub is_root_ns: bool,
}

/// Walk the namespace information for each process in the provided list.
///
/// Reads `task_struct.nsproxy` for each process, then dereferences each
/// namespace pointer (`uts_ns`, `ipc_ns`, `mnt_ns`, `pid_ns_for_children`,
/// `net_ns`, `cgroup_ns`). Compares against PID 1's namespaces to determine
/// `is_root_ns`.
///
/// Processes with a null `nsproxy` (e.g., zombie/dead) are skipped.
pub fn walk_namespaces<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
    _processes: &[ProcessInfo],
) -> Result<Vec<NamespaceInfo>> {
    todo!("DFIR-43: implement namespace enumeration")
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    use crate::ProcessState;

    // nsproxy layout (64 bytes):
    //   uts_ns               @ 0   (pointer, 8 bytes)
    //   ipc_ns               @ 8   (pointer, 8 bytes)
    //   mnt_ns               @ 16  (pointer, 8 bytes)
    //   pid_ns_for_children  @ 24  (pointer, 8 bytes)
    //   net_ns               @ 32  (pointer, 8 bytes)
    //   cgroup_ns            @ 40  (pointer, 8 bytes)
    //
    // task_struct layout for namespace tests (160 bytes):
    //   pid          @ 0   (int, 4 bytes)
    //   comm         @ 4   (char, 16 bytes)
    //   nsproxy      @ 24  (pointer, 8 bytes)
    //   total: 160

    const TASK_SIZE: u64 = 160;
    const NSPROXY_SIZE: u64 = 64;

    // nsproxy field offsets
    const NSPROXY_UTS_OFF: usize = 0;
    const NSPROXY_IPC_OFF: usize = 8;
    const NSPROXY_MNT_OFF: usize = 16;
    const NSPROXY_PID_OFF: usize = 24;
    const NSPROXY_NET_OFF: usize = 32;
    const NSPROXY_CGROUP_OFF: usize = 40;

    // task_struct field offsets
    const TASK_PID_OFF: usize = 0;
    const TASK_COMM_OFF: usize = 4;
    const TASK_NSPROXY_OFF: usize = 24;

    fn build_isf() -> serde_json::Value {
        IsfBuilder::new()
            .add_struct("task_struct", TASK_SIZE)
            .add_field("task_struct", "pid", TASK_PID_OFF as u64, "int")
            .add_field("task_struct", "comm", TASK_COMM_OFF as u64, "char")
            .add_field("task_struct", "nsproxy", TASK_NSPROXY_OFF as u64, "pointer")
            .add_struct("nsproxy", NSPROXY_SIZE)
            .add_field("nsproxy", "uts_ns", NSPROXY_UTS_OFF as u64, "pointer")
            .add_field("nsproxy", "ipc_ns", NSPROXY_IPC_OFF as u64, "pointer")
            .add_field("nsproxy", "mnt_ns", NSPROXY_MNT_OFF as u64, "pointer")
            .add_field("nsproxy", "pid_ns_for_children", NSPROXY_PID_OFF as u64, "pointer")
            .add_field("nsproxy", "net_ns", NSPROXY_NET_OFF as u64, "pointer")
            .add_field("nsproxy", "cgroup_ns", NSPROXY_CGROUP_OFF as u64, "pointer")
            .build_json()
    }

    /// Helper: write a process's task_struct into physical memory.
    fn write_task(
        ptb: PageTableBuilder,
        vaddr: u64,
        paddr: u64,
        pid: u32,
        comm: &str,
        nsproxy_vaddr: u64,
    ) -> PageTableBuilder {
        let mut data = vec![0u8; TASK_SIZE as usize];
        data[TASK_PID_OFF..TASK_PID_OFF + 4].copy_from_slice(&pid.to_le_bytes());

        let comm_bytes = comm.as_bytes();
        let len = comm_bytes.len().min(15);
        data[TASK_COMM_OFF..TASK_COMM_OFF + len].copy_from_slice(&comm_bytes[..len]);
        data[TASK_COMM_OFF + len] = 0; // null terminator

        data[TASK_NSPROXY_OFF..TASK_NSPROXY_OFF + 8]
            .copy_from_slice(&nsproxy_vaddr.to_le_bytes());

        ptb.map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &data)
    }

    /// Helper: write an nsproxy struct into physical memory.
    fn write_nsproxy(
        ptb: PageTableBuilder,
        vaddr: u64,
        paddr: u64,
        uts: u64,
        ipc: u64,
        mnt: u64,
        pid_ns: u64,
        net: u64,
        cgroup: u64,
    ) -> PageTableBuilder {
        let mut data = vec![0u8; NSPROXY_SIZE as usize];
        data[NSPROXY_UTS_OFF..NSPROXY_UTS_OFF + 8].copy_from_slice(&uts.to_le_bytes());
        data[NSPROXY_IPC_OFF..NSPROXY_IPC_OFF + 8].copy_from_slice(&ipc.to_le_bytes());
        data[NSPROXY_MNT_OFF..NSPROXY_MNT_OFF + 8].copy_from_slice(&mnt.to_le_bytes());
        data[NSPROXY_PID_OFF..NSPROXY_PID_OFF + 8].copy_from_slice(&pid_ns.to_le_bytes());
        data[NSPROXY_NET_OFF..NSPROXY_NET_OFF + 8].copy_from_slice(&net.to_le_bytes());
        data[NSPROXY_CGROUP_OFF..NSPROXY_CGROUP_OFF + 8].copy_from_slice(&cgroup.to_le_bytes());

        ptb.map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &data)
    }

    fn make_process(pid: u64, comm: &str, vaddr: u64) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: 0,
            comm: comm.to_string(),
            state: ProcessState::Running,
            vaddr,
            cr3: None,
            start_time: 0,
        }
    }

    #[test]
    fn walk_namespaces_empty() {
        // Empty process list should produce empty result.
        let isf = build_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_namespaces(&reader, &[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn walk_namespaces_root_ns() {
        // Single process (PID 1 / init) — should have is_root_ns = true.
        let isf = build_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Addresses (all below 0x100_0000 = 16MB)
        let task1_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let task1_paddr: u64 = 0x0010_0000; // 1MB

        let nsproxy1_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let nsproxy1_paddr: u64 = 0x0020_0000; // 2MB

        // Root namespace addresses (arbitrary non-zero pointers)
        let root_uts: u64 = 0xFFFF_8000_00A0_0000;
        let root_ipc: u64 = 0xFFFF_8000_00A1_0000;
        let root_mnt: u64 = 0xFFFF_8000_00A2_0000;
        let root_pid: u64 = 0xFFFF_8000_00A3_0000;
        let root_net: u64 = 0xFFFF_8000_00A4_0000;
        let root_cgroup: u64 = 0xFFFF_8000_00A5_0000;

        let ptb = PageTableBuilder::new();
        let ptb = write_task(ptb, task1_vaddr, task1_paddr, 1, "systemd", nsproxy1_vaddr);
        let ptb = write_nsproxy(
            ptb,
            nsproxy1_vaddr,
            nsproxy1_paddr,
            root_uts,
            root_ipc,
            root_mnt,
            root_pid,
            root_net,
            root_cgroup,
        );

        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let procs = vec![make_process(1, "systemd", task1_vaddr)];
        let result = walk_namespaces(&reader, &procs).unwrap();

        assert_eq!(result.len(), 1);
        let ns = &result[0];
        assert_eq!(ns.pid, 1);
        assert_eq!(ns.image_name, "systemd");
        assert_eq!(ns.uts_ns_addr, root_uts);
        assert_eq!(ns.pid_ns_addr, root_pid);
        assert_eq!(ns.net_ns_addr, root_net);
        assert_eq!(ns.mnt_ns_addr, root_mnt);
        assert_eq!(ns.ipc_ns_addr, root_ipc);
        assert_eq!(ns.cgroup_ns_addr, root_cgroup);
        assert!(ns.is_root_ns, "PID 1 must be in root namespace");
    }

    #[test]
    fn walk_namespaces_container() {
        // Two processes: PID 1 (init) in root ns, PID 42 in a container
        // with a different net_ns.
        let isf = build_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Task 1 (init) addresses
        let task1_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let task1_paddr: u64 = 0x0010_0000;

        let nsproxy1_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let nsproxy1_paddr: u64 = 0x0020_0000;

        // Task 2 (container) addresses
        let task2_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let task2_paddr: u64 = 0x0030_0000;

        let nsproxy2_vaddr: u64 = 0xFFFF_8000_0040_0000;
        let nsproxy2_paddr: u64 = 0x0040_0000;

        // Root namespace addresses
        let root_uts: u64 = 0xFFFF_8000_00A0_0000;
        let root_ipc: u64 = 0xFFFF_8000_00A1_0000;
        let root_mnt: u64 = 0xFFFF_8000_00A2_0000;
        let root_pid: u64 = 0xFFFF_8000_00A3_0000;
        let root_net: u64 = 0xFFFF_8000_00A4_0000;
        let root_cgroup: u64 = 0xFFFF_8000_00A5_0000;

        // Container gets a different net_ns
        let container_net: u64 = 0xFFFF_8000_00B0_0000;

        let ptb = PageTableBuilder::new();

        // Write init task + nsproxy
        let ptb = write_task(ptb, task1_vaddr, task1_paddr, 1, "systemd", nsproxy1_vaddr);
        let ptb = write_nsproxy(
            ptb,
            nsproxy1_vaddr,
            nsproxy1_paddr,
            root_uts,
            root_ipc,
            root_mnt,
            root_pid,
            root_net,
            root_cgroup,
        );

        // Write container task + nsproxy (same ns except net_ns)
        let ptb = write_task(ptb, task2_vaddr, task2_paddr, 42, "nginx", nsproxy2_vaddr);
        let ptb = write_nsproxy(
            ptb,
            nsproxy2_vaddr,
            nsproxy2_paddr,
            root_uts,
            root_ipc,
            root_mnt,
            root_pid,
            container_net, // different!
            root_cgroup,
        );

        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let procs = vec![
            make_process(1, "systemd", task1_vaddr),
            make_process(42, "nginx", task2_vaddr),
        ];

        let result = walk_namespaces(&reader, &procs).unwrap();

        assert_eq!(result.len(), 2);

        // PID 1 should be in root ns
        let init_ns = result.iter().find(|n| n.pid == 1).unwrap();
        assert!(init_ns.is_root_ns, "PID 1 must be in root namespace");
        assert_eq!(init_ns.net_ns_addr, root_net);

        // PID 42 should NOT be in root ns (different net_ns)
        let container_ns = result.iter().find(|n| n.pid == 42).unwrap();
        assert!(
            !container_ns.is_root_ns,
            "Container process must not be in root namespace"
        );
        assert_eq!(container_ns.net_ns_addr, container_net);
        assert_eq!(container_ns.image_name, "nginx");

        // Shared namespaces should still match
        assert_eq!(container_ns.uts_ns_addr, root_uts);
        assert_eq!(container_ns.ipc_ns_addr, root_ipc);
        assert_eq!(container_ns.mnt_ns_addr, root_mnt);
        assert_eq!(container_ns.pid_ns_addr, root_pid);
        assert_eq!(container_ns.cgroup_ns_addr, root_cgroup);
    }
}
