//! Linux seccomp-BPF filter analysis for container security forensics.
//!
//! Seccomp (secure computing) profiles restrict the syscalls available to
//! a process. In containerized environments, seccomp-BPF filters are the
//! primary syscall-level sandbox. Analyzing these from memory helps detect
//! container escape attempts -- processes running with no seccomp filter
//! (unconfined) inside a container are highly suspicious.
//!
//! The kernel stores seccomp state in `task_struct.seccomp`:
//! - `seccomp.mode`: 0 = disabled, 1 = strict, 2 = filter
//! - `seccomp.filter`: pointer to a chain of `seccomp_filter` structs
//!   linked via `seccomp_filter.prev`.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{ProcessInfo, Result};

/// Seccomp profile information extracted from a process's `task_struct`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SeccompInfo {
    /// Process ID.
    pub pid: u32,
    /// Process command name.
    pub comm: String,
    /// Seccomp mode: 0 = disabled, 1 = strict, 2 = filter.
    pub seccomp_mode: u8,
    /// Number of chained seccomp-BPF filters.
    pub filter_count: u32,
    /// True if the process has no seccomp enforcement at all.
    /// Suspicious for containerized workloads.
    pub is_unconfined: bool,
}

/// Walk seccomp profile information for each process in the provided list.
///
/// For each process, reads `task_struct.seccomp.mode` to determine the
/// seccomp enforcement level. When mode is 2 (filter), follows the
/// `seccomp.filter` pointer chain (`seccomp_filter.prev`) to count the
/// number of stacked BPF filters.
///
/// Returns `Ok(Vec::new())` if the required struct/field symbols are
/// missing from the profile (e.g., older kernel without seccomp support).
pub fn walk_seccomp_profiles<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    processes: &[ProcessInfo],
) -> Result<Vec<SeccompInfo>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Helper: build an ObjectReader from an IsfBuilder and PageTableBuilder.
    fn make_reader(
        isf: &IsfBuilder,
        ptb: PageTableBuilder,
    ) -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let json = isf.build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();
        let (cr3, mem) = ptb.build();
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
    fn walk_seccomp_empty() {
        // Empty process list should return empty Vec.
        let isf = IsfBuilder::new();
        let ptb = PageTableBuilder::new();
        let reader = make_reader(&isf, ptb);

        let result = walk_seccomp_profiles(&reader, &[]).unwrap();
        assert!(result.is_empty(), "expected empty vec for empty process list");
    }

    #[test]
    fn seccomp_mode_disabled() {
        // A process with seccomp mode 0 should be flagged as unconfined.
        let task_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let task_paddr: u64 = 0x0080_0000;
        // seccomp struct offset within task_struct: we define it at offset 2048
        // seccomp.mode is an int at offset 0 within seccomp struct
        let seccomp_offset: u64 = 2048;

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 9024)
            .add_field("task_struct", "seccomp", seccomp_offset, "seccomp")
            .add_struct("seccomp", 16)
            .add_field("seccomp", "mode", 0, "int")
            .add_field("seccomp", "filter", 8, "pointer");

        let ptb = PageTableBuilder::new()
            .map_4k(task_vaddr, task_paddr, flags::WRITABLE)
            // Write seccomp.mode = 0 (disabled) at task_struct + seccomp_offset + 0
            .write_phys_u64(task_paddr + seccomp_offset, 0u64);

        let reader = make_reader(&isf, ptb);
        let procs = vec![fake_process(100, "nginx", task_vaddr)];

        let result = walk_seccomp_profiles(&reader, &procs).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].pid, 100);
        assert_eq!(result[0].seccomp_mode, 0);
        assert!(result[0].is_unconfined, "mode 0 should be unconfined");
        assert_eq!(result[0].filter_count, 0);
    }

    #[test]
    fn seccomp_mode_filter() {
        // A process with seccomp mode 2 (filter) and one filter in the chain.
        let task_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let task_paddr: u64 = 0x0040_0000;
        let filter_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let filter_paddr: u64 = 0x0060_0000;
        let seccomp_offset: u64 = 2048;

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 9024)
            .add_field("task_struct", "seccomp", seccomp_offset, "seccomp")
            .add_struct("seccomp", 16)
            .add_field("seccomp", "mode", 0, "int")
            .add_field("seccomp", "filter", 8, "pointer")
            .add_struct("seccomp_filter", 16)
            .add_field("seccomp_filter", "prev", 0, "pointer");

        let ptb = PageTableBuilder::new()
            .map_4k(task_vaddr, task_paddr, flags::WRITABLE)
            .map_4k(filter_vaddr, filter_paddr, flags::WRITABLE)
            // seccomp.mode = 2 (filter)
            .write_phys_u64(task_paddr + seccomp_offset, 2u64)
            // seccomp.filter = pointer to filter struct
            .write_phys_u64(task_paddr + seccomp_offset + 8, filter_vaddr)
            // filter.prev = 0 (null, end of chain — single filter)
            .write_phys_u64(filter_paddr, 0u64);

        let reader = make_reader(&isf, ptb);
        let procs = vec![fake_process(200, "containerd", task_vaddr)];

        let result = walk_seccomp_profiles(&reader, &procs).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].pid, 200);
        assert_eq!(result[0].comm, "containerd");
        assert_eq!(result[0].seccomp_mode, 2);
        assert!(!result[0].is_unconfined, "mode 2 should not be unconfined");
        assert_eq!(result[0].filter_count, 1);
    }
}
