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
    pub pid: u64,
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

/// Maximum number of chained filters to follow (cycle protection).
const MAX_FILTER_CHAIN: usize = 256;

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
    if processes.is_empty() {
        return Ok(Vec::new());
    }

    // Verify the required struct fields exist in the symbol table.
    // If seccomp fields are absent, the kernel may not have seccomp support.
    let seccomp_offset = match reader.symbols().field_offset("task_struct", "seccomp") {
        Some(off) => off,
        None => return Ok(Vec::new()),
    };

    // Verify the mode field exists; we don't use the offset directly since
    // read_field resolves it, but its absence means no seccomp support.
    if reader.symbols().field_offset("seccomp", "mode").is_none() {
        return Ok(Vec::new());
    }

    let filter_field_offset = reader.symbols().field_offset("seccomp", "filter");
    let prev_field_offset = reader.symbols().field_offset("seccomp_filter", "prev");

    let mut results = Vec::with_capacity(processes.len());

    for proc in processes {
        let seccomp_base = proc.vaddr + seccomp_offset;

        // Read seccomp.mode (stored as int, we read 4 bytes).
        let mode_raw: u32 = reader
            .read_field(seccomp_base, "seccomp", "mode")
            .unwrap_or(0);
        let seccomp_mode = mode_raw as u8;

        // Count filters in the chain if mode == 2 (filter) and symbols exist.
        let filter_count = if seccomp_mode == 2 {
            if let (Some(_filter_off), Some(_prev_off)) = (filter_field_offset, prev_field_offset) {
                let filter_ptr: u64 = reader
                    .read_field(seccomp_base, "seccomp", "filter")
                    .unwrap_or(0);
                count_filter_chain(reader, filter_ptr)
            } else {
                // We know mode is filter but can't walk the chain.
                0
            }
        } else {
            0
        };

        let is_unconfined = seccomp_mode == 0;

        results.push(SeccompInfo {
            pid: proc.pid,
            comm: proc.comm.clone(),
            seccomp_mode,
            filter_count,
            is_unconfined,
        });
    }

    Ok(results)
}

/// Walk the `seccomp_filter.prev` linked list to count chained filters.
fn count_filter_chain<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    first_filter: u64,
) -> u32 {
    if first_filter == 0 {
        return 0;
    }

    let mut count: u32 = 0;
    let mut current = first_filter;

    for _ in 0..MAX_FILTER_CHAIN {
        if current == 0 {
            break;
        }
        count += 1;

        // Read the `prev` pointer to follow the chain.
        let prev: u64 = reader
            .read_field(current, "seccomp_filter", "prev")
            .unwrap_or(0);
        current = prev;
    }

    count
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
        assert!(
            result.is_empty(),
            "expected empty vec for empty process list"
        );
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
