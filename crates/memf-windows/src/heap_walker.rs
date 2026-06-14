//! Generic process-heap region scanner.
//!
//! Provides [`for_each_heap_region`], which encapsulates the repeated pattern
//! of walking process VADs, filtering to private readable-writable
//! non-executable heap pages, reading each region, and collecting results.
//! All credential walkers delegate to this function.

use std::collections::HashSet;
use std::hash::Hash;

use memf_core::object_reader::ObjectReader;
use memf_core::WalkResult;
use memf_format::PhysicalMemoryProvider;

use crate::{process::walk_processes, types::WinProcessInfo, vad::walk_vad_tree, Result};

/// Maximum bytes consumed from any single VAD region.
///
/// Caps peak memory use when a large anonymous mapping is encountered.
/// Shared by all credential walkers via this module.
pub(crate) const MAX_REGION_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Walk all private, readable-writable, non-executable VAD regions for every
/// process accepted by `filter_fn`, pass each region's bytes to `scan_fn`,
/// and collect the results deduplicated by `key_fn`.
///
/// # Arguments
///
/// * `reader`        — kernel-space `ObjectReader` (kernel CR3 / symbol table).
/// * `ps_head_vaddr` — virtual address of `PsActiveProcessHead`.
/// * `filter_fn`     — returns `true` for processes whose heap should be scanned.
/// * `scan_fn`       — called with `(region_bytes, process)`, returns ≥0 items.
/// * `key_fn`        — extracts a deduplication key from each item.
///
/// # Returns
///
/// A [`WalkResult`] containing all unique items found, plus a count of VAD
/// regions that could not be read (paged-out or truncated in the dump).
pub(crate) fn for_each_heap_region<P, T, K>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
    filter_fn: impl Fn(&WinProcessInfo) -> bool,
    scan_fn: impl Fn(&[u8], &WinProcessInfo) -> Vec<T>,
    key_fn: impl Fn(&T) -> K,
) -> Result<WalkResult<T>>
where
    P: PhysicalMemoryProvider + Clone,
    T: serde::Serialize,
    K: Eq + Hash,
{
    let procs = walk_processes(reader, ps_head_vaddr)?;

    let vad_root_offset = reader.required_field_offset("_EPROCESS", "VadRoot")?;

    let mut result = WalkResult::new(Vec::new(), 0);
    let mut seen: HashSet<K> = HashSet::new();

    for proc in procs.iter().filter(|p| filter_fn(*p)) {
        if proc.cr3 == 0 || proc.peb_addr == 0 {
            continue;
        }

        let vad_root_addr = proc.vaddr.wrapping_add(vad_root_offset as u64);
        // One skip is recorded per unreadable process VAD tree (not per
        // individual region within it). A single failed walk_vad_tree may
        // represent hundreds of unread regions.
        let vads = match walk_vad_tree(reader, vad_root_addr, proc.pid, &proc.image_name) {
            Ok(v) => v,
            Err(_) => {
                result.skip();
                continue;
            }
        };

        let proc_reader = reader.with_cr3(proc.cr3);

        for vad in &vads {
            if !vad.is_private || !vad.protection_str.contains("READWRITE") {
                continue;
            }
            if vad.protection_str.contains("EXECUTE") {
                continue;
            }

            if vad.end_vaddr < vad.start_vaddr {
                continue;
            }
            let region_size = (vad.end_vaddr.saturating_sub(vad.start_vaddr) + 1)
                .min(MAX_REGION_BYTES as u64) as usize;
            if region_size == 0 {
                continue;
            }

            let bytes = match proc_reader.read_bytes(vad.start_vaddr, region_size) {
                Ok(b) => b,
                Err(_) => {
                    result.skip();
                    continue;
                }
            };

            for item in scan_fn(&bytes, proc) {
                let key = key_fn(&item);
                if seen.insert(key) {
                    result.push(item);
                }
            }
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Virtual address used as PsActiveProcessHead in tests.
    /// A self-referential _LIST_ENTRY is mapped here so walk_processes
    /// returns Ok(vec![]) instead of hitting PageNotPresent.
    const PS_HEAD: u64 = 0xFFFF_8000_0010_0000;
    /// Physical backing page for PS_HEAD (must not overlap PageTableBuilder's
    /// internal pages; the builder uses the first few MiB for page tables).
    const PS_HEAD_PHYS: u64 = 0x0050_0000;

    fn make_reader() -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).expect("valid ISF");

        // Build a page at PS_HEAD containing a self-referential _LIST_ENTRY
        // (Flink at offset 0 == PS_HEAD) so walk_list_with terminates immediately
        // with an empty result rather than faulting on address 0.
        let ptb = PageTableBuilder::new()
            .map_4k(PS_HEAD, PS_HEAD_PHYS, flags::PRESENT | flags::WRITABLE)
            .write_phys_u64(PS_HEAD_PHYS, PS_HEAD); // Flink = head → empty list

        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// With PsActiveProcessHead being an empty list, walk_processes returns
    /// Ok(vec![]), so for_each_heap_region must return an empty result.
    #[test]
    fn empty_process_list_yields_empty_result() {
        let reader = make_reader();
        let result = for_each_heap_region(
            &reader,
            PS_HEAD,
            |_p| true,
            |_bytes, _proc| vec!["found".to_string()],
            |s: &String| s.clone(),
        )
        .expect("should not error");
        assert_eq!(result.items.len(), 0);
        assert_eq!(result.skipped, 0);
    }

    /// filter_fn returning false for all processes must yield zero items.
    #[test]
    fn filter_fn_false_for_all_yields_empty() {
        let reader = make_reader();
        let result = for_each_heap_region(
            &reader,
            PS_HEAD,
            |_p| false,
            |_bytes, _proc| vec!["found".to_string()],
            |s: &String| s.clone(),
        )
        .expect("should not error");
        assert_eq!(result.items.len(), 0);
    }

    /// MAX_REGION_BYTES must be exactly 64 MiB.
    #[test]
    fn max_region_bytes_is_64_mib() {
        assert_eq!(
            MAX_REGION_BYTES, 67_108_864,
            "MAX_REGION_BYTES must be exactly 64 MiB"
        );
    }
}
