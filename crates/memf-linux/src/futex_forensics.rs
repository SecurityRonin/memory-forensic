//! Futex forensics for Linux memory forensics.
//!
//! Walks the kernel `futex_queues` hash table to enumerate all pending
//! futex wait entries. Cross-process futexes from unexpected address ranges
//! and abnormally high waiter counts are flagged as suspicious.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about a futex entry found in the kernel futex hash table.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FutexInfo {
    /// Virtual address of the futex key.
    pub key_address: u64,
    /// PID of the process owning the futex.
    pub owner_pid: u32,
    /// Number of waiters on this futex.
    pub waiter_count: u32,
    /// Futex type: "private" or "shared".
    pub futex_type: String,
    /// True when this futex matches attack patterns (confusion attack or DoS).
    pub is_suspicious: bool,
}

/// Classify whether a futex entry is suspicious.
///
/// Suspicious when:
/// - `waiter_count > 1000` (potential DoS via futex starvation), or
/// - `key_address > 0x7FFF_FFFF_FFFF && owner_pid > 0` (kernel-space key
///   from userspace owner — futex confusion / privilege escalation indicator).
pub fn classify_futex(key_address: u64, owner_pid: u32, waiter_count: u32) -> bool {
    waiter_count > 1000 || (key_address > 0x7FFF_FFFF_FFFF && owner_pid > 0)
}

/// Walk the kernel futex hash table and return all pending futex entries.
///
/// Returns `Ok(Vec::new())` when the `futex_queues` symbol or required ISF
/// offsets are absent (graceful degradation).
pub fn walk_futex_table<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<FutexInfo>> {
    // Graceful degradation: require futex_queues symbol.
    let fq_addr = match reader.symbols().symbol_address("futex_queues") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    // Require futex_hash_bucket struct offsets.
    let chain_offset = match reader.symbols().field_offset("futex_hash_bucket", "chain") {
        Some(off) => off,
        None => return Ok(Vec::new()),
    };

    // futex_hash_bucket size from ISF struct_size; default to 64 bytes.
    let bucket_size: u64 = reader
        .symbols()
        .struct_size("futex_hash_bucket")
        .unwrap_or(64);

    // Default to 256 buckets (a common runtime value).
    let bucket_count: u64 = 256;

    let mut results = Vec::new();

    for i in 0..bucket_count.min(4096) {
        let bucket_addr = fq_addr + i * bucket_size;
        let chain_head = bucket_addr + chain_offset as u64;

        // Read hlist_head.first pointer.
        let first_q: u64 = match reader.read_bytes(chain_head, 8) {
            Ok(b) => u64::from_le_bytes(b.try_into().unwrap_or([0u8; 8])),
            Err(_) => continue,
        };

        let mut q_ptr = first_q;
        let mut waiter_count: u32 = 0;
        let mut guard = 0usize;

        let mut first_key: u64 = 0;
        let mut first_pid: u32 = 0;
        let mut first_type = "private".to_string();

        while q_ptr != 0 && guard < 65536 {
            let key_offset: u64 = reader
                .symbols()
                .field_offset("futex_q", "key")
                .map(|o| o as u64)
                .unwrap_or(16);

            let task_offset: u64 = reader
                .symbols()
                .field_offset("futex_q", "task")
                .map(|o| o as u64)
                .unwrap_or(8);

            if waiter_count == 0 {
                // Read the futex key (first 8 bytes of union futex_key).
                first_key = reader
                    .read_bytes(q_ptr + key_offset, 8)
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .map(u64::from_le_bytes)
                    .unwrap_or(0);

                // Determine shared vs private from key.both.offset bit 1.
                let key_offset_field: u64 = reader
                    .read_bytes(q_ptr + key_offset + 8, 8)
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .map(u64::from_le_bytes)
                    .unwrap_or(0);
                first_type = if key_offset_field & 1 == 0 {
                    "private".to_string()
                } else {
                    "shared".to_string()
                };

                // task → task_struct → pid
                let task_ptr: u64 = reader
                    .read_bytes(q_ptr + task_offset, 8)
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .map(u64::from_le_bytes)
                    .unwrap_or(0);
                if task_ptr != 0 {
                    first_pid = reader
                        .read_field::<u32>(task_ptr, "task_struct", "pid")
                        .unwrap_or(0);
                }
            }

            waiter_count += 1;

            // hlist_node.next is at offset 0.
            q_ptr = reader
                .read_bytes(q_ptr, 8)
                .ok()
                .and_then(|b| b.try_into().ok())
                .map(u64::from_le_bytes)
                .unwrap_or(0);
            guard += 1;
        }

        if waiter_count > 0 {
            let is_suspicious = classify_futex(first_key, first_pid, waiter_count);
            results.push(FutexInfo {
                key_address: first_key,
                owner_pid: first_pid,
                waiter_count,
                futex_type: first_type,
                is_suspicious,
            });
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_no_symbol_reader() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn classify_high_waiter_count_suspicious() {
        assert!(
            classify_futex(0x7FFF_0000_0000, 500, 1001),
            "high waiter count must be suspicious"
        );
    }

    #[test]
    fn classify_exactly_1000_waiters_not_suspicious() {
        assert!(
            !classify_futex(0x7FFF_0000_0000, 500, 1000),
            "exactly 1000 waiters must not be suspicious"
        );
    }

    #[test]
    fn classify_kernel_space_key_from_userspace_owner_suspicious() {
        assert!(
            classify_futex(0x8000_0000_0000, 1234, 1),
            "kernel-space futex key with userspace owner must be suspicious"
        );
    }

    #[test]
    fn classify_kernel_space_key_no_owner_not_suspicious() {
        assert!(
            !classify_futex(0x8000_0000_0000, 0, 1),
            "kernel-space key with pid=0 must not be suspicious"
        );
    }

    #[test]
    fn classify_normal_futex_benign() {
        assert!(
            !classify_futex(0x7F00_0000_1000, 1234, 3),
            "normal futex must not be suspicious"
        );
    }

    #[test]
    fn walk_futex_no_symbol_returns_empty() {
        let reader = make_no_symbol_reader();
        let result = walk_futex_table(&reader).unwrap();
        assert!(
            result.is_empty(),
            "no futex_queues symbol → empty vec expected"
        );
    }

    // --- classify_futex additional branch/boundary coverage ---

    #[test]
    fn classify_futex_waiter_count_zero_benign() {
        assert!(
            !classify_futex(0x7FFF_0000_0000, 0, 0),
            "zero waiters must not be suspicious"
        );
    }

    #[test]
    fn classify_futex_exactly_boundary_key_not_suspicious() {
        // key_address == 0x7FFF_FFFF_FFFF is NOT > 0x7FFF_FFFF_FFFF, so not suspicious
        assert!(
            !classify_futex(0x7FFF_FFFF_FFFF, 1, 1),
            "key at exactly 0x7FFF_FFFF_FFFF must not be suspicious"
        );
    }

    #[test]
    fn classify_futex_key_one_above_boundary_suspicious() {
        // key_address == 0x8000_0000_0000 IS > 0x7FFF_FFFF_FFFF and owner_pid > 0
        assert!(
            classify_futex(0x8000_0000_0000, 1, 1),
            "key just above boundary with non-zero pid must be suspicious"
        );
    }

    #[test]
    fn classify_futex_both_conditions_true_suspicious() {
        // Both high waiter count AND kernel-space key with userspace owner
        assert!(
            classify_futex(0xFFFF_8000_0000_0000, 99, 5000),
            "both conditions true must be suspicious"
        );
    }

    // --- walk_futex_table: symbol present but chain offset missing ---

    #[test]
    fn walk_futex_missing_chain_offset_returns_empty() {
        // futex_queues symbol present but futex_hash_bucket.chain field missing
        let isf = IsfBuilder::new()
            .add_symbol("futex_queues", 0xFFFF_8000_ABCD_0000)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_futex_table(&reader).unwrap();
        assert!(
            result.is_empty(),
            "missing futex_hash_bucket.chain offset → empty vec expected"
        );
    }

    // --- walk_futex_table: symbol + chain offset present but memory unreadable ---

    #[test]
    fn walk_futex_unreadable_bucket_returns_empty() {
        // futex_queues points to an unmapped address, so read_bytes on chain_head fails
        let isf = IsfBuilder::new()
            .add_symbol("futex_queues", 0xDEAD_BEEF_CAFE_0000)
            .add_struct("futex_hash_bucket", 64)
            .add_field("futex_hash_bucket", "chain", 0, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // All 256 buckets will fail to read → no waiters found → empty result
        let result = walk_futex_table(&reader).unwrap();
        assert!(
            result.is_empty(),
            "unreadable bucket memory → empty vec expected"
        );
    }

    // --- walk_futex_table: symbol + chain present, mapped memory, all buckets zero → exercises loop ---
    // Exercises the bucket scanning loop: chain_head reads succeed (memory mapped) but
    // first_q == 0 for every bucket → waiter_count stays 0 → no entries pushed.
    #[test]
    fn walk_futex_symbol_present_mapped_zero_buckets_returns_empty() {
        use memf_core::test_builders::flags as ptf;

        // bucket_size=64, chain at offset 0. 256 buckets = 256*64 = 16384 bytes = 4 pages.
        // We map 4 consecutive 4K pages of zeros.
        let fq_vaddr: u64 = 0xFFFF_8800_00B0_0000;
        let fq_paddr_base: u64 = 0x00B0_0000; // unique, < 16 MB; 4 pages = 0xB0_0000..0xB0_4000

        let isf = IsfBuilder::new()
            .add_symbol("futex_queues", fq_vaddr)
            .add_struct("futex_hash_bucket", 64)
            .add_field("futex_hash_bucket", "chain", 0, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let zero_page = [0u8; 4096];
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(fq_vaddr,                  fq_paddr_base,          ptf::WRITABLE)
            .write_phys(fq_paddr_base,          &zero_page)
            .map_4k(fq_vaddr + 0x1000,          fq_paddr_base + 0x1000, ptf::WRITABLE)
            .write_phys(fq_paddr_base + 0x1000, &zero_page)
            .map_4k(fq_vaddr + 0x2000,          fq_paddr_base + 0x2000, ptf::WRITABLE)
            .write_phys(fq_paddr_base + 0x2000, &zero_page)
            .map_4k(fq_vaddr + 0x3000,          fq_paddr_base + 0x3000, ptf::WRITABLE)
            .write_phys(fq_paddr_base + 0x3000, &zero_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_futex_table(&reader).unwrap();
        assert!(
            result.is_empty(),
            "all-zero buckets (first_q==0) → waiter_count stays 0 → empty results"
        );
    }
}
