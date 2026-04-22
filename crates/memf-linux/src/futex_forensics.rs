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

    // --- FutexInfo: Clone + Debug + Serialize ---

    #[test]
    fn futex_info_clone_debug_serialize() {
        let info = FutexInfo {
            key_address: 0x7F00_0000_1000,
            owner_pid: 42,
            waiter_count: 3,
            futex_type: "private".to_string(),
            is_suspicious: false,
        };
        let cloned = info.clone();
        assert_eq!(cloned.owner_pid, 42);
        let dbg = format!("{:?}", cloned);
        assert!(dbg.contains("private"));
        let json = serde_json::to_string(&cloned).unwrap();
        assert!(json.contains("\"owner_pid\":42"));
        assert!(json.contains("\"is_suspicious\":false"));
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
            .map_4k(fq_vaddr, fq_paddr_base, ptf::WRITABLE)
            .write_phys(fq_paddr_base, &zero_page)
            .map_4k(fq_vaddr + 0x1000, fq_paddr_base + 0x1000, ptf::WRITABLE)
            .write_phys(fq_paddr_base + 0x1000, &zero_page)
            .map_4k(fq_vaddr + 0x2000, fq_paddr_base + 0x2000, ptf::WRITABLE)
            .write_phys(fq_paddr_base + 0x2000, &zero_page)
            .map_4k(fq_vaddr + 0x3000, fq_paddr_base + 0x3000, ptf::WRITABLE)
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

    // --- walk_futex_table: first bucket has a non-zero chain pointer → exercises while loop ---
    // Maps a futex_hash_bucket whose chain (hlist_head.first) points to a futex_q node.
    // The node's hlist_node.next (offset 0) is zero → loop runs once → waiter_count==1 →
    // an entry is pushed to results.
    #[test]
    fn walk_futex_one_waiter_pushes_result() {
        use memf_core::test_builders::flags as ptf;

        // Layout:
        //   bucket page (vaddr B):  [0..8]  = ptr to futex_q node (vaddr N)
        //   node page   (vaddr N):  [0..8]  = 0 (hlist_node.next = null → loop ends)
        //                           [8..16] = 0 (task ptr = 0 → first_pid stays 0)
        //                           [16..24]= 0 (key = 0)
        //                           [24..32]= 0 (key_offset_field → "private")
        let bucket_vaddr: u64 = 0xFFFF_8800_00C0_0000;
        let bucket_paddr: u64 = 0x00C0_0000; // < 16 MB
        let node_vaddr: u64 = 0xFFFF_8800_00C1_0000;
        let node_paddr: u64 = 0x00C1_0000;

        let mut bucket_page = [0u8; 4096];
        // chain at offset 0 points to node
        bucket_page[0..8].copy_from_slice(&node_vaddr.to_le_bytes());

        let node_page = [0u8; 4096]; // all zeros: next=0, task=0, key=0

        let isf = IsfBuilder::new()
            .add_symbol("futex_queues", bucket_vaddr)
            .add_struct("futex_hash_bucket", 64)
            .add_field("futex_hash_bucket", "chain", 0, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(bucket_vaddr, bucket_paddr, ptf::WRITABLE)
            .write_phys(bucket_paddr, &bucket_page)
            .map_4k(node_vaddr, node_paddr, ptf::WRITABLE)
            .write_phys(node_paddr, &node_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_futex_table(&reader).unwrap();
        // First bucket has one waiter (node_vaddr → next=0) → one FutexInfo pushed.
        assert_eq!(result.len(), 1, "one waiter in first bucket → one result");
        assert_eq!(result[0].waiter_count, 1);
        assert_eq!(result[0].futex_type, "private");
        assert!(!result[0].is_suspicious, "key=0, pid=0, count=1 → benign");
    }

    // --- walk_futex_table: shared futex (key_offset_field bit 0 == 1) → futex_type "shared" ---
    #[test]
    fn walk_futex_shared_futex_type_detected() {
        use memf_core::test_builders::flags as ptf;

        let bucket_vaddr: u64 = 0xFFFF_8800_00D0_0000;
        let bucket_paddr: u64 = 0x00D0_0000;
        let node_vaddr: u64 = 0xFFFF_8800_00D1_0000;
        let node_paddr: u64 = 0x00D1_0000;

        let mut bucket_page = [0u8; 4096];
        bucket_page[0..8].copy_from_slice(&node_vaddr.to_le_bytes());

        let mut node_page = [0u8; 4096];
        // hlist_node.next at offset 0 = 0 (terminate loop)
        // task ptr at offset 8 = 0
        // futex key at offset 16 = 0
        // key_offset_field at offset 24: bit 0 = 1 → "shared"
        node_page[24..32].copy_from_slice(&1u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_symbol("futex_queues", bucket_vaddr)
            .add_struct("futex_hash_bucket", 64)
            .add_field("futex_hash_bucket", "chain", 0, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(bucket_vaddr, bucket_paddr, ptf::WRITABLE)
            .write_phys(bucket_paddr, &bucket_page)
            .map_4k(node_vaddr, node_paddr, ptf::WRITABLE)
            .write_phys(node_paddr, &node_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_futex_table(&reader).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].futex_type, "shared", "bit 0 set → shared futex");
    }

    // --- walk_futex_table: task_ptr != 0 → read pid from task_struct ---
    // Exercises lines 127-131: when waiter_count==0 and task_ptr is non-zero,
    // the walker reads task_struct.pid to set first_pid.
    #[test]
    fn walk_futex_non_null_task_reads_pid() {
        use memf_core::test_builders::flags as ptf;

        // Layout:
        //   bucket_vaddr : chain (at offset 0) → node_vaddr
        //   node_vaddr   : [0..8]=0 (hlist_node.next), [8..16]=task_vaddr (task ptr),
        //                  [16..24]=0 (futex key), [24..32]=0 (key_offset_field → private)
        //   task_vaddr   : task_struct with pid at offset 0 = 1234
        let bucket_vaddr: u64 = 0xFFFF_8800_00E0_0000;
        let bucket_paddr: u64 = 0x00E0_0000;
        let node_vaddr: u64 = 0xFFFF_8800_00E1_0000;
        let node_paddr: u64 = 0x00E1_0000;
        let task_vaddr: u64 = 0xFFFF_8800_00E2_0000;
        let task_paddr: u64 = 0x00E2_0000;

        let mut bucket_page = [0u8; 4096];
        bucket_page[0..8].copy_from_slice(&node_vaddr.to_le_bytes());

        let mut node_page = [0u8; 4096];
        // hlist_node.next at offset 0 = 0 (one iteration)
        node_page[0..8].copy_from_slice(&0u64.to_le_bytes());
        // task ptr at offset 8 (default futex_q.task offset) = task_vaddr
        node_page[8..16].copy_from_slice(&task_vaddr.to_le_bytes());
        // futex key at offset 16 = 0 (normal userspace key)
        // key_offset_field at offset 24 = 0 → "private"

        let mut task_page = [0u8; 4096];
        // task_struct.pid at offset 0 = 1234 (u32)
        task_page[0..4].copy_from_slice(&1234u32.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_symbol("futex_queues", bucket_vaddr)
            .add_struct("futex_hash_bucket", 64)
            .add_field("futex_hash_bucket", "chain", 0, "pointer")
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "unsigned int")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(bucket_vaddr, bucket_paddr, ptf::WRITABLE)
            .write_phys(bucket_paddr, &bucket_page)
            .map_4k(node_vaddr, node_paddr, ptf::WRITABLE)
            .write_phys(node_paddr, &node_page)
            .map_4k(task_vaddr, task_paddr, ptf::WRITABLE)
            .write_phys(task_paddr, &task_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_futex_table(&reader).unwrap();
        assert_eq!(result.len(), 1, "one waiter → one entry");
        assert_eq!(
            result[0].owner_pid, 1234,
            "pid should be read from task_struct"
        );
        assert_eq!(result[0].waiter_count, 1);
    }

    // --- walk_futex_table: suspicious futex via high waiter count ---
    // Two nodes in a bucket (nodeA.next → nodeB, nodeB.next=0) → waiter_count=2.
    // Key is userspace range, pid=0 → not suspicious for kernel-space key check,
    // but count > 1000 makes it suspicious.
    // We use a chained list to exercise the "waiter_count > 0" loop iterations > 1.
    #[test]
    fn walk_futex_two_waiters_in_bucket() {
        use memf_core::test_builders::flags as ptf;

        let bucket_vaddr: u64 = 0xFFFF_8800_00F0_0000;
        let bucket_paddr: u64 = 0x00F0_0000;
        let node_a_vaddr: u64 = 0xFFFF_8800_00F1_0000;
        let node_a_paddr: u64 = 0x00F1_0000;
        let node_b_vaddr: u64 = 0xFFFF_8800_00F2_0000;
        let node_b_paddr: u64 = 0x00F2_0000;

        let mut bucket_page = [0u8; 4096];
        bucket_page[0..8].copy_from_slice(&node_a_vaddr.to_le_bytes());

        let mut node_a_page = [0u8; 4096];
        // hlist_node.next → node_b_vaddr
        node_a_page[0..8].copy_from_slice(&node_b_vaddr.to_le_bytes());
        // task ptr at offset 8 = 0
        // key at offset 16 = 0 → private
        // key_offset_field at offset 24 = 0

        let mut node_b_page = [0u8; 4096];
        // hlist_node.next = 0 (terminate)
        node_b_page[0..8].copy_from_slice(&0u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_symbol("futex_queues", bucket_vaddr)
            .add_struct("futex_hash_bucket", 64)
            .add_field("futex_hash_bucket", "chain", 0, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(bucket_vaddr, bucket_paddr, ptf::WRITABLE)
            .write_phys(bucket_paddr, &bucket_page)
            .map_4k(node_a_vaddr, node_a_paddr, ptf::WRITABLE)
            .write_phys(node_a_paddr, &node_a_page)
            .map_4k(node_b_vaddr, node_b_paddr, ptf::WRITABLE)
            .write_phys(node_b_paddr, &node_b_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_futex_table(&reader).unwrap();
        assert_eq!(
            result.len(),
            1,
            "one bucket with two waiters → one aggregate entry"
        );
        assert_eq!(result[0].waiter_count, 2, "two nodes → waiter_count = 2");
        assert!(!result[0].is_suspicious, "count=2, key=0, pid=0 → benign");
    }
}
