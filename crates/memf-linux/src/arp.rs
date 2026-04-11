//! Linux ARP cache extraction from the kernel neighbour table.
//!
//! Walks the `arp_tbl` (neigh_table) hash buckets to enumerate all
//! ARP cache entries. Each `neighbour` struct holds the IP address,
//! MAC address, NUD state, and associated network device.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{ArpEntryInfo, Error, NeighState, Result};

/// Walk the kernel ARP neighbour table and extract all entries.
///
/// Reads the `arp_tbl` symbol (type `neigh_table`), dereferences
/// the `nht` pointer to get the `neigh_hash_table`, then iterates
/// hash buckets reading `neighbour` structs linked via `next`.
pub fn walk_arp_cache<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<ArpEntryInfo>> {
        todo!()
    }

fn read_neighbour<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    neigh_addr: u64,
) -> Result<ArpEntryInfo> {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NeighState;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // Synthetic layout:
    //   arp_tbl (neigh_table):
    //     nht @ 0 (pointer to neigh_hash_table)
    //
    //   neigh_hash_table:
    //     hash_buckets @ 0 (pointer to array of neighbour*)
    //     hash_shift   @ 8 (u32) — log2(bucket_count)
    //
    //   neighbour:
    //     next          @ 0  (pointer — next in hash chain)
    //     primary_key   @ 8  (4 bytes — IPv4 address)
    //     ha            @ 12 (6 bytes — MAC address)
    //     nud_state     @ 18 (u8)
    //     dev           @ 24 (pointer to net_device)
    //     total: 64 bytes
    //
    //   net_device:
    //     name @ 0 (char[16])

    const NHT_PTR_OFF: usize = 0;
    // neigh_hash_table offsets
    const HASH_BUCKETS_OFF: usize = 0;
    const HASH_SHIFT_OFF: usize = 8;
    // neighbour offsets
    const NEIGH_NEXT_OFF: usize = 0;
    const NEIGH_KEY_OFF: usize = 8;
    const NEIGH_HA_OFF: usize = 12;
    const NEIGH_NUD_OFF: usize = 18;
    const NEIGH_DEV_OFF: usize = 24;

    fn build_arp_isf() -> serde_json::Value {
        todo!()
    }

    fn make_reader(pages: &[(u64, u64, &[u8])]) -> ObjectReader<SyntheticPhysMem> {
        todo!()
    }

    /// Single ARP entry: 192.168.1.1 -> aa:bb:cc:dd:ee:ff on eth0
    #[test]
    fn walk_single_arp_entry() {
        todo!()
    }

    /// Empty ARP table (hash_shift=0, bucket[0] is null).
    #[test]
    fn walk_empty_arp_table() {
        todo!()
    }

    /// Two ARP entries chained in same bucket.
    #[test]
    fn walk_two_entries_in_chain() {
        todo!()
    }
}
