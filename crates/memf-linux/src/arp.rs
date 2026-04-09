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
    let arp_tbl_addr = reader
        .symbols()
        .symbol_address("arp_tbl")
        .ok_or_else(|| Error::Walker("symbol 'arp_tbl' not found".into()))?;

    // neigh_table.nht → pointer to neigh_hash_table
    let nht_ptr: u64 = reader.read_field(arp_tbl_addr, "neigh_table", "nht")?;
    if nht_ptr == 0 {
        return Ok(Vec::new());
    }

    // neigh_hash_table.hash_buckets → pointer to array of neighbour*
    let buckets_ptr: u64 = reader.read_field(nht_ptr, "neigh_hash_table", "hash_buckets")?;
    // neigh_hash_table.hash_shift → log2(bucket_count)
    let hash_shift: u32 = reader.read_field(nht_ptr, "neigh_hash_table", "hash_shift")?;
    let bucket_count: u64 = 1u64 << hash_shift;

    if buckets_ptr == 0 {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();

    for i in 0..bucket_count {
        // Each bucket is a pointer (8 bytes) to the first neighbour
        let bucket_addr = buckets_ptr + i * 8;
        let neigh_ptr: u64 = match reader.read_bytes(bucket_addr, 8) {
            Ok(bytes) => u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")),
            Err(_) => continue,
        };

        let mut current = neigh_ptr;
        let mut chain_len = 0;
        while current != 0 && chain_len < 1000 {
            if let Ok(entry) = read_neighbour(reader, current) {
                entries.push(entry);
            }

            // Follow neighbour.next pointer
            current = match reader.read_field::<u64>(current, "neighbour", "next") {
                Ok(v) => v,
                Err(_) => break,
            };
            chain_len += 1;
        }
    }

    Ok(entries)
}

fn read_neighbour<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    neigh_addr: u64,
) -> Result<ArpEntryInfo> {
    // Read the 4-byte IPv4 address from primary_key
    let ip_raw: u32 = reader.read_field(neigh_addr, "neighbour", "primary_key")?;
    let ip_bytes = ip_raw.to_le_bytes();
    let ip_addr = format!(
        "{}.{}.{}.{}",
        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
    );

    // Read the 6-byte MAC address from ha field
    let ha_offset = reader
        .symbols()
        .field_offset("neighbour", "ha")
        .ok_or_else(|| Error::Walker("neighbour.ha field not found".into()))?;
    let mac_bytes = reader.read_bytes(neigh_addr + ha_offset, 6)?;
    let mac_addr = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]
    );

    // Read NUD state
    let nud_state: u8 = reader.read_field(neigh_addr, "neighbour", "nud_state")?;

    // Read device name via dev pointer → net_device.name
    let dev_ptr: u64 = reader.read_field(neigh_addr, "neighbour", "dev")?;
    let dev_name = if dev_ptr != 0 {
        reader.read_field_string(dev_ptr, "net_device", "name", 16)?
    } else {
        String::from("?")
    };

    Ok(ArpEntryInfo {
        ip_addr,
        mac_addr,
        dev_name,
        state: NeighState::from_raw(nud_state),
    })
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
        IsfBuilder::new()
            .add_struct("neigh_table", 64)
            .add_field("neigh_table", "nht", 0, "pointer")
            .add_struct("neigh_hash_table", 16)
            .add_field("neigh_hash_table", "hash_buckets", 0, "pointer")
            .add_field("neigh_hash_table", "hash_shift", 8, "unsigned int")
            .add_struct("neighbour", 64)
            .add_field("neighbour", "next", 0, "pointer")
            .add_field("neighbour", "primary_key", 8, "unsigned int")
            .add_field("neighbour", "ha", 12, "char")
            .add_field("neighbour", "nud_state", 18, "unsigned char")
            .add_field("neighbour", "dev", 24, "pointer")
            .add_struct("net_device", 256)
            .add_field("net_device", "name", 0, "char")
            .add_symbol("arp_tbl", 0xFFFF_8000_0010_0000)
            .build_json()
    }

    fn make_reader(pages: &[(u64, u64, &[u8])]) -> ObjectReader<SyntheticPhysMem> {
        let isf = build_arp_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut builder = PageTableBuilder::new();
        for &(vaddr, paddr, data) in pages {
            builder = builder
                .map_4k(vaddr, paddr, flags::WRITABLE)
                .write_phys(paddr, data);
        }
        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// Single ARP entry: 192.168.1.1 -> aa:bb:cc:dd:ee:ff on eth0
    #[test]
    fn walk_single_arp_entry() {
        let arp_tbl_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let arp_tbl_paddr: u64 = 0x0080_0000;

        let nht_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let nht_paddr: u64 = 0x0090_0000;

        let neigh_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let neigh_paddr: u64 = 0x00A0_0000;

        let dev_vaddr: u64 = 0xFFFF_8000_0040_0000;
        let dev_paddr: u64 = 0x00B0_0000;

        // bucket array lives at nht_vaddr + 0x100
        let bucket_array_vaddr: u64 = nht_vaddr + 0x100;

        // -- arp_tbl page: nht pointer
        let mut arp_data = vec![0u8; 4096];
        arp_data[NHT_PTR_OFF..NHT_PTR_OFF + 8].copy_from_slice(&nht_vaddr.to_le_bytes());

        // -- nht page: bucket array pointer + hash_shift
        let mut nht_data = vec![0u8; 4096];
        nht_data[HASH_BUCKETS_OFF..HASH_BUCKETS_OFF + 8]
            .copy_from_slice(&bucket_array_vaddr.to_le_bytes());
        // hash_shift = 0 means 1 bucket (2^0 = 1)
        nht_data[HASH_SHIFT_OFF..HASH_SHIFT_OFF + 4].copy_from_slice(&0u32.to_le_bytes());
        // bucket[0] = pointer to neighbour
        nht_data[0x100..0x108].copy_from_slice(&neigh_vaddr.to_le_bytes());

        // -- neighbour page
        let mut neigh_data = vec![0u8; 4096];
        neigh_data[NEIGH_NEXT_OFF..NEIGH_NEXT_OFF + 8].copy_from_slice(&0u64.to_le_bytes()); // null = end of chain
        let ip: u32 = u32::from_le_bytes([192, 168, 1, 1]);
        neigh_data[NEIGH_KEY_OFF..NEIGH_KEY_OFF + 4].copy_from_slice(&ip.to_le_bytes());
        neigh_data[NEIGH_HA_OFF..NEIGH_HA_OFF + 6]
            .copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        neigh_data[NEIGH_NUD_OFF] = 0x02; // REACHABLE
        neigh_data[NEIGH_DEV_OFF..NEIGH_DEV_OFF + 8].copy_from_slice(&dev_vaddr.to_le_bytes());

        // -- net_device page
        let mut dev_data = vec![0u8; 4096];
        dev_data[..4].copy_from_slice(b"eth0");

        let reader = make_reader(&[
            (arp_tbl_vaddr, arp_tbl_paddr, &arp_data),
            (nht_vaddr, nht_paddr, &nht_data),
            (neigh_vaddr, neigh_paddr, &neigh_data),
            (dev_vaddr, dev_paddr, &dev_data),
        ]);

        let entries = walk_arp_cache(&reader).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip_addr, "192.168.1.1");
        assert_eq!(entries[0].mac_addr, "aa:bb:cc:dd:ee:ff");
        assert_eq!(entries[0].dev_name, "eth0");
        assert_eq!(entries[0].state, NeighState::Reachable);
    }

    /// Empty ARP table (hash_shift=0, bucket[0] is null).
    #[test]
    fn walk_empty_arp_table() {
        let arp_tbl_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let arp_tbl_paddr: u64 = 0x0080_0000;
        let nht_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let nht_paddr: u64 = 0x0090_0000;
        let bucket_array_vaddr: u64 = nht_vaddr + 0x100;

        let mut arp_data = vec![0u8; 4096];
        arp_data[NHT_PTR_OFF..NHT_PTR_OFF + 8].copy_from_slice(&nht_vaddr.to_le_bytes());

        let mut nht_data = vec![0u8; 4096];
        nht_data[HASH_BUCKETS_OFF..HASH_BUCKETS_OFF + 8]
            .copy_from_slice(&bucket_array_vaddr.to_le_bytes());
        nht_data[HASH_SHIFT_OFF..HASH_SHIFT_OFF + 4].copy_from_slice(&0u32.to_le_bytes());
        // bucket[0] = 0 (null)
        nht_data[0x100..0x108].copy_from_slice(&0u64.to_le_bytes());

        let reader = make_reader(&[
            (arp_tbl_vaddr, arp_tbl_paddr, &arp_data),
            (nht_vaddr, nht_paddr, &nht_data),
        ]);

        let entries = walk_arp_cache(&reader).unwrap();
        assert!(entries.is_empty());
    }

    /// Two ARP entries chained in same bucket.
    #[test]
    fn walk_two_entries_in_chain() {
        let arp_tbl_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let arp_tbl_paddr: u64 = 0x0080_0000;
        let nht_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let nht_paddr: u64 = 0x0090_0000;
        let neigh1_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let neigh1_paddr: u64 = 0x00A0_0000;
        let neigh2_vaddr: u64 = 0xFFFF_8000_0050_0000;
        let neigh2_paddr: u64 = 0x00C0_0000;
        let dev_vaddr: u64 = 0xFFFF_8000_0040_0000;
        let dev_paddr: u64 = 0x00B0_0000;
        let bucket_array_vaddr: u64 = nht_vaddr + 0x100;

        let mut arp_data = vec![0u8; 4096];
        arp_data[NHT_PTR_OFF..NHT_PTR_OFF + 8].copy_from_slice(&nht_vaddr.to_le_bytes());

        let mut nht_data = vec![0u8; 4096];
        nht_data[HASH_BUCKETS_OFF..HASH_BUCKETS_OFF + 8]
            .copy_from_slice(&bucket_array_vaddr.to_le_bytes());
        nht_data[HASH_SHIFT_OFF..HASH_SHIFT_OFF + 4].copy_from_slice(&0u32.to_le_bytes());
        nht_data[0x100..0x108].copy_from_slice(&neigh1_vaddr.to_le_bytes());

        // neigh1 -> neigh2
        let mut neigh1_data = vec![0u8; 4096];
        neigh1_data[NEIGH_NEXT_OFF..NEIGH_NEXT_OFF + 8]
            .copy_from_slice(&neigh2_vaddr.to_le_bytes());
        let ip1: u32 = u32::from_le_bytes([10, 0, 0, 1]);
        neigh1_data[NEIGH_KEY_OFF..NEIGH_KEY_OFF + 4].copy_from_slice(&ip1.to_le_bytes());
        neigh1_data[NEIGH_HA_OFF..NEIGH_HA_OFF + 6]
            .copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        neigh1_data[NEIGH_NUD_OFF] = 0x04; // STALE
        neigh1_data[NEIGH_DEV_OFF..NEIGH_DEV_OFF + 8].copy_from_slice(&dev_vaddr.to_le_bytes());

        // neigh2 -> null
        let mut neigh2_data = vec![0u8; 4096];
        neigh2_data[NEIGH_NEXT_OFF..NEIGH_NEXT_OFF + 8].copy_from_slice(&0u64.to_le_bytes());
        let ip2: u32 = u32::from_le_bytes([10, 0, 0, 2]);
        neigh2_data[NEIGH_KEY_OFF..NEIGH_KEY_OFF + 4].copy_from_slice(&ip2.to_le_bytes());
        neigh2_data[NEIGH_HA_OFF..NEIGH_HA_OFF + 6]
            .copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00]);
        neigh2_data[NEIGH_NUD_OFF] = 0x80; // PERMANENT
        neigh2_data[NEIGH_DEV_OFF..NEIGH_DEV_OFF + 8].copy_from_slice(&dev_vaddr.to_le_bytes());

        let mut dev_data = vec![0u8; 4096];
        dev_data[..5].copy_from_slice(b"ens33");

        let reader = make_reader(&[
            (arp_tbl_vaddr, arp_tbl_paddr, &arp_data),
            (nht_vaddr, nht_paddr, &nht_data),
            (neigh1_vaddr, neigh1_paddr, &neigh1_data),
            (neigh2_vaddr, neigh2_paddr, &neigh2_data),
            (dev_vaddr, dev_paddr, &dev_data),
        ]);

        let entries = walk_arp_cache(&reader).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ip_addr, "10.0.0.1");
        assert_eq!(entries[0].mac_addr, "11:22:33:44:55:66");
        assert_eq!(entries[0].state, NeighState::Stale);
        assert_eq!(entries[1].ip_addr, "10.0.0.2");
        assert_eq!(entries[1].mac_addr, "aa:bb:cc:dd:ee:00");
        assert_eq!(entries[1].state, NeighState::Permanent);
        assert!(entries.iter().all(|e| e.dev_name == "ens33"));
    }
}
