//! Windows DNS resolver cache extraction.
//!
//! The Windows DNS Client service (`Dnscache`) maintains an in-memory cache
//! of recently resolved DNS records in `dnsrslvr.dll`. Extracting this cache
//! from memory reveals what domains a system has resolved — critical for
//! identifying C2 infrastructure, data exfiltration endpoints, and lateral
//! movement targets during DFIR triage.
//!
//! The cache uses a hash table of `DNS_HASHTABLE_ENTRY` structures, each
//! containing a doubly-linked list of `DNS_CACHE_ENTRY` records. Each record
//! stores the queried name, record type, TTL, and resolved data.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{DnsCacheEntry, DnsRecordType, Result};

/// Maximum number of hash table buckets to iterate (safety limit).
const MAX_HASH_BUCKETS: u64 = 4096;

/// Maximum number of UTF-16LE code units to read for a wide string (safety limit).
const MAX_WIDE_CHARS: usize = 512;

/// Maximum chain length per bucket (safety limit against corruption).
const MAX_CHAIN_LENGTH: usize = 512;

/// Walk the Windows DNS resolver cache and extract cached DNS records.
///
/// Looks for the DNS cache hash table in `svchost.exe` / `Dnscache` service
/// memory. Iterates hash buckets, follows entry chains via `Next` pointer,
/// and extracts name, type, TTL, and resolved data for each record.
pub fn walk_dns_cache<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<DnsCacheEntry>> {
    // Look for DnsHashTable symbol (from dnsrslvr.dll debug info)
    let hash_table_addr = reader
        .symbols()
        .symbol_address("g_HashTable")
        .or_else(|| reader.symbols().symbol_address("g_CacheHashTable"))
        .or_else(|| reader.symbols().symbol_address("DnsCacheHashTable"));

    let Some(hash_table_addr) = hash_table_addr else {
        return Ok(Vec::new());
    };

    let bucket_count: u32 = reader
        .read_field(hash_table_addr, "DNS_HASHTABLE", "BucketCount")
        .unwrap_or(256);
    let bucket_count = u64::from(bucket_count).min(MAX_HASH_BUCKETS);

    let buckets_offset = reader
        .symbols()
        .field_offset("DNS_HASHTABLE", "Buckets")
        .unwrap_or(8);
    let buckets_addr = hash_table_addr + buckets_offset;

    let mut entries = Vec::new();

    for i in 0..bucket_count {
        let bucket_ptr_addr = buckets_addr + i * 8;
        let entry_ptr: u64 = match reader.read_bytes(bucket_ptr_addr, 8) {
            Ok(bytes) => u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")),
            Err(_) => continue,
        };

        let mut current = entry_ptr;
        let mut chain_len = 0;

        while current != 0 && chain_len < MAX_CHAIN_LENGTH {
            if let Ok(entry) = read_cache_entry(reader, current) {
                entries.push(entry);
            }
            current = match reader.read_field::<u64>(current, "DNS_CACHE_ENTRY", "Next") {
                Ok(v) => v,
                Err(_) => break,
            };
            chain_len += 1;
        }
    }

    Ok(entries)
}

/// Read a null-terminated UTF-16LE wide string (`LPWSTR`) from a virtual address.
///
/// Reads up to `MAX_WIDE_CHARS` code units (2 bytes each), stopping at the
/// first null (0x0000) code unit. This handles the `LPWSTR` / `PWSTR` pointer
/// type common in Windows user-mode structures (as opposed to `_UNICODE_STRING`
/// which carries an explicit length field).
fn read_wide_string<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ptr: u64,
) -> Result<String> {
    let raw = reader.read_bytes(ptr, MAX_WIDE_CHARS * 2)?;
    let u16s: Vec<u16> = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|&c| c != 0)
        .collect();
    Ok(String::from_utf16_lossy(&u16s))
}

/// Read a single DNS cache entry from the given address.
fn read_cache_entry<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    addr: u64,
) -> Result<DnsCacheEntry> {
    let name = {
        let name_ptr: u64 = reader.read_field(addr, "DNS_CACHE_ENTRY", "Name")?;
        if name_ptr == 0 {
            String::new()
        } else {
            read_wide_string(reader, name_ptr).unwrap_or_default()
        }
    };

    let record_type_raw: u16 = reader
        .read_field(addr, "DNS_CACHE_ENTRY", "Type")
        .unwrap_or(0);
    let record_type = DnsRecordType::from_raw(record_type_raw);

    let ttl: u32 = reader
        .read_field(addr, "DNS_CACHE_ENTRY", "Ttl")
        .unwrap_or(0);

    let data = read_record_data(reader, addr, record_type_raw).unwrap_or_default();

    Ok(DnsCacheEntry {
        name,
        record_type,
        data,
        ttl,
    })
}

/// Read the resolved data from a DNS cache entry based on record type.
fn read_record_data<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    entry_addr: u64,
    record_type: u16,
) -> Result<String> {
    let data_ptr: u64 = reader.read_field(entry_addr, "DNS_CACHE_ENTRY", "Data")?;
    if data_ptr == 0 {
        return Ok(String::new());
    }

    match record_type {
        // A record: 4 bytes IPv4
        1 => {
            let bytes = reader.read_bytes(data_ptr, 4)?;
            Ok(format!(
                "{}.{}.{}.{}",
                bytes[0], bytes[1], bytes[2], bytes[3]
            ))
        }
        // AAAA record: 16 bytes IPv6
        28 => {
            let bytes = reader.read_bytes(data_ptr, 16)?;
            let mut parts = Vec::with_capacity(8);
            for chunk in bytes.chunks(2) {
                parts.push(format!("{:02x}{:02x}", chunk[0], chunk[1]));
            }
            Ok(parts.join(":"))
        }
        // CNAME, PTR: pointer to wide string
        5 | 12 => read_wide_string(reader, data_ptr),
        // Other types: hex dump of first 32 bytes
        _ => {
            let len = reader
                .read_field::<u16>(entry_addr, "DNS_CACHE_ENTRY", "DataLength")
                .unwrap_or(0);
            let read_len = usize::from(len).min(32);
            if read_len == 0 {
                return Ok(String::new());
            }
            let bytes = reader.read_bytes(data_ptr, read_len)?;
            Ok(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// No DNS cache symbol → empty result (not an error).
    #[test]
    fn walk_dns_cache_no_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("DNS_HASHTABLE", 64)
            .add_field("DNS_HASHTABLE", "BucketCount", 0, "unsigned int")
            .add_field("DNS_HASHTABLE", "Buckets", 8, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_dns_cache(&reader).unwrap();
        assert!(result.is_empty());
    }

    // Synthetic layout:
    //   g_HashTable @ 0xFFFF_8000_0020_0000 (DNS_HASHTABLE)
    //     BucketCount @ offset 0 (u32) = 2
    //     Buckets     @ offset 8 (array of pointers)
    //       bucket[0] → 0xFFFF_8000_0020_1000 (DNS_CACHE_ENTRY)
    //       bucket[1] → 0 (empty)
    //
    //   DNS_CACHE_ENTRY @ 0xFFFF_8000_0020_1000:
    //     Next    @ 0  (pointer, 8 bytes) = 0 (no chain)
    //     Name    @ 8  (pointer to wide string at 0xFFFF_8000_0020_2000)
    //     Type    @ 16 (u16) = 1 (A record)
    //     Ttl     @ 20 (u32) = 300
    //     DataLength @ 24 (u16) = 4
    //     Data    @ 32 (pointer to 4 bytes at 0xFFFF_8000_0020_3000)
    //
    //   Name string @ 0xFFFF_8000_0020_2000: "evil.c2.example.com\0" (wide)
    //   Data bytes  @ 0xFFFF_8000_0020_3000: [10, 0, 0, 1] → "10.0.0.1"

    const HASHTABLE_VADDR: u64 = 0xFFFF_8000_0020_0000;
    const HASHTABLE_PADDR: u64 = 0x0080_0000;
    const ENTRY_VADDR: u64 = 0xFFFF_8000_0020_1000;
    const ENTRY_PADDR: u64 = 0x0080_1000;
    const NAME_VADDR: u64 = 0xFFFF_8000_0020_2000;
    const NAME_PADDR: u64 = 0x0080_2000;
    const DATA_VADDR: u64 = 0xFFFF_8000_0020_3000;
    const DATA_PADDR: u64 = 0x0080_3000;

    fn build_dns_reader() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("DNS_HASHTABLE", 64)
            .add_field("DNS_HASHTABLE", "BucketCount", 0, "unsigned int")
            .add_field("DNS_HASHTABLE", "Buckets", 8, "pointer")
            .add_struct("DNS_CACHE_ENTRY", 48)
            .add_field("DNS_CACHE_ENTRY", "Next", 0, "pointer")
            .add_field("DNS_CACHE_ENTRY", "Name", 8, "pointer")
            .add_field("DNS_CACHE_ENTRY", "Type", 16, "unsigned short")
            .add_field("DNS_CACHE_ENTRY", "Ttl", 20, "unsigned int")
            .add_field("DNS_CACHE_ENTRY", "DataLength", 24, "unsigned short")
            .add_field("DNS_CACHE_ENTRY", "Data", 32, "pointer")
            .add_symbol("g_HashTable", HASHTABLE_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut ht_data = vec![0u8; 4096];
        ht_data[0..4].copy_from_slice(&2u32.to_le_bytes()); // BucketCount
        ht_data[8..16].copy_from_slice(&ENTRY_VADDR.to_le_bytes()); // Buckets[0]

        let mut entry_data = vec![0u8; 4096];
        entry_data[0..8].copy_from_slice(&0u64.to_le_bytes()); // Next = NULL
        entry_data[8..16].copy_from_slice(&NAME_VADDR.to_le_bytes()); // Name ptr
        entry_data[16..18].copy_from_slice(&1u16.to_le_bytes()); // Type = A
        entry_data[20..24].copy_from_slice(&300u32.to_le_bytes()); // TTL = 300
        entry_data[24..26].copy_from_slice(&4u16.to_le_bytes()); // DataLength = 4
        entry_data[32..40].copy_from_slice(&DATA_VADDR.to_le_bytes()); // Data ptr

        let mut name_data = vec![0u8; 4096];
        let name = "evil.c2.example.com";
        for (i, ch) in name.encode_utf16().enumerate() {
            let off = i * 2;
            name_data[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }

        let mut ip_data = vec![0u8; 4096];
        ip_data[0] = 10;
        ip_data[1] = 0;
        ip_data[2] = 0;
        ip_data[3] = 1;

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(HASHTABLE_VADDR, HASHTABLE_PADDR, flags::WRITABLE)
            .write_phys(HASHTABLE_PADDR, &ht_data)
            .map_4k(ENTRY_VADDR, ENTRY_PADDR, flags::WRITABLE)
            .write_phys(ENTRY_PADDR, &entry_data)
            .map_4k(NAME_VADDR, NAME_PADDR, flags::WRITABLE)
            .write_phys(NAME_PADDR, &name_data)
            .map_4k(DATA_VADDR, DATA_PADDR, flags::WRITABLE)
            .write_phys(DATA_PADDR, &ip_data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    // ── walk_dns_cache: AAAA (type 28), CNAME (type 5), PTR (type 12), fallback ──

    fn build_dns_reader_with_type(
        record_type: u16,
        data_bytes: Vec<u8>,
        data_vaddr: u64,
        data_paddr: u64,
    ) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("DNS_HASHTABLE", 64)
            .add_field("DNS_HASHTABLE", "BucketCount", 0, "unsigned int")
            .add_field("DNS_HASHTABLE", "Buckets", 8, "pointer")
            .add_struct("DNS_CACHE_ENTRY", 48)
            .add_field("DNS_CACHE_ENTRY", "Next", 0, "pointer")
            .add_field("DNS_CACHE_ENTRY", "Name", 8, "pointer")
            .add_field("DNS_CACHE_ENTRY", "Type", 16, "unsigned short")
            .add_field("DNS_CACHE_ENTRY", "Ttl", 20, "unsigned int")
            .add_field("DNS_CACHE_ENTRY", "DataLength", 24, "unsigned short")
            .add_field("DNS_CACHE_ENTRY", "Data", 32, "pointer")
            .add_symbol("g_HashTable", HASHTABLE_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut ht_data = vec![0u8; 4096];
        ht_data[0..4].copy_from_slice(&1u32.to_le_bytes()); // BucketCount = 1
        ht_data[8..16].copy_from_slice(&ENTRY_VADDR.to_le_bytes()); // Buckets[0]

        let mut entry_data = vec![0u8; 4096];
        entry_data[0..8].copy_from_slice(&0u64.to_le_bytes()); // Next = NULL
        entry_data[8..16].copy_from_slice(&NAME_VADDR.to_le_bytes()); // Name ptr
        entry_data[16..18].copy_from_slice(&record_type.to_le_bytes()); // Type
        entry_data[20..24].copy_from_slice(&60u32.to_le_bytes()); // TTL = 60
        entry_data[24..26].copy_from_slice(&(data_bytes.len() as u16).to_le_bytes());
        entry_data[32..40].copy_from_slice(&data_vaddr.to_le_bytes()); // Data ptr

        let mut name_data = vec![0u8; 4096];
        let name = "test.example.com";
        for (i, ch) in name.encode_utf16().enumerate() {
            let off = i * 2;
            name_data[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }

        let mut ip_data = vec![0u8; 4096];
        ip_data[..data_bytes.len().min(4096)].copy_from_slice(&data_bytes[..data_bytes.len().min(4096)]);

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(HASHTABLE_VADDR, HASHTABLE_PADDR, flags::WRITABLE)
            .write_phys(HASHTABLE_PADDR, &ht_data)
            .map_4k(ENTRY_VADDR, ENTRY_PADDR, flags::WRITABLE)
            .write_phys(ENTRY_PADDR, &entry_data)
            .map_4k(NAME_VADDR, NAME_PADDR, flags::WRITABLE)
            .write_phys(NAME_PADDR, &name_data)
            .map_4k(data_vaddr, data_paddr, flags::WRITABLE)
            .write_phys(data_paddr, &ip_data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// AAAA record (type 28) produces formatted IPv6 string.
    #[test]
    fn walk_dns_cache_aaaa_record() {
        let ipv6_bytes = [
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
            0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
        ];
        let data_vaddr: u64 = 0xFFFF_8000_0020_4000;
        let data_paddr: u64 = 0x0080_4000;
        let reader = build_dns_reader_with_type(28, ipv6_bytes.to_vec(), data_vaddr, data_paddr);
        let entries = walk_dns_cache(&reader).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.record_type, DnsRecordType::Aaaa);
        assert_eq!(e.data.matches(':').count(), 7);
        assert_eq!(e.data, "2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    }

    /// CNAME record (type 5) reads as wide string from data pointer.
    #[test]
    fn walk_dns_cache_cname_record() {
        let cname = "cname.example.com";
        let mut wide_bytes = vec![0u8; 512];
        for (i, ch) in cname.encode_utf16().enumerate() {
            let off = i * 2;
            wide_bytes[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }
        let data_vaddr: u64 = 0xFFFF_8000_0020_5000;
        let data_paddr: u64 = 0x0080_5000;
        let reader = build_dns_reader_with_type(5, wide_bytes, data_vaddr, data_paddr);
        let entries = walk_dns_cache(&reader).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.record_type, DnsRecordType::Cname);
        assert_eq!(e.data, cname);
    }

    /// PTR record (type 12) reads as wide string.
    #[test]
    fn walk_dns_cache_ptr_record() {
        let ptr_name = "1.0.0.10.in-addr.arpa";
        let mut wide_bytes = vec![0u8; 512];
        for (i, ch) in ptr_name.encode_utf16().enumerate() {
            let off = i * 2;
            wide_bytes[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }
        let data_vaddr: u64 = 0xFFFF_8000_0020_6000;
        let data_paddr: u64 = 0x0080_6000;
        let reader = build_dns_reader_with_type(12, wide_bytes, data_vaddr, data_paddr);
        let entries = walk_dns_cache(&reader).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.record_type, DnsRecordType::Ptr);
        assert_eq!(e.data, ptr_name);
    }

    /// Unknown record type (e.g. MX = 15) dumps as hex via DataLength field.
    #[test]
    fn walk_dns_cache_unknown_type_hex_dump() {
        let data_bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let data_vaddr: u64 = 0xFFFF_8000_0020_7000;
        let data_paddr: u64 = 0x0080_7000;
        let reader = build_dns_reader_with_type(15, data_bytes, data_vaddr, data_paddr);
        let entries = walk_dns_cache(&reader).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.record_type, DnsRecordType::Mx);
        assert_eq!(e.data, "deadbeef");
    }

    /// read_wide_string with null-ptr name returns empty string name.
    #[test]
    fn walk_dns_cache_null_name_ptr_returns_empty_name() {
        let isf = IsfBuilder::new()
            .add_struct("DNS_HASHTABLE", 64)
            .add_field("DNS_HASHTABLE", "BucketCount", 0, "unsigned int")
            .add_field("DNS_HASHTABLE", "Buckets", 8, "pointer")
            .add_struct("DNS_CACHE_ENTRY", 48)
            .add_field("DNS_CACHE_ENTRY", "Next", 0, "pointer")
            .add_field("DNS_CACHE_ENTRY", "Name", 8, "pointer")
            .add_field("DNS_CACHE_ENTRY", "Type", 16, "unsigned short")
            .add_field("DNS_CACHE_ENTRY", "Ttl", 20, "unsigned int")
            .add_field("DNS_CACHE_ENTRY", "DataLength", 24, "unsigned short")
            .add_field("DNS_CACHE_ENTRY", "Data", 32, "pointer")
            .add_symbol("g_HashTable", HASHTABLE_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut ht_data = vec![0u8; 4096];
        ht_data[0..4].copy_from_slice(&1u32.to_le_bytes()); // BucketCount = 1
        ht_data[8..16].copy_from_slice(&ENTRY_VADDR.to_le_bytes());

        let mut entry_data = vec![0u8; 4096];
        entry_data[0..8].copy_from_slice(&0u64.to_le_bytes()); // Next = NULL
        entry_data[8..16].copy_from_slice(&0u64.to_le_bytes()); // Name = NULL
        entry_data[16..18].copy_from_slice(&1u16.to_le_bytes()); // Type = A
        entry_data[20..24].copy_from_slice(&60u32.to_le_bytes());
        entry_data[24..26].copy_from_slice(&4u16.to_le_bytes());
        entry_data[32..40].copy_from_slice(&DATA_VADDR.to_le_bytes());

        let mut ip_data = vec![0u8; 4096];
        ip_data[0] = 1; ip_data[1] = 2; ip_data[2] = 3; ip_data[3] = 4;

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(HASHTABLE_VADDR, HASHTABLE_PADDR, flags::WRITABLE)
            .write_phys(HASHTABLE_PADDR, &ht_data)
            .map_4k(ENTRY_VADDR, ENTRY_PADDR, flags::WRITABLE)
            .write_phys(ENTRY_PADDR, &entry_data)
            .map_4k(DATA_VADDR, DATA_PADDR, flags::WRITABLE)
            .write_phys(DATA_PADDR, &ip_data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let entries = walk_dns_cache(&reader).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "");
        assert_eq!(entries[0].data, "1.2.3.4");
    }

    /// walk_dns_cache: entry with Data=0 for A record → empty data string.
    #[test]
    fn walk_dns_cache_null_data_ptr_returns_empty_data() {
        let isf = IsfBuilder::new()
            .add_struct("DNS_HASHTABLE", 64)
            .add_field("DNS_HASHTABLE", "BucketCount", 0, "unsigned int")
            .add_field("DNS_HASHTABLE", "Buckets", 8, "pointer")
            .add_struct("DNS_CACHE_ENTRY", 48)
            .add_field("DNS_CACHE_ENTRY", "Next", 0, "pointer")
            .add_field("DNS_CACHE_ENTRY", "Name", 8, "pointer")
            .add_field("DNS_CACHE_ENTRY", "Type", 16, "unsigned short")
            .add_field("DNS_CACHE_ENTRY", "Ttl", 20, "unsigned int")
            .add_field("DNS_CACHE_ENTRY", "DataLength", 24, "unsigned short")
            .add_field("DNS_CACHE_ENTRY", "Data", 32, "pointer")
            .add_symbol("g_HashTable", HASHTABLE_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut ht_data = vec![0u8; 4096];
        ht_data[0..4].copy_from_slice(&1u32.to_le_bytes());
        ht_data[8..16].copy_from_slice(&ENTRY_VADDR.to_le_bytes());

        let mut entry_data = vec![0u8; 4096];
        entry_data[0..8].copy_from_slice(&0u64.to_le_bytes()); // Next = NULL
        entry_data[8..16].copy_from_slice(&NAME_VADDR.to_le_bytes());
        entry_data[16..18].copy_from_slice(&1u16.to_le_bytes()); // Type = A
        entry_data[20..24].copy_from_slice(&300u32.to_le_bytes());
        entry_data[24..26].copy_from_slice(&4u16.to_le_bytes());
        entry_data[32..40].copy_from_slice(&0u64.to_le_bytes()); // Data = NULL

        let mut name_data = vec![0u8; 4096];
        let name = "nulldata.example.com";
        for (i, ch) in name.encode_utf16().enumerate() {
            let off = i * 2;
            name_data[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(HASHTABLE_VADDR, HASHTABLE_PADDR, flags::WRITABLE)
            .write_phys(HASHTABLE_PADDR, &ht_data)
            .map_4k(ENTRY_VADDR, ENTRY_PADDR, flags::WRITABLE)
            .write_phys(ENTRY_PADDR, &entry_data)
            .map_4k(NAME_VADDR, NAME_PADDR, flags::WRITABLE)
            .write_phys(NAME_PADDR, &name_data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let entries = walk_dns_cache(&reader).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, name);
        assert_eq!(entries[0].data, "");
    }

    /// DnsCacheEntry serializes correctly.
    #[test]
    fn dns_cache_entry_serializes() {
        let entry = DnsCacheEntry {
            name: "evil.c2.example.com".to_string(),
            record_type: DnsRecordType::A,
            data: "10.0.0.1".to_string(),
            ttl: 300,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("evil.c2.example.com"));
        assert!(json.contains("10.0.0.1"));
        assert!(json.contains("300"));
    }

    /// Single A record in the DNS cache → correct DnsCacheEntry.
    #[test]
    fn walk_dns_cache_single_a_record() {
        let reader = build_dns_reader();
        let entries = walk_dns_cache(&reader).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.name, "evil.c2.example.com");
        assert_eq!(e.record_type, DnsRecordType::A);
        assert_eq!(e.data, "10.0.0.1");
        assert_eq!(e.ttl, 300);
    }
}
