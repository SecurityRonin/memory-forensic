//! Linux netfilter (iptables) rule extraction from kernel memory.
//!
//! Reads the kernel's iptables rule structures from the `xt_table` chain.
//! The kernel organizes rules into tables (filter, nat, mangle) and chains
//! (INPUT, OUTPUT, FORWARD, PREROUTING, POSTROUTING).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, NetfilterRuleInfo, Result};

/// Known iptables table names and their kernel symbols.
const TABLE_NAMES: &[(&str, &str)] = &[
    ("filter", "iptable_filter_net_ops"),
    ("nat", "iptable_nat_net_ops"),
    ("mangle", "iptable_mangle_net_ops"),
];

/// Walk kernel iptables tables and extract rules.
///
/// Attempts to find the `init_net` namespace, then reads each registered
/// iptables table (filter, nat, mangle) and parses rule entries.
pub fn walk_netfilter_rules<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<NetfilterRuleInfo>> {
    // Look for init_net symbol
    let init_net_addr = reader
        .symbols()
        .symbol_address("init_net")
        .ok_or_else(|| Error::Walker("symbol 'init_net' not found".into()))?;

    let mut rules = Vec::new();

    // Try to read xt_table for each known table
    for &(table_name, _symbol) in TABLE_NAMES {
        // Find the table's xt_table by walking net->xt.tables[AF_INET]
        // AF_INET = 2, so offset into xt.tables array
        if let Ok(table_rules) = read_xt_table(reader, init_net_addr, table_name) {
            rules.extend(table_rules);
        }
    }

    Ok(rules)
}

fn read_xt_table<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    init_net_addr: u64,
    table_name: &str,
) -> Result<Vec<NetfilterRuleInfo>> {
    // Read net.xt offset
    let xt_offset = reader
        .symbols()
        .field_offset("net", "xt")
        .ok_or_else(|| Error::Walker("net.xt field not found".into()))?;
    let xt_addr = init_net_addr + xt_offset;

    // xt contains tables_lock and tables array.
    // netns_xt.tables is an array of list_head, indexed by protocol family.
    // AF_INET = 2
    let tables_offset = reader
        .symbols()
        .field_offset("netns_xt", "tables")
        .ok_or_else(|| Error::Walker("netns_xt.tables not found".into()))?;

    let list_head_size = reader.symbols().struct_size("list_head").unwrap_or(16);
    let af_inet_list = xt_addr + tables_offset + 2 * list_head_size; // AF_INET = 2

    // Walk the list to find xt_table with matching name
    let table_addrs = reader.walk_list(af_inet_list, "xt_table", "list")?;

    for &table_addr in &table_addrs {
        let name = reader.read_field_string(table_addr, "xt_table", "name", 32)?;
        if name == table_name {
            return parse_table_rules(reader, table_addr, table_name);
        }
    }

    Ok(Vec::new())
}

fn parse_table_rules<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    table_addr: u64,
    table_name: &str,
) -> Result<Vec<NetfilterRuleInfo>> {
    // Read xt_table.private → pointer to xt_table_info.
    let private_ptr = reader.read_pointer(table_addr, "xt_table", "private")?;
    if private_ptr == 0 {
        return Ok(Vec::new());
    }

    // Read xt_table_info.entries → virtual address of the flat ipt_entry region.
    let entries_vaddr = reader.read_pointer(private_ptr, "xt_table_info", "entries")?;
    // Read xt_table_info.size → byte length of the region.
    let size: u64 = reader.read_field::<u64>(private_ptr, "xt_table_info", "size")?;

    parse_ipt_entries(reader, entries_vaddr, size, table_name)
}

/// Parse a flat region of `ipt_entry` structures from raw memory.
///
/// `data_vaddr` is the virtual address of the first entry; `data_len` is the
/// byte length of the region.  Entries are walked via `next_offset` until it
/// is 0 or the end of the region is reached.
///
/// `ipt_entry` field offsets (kernel ABI, x86-64):
///   0x00: src_ip (u32)
///   0x04: dst_ip (u32)
///   0x10: protocol (u16)
///   0x58: target_offset (u16) — offset within entry to `ipt_entry_target`
///   0x5A: next_offset (u16) — stride to next entry; 0 = end of table
///
/// `ipt_entry_target` at `entry_base + target_offset`:
///   +0: name (29 bytes, null-terminated ASCII)
pub fn parse_ipt_entries<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    data_vaddr: u64,
    data_len: u64,
    table_name: &str,
) -> Result<Vec<NetfilterRuleInfo>> {
    const MAX_RULES: usize = 10_000;
    let data_len = data_len as usize;
    // Read the entire data region at once.
    let data = reader.read_bytes(data_vaddr, data_len).unwrap_or_default();
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut rules = Vec::new();
    let mut offset = 0usize;

    for _ in 0..MAX_RULES {
        // Need at least 0x5C bytes to read target_offset + next_offset.
        if offset + 0x5C > data.len() {
            break;
        }

        let src_ip = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]));
        let dst_ip = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap_or([0; 4]));
        let proto = u16::from_le_bytes(
            data[offset + 0x10..offset + 0x12]
                .try_into()
                .unwrap_or([0; 2]),
        );
        let target_off = u16::from_le_bytes(
            data[offset + 0x58..offset + 0x5A]
                .try_into()
                .unwrap_or([0; 2]),
        ) as usize;
        let next_off = u16::from_le_bytes(
            data[offset + 0x5A..offset + 0x5C]
                .try_into()
                .unwrap_or([0; 2]),
        ) as usize;

        // Parse ipt_entry_target.name (29 bytes at entry_base + target_offset).
        let target_name = if target_off > 0 && offset + target_off + 29 <= data.len() {
            let name_bytes = &data[offset + target_off..offset + target_off + 29];
            let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(29);
            String::from_utf8_lossy(&name_bytes[..end]).into_owned()
        } else {
            String::new()
        };

        let source = if src_ip != 0 {
            Some(format_ipv4(src_ip))
        } else {
            None
        };
        let destination = if dst_ip != 0 {
            Some(format_ipv4(dst_ip))
        } else {
            None
        };

        rules.push(NetfilterRuleInfo {
            table: table_name.to_string(),
            chain: String::new(), // chain resolution requires hook_entry offsets
            target: target_name,
            protocol: protocol_name(proto),
            source,
            destination,
        });

        if next_off == 0 {
            break;
        }
        offset += next_off;
        if offset >= data.len() {
            break;
        }
    }

    Ok(rules)
}

/// Format a raw u32 IPv4 address (little-endian stored) as a dotted string.
fn format_ipv4(ip: u32) -> String {
    let b = ip.to_le_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// Parse a protocol number to name.
pub fn protocol_name(proto: u16) -> String {
    match proto {
        0 => "all".to_string(),
        6 => "tcp".to_string(),
        17 => "udp".to_string(),
        1 => "icmp".to_string(),
        _ => format!("proto:{proto}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    #[test]
    fn protocol_name_known() {
        assert_eq!(protocol_name(0), "all");
        assert_eq!(protocol_name(6), "tcp");
        assert_eq!(protocol_name(17), "udp");
        assert_eq!(protocol_name(1), "icmp");
    }

    #[test]
    fn protocol_name_unknown() {
        assert_eq!(protocol_name(132), "proto:132");
        assert_eq!(protocol_name(255), "proto:255");
    }

    // ---------------------------------------------------------------------------
    // ipt_entry parsing tests
    // ---------------------------------------------------------------------------

    /// Build a minimal reader that maps a fake table data region and exposes
    /// `parse_ipt_entries` directly.
    fn make_ipt_entry_data(src_ip: u32, dst_ip: u32, proto: u16, target_name: &str) -> Vec<u8> {
        // ipt_entry layout (offsets per kernel ABI):
        //   0x00: src_ip (u32)
        //   0x04: dst_ip (u32)
        //   0x10: protocol (u16)
        //   0x58: target_offset (u16) — relative offset to ipt_entry_target within entry
        //   0x5A: next_offset (u16) — stride to next entry (0 = end)
        //
        // ipt_entry_target (at base + target_offset):
        //   +0: name (29 bytes, null-terminated)
        //
        // We place one entry at the start.  target_offset = 0x60 (96 bytes into entry).
        // next_offset = 0 means no more entries.
        let mut data = vec![0u8; 256];

        // src_ip at 0x00
        data[0x00..0x04].copy_from_slice(&src_ip.to_le_bytes());
        // dst_ip at 0x04
        data[0x04..0x08].copy_from_slice(&dst_ip.to_le_bytes());
        // protocol at 0x10
        data[0x10..0x12].copy_from_slice(&proto.to_le_bytes());
        // target_offset at 0x58: 0x60 (96 bytes in)
        let target_off: u16 = 0x60;
        data[0x58..0x5A].copy_from_slice(&target_off.to_le_bytes());
        // next_offset at 0x5A: 0 = end
        data[0x5A..0x5C].copy_from_slice(&0u16.to_le_bytes());
        // target name at base + target_offset
        let name_bytes = target_name.as_bytes();
        let len = name_bytes.len().min(28);
        data[0x60..0x60 + len].copy_from_slice(&name_bytes[..len]);

        data
    }

    fn make_ipt_reader(
        entry_data: &[u8],
        entry_vaddr: u64,
        entry_paddr: u64,
    ) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mut mem) = PageTableBuilder::new()
            .map_4k(entry_vaddr, entry_paddr, flags::PRESENT | flags::WRITABLE)
            .build();
        mem.write_bytes(entry_paddr, entry_data);
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn parse_ipt_entries_src_ip_and_target() {
        // src = 192.168.1.1 = 0xC0A80101 (LE), dst = 0, proto = tcp (6), target = "ACCEPT"
        let src_ip: u32 = 0xC0A8_0101_u32.to_le();
        let dst_ip: u32 = 0;
        let data = make_ipt_entry_data(src_ip, dst_ip, 6, "ACCEPT");

        let entry_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let entry_paddr: u64 = 0x0080_0000;
        let reader = make_ipt_reader(&data, entry_vaddr, entry_paddr);

        let rules = parse_ipt_entries(&reader, entry_vaddr, data.len() as u64, "filter").unwrap();
        assert_eq!(rules.len(), 1, "should parse exactly one ipt_entry");
        let rule = &rules[0];
        assert_eq!(rule.target, "ACCEPT");
        assert_eq!(rule.protocol, "tcp");
        assert!(rule.source.is_some());
    }

    #[test]
    fn parse_ipt_entries_drop_rule() {
        // src = 0 (any), dst = 10.0.0.1, proto = all (0), target = "DROP"
        let data = make_ipt_entry_data(0, 0x0A00_0001_u32.to_le(), 0, "DROP");

        let entry_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let entry_paddr: u64 = 0x0090_0000;
        let reader = make_ipt_reader(&data, entry_vaddr, entry_paddr);

        let rules = parse_ipt_entries(&reader, entry_vaddr, data.len() as u64, "nat").unwrap();
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert_eq!(rule.target, "DROP");
        assert_eq!(rule.protocol, "all");
    }

    #[test]
    fn parse_ipt_entries_empty_data_returns_empty() {
        // data_len = 0 → read_bytes will return empty, parse returns Ok([])
        let entry_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let entry_paddr: u64 = 0x00A0_0000;
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let rules = parse_ipt_entries(&reader, entry_vaddr, 0, "filter").unwrap();
        assert!(rules.is_empty(), "zero data_len should produce no rules");
    }

    #[test]
    fn parse_ipt_entries_icmp_protocol() {
        // icmp protocol (1)
        let data = make_ipt_entry_data(0, 0, 1, "ACCEPT");
        let entry_vaddr: u64 = 0xFFFF_8000_0040_0000;
        let entry_paddr: u64 = 0x00B0_0000;
        let reader = make_ipt_reader(&data, entry_vaddr, entry_paddr);

        let rules = parse_ipt_entries(&reader, entry_vaddr, data.len() as u64, "filter").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].protocol, "icmp");
    }

    #[test]
    fn parse_ipt_entries_udp_protocol() {
        // udp protocol (17)
        let data = make_ipt_entry_data(0, 0, 17, "ACCEPT");
        let entry_vaddr: u64 = 0xFFFF_8000_0050_0000;
        let entry_paddr: u64 = 0x00C0_0000;
        let reader = make_ipt_reader(&data, entry_vaddr, entry_paddr);

        let rules = parse_ipt_entries(&reader, entry_vaddr, data.len() as u64, "mangle").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].protocol, "udp");
    }

    #[test]
    fn parse_ipt_entries_unknown_protocol() {
        // Unknown protocol number 47 (GRE)
        let data = make_ipt_entry_data(0, 0, 47, "ACCEPT");
        let entry_vaddr: u64 = 0xFFFF_8000_0060_0000;
        let entry_paddr: u64 = 0x00D0_0000;
        let reader = make_ipt_reader(&data, entry_vaddr, entry_paddr);

        let rules = parse_ipt_entries(&reader, entry_vaddr, data.len() as u64, "filter").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].protocol, "proto:47");
    }

    #[test]
    fn walk_netfilter_rules_missing_init_net_returns_error() {
        // init_net symbol absent → Error returned
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_netfilter_rules(&reader);
        assert!(result.is_err(), "missing init_net should return an error");
    }

    #[test]
    fn walk_netfilter_rules_init_net_present_no_xt_field_returns_empty() {
        // init_net present but net.xt field missing → read_xt_table returns Err
        // → errors are swallowed in the for loop → Ok(vec![])
        let init_net_vaddr: u64 = 0xFFFF_8800_0080_0000;
        let init_net_paddr: u64 = 0x00D0_0000;

        let page = [0u8; 4096];

        let isf = IsfBuilder::new()
            .add_symbol("init_net", init_net_vaddr)
            // "net" struct exists but has no "xt" field → field_offset returns None
            .add_struct("net", 256)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(init_net_vaddr, init_net_paddr, flags::WRITABLE)
            .write_phys(init_net_paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_netfilter_rules(&reader).unwrap_or_default();
        assert!(
            result.is_empty(),
            "missing net.xt field → all tables fail → empty result"
        );
    }

    #[test]
    fn walk_netfilter_rules_init_net_present_no_netns_xt_tables_returns_empty() {
        // init_net + net.xt present, but netns_xt.tables missing → read_xt_table fails
        let init_net_vaddr: u64 = 0xFFFF_8800_0090_0000;
        let init_net_paddr: u64 = 0x00E0_0000;

        let page = [0u8; 4096];

        let isf = IsfBuilder::new()
            .add_symbol("init_net", init_net_vaddr)
            .add_struct("net", 256)
            .add_field("net", "xt", 0x00u64, "netns_xt")
            // netns_xt struct exists but no "tables" field
            .add_struct("netns_xt", 256)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(init_net_vaddr, init_net_paddr, flags::WRITABLE)
            .write_phys(init_net_paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_netfilter_rules(&reader).unwrap_or_default();
        assert!(
            result.is_empty(),
            "missing netns_xt.tables → all tables fail → empty result"
        );
    }

    #[test]
    fn walk_netfilter_rules_init_net_with_empty_xt_list() {
        // init_net + net.xt + netns_xt.tables present; walk_list on the list_head
        // returns empty because the list_head is self-pointing (no entries)
        let init_net_vaddr: u64 = 0xFFFF_8800_00A0_0000;
        let init_net_paddr: u64 = 0x00B0_0000;

        // We put list_head for AF_INET (index 2) at offset = xt_offset + tables_offset + 2*16
        // xt_offset = 0, tables_offset = 0, list_head_size=16 → AF_INET list at byte 32
        // list_head is self-pointing → empty list
        let af_inet_list_offset: usize = 32; // 0 + 0 + 2*16
        let af_inet_list_vaddr = init_net_vaddr + af_inet_list_offset as u64;

        let mut page = [0u8; 4096];
        // Self-pointing list_head at offset 32
        page[af_inet_list_offset..af_inet_list_offset + 8]
            .copy_from_slice(&af_inet_list_vaddr.to_le_bytes());
        page[af_inet_list_offset + 8..af_inet_list_offset + 16]
            .copy_from_slice(&af_inet_list_vaddr.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_symbol("init_net", init_net_vaddr)
            .add_struct("net", 256)
            .add_field("net", "xt", 0x00u64, "netns_xt")
            .add_struct("netns_xt", 256)
            .add_field("netns_xt", "tables", 0x00u64, "pointer")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0x00u64, "pointer")
            .add_field("list_head", "prev", 0x08u64, "pointer")
            .add_struct("xt_table", 128)
            .add_field("xt_table", "list", 0x00u64, "list_head")
            .add_field("xt_table", "name", 0x10u64, "char")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(init_net_vaddr, init_net_paddr, flags::WRITABLE)
            .write_phys(init_net_paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_netfilter_rules(&reader).unwrap_or_default();
        assert!(
            result.is_empty(),
            "empty xt_table list should produce no rules"
        );
    }

    #[test]
    fn format_ipv4_correct() {
        // 192.168.1.1 stored as little-endian u32: 0xC0A80101
        // bytes: [0x01, 0x01, 0xA8, 0xC0] → "1.1.168.192"
        // Actually: to_le_bytes of 0xC0A80101 = [0x01, 0x01, 0xA8, 0xC0]
        // format_ipv4 formats b[0].b[1].b[2].b[3]
        // We test through parse_ipt_entries with a known src_ip
        let src_ip: u32 = u32::from_le_bytes([1, 2, 3, 4]); // stored as-is
        let data = make_ipt_entry_data(src_ip, 0, 6, "ACCEPT");
        let entry_vaddr: u64 = 0xFFFF_8000_0070_0000;
        let entry_paddr: u64 = 0x00E0_0000;
        let reader = make_ipt_reader(&data, entry_vaddr, entry_paddr);

        let rules = parse_ipt_entries(&reader, entry_vaddr, data.len() as u64, "filter").unwrap();
        assert_eq!(rules.len(), 1);
        // source should be Some with dotted notation
        let src = rules[0].source.as_deref().unwrap_or("");
        assert!(
            src.contains('.'),
            "source IP should be dotted notation: {src}"
        );
    }

    // --- parse_ipt_entries: two chained entries (non-zero next_offset) ---
    // Exercises lines 182-186: when next_off != 0, offset advances to next entry.
    #[test]
    fn parse_ipt_entries_two_chained_entries() {
        // Two ipt_entry records back to back. First has next_off = 128 (size of one record).
        // Second has next_off = 0 (terminates).
        let entry_size = 128usize;
        let mut data = vec![0u8; entry_size * 2];

        // Entry 1: src=1.2.3.4 (stored as bytes [1,2,3,4] → u32), proto=6, target="ACCEPT", next=128
        let src1 = u32::from_le_bytes([1, 2, 3, 4]);
        data[0x00..0x04].copy_from_slice(&src1.to_le_bytes());
        data[0x10..0x12].copy_from_slice(&6u16.to_le_bytes()); // tcp
                                                               // target_offset at 0x58: 0x60 → but 0x60 > entry_size(128=0x80), still within 2*128=256
        let target_off1: u16 = 0x60;
        data[0x58..0x5A].copy_from_slice(&target_off1.to_le_bytes());
        // next_offset at 0x5A = 128
        data[0x5A..0x5C].copy_from_slice(&(entry_size as u16).to_le_bytes());
        // target name at 0x60: "ACCEPT"
        data[0x60..0x66].copy_from_slice(b"ACCEPT");

        // Entry 2 at offset 128: dst=5.6.7.8, proto=17, target="DROP", next=0
        let dst2 = u32::from_le_bytes([5, 6, 7, 8]);
        data[entry_size + 0x04..entry_size + 0x08].copy_from_slice(&dst2.to_le_bytes());
        data[entry_size + 0x10..entry_size + 0x12].copy_from_slice(&17u16.to_le_bytes()); // udp
                                                                                          // target_offset for entry 2: since entry 2 starts at 128, target at 128+0x60=0xE0
                                                                                          // but we need it relative to entry 2's base: 0x60 places it at offset 96 within entry
                                                                                          // data[entry_size+0x60..] is within our 256-byte buffer
        let target_off2: u16 = 0x60;
        data[entry_size + 0x58..entry_size + 0x5A].copy_from_slice(&target_off2.to_le_bytes());
        data[entry_size + 0x5A..entry_size + 0x5C].copy_from_slice(&0u16.to_le_bytes()); // next=0
        data[entry_size + 0x60..entry_size + 0x64].copy_from_slice(b"DROP");

        let entry_vaddr: u64 = 0xFFFF_8000_0080_0000;
        let entry_paddr: u64 = 0x00F0_0000;
        let reader = make_ipt_reader(&data, entry_vaddr, entry_paddr);

        let rules = parse_ipt_entries(&reader, entry_vaddr, data.len() as u64, "filter").unwrap();
        assert_eq!(
            rules.len(),
            2,
            "two chained entries should produce two rules"
        );
        assert_eq!(rules[0].target, "ACCEPT");
        assert_eq!(rules[0].protocol, "tcp");
        assert!(rules[0].source.is_some(), "entry 1 has src_ip");
        assert_eq!(rules[1].target, "DROP");
        assert_eq!(rules[1].protocol, "udp");
        assert!(rules[1].destination.is_some(), "entry 2 has dst_ip");
    }

    // --- parse_ipt_entries: target_offset == 0 → target_name is empty string ---
    // Exercises line 153: target_off == 0 → target_name = ""
    #[test]
    fn parse_ipt_entries_zero_target_offset_empty_target_name() {
        let mut data = vec![0u8; 256];
        // target_offset at 0x58 = 0 → condition `target_off > 0` is false → empty name
        // next_offset at 0x5A = 0 → terminates
        let entry_vaddr: u64 = 0xFFFF_8000_0090_0000;
        let entry_paddr: u64 = 0x00F1_0000;
        let reader = make_ipt_reader(&data, entry_vaddr, entry_paddr);

        let rules = parse_ipt_entries(&reader, entry_vaddr, data.len() as u64, "filter").unwrap();
        assert_eq!(rules.len(), 1);
        assert!(
            rules[0].target.is_empty(),
            "zero target_offset must produce empty target name"
        );
    }

    // --- walk_netfilter_rules: xt_table list has an entry whose name matches ---
    // Exercises lines 72-76: the loop inside read_xt_table finds a matching table name
    // → parse_table_rules is called → returns empty (stub) → rules stays empty.
    #[test]
    fn walk_netfilter_rules_matching_table_name_calls_parse() {
        // We need:
        //   init_net symbol, net.xt at offset 0, netns_xt.tables at offset 0,
        //   list_head for AF_INET (index 2 × 16 = offset 32) that points to an
        //   xt_table entry whose "name" field contains "filter".
        //
        // init_net_vaddr layout:
        //   [0..16]  = net.xt (embedded netns_xt, tables at offset 0 within it)
        //   [32..40] = AF_INET list_head.next → xt_table_vaddr (pointing at the table)
        //   [40..48] = AF_INET list_head.prev → af_inet_list_vaddr (self)
        //
        // xt_table_vaddr layout (same page, offset 0x100):
        //   list.next @ offset 0 → af_inet_list_vaddr  (back to head → list terminates after one entry)
        //   list.prev @ offset 8 → af_inet_list_vaddr
        //   name      @ offset 0x10 → "filter\0"
        //   (no private/entries fields needed — parse_table_rules stub returns empty)

        let init_net_vaddr: u64 = 0xFFFF_8800_00A1_0000;
        let init_net_paddr: u64 = 0x00A1_0000;

        let af_inet_offset: u64 = 32; // 2 * list_head_size(16)
        let af_inet_list_vaddr = init_net_vaddr + af_inet_offset;
        let xt_table_off: u64 = 0x100;
        let xt_table_vaddr = init_net_vaddr + xt_table_off;

        let mut page = [0u8; 4096];

        // AF_INET list_head at [32..48]: next=xt_table_vaddr, prev=af_inet_list_vaddr
        page[32..40].copy_from_slice(&xt_table_vaddr.to_le_bytes()); // list_head.next → xt_table
        page[40..48].copy_from_slice(&af_inet_list_vaddr.to_le_bytes()); // list_head.prev

        // xt_table at [0x100..]:
        //   list.next @ 0x100 = af_inet_list_vaddr (back to head, terminates walk_list)
        //   list.prev @ 0x108 = af_inet_list_vaddr
        //   name @ 0x110 = "filter\0"
        page[0x100..0x108].copy_from_slice(&af_inet_list_vaddr.to_le_bytes()); // list.next
        page[0x108..0x110].copy_from_slice(&af_inet_list_vaddr.to_le_bytes()); // list.prev
        let name_bytes = b"filter\0";
        page[0x110..0x110 + name_bytes.len()].copy_from_slice(name_bytes);

        let isf = IsfBuilder::new()
            .add_symbol("init_net", init_net_vaddr)
            .add_struct("net", 256)
            .add_field("net", "xt", 0x00u64, "netns_xt")
            .add_struct("netns_xt", 256)
            .add_field("netns_xt", "tables", 0x00u64, "pointer")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0x00u64, "pointer")
            .add_field("list_head", "prev", 0x08u64, "pointer")
            .add_struct("xt_table", 128)
            .add_field("xt_table", "list", 0x00u64, "list_head")
            .add_field("xt_table", "name", 0x10u64, "char")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(init_net_vaddr, init_net_paddr, flags::WRITABLE)
            .write_phys(init_net_paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // parse_table_rules is a stub that returns Ok([]) → total result is empty
        let result = walk_netfilter_rules(&reader).unwrap_or_default();
        assert!(
            result.is_empty(),
            "matching table name calls parse_table_rules (stub) → still empty"
        );
    }

    // ---------------------------------------------------------------------------
    // parse_table_rules tests
    // ---------------------------------------------------------------------------

    /// Build a reader wired up with `xt_table` and `xt_table_info` ISF types plus
    /// the real entry data so that `parse_table_rules` can follow the full chain:
    ///   xt_table.private → xt_table_info → (entries vaddr, size) → ipt_entry region
    fn make_parse_table_rules_reader(
        private_ptr: u64, // value stored in xt_table.private (0 = null test)
        table_vaddr: u64,
        table_paddr: u64,
        table_info_vaddr: u64,
        table_info_paddr: u64,
        entries_vaddr: u64,
        entries_paddr: u64,
        entry_data: &[u8],
    ) -> ObjectReader<SyntheticPhysMem> {
        // ISF: add xt_table.private (pointer), xt_table_info.entries (pointer),
        //      xt_table_info.size (unsigned long)
        let isf = IsfBuilder::new()
            // xt_table: only need the fields parse_table_rules reads
            .add_struct("xt_table", 256)
            .add_field("xt_table", "private", 0x00u64, "pointer")
            // xt_table_info: entries at offset 0, size at offset 8
            .add_struct("xt_table_info", 256)
            .add_field("xt_table_info", "entries", 0x00u64, "pointer")
            .add_field("xt_table_info", "size", 0x08u64, "unsigned long")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let entry_size = entry_data.len() as u64;

        // xt_table page: private pointer at offset 0
        let mut table_page = [0u8; 4096];
        table_page[0x00..0x08].copy_from_slice(&private_ptr.to_le_bytes());

        // xt_table_info page: entries pointer at offset 0, size at offset 8
        let mut info_page = [0u8; 4096];
        info_page[0x00..0x08].copy_from_slice(&entries_vaddr.to_le_bytes());
        info_page[0x08..0x10].copy_from_slice(&entry_size.to_le_bytes());

        let mut builder = PageTableBuilder::new()
            .map_4k(table_vaddr, table_paddr, flags::PRESENT | flags::WRITABLE)
            .write_phys(table_paddr, &table_page);

        if private_ptr != 0 {
            builder = builder
                .map_4k(
                    table_info_vaddr,
                    table_info_paddr,
                    flags::PRESENT | flags::WRITABLE,
                )
                .write_phys(table_info_paddr, &info_page)
                .map_4k(
                    entries_vaddr,
                    entries_paddr,
                    flags::PRESENT | flags::WRITABLE,
                )
                .write_phys(entries_paddr, entry_data);
        }

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// parse_table_rules should follow xt_table.private → xt_table_info → ipt_entry region
    /// and return at least one NetfilterRuleInfo when given a valid ipt_entry.
    #[test]
    fn parse_table_rules_returns_rules_from_xt_table() {
        let entry_data = make_ipt_entry_data(0, 0, 6, "ACCEPT");

        let table_vaddr: u64 = 0xFFFF_8000_0100_0000;
        let table_paddr: u64 = 0x0010_0000;
        let table_info_vaddr: u64 = 0xFFFF_8000_0101_0000;
        let table_info_paddr: u64 = 0x0011_0000;
        let entries_vaddr: u64 = 0xFFFF_8000_0102_0000;
        let entries_paddr: u64 = 0x0012_0000;

        let reader = make_parse_table_rules_reader(
            table_info_vaddr, // private → points to xt_table_info
            table_vaddr,
            table_paddr,
            table_info_vaddr,
            table_info_paddr,
            entries_vaddr,
            entries_paddr,
            &entry_data,
        );

        let rules = parse_table_rules(&reader, table_vaddr, "filter").unwrap();
        assert!(
            !rules.is_empty(),
            "parse_table_rules should return at least one rule from the ipt_entry region"
        );
        assert_eq!(rules[0].target, "ACCEPT");
        assert_eq!(rules[0].protocol, "tcp");
    }

    /// When xt_table.private is 0 (null), parse_table_rules must return an empty Vec.
    #[test]
    fn parse_table_rules_empty_when_private_null() {
        let table_vaddr: u64 = 0xFFFF_8000_0110_0000;
        let table_paddr: u64 = 0x0013_0000;

        let reader = make_parse_table_rules_reader(
            0, // private = null
            table_vaddr,
            table_paddr,
            0, // unused
            0,
            0,
            0,
            &[],
        );

        let rules = parse_table_rules(&reader, table_vaddr, "filter").unwrap();
        assert!(
            rules.is_empty(),
            "null xt_table.private must produce an empty rule list"
        );
    }

    // --- NetfilterRuleInfo: Clone + Debug coverage ---
    #[test]
    fn netfilter_rule_info_clone_debug() {
        use crate::NetfilterRuleInfo;
        let rule = NetfilterRuleInfo {
            table: "filter".to_string(),
            chain: "INPUT".to_string(),
            target: "DROP".to_string(),
            protocol: "tcp".to_string(),
            source: Some("1.2.3.4".to_string()),
            destination: None,
        };
        let cloned = rule.clone();
        assert_eq!(cloned.table, "filter");
        assert_eq!(cloned.target, "DROP");
        let dbg = format!("{:?}", cloned);
        assert!(dbg.contains("DROP"));
        assert!(dbg.contains("1.2.3.4"));
    }
}
