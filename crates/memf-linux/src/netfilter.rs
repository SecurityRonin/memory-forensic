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

#[allow(clippy::unnecessary_wraps)] // will do fallible parsing once ipt_entry is implemented
fn parse_table_rules<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    table_addr: u64,
    table_name: &str,
) -> Result<Vec<NetfilterRuleInfo>> {
    // Resolve the private table data pointer: xt_table.private → xt_table_info.
    // xt_table_info.entries holds the actual ipt_entry data region.
    // For now delegate to parse_ipt_entries if we can read the entries pointer.
    // This is a stub that returns empty until ipt_entry parsing is implemented.
    let _ = (reader, table_addr, table_name);
    Ok(Vec::new())
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
        let dst_ip = u32::from_le_bytes(
            data[offset + 4..offset + 8]
                .try_into()
                .unwrap_or([0; 4]),
        );
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
}
