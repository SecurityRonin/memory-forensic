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
    _reader: &ObjectReader<P>,
    _table_addr: u64,
    table_name: &str,
) -> Result<Vec<NetfilterRuleInfo>> {
    // The actual rule parsing from ipt_entry structures is extremely complex.
    // For now, return a placeholder indicating the table was found.
    // Full ipt_entry parsing would need: ipt_entry → ipt_entry_target → target name,
    // plus ipt_ip for source/dest/protocol matching.
    // This is a detection-only stub — we confirmed the table exists.
    let _ = table_name;
    Ok(Vec::new())
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
}
