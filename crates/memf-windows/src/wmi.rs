//! WMI persistent event subscription detection.
//!
//! Windows Management Instrumentation (WMI) supports persistent event
//! subscriptions that survive reboots -- a technique heavily used by APTs
//! for fileless persistence. The kernel maintains a binding table
//! (`WmipBindingTable` / `CimBindingTable`) linking event filters to
//! event consumers. By walking this table from memory, we can detect
//! subscriptions that would otherwise require CIM repository parsing.
//!
//! Suspicious consumers include `CommandLineEventConsumer` (executes
//! arbitrary commands) and `ActiveScriptEventConsumer` (runs VBScript/
//! JScript), especially when paired with queries targeting process
//! creation events (`Win32_ProcessStartTrace`, `__InstanceCreationEvent`).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;

/// Maximum number of WMI binding entries to iterate (safety limit).
const MAX_BINDINGS: usize = 4096;

/// Information about a WMI persistent event subscription recovered from memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WmiSubscriptionInfo {
    /// Name of the event filter (e.g., "BVTFilter").
    pub filter_name: String,
    /// Name of the event consumer (e.g., "BVTConsumer").
    pub consumer_name: String,
    /// Consumer class name (e.g., "CommandLineEventConsumer", "ActiveScriptEventConsumer").
    pub consumer_type: String,
    /// WQL query string from the event filter.
    pub query: String,
    /// Heuristic flag: true if the subscription looks suspicious.
    pub is_suspicious: bool,
}

/// Enumerate WMI persistent event subscriptions from kernel memory.
///
/// Walks the `WmipBindingTable` (or `CimBindingTable`) -- an array of
/// pointers to `_WMI_BINDING` structures. Each binding links an event
/// filter to an event consumer. Returns an empty `Vec` if the required
/// WMI symbols are not present (graceful degradation).
///
/// # Errors
///
/// Returns an error if memory reads fail for the binding table after
/// the symbol has been located and validated.
pub fn walk_wmi_subscriptions<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<WmiSubscriptionInfo>> {
    // Try WmipBindingTable first (Win10+), then CimBindingTable (older).
    let table_addr = match reader.symbols().symbol_address("WmipBindingTable") {
        Some(addr) => addr,
        None => match reader.symbols().symbol_address("CimBindingTable") {
            Some(addr) => addr,
            None => return Ok(Vec::new()),
        },
    };

    // Read the pointer to the actual binding array.
    let array_addr: u64 = match reader.read_bytes(table_addr, 8) {
        Ok(bytes) => {
            let arr: [u8; 8] = match bytes[..8].try_into() {
                Ok(a) => a,
                Err(_) => return Ok(Vec::new()),
            };
            u64::from_le_bytes(arr)
        }
        Err(_) => return Ok(Vec::new()),
    };

    if array_addr == 0 {
        return Ok(Vec::new());
    }

    // Read binding count from WmipBindingCount symbol.
    let binding_count = match reader.symbols().symbol_address("WmipBindingCount") {
        Some(count_addr) => match reader.read_bytes(count_addr, 4) {
            Ok(bytes) => {
                let arr: [u8; 4] = match bytes[..4].try_into() {
                    Ok(a) => a,
                    Err(_) => return Ok(Vec::new()),
                };
                (u32::from_le_bytes(arr) as usize).min(MAX_BINDINGS)
            }
            Err(_) => return Ok(Vec::new()),
        },
        None => MAX_BINDINGS,
    };

    // Get field offsets for _WMI_BINDING structure.
    let filter_name_offset = reader
        .symbols()
        .field_offset("_WMI_BINDING", "FilterName")
        .unwrap_or(0x00);
    let consumer_name_offset = reader
        .symbols()
        .field_offset("_WMI_BINDING", "ConsumerName")
        .unwrap_or(0x10);
    let consumer_type_offset = reader
        .symbols()
        .field_offset("_WMI_BINDING", "ConsumerType")
        .unwrap_or(0x20);
    let query_offset = reader
        .symbols()
        .field_offset("_WMI_BINDING", "Query")
        .unwrap_or(0x30);

    let binding_size = reader.symbols().struct_size("_WMI_BINDING").unwrap_or(0x80) as u64;

    let mut subscriptions = Vec::new();

    for i in 0..binding_count {
        let entry_addr = array_addr + (i as u64) * binding_size;

        // Read filter name (UNICODE_STRING).
        let filter_name =
            read_unicode_string(reader, entry_addr + filter_name_offset).unwrap_or_default();

        // Skip empty entries.
        if filter_name.is_empty() {
            continue;
        }

        // Read consumer name (UNICODE_STRING).
        let consumer_name =
            read_unicode_string(reader, entry_addr + consumer_name_offset).unwrap_or_default();

        // Read consumer type (UNICODE_STRING).
        let consumer_type =
            read_unicode_string(reader, entry_addr + consumer_type_offset).unwrap_or_default();

        // Read WQL query (UNICODE_STRING).
        let query = read_unicode_string(reader, entry_addr + query_offset).unwrap_or_default();

        let is_suspicious = classify_wmi_consumer(&consumer_type, &query);

        subscriptions.push(WmiSubscriptionInfo {
            filter_name,
            consumer_name,
            consumer_type,
            query,
            is_suspicious,
        });
    }

    Ok(subscriptions)
}

/// Classify whether a WMI event subscription is suspicious.
///
/// Returns `true` if the consumer type is one that can execute arbitrary
/// code (`CommandLineEventConsumer`, `ActiveScriptEventConsumer`) or if
/// the WQL query targets process creation events -- common indicators of
/// WMI-based persistence used by threat actors.
pub fn classify_wmi_consumer(consumer_type: &str, query: &str) -> bool {
    // Suspicious consumer types that can execute arbitrary code.
    let suspicious_types = ["CommandLineEventConsumer", "ActiveScriptEventConsumer"];

    if suspicious_types.iter().any(|t| consumer_type.contains(t)) {
        return true;
    }

    // Suspicious WQL query patterns targeting process creation.
    let query_lower = query.to_lowercase();
    let suspicious_queries = [
        "win32_processstarttrace",
        "__instancecreationevent",
        "win32_processstoptrace",
    ];

    suspicious_queries.iter().any(|q| query_lower.contains(q))
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// No WMI binding symbol -> empty Vec (graceful degradation).
    #[test]
    fn walk_wmi_subscriptions_no_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("_WMI_BINDING", 0x80)
            .add_field("_WMI_BINDING", "FilterName", 0x00, "_UNICODE_STRING")
            .add_field("_WMI_BINDING", "ConsumerName", 0x10, "_UNICODE_STRING")
            .add_field("_WMI_BINDING", "ConsumerType", 0x20, "_UNICODE_STRING")
            .add_field("_WMI_BINDING", "Query", 0x30, "_UNICODE_STRING")
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_wmi_subscriptions(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// CommandLineEventConsumer is classified as suspicious.
    #[test]
    fn classify_wmi_suspicious_cmd() {
        assert!(classify_wmi_consumer(
            "CommandLineEventConsumer",
            "SELECT * FROM __InstanceCreationEvent WITHIN 5"
        ));
    }

    /// ActiveScriptEventConsumer is classified as suspicious.
    #[test]
    fn classify_wmi_suspicious_script() {
        assert!(classify_wmi_consumer(
            "ActiveScriptEventConsumer",
            "SELECT * FROM Win32_ProcessStartTrace"
        ));
    }

    /// Intrinsic event consumer types are NOT suspicious when paired with
    /// non-process-creation queries.
    #[test]
    fn classify_wmi_benign_intrinsic() {
        assert!(!classify_wmi_consumer(
            "LogFileEventConsumer",
            "SELECT * FROM __InstanceModificationEvent WHERE TargetInstance ISA 'Win32_Service'"
        ));
        assert!(!classify_wmi_consumer(
            "NTEventLogEventConsumer",
            "SELECT * FROM Win32_VolumeChangeEvent"
        ));
    }

    /// Process-creation queries are suspicious even with benign consumer types.
    #[test]
    fn classify_wmi_suspicious_query_pattern() {
        assert!(classify_wmi_consumer(
            "LogFileEventConsumer",
            "SELECT * FROM Win32_ProcessStartTrace"
        ));
        assert!(classify_wmi_consumer(
            "SMTPEventConsumer",
            "SELECT * FROM __InstanceCreationEvent WHERE TargetInstance ISA 'Win32_Process'"
        ));
    }

    /// Single WMI subscription recovered from synthetic memory.
    #[test]
    fn walk_wmi_subscriptions_single_binding() {
        // Memory layout:
        //   WmipBindingTable @ 0xFFFF_8000_0010_0000 -> points to array_addr
        //   WmipBindingCount @ 0xFFFF_8000_0010_1000 -> 1 (u32)
        //   _WMI_BINDING array @ 0xFFFF_8000_0020_0000
        //     [0]: FilterName, ConsumerName, ConsumerType, Query as UNICODE_STRINGs
        //   String buffers at 0xFFFF_8000_0030_xxxx

        let table_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let count_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let binding_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let filter_buf_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let consumer_buf_vaddr: u64 = 0xFFFF_8000_0030_1000;
        let type_buf_vaddr: u64 = 0xFFFF_8000_0030_2000;
        let query_buf_vaddr: u64 = 0xFFFF_8000_0030_3000;

        let table_paddr: u64 = 0x0010_0000;
        let count_paddr: u64 = 0x0011_0000;
        let binding_paddr: u64 = 0x0020_0000;
        let filter_buf_paddr: u64 = 0x0030_0000;
        let consumer_buf_paddr: u64 = 0x0031_0000;
        let type_buf_paddr: u64 = 0x0032_0000;
        let query_buf_paddr: u64 = 0x0033_0000;

        let isf = IsfBuilder::new()
            .add_struct("_WMI_BINDING", 0x80)
            .add_field("_WMI_BINDING", "FilterName", 0x00, "_UNICODE_STRING")
            .add_field("_WMI_BINDING", "ConsumerName", 0x10, "_UNICODE_STRING")
            .add_field("_WMI_BINDING", "ConsumerType", 0x20, "_UNICODE_STRING")
            .add_field("_WMI_BINDING", "Query", 0x30, "_UNICODE_STRING")
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            .add_symbol("WmipBindingTable", table_vaddr)
            .add_symbol("WmipBindingCount", count_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Encode a Rust string as UTF-16LE bytes.
        fn utf16le(s: &str) -> Vec<u8> {
            s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
        }

        let filter_name = utf16le("MalFilter");
        let consumer_name = utf16le("MalConsumer");
        let consumer_type = utf16le("CommandLineEventConsumer");
        let query_str = utf16le("SELECT * FROM __InstanceCreationEvent WITHIN 5");

        // Build _WMI_BINDING[0] structure data.
        let mut binding_data = vec![0u8; 0x80];

        // FilterName at offset 0x00 (_UNICODE_STRING: Length u16, MaxLen u16, pad 4, Buffer u64)
        binding_data[0x00..0x02].copy_from_slice(&(filter_name.len() as u16).to_le_bytes());
        binding_data[0x02..0x04].copy_from_slice(&((filter_name.len() + 2) as u16).to_le_bytes());
        binding_data[0x08..0x10].copy_from_slice(&filter_buf_vaddr.to_le_bytes());

        // ConsumerName at offset 0x10
        binding_data[0x10..0x12].copy_from_slice(&(consumer_name.len() as u16).to_le_bytes());
        binding_data[0x12..0x14].copy_from_slice(&((consumer_name.len() + 2) as u16).to_le_bytes());
        binding_data[0x18..0x20].copy_from_slice(&consumer_buf_vaddr.to_le_bytes());

        // ConsumerType at offset 0x20
        binding_data[0x20..0x22].copy_from_slice(&(consumer_type.len() as u16).to_le_bytes());
        binding_data[0x22..0x24].copy_from_slice(&((consumer_type.len() + 2) as u16).to_le_bytes());
        binding_data[0x28..0x30].copy_from_slice(&type_buf_vaddr.to_le_bytes());

        // Query at offset 0x30
        binding_data[0x30..0x32].copy_from_slice(&(query_str.len() as u16).to_le_bytes());
        binding_data[0x32..0x34].copy_from_slice(&((query_str.len() + 2) as u16).to_le_bytes());
        binding_data[0x38..0x40].copy_from_slice(&query_buf_vaddr.to_le_bytes());

        // Build page table with all mappings and write physical data inline.
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(table_vaddr, table_paddr, flags::WRITABLE)
            .write_phys(table_paddr, &binding_vaddr.to_le_bytes())
            .map_4k(count_vaddr, count_paddr, flags::WRITABLE)
            .write_phys(count_paddr, &1u32.to_le_bytes())
            .map_4k(binding_vaddr, binding_paddr, flags::WRITABLE)
            .write_phys(binding_paddr, &binding_data)
            .map_4k(filter_buf_vaddr, filter_buf_paddr, flags::WRITABLE)
            .write_phys(filter_buf_paddr, &filter_name)
            .map_4k(consumer_buf_vaddr, consumer_buf_paddr, flags::WRITABLE)
            .write_phys(consumer_buf_paddr, &consumer_name)
            .map_4k(type_buf_vaddr, type_buf_paddr, flags::WRITABLE)
            .write_phys(type_buf_paddr, &consumer_type)
            .map_4k(query_buf_vaddr, query_buf_paddr, flags::WRITABLE)
            .write_phys(query_buf_paddr, &query_str)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_wmi_subscriptions(&reader).unwrap();
        assert_eq!(result.len(), 1);

        let sub = &result[0];
        assert_eq!(sub.filter_name, "MalFilter");
        assert_eq!(sub.consumer_name, "MalConsumer");
        assert_eq!(sub.consumer_type, "CommandLineEventConsumer");
        assert!(sub.query.contains("__InstanceCreationEvent"));
        assert!(sub.is_suspicious);
    }
}
