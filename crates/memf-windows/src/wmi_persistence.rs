//! WMI persistent event subscription detection.
//!
//! WMI subscriptions (EventFilter + EventConsumer + FilterToConsumerBinding)
//! are a heavily-used APT persistence mechanism. Subscriptions survive reboots
//! and execute arbitrary commands or scripts when trigger conditions fire.
//!
//! This module provides:
//! - A heuristic classifier for suspicious WMI subscriptions
//! - A graceful-degradation walker that returns empty when WMI symbols absent
//!
//! A full implementation would scan WMI service process heaps
//! (`WmiPrvSE.exe` / `svchost.exe` hosting `winmgmt`) for subscription
//! objects, or parse the `WmipBindingTable` kernel structure if present.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about a WMI persistent event subscription.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WmiSubscriptionInfo {
    /// Subscription object type: "EventFilter", "EventConsumer", or "Binding".
    pub subscription_type: String,
    /// Name of this subscription.
    pub name: String,
    /// WQL query string (for EventFilter entries).
    pub query: String,
    /// Consumer class name (e.g. "CommandLineEventConsumer").
    pub consumer_type: String,
    /// Command line to execute (for CommandLineEventConsumer).
    pub command_line: String,
    /// Script text (for ActiveScriptEventConsumer).
    pub script_text: String,
    /// True if heuristics indicate suspicious persistence.
    pub is_suspicious: bool,
}

/// Heuristic classifier for suspicious WMI subscriptions.
///
/// Returns `true` if the subscription exhibits characteristics associated
/// with malicious persistence:
/// - EventFilter queries targeting modification events with `TargetInstance ISA`
/// - CommandLineEventConsumer running PowerShell, cmd.exe, or writing to temp paths
/// - Well-known malicious subscription names
pub fn classify_wmi_subscription(name: &str, query: &str, command: &str) -> bool {
    let q = query.to_ascii_lowercase();
    let c = command.to_ascii_lowercase();

    // Suspicious WQL patterns: persistence-oriented modification event queries
    let suspicious_query = q.contains("__instancemodificationevent") && q.contains("targetinstance isa")
        || q.contains("win32_processtrace")
        || q.contains("__instancecreationevent") && q.contains("win32_process");

    // Suspicious consumer commands: code execution paths
    let suspicious_command = c.contains("powershell")
        || c.contains("cmd.exe /c")
        || c.contains("\\temp\\")
        || c.contains("\\appdata\\")
        || c.contains("wscript")
        || c.contains("cscript");

    // Known malicious subscription names
    let suspicious_name = name.eq_ignore_ascii_case("updater")
        || name.eq_ignore_ascii_case("sysmon bypass")
        || name.eq_ignore_ascii_case("windows update");

    suspicious_query || suspicious_command || suspicious_name
}

/// Walk memory for WMI persistent event subscriptions.
///
/// Returns `Ok(Vec::new())` when WMI-related kernel symbols are absent
/// (graceful degradation). A full implementation would scan the
/// `WmipBindingTable` or WMI service process heaps.
pub fn walk_wmi_subscriptions<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<WmiSubscriptionInfo>> {
    // Graceful degradation: require WmipBindingTable or PsActiveProcessHead
    if reader
        .symbols()
        .symbol_address("WmipBindingTable")
        .is_none()
        && reader
            .symbols()
            .symbol_address("PsActiveProcessHead")
            .is_none()
    {
        return Ok(Vec::new());
    }

    // In a full implementation we would:
    // 1. Locate WmipBindingTable or walk WMI service process heaps
    // 2. Parse CIM object blobs for EventFilter/Consumer objects
    // 3. Extract name, query, consumer type, command/script fields
    // 4. Call classify_wmi_subscription and build entries
    //
    // Returning empty pending full WMI object parser implementation.
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A CommandLineEventConsumer running PowerShell is suspicious.
    #[test]
    fn classify_suspicious_wmi_powershell_consumer() {
        assert!(classify_wmi_subscription(
            "PersistenceFilter",
            "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'",
            "powershell.exe -enc dXBkYXRl"
        ));
    }

    /// A benign intrinsic WMI subscription is not suspicious.
    #[test]
    fn classify_benign_wmi_subscription() {
        assert!(!classify_wmi_subscription(
            "SCM Event Log Filter",
            "SELECT * FROM MSFT_SCMEventLogEvent",
            ""
        ));
    }

    /// Without WMI or process symbols, walker returns empty.
    #[test]
    fn walk_wmi_no_symbol_returns_empty() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let page_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let page_paddr: u64 = 0x0080_0000;
        let ptb = PageTableBuilder::new()
            .map_4k(page_vaddr, page_paddr, flags::WRITABLE)
            .write_phys(page_paddr, &[0u8; 16]);
        let (cr3, mem) = ptb.build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_wmi_subscriptions(&reader).unwrap();
        assert!(results.is_empty());
    }
}
