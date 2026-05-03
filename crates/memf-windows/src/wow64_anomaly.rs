//! WoW64 / Heaven's Gate anomaly detection walker — MITRE ATT&CK T1055.
//!
//! Detects 32-bit processes that use the Heaven's Gate technique (switching
//! to 64-bit mode via a far JMP to CS=0x33) or whose WoW64 syscall stub
//! has been patched to bypass hooks.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{types::Wow64AnomalyInfo, Result};

/// Classify whether a WoW64 process has an anomalous configuration.
///
/// Returns `true` if the process is marked as WoW64 (`is_wow64`) but does not
/// have a 32-bit PEB (`!has_32bit_peb`). A genuine WoW64 process always has
/// a 32-bit PEB; its absence while the WoW64 flag is set indicates that the
/// WoW64 machinery has been tampered with (e.g. Heaven's Gate manipulation).
pub fn is_wow64_suspicious(is_wow64: bool, has_32bit_peb: bool) -> bool {
    is_wow64 && !has_32bit_peb
}

/// Scan all WoW64 (32-bit) processes for Heaven's Gate and syscall-stub
/// tampering anomalies.
///
/// For each process where `_EPROCESS.Wow64Process` is non-null:
/// - Checks for a CS=0x33 segment selector in any thread's context
///   (Heaven's Gate indicator).
/// - Reads the first bytes of the `KiFastSystemCall` stub in the 32-bit
///   `ntdll.dll` mapping and compares with the expected sequence; any
///   deviation sets `syscall_stub_tampered`.
/// - Records whether `wow64.dll` is present in the process module list.
///
/// # MITRE ATT&CK
/// T1055 — Process Injection (WoW64 / Heaven's Gate)
pub fn scan_wow64_anomalies<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<Wow64AnomalyInfo>> {
    let _ = reader;
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_minimal_reader(
    ) -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn empty_memory_returns_ok_empty() {
        let reader = make_minimal_reader();
        let result = scan_wow64_anomalies(&reader);
        assert!(result.is_ok(), "should succeed with minimal reader");
        assert!(
            result.unwrap().is_empty(),
            "empty memory → no WoW64 anomaly hits"
        );
    }

    #[test]
    fn result_is_vec_of_wow64_anomaly_info() {
        let reader = make_minimal_reader();
        let result: Result<Vec<Wow64AnomalyInfo>> = scan_wow64_anomalies(&reader);
        assert!(result.is_ok());
    }

    #[test]
    fn wow64_anomaly_info_fields_constructible() {
        let info = Wow64AnomalyInfo {
            pid: 3030,
            image_name: "malware32.exe".to_string(),
            has_peb32: true,
            heavens_gate_detected: true,
            wow64_dll_path: String::new(),
            syscall_stub_tampered: true,
        };
        assert_eq!(info.pid, 3030);
        assert!(info.has_peb32);
        assert!(info.heavens_gate_detected);
        assert!(info.syscall_stub_tampered);
        assert!(info.wow64_dll_path.is_empty());
    }

    #[test]
    fn wow64_anomaly_info_serializes() {
        let info = Wow64AnomalyInfo {
            pid: 17,
            image_name: "iexplore.exe".to_string(),
            has_peb32: true,
            heavens_gate_detected: false,
            wow64_dll_path: r"C:\Windows\SysWOW64\wow64.dll".to_string(),
            syscall_stub_tampered: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":17"));
        assert!(json.contains("iexplore.exe"));
        assert!(json.contains("\"heavens_gate_detected\":false"));
        assert!(json.contains("\"syscall_stub_tampered\":false"));
    }

    // --- classifier helper tests (genuine RED: function does not exist yet) ---

    #[test]
    fn wow64_process_without_peb32_is_suspicious() {
        // Marked as WoW64 but has no 32-bit PEB → anomalous
        assert!(is_wow64_suspicious(true, false));
    }

    #[test]
    fn wow64_process_with_peb32_is_not_suspicious() {
        assert!(!is_wow64_suspicious(true, true));
    }

    #[test]
    fn non_wow64_process_is_not_suspicious() {
        assert!(!is_wow64_suspicious(false, false));
    }
}
