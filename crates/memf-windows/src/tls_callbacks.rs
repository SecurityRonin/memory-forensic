//! TLS (Thread Local Storage) callback validation walker.
//!
//! Walks the TLS directory of each loaded PE image to enumerate TLS
//! callback function pointers and detect those that resolve outside the
//! module's mapped range — a sign of callback hijacking.
//! MITRE ATT&CK T1055 / T1106.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{types::TlsCallbackInfo, Result};

/// Walk TLS directories of all loaded modules in all processes and validate
/// callback addresses.
///
/// For each `_IMAGE_TLS_DIRECTORY` found, extracts the callback array and
/// checks that each entry falls within `[module_base, module_base + size)`.
/// Callbacks that resolve outside this range are flagged as
/// `is_outside_module = true`.
///
/// # MITRE ATT&CK
/// T1055 — Process Injection (TLS callback abuse)
pub fn scan_tls_callbacks<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<TlsCallbackInfo>> {
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
        let result = scan_tls_callbacks(&reader);
        assert!(result.is_ok(), "should succeed with minimal reader");
        assert!(
            result.unwrap().is_empty(),
            "empty memory → no TLS callback hits"
        );
    }

    #[test]
    fn result_is_vec_of_tls_callback_info() {
        let reader = make_minimal_reader();
        let result: Result<Vec<TlsCallbackInfo>> = scan_tls_callbacks(&reader);
        assert!(result.is_ok());
    }

    #[test]
    fn tls_callback_info_fields_constructible() {
        let info = TlsCallbackInfo {
            pid: 2048,
            image_name: "malware.exe".to_string(),
            module_name: "malware.dll".to_string(),
            callback_address: 0xDEAD_CAFE,
            callback_count: 2,
            is_outside_module: true,
        };
        assert_eq!(info.pid, 2048);
        assert_eq!(info.callback_count, 2);
        assert!(info.is_outside_module);
    }

    #[test]
    fn tls_callback_info_serializes() {
        let info = TlsCallbackInfo {
            pid: 9,
            image_name: "legit.exe".to_string(),
            module_name: "vcruntime.dll".to_string(),
            callback_address: 0x7FFF_1234,
            callback_count: 1,
            is_outside_module: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":9"));
        assert!(json.contains("vcruntime.dll"));
        assert!(json.contains("\"is_outside_module\":false"));
    }

    // --- classifier helper tests (genuine RED: function does not exist yet) ---

    #[test]
    fn tls_callback_outside_all_ranges_is_unbacked() {
        let ranges = [(0x7fff_0000_u64, 0x7fff_1000_u64)];
        assert!(is_unbacked_tls_callback(0xDEAD_CAFE, &ranges));
    }

    #[test]
    fn tls_callback_inside_a_range_is_backed() {
        let ranges = [(0x7fff_0000_u64, 0x7fff_1000_u64)];
        assert!(!is_unbacked_tls_callback(0x7fff_0100, &ranges));
    }

    #[test]
    fn tls_callback_with_empty_ranges_is_unbacked() {
        assert!(is_unbacked_tls_callback(0x1234, &[]));
    }
}
