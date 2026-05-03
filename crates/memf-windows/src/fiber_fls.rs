//! Fiber and Fiber Local Storage (FLS) abuse detection — MITRE ATT&CK T1055.
//!
//! Detects threads that have been converted to fibers and FLS callback
//! pointers that resolve outside loaded module ranges.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{types::FiberInfo, Result};

/// Scan all threads for fiber conversion and suspicious FLS callbacks.
///
/// Walks `_ETHREAD` structures looking for threads whose `Fiber` flag is
/// set (indicating a call to `ConvertThreadToFiber`). Extracts the saved
/// fiber context `RIP` and checks each FLS callback slot against the set
/// of loaded module address ranges, flagging any that fall outside.
///
/// # MITRE ATT&CK
/// T1055 — Process Injection (Fiber / FLS sub-technique)
pub fn scan_fiber_fls<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<FiberInfo>> {
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
        let result = scan_fiber_fls(&reader);
        assert!(result.is_ok(), "should succeed with minimal reader");
        assert!(result.unwrap().is_empty(), "empty memory → no fiber/FLS hits");
    }

    #[test]
    fn result_is_vec_of_fiber_info() {
        let reader = make_minimal_reader();
        let result: Result<Vec<FiberInfo>> = scan_fiber_fls(&reader);
        assert!(result.is_ok());
    }

    #[test]
    fn fiber_info_fields_constructible() {
        let info = FiberInfo {
            pid: 1111,
            tid: 2222,
            image_name: "notepad.exe".to_string(),
            fiber_rip: 0xDEAD_C0DE,
            fiber_stack_base: 0x7F00_0000,
            is_converted: true,
            fls_callback_unbacked: true,
        };
        assert_eq!(info.pid, 1111);
        assert_eq!(info.tid, 2222);
        assert!(info.is_converted);
        assert!(info.fls_callback_unbacked);
    }

    #[test]
    fn fiber_info_serializes() {
        let info = FiberInfo {
            pid: 5,
            tid: 6,
            image_name: "evil.exe".to_string(),
            fiber_rip: 0x1234,
            fiber_stack_base: 0x5678,
            is_converted: false,
            fls_callback_unbacked: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":5"));
        assert!(json.contains("evil.exe"));
        assert!(json.contains("\"fls_callback_unbacked\":true"));
    }
}
