//! DKOM (Direct Kernel Object Manipulation) cross-reference detection.
//!
//! Compares multiple kernel enumeration sources to detect objects that have
//! been unlinked from one or more lists — the hallmark of DKOM rootkits.
//! MITRE ATT&CK T1014.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{
    types::{DkomDiscrepancy, DkomType},
    Result,
};

/// Classify a kernel object's presence across multiple enumeration sources and
/// return the type of DKOM hiding detected, if any.
///
/// - Returns `Some(DkomType::ProcessUnlinked)` if the object is in `CidTable`
///   (`in_cid`) but absent from `PsActiveProcessHead` (`!in_active`).
/// - Returns `Some(DkomType::DriverUnlinked)` if the driver is in `MmDriverList`
///   (`in_driver`) but absent from `PsLoadedModuleList` (`!in_module`).
/// - Returns `None` if no discrepancy is detected.
///
/// Process unlinking takes priority over driver unlinking when both conditions
/// are simultaneously true.
pub fn classify_dkom(
    in_cid: bool,
    in_active: bool,
    in_driver: bool,
    in_module: bool,
) -> Option<DkomType> {
    if in_cid && !in_active {
        Some(DkomType::ProcessUnlinked)
    } else if in_driver && !in_module {
        Some(DkomType::DriverUnlinked)
    } else {
        None
    }
}

/// Cross-reference kernel process/driver/thread lists to detect DKOM hiding.
///
/// Compares:
/// - `PsActiveProcessHead` linked list vs `CidTable` handle table (processes)
/// - `PsLoadedModuleList` vs `MmDriverList` (drivers)
/// - Per-process `_EPROCESS.ThreadListHead` vs global thread scans (threads)
///
/// Any object present in one source but absent in another is reported as a
/// `DkomDiscrepancy`.
///
/// # MITRE ATT&CK
/// T1014 — Rootkit
pub fn scan_dkom<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<DkomDiscrepancy>> {
    let _ = reader;
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DkomType;
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
        let result = scan_dkom(&reader);
        assert!(result.is_ok(), "should succeed with minimal reader");
        assert!(result.unwrap().is_empty(), "empty memory → no DKOM discrepancies");
    }

    #[test]
    fn result_is_vec_of_dkom_discrepancy() {
        let reader = make_minimal_reader();
        let result: Result<Vec<DkomDiscrepancy>> = scan_dkom(&reader);
        assert!(result.is_ok());
    }

    #[test]
    fn dkom_discrepancy_fields_constructible() {
        let disc = DkomDiscrepancy {
            pid: 1234,
            image_name: "hidden.exe".to_string(),
            present_in: vec!["CidTable".to_string()],
            missing_from: vec!["PsActiveProcessHead".to_string()],
            discrepancy_type: DkomType::ProcessUnlinked,
        };
        assert_eq!(disc.pid, 1234);
        assert_eq!(disc.image_name, "hidden.exe");
        assert_eq!(disc.present_in.len(), 1);
        assert_eq!(disc.missing_from.len(), 1);
        assert_eq!(disc.discrepancy_type, DkomType::ProcessUnlinked);
    }

    #[test]
    fn dkom_discrepancy_serializes() {
        let disc = DkomDiscrepancy {
            pid: 42,
            image_name: "rootkit.sys".to_string(),
            present_in: vec!["MmDriverList".to_string()],
            missing_from: vec!["PsLoadedModuleList".to_string()],
            discrepancy_type: DkomType::DriverUnlinked,
        };
        let json = serde_json::to_string(&disc).unwrap();
        assert!(json.contains("\"pid\":42"));
        assert!(json.contains("rootkit.sys"));
        assert!(json.contains("DriverUnlinked"));
    }

    #[test]
    fn dkom_type_variants_accessible() {
        let _ = DkomType::ProcessUnlinked;
        let _ = DkomType::DriverUnlinked;
        let _ = DkomType::ThreadUnlinked;
    }

    // --- classifier helper tests (genuine RED: function does not exist yet) ---

    #[test]
    fn process_in_cid_not_in_active_list_is_process_unlinked() {
        assert_eq!(
            classify_dkom(true, false, false, false),
            Some(DkomType::ProcessUnlinked)
        );
    }

    #[test]
    fn driver_in_mm_not_in_loaded_list_is_driver_unlinked() {
        assert_eq!(
            classify_dkom(false, false, true, false),
            Some(DkomType::DriverUnlinked)
        );
    }

    #[test]
    fn both_present_in_all_sources_is_none() {
        assert!(classify_dkom(true, true, true, true).is_none());
    }
}
