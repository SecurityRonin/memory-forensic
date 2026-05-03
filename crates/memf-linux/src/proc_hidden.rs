//! Hidden process detection via PID namespace vs task list discrepancy.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::types::HiddenProcessInfo;
use crate::Result;

/// Classify whether a process is DKOM-hidden based on its visibility in the
/// task list and PID hash table.
///
/// Returns `true` if the process is absent from either the task list or the
/// PID hash table — both must be present for a process to be considered
/// visible by the kernel.
pub fn is_dkom_hidden(in_task_list: bool, in_pid_hash: bool) -> bool {
    !in_task_list || !in_pid_hash
}

/// Scan for processes hidden by DKOM or PID namespace tricks.
///
/// Compares the PID namespace, task list, and PID hash table for discrepancies.
/// Returns `Ok(vec![])` as a stub until full implementation is added.
pub fn find_hidden_processes<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<HiddenProcessInfo>> {
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
        let result = find_hidden_processes(&reader);
        assert!(result.is_ok(), "should succeed with minimal reader");
        assert!(
            result.unwrap().is_empty(),
            "empty memory → no hidden processes"
        );
    }

    #[test]
    fn result_is_vec_of_hidden_process_info() {
        let reader = make_minimal_reader();
        let result: Result<Vec<HiddenProcessInfo>> = find_hidden_processes(&reader);
        assert!(result.is_ok());
    }

    #[test]
    fn hidden_process_info_fields_constructible() {
        let info = HiddenProcessInfo {
            pid: 1234,
            comm: "evil".to_string(),
            present_in_pid_ns: false,
            present_in_task_list: true,
            present_in_pid_hash: true,
        };
        assert_eq!(info.pid, 1234);
        assert_eq!(info.comm, "evil");
        assert!(!info.present_in_pid_ns);
        assert!(info.present_in_task_list);
        assert!(info.present_in_pid_hash);
    }

    #[test]
    fn hidden_process_info_serializes() {
        let info = HiddenProcessInfo {
            pid: 42,
            comm: "rootkit".to_string(),
            present_in_pid_ns: false,
            present_in_task_list: false,
            present_in_pid_hash: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":42"));
        assert!(json.contains("rootkit"));
        assert!(json.contains("\"present_in_pid_hash\":true"));
    }

    // --- classifier helper tests (genuine RED: function does not exist yet) ---

    #[test]
    fn process_missing_from_task_list_is_hidden() {
        // Missing from task list but in PID hash → DKOM hidden
        assert!(is_dkom_hidden(false, true));
    }

    #[test]
    fn process_missing_from_pid_hash_is_hidden() {
        // In task list but missing from PID hash → also suspicious
        assert!(is_dkom_hidden(true, false));
    }

    #[test]
    fn process_in_all_sources_is_not_hidden() {
        assert!(!is_dkom_hidden(true, true));
    }
}
