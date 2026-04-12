//! SCM vs Registry service discrepancy detection (svc_diff).
//!
//! Compares the in-memory service list from the Service Control Manager
//! (`services.exe`) against the `SYSTEM\CurrentControlSet\Services` registry
//! hive to detect anti-forensic discrepancies:
//!
//! - **Memory-only services** — present in SCM but deleted from registry.
//!   Indicates an attacker installed a service then cleaned the registry to
//!   hide persistence. The service remains in memory until reboot.
//!
//! - **Registry-only auto/system services** — present in registry with
//!   `AutoStart` (2) or `SystemStart` (1) start type but not loaded in SCM.
//!   Indicates disabled persistence or a service that failed to start,
//!   which may warrant investigation.
//!
//! Maps to MITRE ATT&CK T1543.003 (Create or Modify System Process:
//! Windows Service).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{registry_keys, service, Result};

/// A single service discrepancy entry comparing SCM memory vs registry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SvcDiffEntry {
    /// Service name (short internal name, e.g., `"Dnscache"`).
    pub service_name: String,
    /// Display name shown in the Services MMC snap-in.
    pub display_name: String,
    /// Path to the service binary.
    pub binary_path: String,
    /// Whether this service was found in SCM memory.
    pub in_scm: bool,
    /// Whether this service was found in the SYSTEM registry hive.
    pub in_registry: bool,
    /// Start type value (0=Boot, 1=System, 2=Auto, 3=Demand, 4=Disabled).
    pub start_type: u32,
    /// Whether this entry is classified as suspicious.
    pub is_suspicious: bool,
}

/// Classify whether a service discrepancy is suspicious.
///
/// A service is suspicious if:
/// - It exists in SCM memory but NOT in registry (`in_scm && !in_registry`):
///   indicates the registry entry was deleted after the service was loaded
///   (anti-forensic cleanup).
/// - It has an Auto (2) or System (1) start type in registry but is NOT
///   loaded in SCM (`!in_scm && in_registry && start_type in {1, 2}`):
///   indicates the service was disabled or tampered with despite being
///   configured to start automatically.
pub fn classify_svc_diff(in_scm: bool, in_registry: bool, start_type: u32) -> bool {
        todo!()
    }

/// Walk SCM service records and SYSTEM registry hive services, then diff.
///
/// `scm_list_head` is the virtual address of the `ServiceRecordListHead`
/// symbol inside `services.exe` memory.
///
/// `system_hive_addr` is the virtual address of the SYSTEM hive's
/// `_HBASE_BLOCK` (from `RegistryHive::hive_addr`).
///
/// Returns a list of [`SvcDiffEntry`] for every service that appears in
/// either source, with discrepancy flags set. Only entries where
/// `is_suspicious` is `true` represent forensic anomalies.
pub fn walk_svc_diff<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    scm_list_head: u64,
    system_hive_addr: u64,
) -> Result<Vec<SvcDiffEntry>> {
        todo!()
    }

// ── Internal hive navigation helpers ─────────────────────────────────

const HBIN_START: u64 = 0x1000;
const ROOT_CELL_OFFSET: u64 = 0x24;
const NK_SIG: u16 = 0x6B6E;
const NK_STABLE_COUNT: usize = 0x14;
const NK_STABLE_LIST: usize = 0x1C;
const NK_NAME_LEN: usize = 0x48;
const NK_NAME_DATA: usize = 0x4C;

fn cell_vaddr(hive_addr: u64, cell_index: u32) -> u64 {
        todo!()
    }

fn read_cell<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, vaddr: u64) -> Option<Vec<u8>> {
        todo!()
    }

fn key_node_name(data: &[u8]) -> String {
        todo!()
    }

fn find_key_cell<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    path: &str,
) -> Option<u32> {
        todo!()
    }

/// Return the names of all direct subkeys of the key at `path`.
fn enum_direct_subkeys<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    path: &str,
) -> Vec<String> {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_reader() -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        todo!()
    }

    // ── classify_svc_diff unit tests ────────────────────────────────

    #[test]
    fn classify_memory_only_service_is_suspicious() {
        todo!()
    }

    #[test]
    fn classify_registry_only_auto_start_is_suspicious() {
        todo!()
    }

    #[test]
    fn classify_registry_only_system_start_is_suspicious() {
        todo!()
    }

    #[test]
    fn classify_registry_only_demand_start_not_suspicious() {
        todo!()
    }

    #[test]
    fn classify_registry_only_disabled_not_suspicious() {
        todo!()
    }

    #[test]
    fn classify_both_present_not_suspicious() {
        todo!()
    }

    #[test]
    fn classify_neither_present_not_suspicious() {
        todo!()
    }

    #[test]
    fn classify_registry_only_boot_start_not_suspicious() {
        todo!()
    }

    /// Unknown start type (e.g. 99) is not suspicious for registry-only.
    #[test]
    fn classify_registry_only_unknown_start_type_benign() {
        todo!()
    }

    // ── SvcDiffEntry struct tests ───────────────────────────────────

    #[test]
    fn svc_diff_entry_construction() {
        todo!()
    }

    #[test]
    fn svc_diff_entry_serialization() {
        todo!()
    }

    // ── walk_svc_diff with zero addresses ────────────────────────────

    /// Both addresses zero → empty result, no error.
    #[test]
    fn walk_svc_diff_both_zero_empty() {
        todo!()
    }

    /// scm_list_head zero, non-zero but unmapped system_hive → empty.
    #[test]
    fn walk_svc_diff_zero_scm_unmapped_hive_empty() {
        todo!()
    }

    /// Non-zero scm_list_head pointing to unmapped memory, zero hive →
    /// SCM walk fails gracefully (unwrap_or_default) → empty diff result.
    #[test]
    fn walk_svc_diff_unmapped_scm_zero_hive_empty() {
        todo!()
    }

    // ── cell_vaddr / internal helpers ─────────────────────────────────

    #[test]
    fn cell_vaddr_calculation() {
        todo!()
    }

    #[test]
    fn hive_constants_correct() {
        todo!()
    }

    // ── key_node_name helper ──────────────────────────────────────────

    #[test]
    fn key_node_name_too_short() {
        todo!()
    }

    #[test]
    fn key_node_name_valid() {
        todo!()
    }

    #[test]
    fn key_node_name_clamped_to_available() {
        todo!()
    }

    // ── find_key_cell / enum_direct_subkeys with bad data ────────────────

    /// find_key_cell with a mapped hive_addr but bad root cell bytes returns None.
    /// This exercises the root bytes read path and the NK_SIG check branches.
    #[test]
    fn find_key_cell_bad_root_cell_data() {
        todo!()
    }

    /// enum_direct_subkeys with a mapped hive_addr that has no valid NK_SIG
    /// returns an empty Vec (exercises all the early-return guards).
    #[test]
    fn enum_direct_subkeys_bad_sig_returns_empty() {
        todo!()
    }

    /// walk_svc_diff with non-zero hive_addr but no readable root cell bytes
    /// (all reads fail) returns Ok(empty) gracefully.
    #[test]
    fn walk_svc_diff_nonzero_hive_unreadable_returns_empty() {
        todo!()
    }

    /// cell_vaddr wrapping arithmetic does not panic.
    #[test]
    fn cell_vaddr_wrapping() {
        todo!()
    }

    /// key_node_name with exactly NK_NAME_DATA bytes and zero length returns empty string.
    #[test]
    fn key_node_name_zero_length() {
        todo!()
    }

    // ── Additional coverage: classify + helpers ──────────────────────

    /// classify_svc_diff: both absent (not in SCM, not in registry) is benign.
    #[test]
    fn classify_both_absent_benign() {
        todo!()
    }

    /// classify_svc_diff: in SCM AND in registry is benign (normal service).
    #[test]
    fn classify_both_present_benign() {
        todo!()
    }

    /// classify_svc_diff: registry-only with demand start (3) is benign.
    #[test]
    fn classify_registry_only_demand_start_benign() {
        todo!()
    }

    /// classify_svc_diff: registry-only with disabled (4) is benign.
    #[test]
    fn classify_registry_only_disabled_benign() {
        todo!()
    }

    /// classify_svc_diff: registry-only boot start (0) is benign (not 1 or 2).
    #[test]
    fn classify_registry_only_boot_start_benign() {
        todo!()
    }

    /// SvcDiffEntry construction and serialization.
    #[test]
    fn svc_diff_entry_serializes() {
        todo!()
    }

    /// key_node_name with data shorter than NK_NAME_DATA returns empty (wave5 variant).
    #[test]
    fn key_node_name_too_short_w5() {
        todo!()
    }

    /// key_node_name with a non-zero name length extracts the name correctly.
    #[test]
    fn key_node_name_extracts_name() {
        todo!()
    }

    /// cell_vaddr wraps correctly without panicking.
    #[test]
    fn cell_vaddr_arithmetic() {
        todo!()
    }

    /// read_cell on unmapped address returns None.
    #[test]
    fn read_cell_unmapped_returns_none() {
        todo!()
    }

    /// find_key_cell on unmapped hive returns None.
    #[test]
    fn find_key_cell_unmapped_returns_none() {
        todo!()
    }

    /// enum_direct_subkeys on unmapped hive returns empty Vec.
    #[test]
    fn enum_direct_subkeys_unmapped_returns_empty() {
        todo!()
    }

    /// walk_svc_diff with both addresses zero → empty Vec (wave5 variant).
    #[test]
    fn walk_svc_diff_both_zero_empty_w5() {
        todo!()
    }

    /// walk_svc_diff with zero SCM head and unmapped hive → empty Vec (wave5 variant).
    #[test]
    fn walk_svc_diff_zero_scm_unmapped_hive_empty_w5() {
        todo!()
    }

    // ── find_key_cell with multiple path components ────────────────────

    /// find_key_cell("CurrentControlSet\\Services") on a hive where the
    /// root NK cell has NK_SIG and count > 0 but the list cell points to
    /// a child with valid NK_SIG whose name matches "CurrentControlSet".
    /// The child also has stable_count = 0 → path component "Services"
    /// not found → returns None.
    #[test]
    fn find_key_cell_currentcontrolset_found_services_not_found() {
        todo!()
    }

    /// enum_direct_subkeys: root NK found with a valid lh-list containing
    /// one child NK. The child has a valid name → names Vec has one entry.
    #[test]
    fn enum_direct_subkeys_lh_list_returns_names() {
        todo!()
    }

    /// find_key_cell: path with empty components (double backslash) is
    /// filtered by the split logic.
    #[test]
    fn find_key_cell_empty_path_components_filtered() {
        todo!()
    }

    /// key_node_name with zero length field returns empty string.
    #[test]
    fn key_node_name_zero_len_field_returns_empty() {
        todo!()
    }

    /// walk_svc_diff: non-zero system hive with root NK having stable_count=0
    /// produces empty registry subkeys → no registry-only entries → empty result.
    #[test]
    fn walk_svc_diff_hive_with_zero_services_subkeys_empty() {
        todo!()
    }

    /// enum_direct_subkeys with li-list returns names.
    #[test]
    fn enum_direct_subkeys_li_list_returns_names() {
        todo!()
    }

    /// find_key_cell: empty path string returns Some(root_cell) immediately
    /// (no path components to iterate).
    #[test]
    fn find_key_cell_empty_path_returns_root() {
        todo!()
    }

    // ── walk_svc_diff with a real SCM service list ─────────────────────

    /// ISF builder that includes _SERVICE_RECORD, _LIST_ENTRY, _UNICODE_STRING.
    fn make_svc_diff_reader(ptb: PageTableBuilder) -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        todo!()
    }

    /// Encode a string as UTF-16LE bytes.
    fn utf16le_bytes(s: &str) -> Vec<u8> {
        todo!()
    }

    /// walk_svc_diff: one SCM service ("EvilSvc", AutoStart) not in registry
    /// → in_scm=true, in_registry=false, is_suspicious=true.
    ///
    /// Covers walk_svc_diff lines 84-93 (SCM map built) and 129-149 (SCM loop).
    #[test]
    fn walk_svc_diff_scm_service_not_in_registry_is_suspicious() {
        todo!()
    }

    /// walk_svc_diff: registry-only AutoStart service not in SCM → suspicious.
    ///
    /// Covers walk_svc_diff lines 101-106 (service_subkeys populated),
    /// lines 110-122 (for loop over subkeys with read_registry_values),
    /// and lines 153-168 (registry-only entries loop).
    #[test]
    fn walk_svc_diff_registry_only_auto_start_service_is_suspicious() {
        todo!()
    }
}
