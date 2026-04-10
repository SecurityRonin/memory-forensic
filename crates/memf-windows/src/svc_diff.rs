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
    if in_scm && !in_registry {
        // Memory-only service: registry key was deleted (anti-forensic)
        return true;
    }
    if !in_scm && in_registry && (start_type == 1 || start_type == 2) {
        // Auto/System service not loaded in SCM (disabled persistence)
        return true;
    }
    false
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
    use std::collections::HashMap;

    // ── 1. Collect services from SCM memory ──────────────────────────
    let scm_services: Vec<crate::ServiceInfo> = if scm_list_head != 0 {
        service::walk_services(reader, scm_list_head).unwrap_or_default()
    } else {
        Vec::new()
    };

    // Build a map: lowercase service name -> ServiceInfo.
    let scm_map: HashMap<String, crate::ServiceInfo> = scm_services
        .into_iter()
        .map(|s| (s.name.to_ascii_lowercase(), s))
        .collect();

    // ── 2. Collect services from SYSTEM registry hive ────────────────
    // Services live under SYSTEM\CurrentControlSet\Services.
    const SERVICES_KEY: &str = "CurrentControlSet\\Services";

    // Walk the Services key one level deep to get service subkey names.
    let service_subkeys: Vec<String> = if system_hive_addr != 0 {
        // Find the Services key cell, then enumerate its direct subkeys.
        enum_direct_subkeys(reader, system_hive_addr, SERVICES_KEY)
    } else {
        Vec::new()
    };

    // Build a map: lowercase service name -> start_type from registry.
    let mut reg_map: HashMap<String, u32> = HashMap::new();
    for svc_name in &service_subkeys {
        let svc_path = format!("{SERVICES_KEY}\\{svc_name}");
        let cell = match find_key_cell(reader, system_hive_addr, &svc_path) {
            Some(c) => c,
            None => continue,
        };
        let start_type = registry_keys::read_registry_values(reader, system_hive_addr, cell)
            .unwrap_or_default()
            .into_iter()
            .find(|v| v.name.eq_ignore_ascii_case("Start"))
            .and_then(|v| v.data_preview.parse::<u32>().ok())
            .unwrap_or(3); // Default to Demand start.
        reg_map.insert(svc_name.to_ascii_lowercase(), start_type);
    }

    // ── 3. Build unified diff entries ────────────────────────────────
    let mut result: Vec<SvcDiffEntry> = Vec::new();

    // All SCM services.
    for (lower_name, svc) in &scm_map {
        let in_registry = reg_map.contains_key(lower_name);
        let svc_start_raw: u32 = match &svc.start_type {
            crate::ServiceStartType::BootStart => 0,
            crate::ServiceStartType::SystemStart => 1,
            crate::ServiceStartType::AutoStart => 2,
            crate::ServiceStartType::DemandStart => 3,
            crate::ServiceStartType::Disabled => 4,
            crate::ServiceStartType::Unknown(v) => *v,
        };
        let start_type = reg_map.get(lower_name).copied().unwrap_or(svc_start_raw);
        let is_suspicious = classify_svc_diff(true, in_registry, start_type);
        result.push(SvcDiffEntry {
            service_name: svc.name.clone(),
            display_name: svc.display_name.clone(),
            binary_path: svc.image_path.clone(),
            in_scm: true,
            in_registry,
            start_type,
            is_suspicious,
        });
    }

    // Registry-only services (not seen in SCM).
    for svc_name in &service_subkeys {
        let lower = svc_name.to_ascii_lowercase();
        if scm_map.contains_key(&lower) {
            continue; // Already included above.
        }
        let start_type = reg_map.get(&lower).copied().unwrap_or(3);
        let is_suspicious = classify_svc_diff(false, true, start_type);
        result.push(SvcDiffEntry {
            service_name: svc_name.clone(),
            display_name: String::new(),
            binary_path: String::new(),
            in_scm: false,
            in_registry: true,
            start_type,
            is_suspicious,
        });
    }

    Ok(result)
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
    hive_addr
        .wrapping_add(HBIN_START)
        .wrapping_add(cell_index as u64)
}

fn read_cell<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, vaddr: u64) -> Option<Vec<u8>> {
    reader.read_bytes(vaddr + 4, 4096).ok()
}

fn key_node_name(data: &[u8]) -> String {
    if data.len() < NK_NAME_DATA {
        return String::new();
    }
    let len = u16::from_le_bytes(
        data[NK_NAME_LEN..NK_NAME_LEN + 2]
            .try_into()
            .unwrap_or([0; 2]),
    ) as usize;
    let end = NK_NAME_DATA + len.min(data.len().saturating_sub(NK_NAME_DATA));
    String::from_utf8_lossy(&data[NK_NAME_DATA..end]).into_owned()
}

fn find_key_cell<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    path: &str,
) -> Option<u32> {
    let root_bytes = reader.read_bytes(hive_addr + ROOT_CELL_OFFSET, 4).ok()?;
    let mut current = u32::from_le_bytes(root_bytes[..4].try_into().ok()?);

    for component in path.split('\\').filter(|s| !s.is_empty()) {
        let data = read_cell(reader, cell_vaddr(hive_addr, current))?;
        if data.len() < 4 {
            return None;
        }
        let sig = u16::from_le_bytes(data[0..2].try_into().ok()?);
        if sig != NK_SIG {
            return None;
        }
        let count = u32::from_le_bytes(data[NK_STABLE_COUNT..NK_STABLE_COUNT + 4].try_into().ok()?)
            as usize;
        if count == 0 {
            return None;
        }
        let list_cell =
            u32::from_le_bytes(data[NK_STABLE_LIST..NK_STABLE_LIST + 4].try_into().ok()?);
        let list_data = read_cell(reader, cell_vaddr(hive_addr, list_cell))?;
        if list_data.len() < 4 {
            return None;
        }
        let list_sig = u16::from_le_bytes(list_data[0..2].try_into().ok()?);
        let list_count = u16::from_le_bytes(list_data[2..4].try_into().ok()?) as usize;
        let entry_size = match list_sig {
            0x666C | 0x686C => 8,
            0x696C => 4,
            _ => return None,
        };
        let mut found = None;
        for i in 0..list_count {
            let off = 4 + i * entry_size;
            if off + 4 > list_data.len() {
                break;
            }
            let child_cell = u32::from_le_bytes(list_data[off..off + 4].try_into().ok()?);
            let child_data = read_cell(reader, cell_vaddr(hive_addr, child_cell))?;
            if key_node_name(&child_data).eq_ignore_ascii_case(component) {
                found = Some(child_cell);
                break;
            }
        }
        current = found?;
    }
    Some(current)
}

/// Return the names of all direct subkeys of the key at `path`.
fn enum_direct_subkeys<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    path: &str,
) -> Vec<String> {
    let cell = match find_key_cell(reader, hive_addr, path) {
        Some(c) => c,
        None => return Vec::new(),
    };
    let data = match read_cell(reader, cell_vaddr(hive_addr, cell)) {
        Some(d) => d,
        None => return Vec::new(),
    };
    if data.len() < 4 {
        return Vec::new();
    }
    let sig = match data[0..2].try_into().ok().map(u16::from_le_bytes) {
        Some(s) => s,
        None => return Vec::new(),
    };
    if sig != NK_SIG {
        return Vec::new();
    }
    let count = u32::from_le_bytes(
        match data[NK_STABLE_COUNT..NK_STABLE_COUNT + 4].try_into() {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        },
    ) as usize;
    if count == 0 {
        return Vec::new();
    }
    let list_cell = u32::from_le_bytes(match data[NK_STABLE_LIST..NK_STABLE_LIST + 4].try_into() {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    });
    let list_data = match read_cell(reader, cell_vaddr(hive_addr, list_cell)) {
        Some(d) => d,
        None => return Vec::new(),
    };
    if list_data.len() < 4 {
        return Vec::new();
    }
    let list_sig = u16::from_le_bytes(match list_data[0..2].try_into() {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    });
    let list_count = u16::from_le_bytes(match list_data[2..4].try_into() {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    }) as usize;
    let entry_size = match list_sig {
        0x666C | 0x686C => 8,
        0x696C => 4,
        _ => return Vec::new(),
    };
    let mut names = Vec::new();
    for i in 0..list_count {
        let off = 4 + i * entry_size;
        if off + 4 > list_data.len() {
            break;
        }
        let child_cell = match list_data[off..off + 4]
            .try_into()
            .ok()
            .map(u32::from_le_bytes)
        {
            Some(c) => c,
            None => continue,
        };
        if let Some(child_data) = read_cell(reader, cell_vaddr(hive_addr, child_cell)) {
            let name = key_node_name(&child_data);
            if !name.is_empty() {
                names.push(name);
            }
        }
    }
    names
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
        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    // ── classify_svc_diff unit tests ────────────────────────────────

    #[test]
    fn classify_memory_only_service_is_suspicious() {
        // Service in SCM but not in registry = anti-forensic cleanup
        assert!(classify_svc_diff(true, false, 2));
        assert!(classify_svc_diff(true, false, 0));
        assert!(classify_svc_diff(true, false, 3));
        assert!(classify_svc_diff(true, false, 4));
    }

    #[test]
    fn classify_registry_only_auto_start_is_suspicious() {
        // Auto-start (2) in registry but not in SCM
        assert!(classify_svc_diff(false, true, 2));
    }

    #[test]
    fn classify_registry_only_system_start_is_suspicious() {
        // System-start (1) in registry but not in SCM
        assert!(classify_svc_diff(false, true, 1));
    }

    #[test]
    fn classify_registry_only_demand_start_not_suspicious() {
        // Demand-start (3) in registry but not in SCM is normal
        assert!(!classify_svc_diff(false, true, 3));
    }

    #[test]
    fn classify_registry_only_disabled_not_suspicious() {
        // Disabled (4) in registry but not in SCM is expected
        assert!(!classify_svc_diff(false, true, 4));
    }

    #[test]
    fn classify_both_present_not_suspicious() {
        // Service in both SCM and registry is normal
        assert!(!classify_svc_diff(true, true, 0));
        assert!(!classify_svc_diff(true, true, 1));
        assert!(!classify_svc_diff(true, true, 2));
        assert!(!classify_svc_diff(true, true, 3));
        assert!(!classify_svc_diff(true, true, 4));
    }

    #[test]
    fn classify_neither_present_not_suspicious() {
        // Not in SCM and not in registry (shouldn't happen, but handle gracefully)
        assert!(!classify_svc_diff(false, false, 0));
        assert!(!classify_svc_diff(false, false, 2));
    }

    #[test]
    fn classify_registry_only_boot_start_not_suspicious() {
        // Boot-start (0) services are loaded by the boot loader, not SCM,
        // so absence from SCM is normal.
        assert!(!classify_svc_diff(false, true, 0));
    }

    /// Unknown start type (e.g. 99) is not suspicious for registry-only.
    #[test]
    fn classify_registry_only_unknown_start_type_benign() {
        assert!(!classify_svc_diff(false, true, 99));
    }

    // ── SvcDiffEntry struct tests ───────────────────────────────────

    #[test]
    fn svc_diff_entry_construction() {
        let entry = SvcDiffEntry {
            service_name: "EvilSvc".into(),
            display_name: "Evil Service".into(),
            binary_path: "C:\\Windows\\Temp\\evil.exe".into(),
            in_scm: true,
            in_registry: false,
            start_type: 2,
            is_suspicious: true,
        };
        assert_eq!(entry.service_name, "EvilSvc");
        assert_eq!(entry.display_name, "Evil Service");
        assert_eq!(entry.binary_path, "C:\\Windows\\Temp\\evil.exe");
        assert!(entry.in_scm);
        assert!(!entry.in_registry);
        assert_eq!(entry.start_type, 2);
        assert!(entry.is_suspicious);
    }

    #[test]
    fn svc_diff_entry_serialization() {
        let entry = SvcDiffEntry {
            service_name: "TestSvc".into(),
            display_name: "Test Service".into(),
            binary_path: "C:\\test.exe".into(),
            in_scm: true,
            in_registry: true,
            start_type: 3,
            is_suspicious: false,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"service_name\":\"TestSvc\""));
        assert!(json.contains("\"in_scm\":true"));
        assert!(json.contains("\"in_registry\":true"));
        assert!(json.contains("\"is_suspicious\":false"));
        assert!(json.contains("\"start_type\":3"));
    }

    // ── walk_svc_diff with zero addresses ────────────────────────────

    /// Both addresses zero → empty result, no error.
    #[test]
    fn walk_svc_diff_both_zero_empty() {
        let reader = make_reader();
        let result = walk_svc_diff(&reader, 0, 0).unwrap();
        assert!(result.is_empty());
    }

    /// scm_list_head zero, non-zero but unmapped system_hive → empty.
    #[test]
    fn walk_svc_diff_zero_scm_unmapped_hive_empty() {
        let reader = make_reader();
        let result = walk_svc_diff(&reader, 0, 0xDEAD_BEEF_0000).unwrap();
        assert!(result.is_empty());
    }

    /// Non-zero scm_list_head pointing to unmapped memory, zero hive →
    /// SCM walk fails gracefully (unwrap_or_default) → empty diff result.
    #[test]
    fn walk_svc_diff_unmapped_scm_zero_hive_empty() {
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // Non-zero scm_list_head pointing to unmapped memory.
        let result = walk_svc_diff(&reader, 0xFFFF_8000_DEAD_0000, 0).unwrap_or_default();
        assert!(result.is_empty());
    }

    // ── cell_vaddr / internal helpers ─────────────────────────────────

    #[test]
    fn cell_vaddr_calculation() {
        let hive: u64 = 0x1000_0000;
        let cell: u32 = 0x200;
        let expected = hive + HBIN_START + cell as u64;
        assert_eq!(cell_vaddr(hive, cell), expected);
    }

    #[test]
    fn hive_constants_correct() {
        assert_eq!(HBIN_START, 0x1000);
        assert_eq!(ROOT_CELL_OFFSET, 0x24);
        assert_eq!(NK_SIG, 0x6B6E);
    }

    // ── key_node_name helper ──────────────────────────────────────────

    #[test]
    fn key_node_name_too_short() {
        let data = vec![0u8; NK_NAME_DATA - 1];
        assert_eq!(key_node_name(&data), "");
    }

    #[test]
    fn key_node_name_valid() {
        // NK_NAME_LEN = 0x48, NK_NAME_DATA = 0x4C
        let mut data = vec![0u8; 0x60];
        let name = b"Services";
        data[NK_NAME_LEN] = name.len() as u8;
        data[NK_NAME_LEN + 1] = 0;
        data[NK_NAME_DATA..NK_NAME_DATA + name.len()].copy_from_slice(name);
        assert_eq!(key_node_name(&data), "Services");
    }

    #[test]
    fn key_node_name_clamped_to_available() {
        // length field says 10 bytes but only 5 bytes are available after NK_NAME_DATA
        let mut data = vec![0u8; NK_NAME_DATA + 5];
        data[NK_NAME_LEN] = 10;
        data[NK_NAME_LEN + 1] = 0;
        for i in 0..5 {
            data[NK_NAME_DATA + i] = b'X';
        }
        // Should not panic; returns whatever fits
        let name = key_node_name(&data);
        assert!(name.len() <= 5);
    }

    // ── find_key_cell / enum_direct_subkeys with bad data ────────────────

    /// find_key_cell with a mapped hive_addr but bad root cell bytes returns None.
    /// This exercises the root bytes read path and the NK_SIG check branches.
    #[test]
    fn find_key_cell_bad_root_cell_data() {
        use memf_core::test_builders::{flags, PageTableBuilder};

        // hive_addr chosen so cell_vaddr arithmetic lands within our mapped page.
        // ROOT_CELL_OFFSET (0x24) is read from hive_addr + 0x24.
        // We need: hive_addr + 0x24 to be readable (4 bytes), and
        // cell_vaddr(hive_addr, root_cell_index) + 4 to be readable (4096 bytes).
        //
        // cell_vaddr = hive_addr + HBIN_START(0x1000) + cell_index
        //
        // Strategy: put hive_addr at 0x0050_0000, so
        //   hive_addr + 0x24 = 0x0050_0024 (root cell offset read)
        //   root_cell_index from bytes [0,0,0,0] = 0
        //   cell_vaddr = 0x0050_0000 + 0x1000 + 0 = 0x0051_0000
        //
        // Map one page covering 0x0050_0000..0x0051_0FFF.
        // Write: root_cell_index = 0 at offset 0x24.
        // At cell_vaddr(0x0050_0000, 0) = 0x0051_0000: write bad NK sig (not 0x6B6E).

        let hive_vaddr: u64 = 0xFFFF_8000_0050_0000;
        let hive_paddr: u64 = 0x0050_0000;
        let cell_vaddr_val = hive_vaddr + HBIN_START; // cell index 0 -> +0x1000
        let cell_paddr: u64 = 0x0051_0000;

        // root cell index = 0 (4 LE bytes at hive_paddr + 0x24)
        let mut hive_page = [0u8; 4096];
        // leave [0x24..0x28] as 0 → root_cell_index = 0

        // At the cell page: write bad signature (0xDEAD instead of NK_SIG)
        let mut cell_page = [0u8; 4096];
        cell_page[0] = 0xAD;
        cell_page[1] = 0xDE; // 0xDEAD — not 0x6B6E

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(cell_vaddr_val, cell_paddr, flags::WRITABLE)
            .write_phys(cell_paddr, &cell_page)
            .build();

        let isf = IsfBuilder::new().add_struct("_HHIVE", 0x600).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // find_key_cell should return None because sig != NK_SIG
        let result = find_key_cell(&reader, hive_vaddr, "CurrentControlSet\\Services");
        assert!(result.is_none(), "bad NK sig should return None");
    }

    /// enum_direct_subkeys with a mapped hive_addr that has no valid NK_SIG
    /// returns an empty Vec (exercises all the early-return guards).
    #[test]
    fn enum_direct_subkeys_bad_sig_returns_empty() {
        use memf_core::test_builders::{flags, PageTableBuilder};

        let hive_vaddr: u64 = 0xFFFF_8000_0060_0000;
        let hive_paddr: u64 = 0x0060_0000;
        let cell_vaddr_val = hive_vaddr + HBIN_START;
        let cell_paddr: u64 = 0x0061_0000;

        let hive_page = [0u8; 4096]; // root_cell_index = 0
        let mut cell_page = [0u8; 4096];
        // Write valid NK_SIG so find_key_cell recurse doesn't hit sig check,
        // but set stable count = 0 so it returns None immediately.
        let sig_bytes = NK_SIG.to_le_bytes();
        cell_page[0] = sig_bytes[0];
        cell_page[1] = sig_bytes[1];
        // NK_STABLE_COUNT (0x14) = 0 (already 0 from zeroed array)

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(cell_vaddr_val, cell_paddr, flags::WRITABLE)
            .write_phys(cell_paddr, &cell_page)
            .build();

        let isf = IsfBuilder::new().add_struct("_HHIVE", 0x600).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // find_key_cell("CurrentControlSet\\Services") iterates path components,
        // reads the root cell (NK_SIG ok, count==0) → returns None → enum returns [].
        let names = enum_direct_subkeys(&reader, hive_vaddr, "CurrentControlSet\\Services");
        assert!(names.is_empty(), "zero stable count should return empty");
    }

    /// walk_svc_diff with non-zero hive_addr but no readable root cell bytes
    /// (all reads fail) returns Ok(empty) gracefully.
    #[test]
    fn walk_svc_diff_nonzero_hive_unreadable_returns_empty() {
        let reader = make_reader(); // no pages mapped
        // hive_addr non-zero but all reads fail → enum_direct_subkeys returns []
        // → scm_services empty → result empty
        let result = walk_svc_diff(&reader, 0, 0xFFFF_8000_BEEF_0000).unwrap();
        assert!(result.is_empty());
    }

    /// cell_vaddr wrapping arithmetic does not panic.
    #[test]
    fn cell_vaddr_wrapping() {
        // u64::MAX + 1 wraps to 0 (saturating_add not used, wrapping_add is used).
        let v = cell_vaddr(u64::MAX, 0);
        // Should not panic regardless of result.
        let _ = v;
    }

    /// key_node_name with exactly NK_NAME_DATA bytes and zero length returns empty string.
    #[test]
    fn key_node_name_zero_length() {
        let mut data = vec![0u8; NK_NAME_DATA + 8];
        // name length field = 0
        data[NK_NAME_LEN] = 0;
        data[NK_NAME_LEN + 1] = 0;
        let name = key_node_name(&data);
        assert_eq!(name, "");
    }
}
