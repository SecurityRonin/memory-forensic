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
    const SERVICES_KEY: &str = "CurrentControlSet\\Services";

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
            .map_or(3, |v| {
                let s = v.data_preview.trim();
                // Handle "0x00000002 (2)" format (REG_DWORD display) and plain "2" format.
                if let Some(dec) = s.split('(').nth(1).and_then(|p| p.split(')').next()) {
                    dec.trim().parse::<u32>().unwrap_or(3)
                } else {
                    s.parse::<u32>().unwrap_or(3)
                }
            }); // Default to Demand start.
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
        .wrapping_add(u64::from(cell_index))
}

fn read_cell<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, vaddr: u64) -> Option<Vec<u8>> {
    // Read the 4-byte cell size header first. Allocated cells have a negative
    // (two's-complement) size; the data length is abs(size) - 4, capped at 64 KiB.
    let size_bytes = reader.read_bytes(vaddr, 4).ok()?;
    let raw_size = i32::from_le_bytes(size_bytes[..4].try_into().ok()?);
    #[allow(clippy::cast_sign_loss)]
    let data_len = if raw_size < 0 {
        (raw_size.unsigned_abs().saturating_sub(4) as usize).min(65536)
    } else {
        // Free cell (positive size): raw_size >= 0 so cast is safe.
        (raw_size as u32).saturating_sub(4) as usize
    };
    if data_len == 0 {
        return Some(Vec::new());
    }
    reader.read_bytes(vaddr + 4, data_len).ok()
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
        let isf = IsfBuilder::new().add_struct("_HHIVE", 0x600).build_json();
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

        let isf = IsfBuilder::new().add_struct("_HHIVE", 0x600).build_json();
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
        let expected = hive + HBIN_START + u64::from(cell);
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

        let hive_vaddr: u64 = 0xFFFF_8000_0050_0000;
        let hive_paddr: u64 = 0x0050_0000;
        let cell_vaddr_val = hive_vaddr + HBIN_START; // cell index 0 -> +0x1000
        let cell_paddr: u64 = 0x0051_0000;

        // root cell index = 0 (4 LE bytes at hive_paddr + 0x24)
        let hive_page = [0u8; 4096];
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

    // ── Additional coverage: classify + helpers ──────────────────────

    /// classify_svc_diff: both absent (not in SCM, not in registry) is benign.
    #[test]
    fn classify_both_absent_benign() {
        // Neither condition fires.
        assert!(!classify_svc_diff(false, false, 2));
        assert!(!classify_svc_diff(false, false, 0));
    }

    /// classify_svc_diff: in SCM AND in registry is benign (normal service).
    #[test]
    fn classify_both_present_benign() {
        assert!(!classify_svc_diff(true, true, 2));
        assert!(!classify_svc_diff(true, true, 1));
        assert!(!classify_svc_diff(true, true, 3));
    }

    /// classify_svc_diff: registry-only with demand start (3) is benign.
    #[test]
    fn classify_registry_only_demand_start_benign() {
        assert!(!classify_svc_diff(false, true, 3));
    }

    /// classify_svc_diff: registry-only with disabled (4) is benign.
    #[test]
    fn classify_registry_only_disabled_benign() {
        assert!(!classify_svc_diff(false, true, 4));
    }

    /// classify_svc_diff: registry-only boot start (0) is benign (not 1 or 2).
    #[test]
    fn classify_registry_only_boot_start_benign() {
        assert!(!classify_svc_diff(false, true, 0));
    }

    /// SvcDiffEntry construction and serialization.
    #[test]
    fn svc_diff_entry_serializes() {
        let entry = SvcDiffEntry {
            service_name: "EvilSvc".to_string(),
            display_name: "Evil Service".to_string(),
            binary_path: "C:\\evil.exe".to_string(),
            in_scm: true,
            in_registry: false,
            start_type: 2,
            is_suspicious: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("EvilSvc"));
        assert!(json.contains("is_suspicious"));
        assert!(json.contains("in_scm"));
    }

    /// key_node_name with data shorter than NK_NAME_DATA returns empty (wave5 variant).
    #[test]
    fn key_node_name_too_short_w5() {
        let data = vec![0u8; NK_NAME_DATA - 1];
        assert_eq!(key_node_name(&data), "");
    }

    /// key_node_name with a non-zero name length extracts the name correctly.
    #[test]
    fn key_node_name_extracts_name() {
        let name = b"Services";
        let mut data = vec![0u8; NK_NAME_DATA + name.len() + 4];
        data[NK_NAME_LEN] = name.len() as u8;
        data[NK_NAME_LEN + 1] = 0;
        data[NK_NAME_DATA..NK_NAME_DATA + name.len()].copy_from_slice(name);
        assert_eq!(key_node_name(&data), "Services");
    }

    /// cell_vaddr wraps correctly without panicking.
    #[test]
    fn cell_vaddr_arithmetic() {
        let hive: u64 = 0x0010_0000;
        let idx: u32 = 0x300;
        let result = cell_vaddr(hive, idx);
        assert_eq!(result, hive + HBIN_START + u64::from(idx));
    }

    /// read_cell on unmapped address returns None.
    #[test]
    fn read_cell_unmapped_returns_none() {
        let reader = make_reader();
        assert!(read_cell(&reader, 0xDEAD_BEEF_0000).is_none());
    }

    /// find_key_cell on unmapped hive returns None.
    #[test]
    fn find_key_cell_unmapped_returns_none() {
        let reader = make_reader();
        assert!(find_key_cell(&reader, 0xDEAD_BEEF_0000, "CurrentControlSet").is_none());
    }

    /// enum_direct_subkeys on unmapped hive returns empty Vec.
    #[test]
    fn enum_direct_subkeys_unmapped_returns_empty() {
        let reader = make_reader();
        let names = enum_direct_subkeys(&reader, 0xDEAD_BEEF_0000, "CurrentControlSet\\Services");
        assert!(names.is_empty());
    }

    /// walk_svc_diff with both addresses zero → empty Vec (wave5 variant).
    #[test]
    fn walk_svc_diff_both_zero_empty_w5() {
        let reader = make_reader();
        let result = walk_svc_diff(&reader, 0, 0).unwrap();
        assert!(result.is_empty());
    }

    /// walk_svc_diff with zero SCM head and unmapped hive → empty Vec (wave5 variant).
    #[test]
    fn walk_svc_diff_zero_scm_unmapped_hive_empty_w5() {
        let reader = make_reader();
        let result = walk_svc_diff(&reader, 0, 0xFFFF_8000_DEAD_0000).unwrap();
        assert!(result.is_empty());
    }

    // ── find_key_cell with multiple path components ────────────────────

    /// find_key_cell("CurrentControlSet\\Services") on a hive where the
    /// root NK cell has NK_SIG and count > 0 but the list cell points to
    /// a child with valid NK_SIG whose name matches "CurrentControlSet".
    /// The child also has stable_count = 0 → path component "Services"
    /// not found → returns None.
    #[test]
    fn find_key_cell_currentcontrolset_found_services_not_found() {
        use memf_core::test_builders::{flags, PageTableBuilder};

        let hive_vaddr: u64 = 0xFFFF_8000_0070_0000;
        let hive_paddr: u64 = 0x0070_0000;
        let cell_page_vaddr = hive_vaddr.wrapping_add(HBIN_START);
        let cell_page_paddr: u64 = 0x0071_0000;

        let hive_page = [0u8; 4096];

        let mut cell_page = vec![0u8; 0x1000];

        // Root cell:
        cell_page[0..4].copy_from_slice(&(-0x400i32).to_le_bytes());
        let n = 4usize;
        cell_page[n..n + 2].copy_from_slice(&NK_SIG.to_le_bytes());
        // stable_count = 1
        cell_page[n + NK_STABLE_COUNT..n + NK_STABLE_COUNT + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        // list_cell = 0x80
        cell_page[n + NK_STABLE_LIST..n + NK_STABLE_LIST + 4]
            .copy_from_slice(&0x80u32.to_le_bytes());

        // List cell at 0x80 (lh, 8-byte entries):
        let lc = 0x80usize;
        cell_page[lc..lc + 4].copy_from_slice(&(-0x80i32).to_le_bytes());
        cell_page[lc + 4..lc + 6].copy_from_slice(&0x686Cu16.to_le_bytes()); // "lh"
        cell_page[lc + 6..lc + 8].copy_from_slice(&1u16.to_le_bytes());
        cell_page[lc + 8..lc + 12].copy_from_slice(&0x100u32.to_le_bytes()); // child_cell = 0x100

        // Child cell at 0x100 ("CurrentControlSet"):
        let cc = 0x100usize;
        cell_page[cc..cc + 4].copy_from_slice(&(-0x100i32).to_le_bytes());
        let cn = cc + 4;
        cell_page[cn..cn + 2].copy_from_slice(&NK_SIG.to_le_bytes());
        let ccs_name = b"CurrentControlSet";
        cell_page[cn + NK_NAME_LEN..cn + NK_NAME_LEN + 2]
            .copy_from_slice(&(ccs_name.len() as u16).to_le_bytes());
        cell_page[cn + NK_NAME_DATA..cn + NK_NAME_DATA + ccs_name.len()].copy_from_slice(ccs_name);
        // stable_count = 0 (already zero-initialized) → Services not found

        let isf = IsfBuilder::new().add_struct("_HHIVE", 0x600).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(cell_page_vaddr, cell_page_paddr, flags::WRITABLE)
            .write_phys(cell_page_paddr, &cell_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = find_key_cell(&reader, hive_vaddr, "CurrentControlSet\\Services");
        // "CurrentControlSet" found, "Services" subkey not found → None
        assert!(result.is_none(), "Services not found → None");
    }

    /// enum_direct_subkeys: root NK found with a valid lh-list containing
    /// one child NK. The child has a valid name → names Vec has one entry.
    #[test]
    fn enum_direct_subkeys_lh_list_returns_names() {
        use memf_core::test_builders::{flags, PageTableBuilder};

        let hive_vaddr: u64 = 0xFFFF_8000_0080_0000;
        let hive_paddr: u64 = 0x0080_0000;
        let cell_page_vaddr = hive_vaddr.wrapping_add(HBIN_START);
        let cell_page_paddr: u64 = 0x0081_0000;

        let hive_page = [0u8; 4096];

        let mut cell_page = vec![0u8; 0x1000];

        // Root cell:
        cell_page[0..4].copy_from_slice(&(-0x400i32).to_le_bytes());
        let n = 4usize;
        cell_page[n..n + 2].copy_from_slice(&NK_SIG.to_le_bytes());
        cell_page[n + NK_STABLE_COUNT..n + NK_STABLE_COUNT + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        cell_page[n + NK_STABLE_LIST..n + NK_STABLE_LIST + 4]
            .copy_from_slice(&0x80u32.to_le_bytes());

        // lh list at 0x80:
        let lc = 0x80usize;
        cell_page[lc..lc + 4].copy_from_slice(&(-0x80i32).to_le_bytes());
        cell_page[lc + 4..lc + 6].copy_from_slice(&0x686Cu16.to_le_bytes()); // "lh"
        cell_page[lc + 6..lc + 8].copy_from_slice(&1u16.to_le_bytes());
        cell_page[lc + 8..lc + 12].copy_from_slice(&0x100u32.to_le_bytes());

        // Child NK at 0x100 named "Dnscache":
        let cc = 0x100usize;
        cell_page[cc..cc + 4].copy_from_slice(&(-0x100i32).to_le_bytes());
        let cn = cc + 4;
        cell_page[cn..cn + 2].copy_from_slice(&NK_SIG.to_le_bytes());
        let svc_name = b"Dnscache";
        cell_page[cn + NK_NAME_LEN..cn + NK_NAME_LEN + 2]
            .copy_from_slice(&(svc_name.len() as u16).to_le_bytes());
        cell_page[cn + NK_NAME_DATA..cn + NK_NAME_DATA + svc_name.len()].copy_from_slice(svc_name);

        let isf = IsfBuilder::new().add_struct("_HHIVE", 0x600).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(cell_page_vaddr, cell_page_paddr, flags::WRITABLE)
            .write_phys(cell_page_paddr, &cell_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // Empty path: find_key_cell("") → iterates zero path components → returns Some(0)
        // enum_direct_subkeys then enumerates lh list → ["Dnscache"]
        let names = enum_direct_subkeys(&reader, hive_vaddr, "");
        assert_eq!(names.len(), 1, "should find one service name");
        assert_eq!(names[0], "Dnscache");
    }

    /// find_key_cell: path with empty components (double backslash) is
    /// filtered by the split logic.
    #[test]
    fn find_key_cell_empty_path_components_filtered() {
        use memf_core::test_builders::{flags, PageTableBuilder};

        let hive_vaddr: u64 = 0xFFFF_8000_0090_0000;
        let hive_paddr: u64 = 0x0090_0000;
        let cell_page_vaddr = hive_vaddr.wrapping_add(HBIN_START);
        let cell_page_paddr: u64 = 0x0091_0000;

        let hive_page = [0u8; 4096];

        let mut cell_page = vec![0u8; 0x1000];
        cell_page[0..4].copy_from_slice(&(-0x80i32).to_le_bytes());
        cell_page[4..6].copy_from_slice(&NK_SIG.to_le_bytes());
        // stable_count = 0 → Services not found

        let isf = IsfBuilder::new().add_struct("_HHIVE", 0x600).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(cell_page_vaddr, cell_page_paddr, flags::WRITABLE)
            .write_phys(cell_page_paddr, &cell_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // "\\Services" → ["Services"] → stable_count=0 → None
        let result = find_key_cell(&reader, hive_vaddr, "\\Services");
        assert!(result.is_none());
    }

    /// key_node_name with zero length field returns empty string.
    #[test]
    fn key_node_name_zero_len_field_returns_empty() {
        let mut data = vec![0u8; NK_NAME_DATA + 8];
        data[NK_NAME_LEN] = 0;
        data[NK_NAME_LEN + 1] = 0;
        assert_eq!(key_node_name(&data), "");
    }

    /// walk_svc_diff: non-zero system hive with root NK having stable_count=0
    /// produces empty registry subkeys → no registry-only entries → empty result.
    #[test]
    fn walk_svc_diff_hive_with_zero_services_subkeys_empty() {
        use memf_core::test_builders::{flags, PageTableBuilder};

        let hive_vaddr: u64 = 0xFFFF_8000_00A0_0000;
        let hive_paddr: u64 = 0x00A0_0000;
        let cell_page_vaddr = hive_vaddr.wrapping_add(HBIN_START);
        let cell_page_paddr: u64 = 0x00A1_0000;

        let hive_page = [0u8; 4096];

        let mut cell_page = vec![0u8; 0x1000];
        // Root NK: valid sig but stable_count = 0 → "CurrentControlSet" not found
        cell_page[0..4].copy_from_slice(&(-0x80i32).to_le_bytes());
        cell_page[4..6].copy_from_slice(&NK_SIG.to_le_bytes());

        let isf = IsfBuilder::new().add_struct("_HHIVE", 0x600).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(cell_page_vaddr, cell_page_paddr, flags::WRITABLE)
            .write_phys(cell_page_paddr, &cell_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // SCM head = 0 → empty SCM, hive has no CurrentControlSet → no registry entries
        let result = walk_svc_diff(&reader, 0, hive_vaddr).unwrap();
        assert!(result.is_empty());
    }

    /// enum_direct_subkeys with li-list returns names.
    #[test]
    fn enum_direct_subkeys_li_list_returns_names() {
        use memf_core::test_builders::{flags, PageTableBuilder};

        let hive_vaddr: u64 = 0xFFFF_8000_00B0_0000;
        let hive_paddr: u64 = 0x00B0_0000;
        let cell_page_vaddr = hive_vaddr.wrapping_add(HBIN_START);
        let cell_page_paddr: u64 = 0x00B1_0000;

        let hive_page = [0u8; 4096]; // root_cell_index = 0

        let mut cell_page = vec![0u8; 0x1000];

        // Root NK: lf list but with li sig
        cell_page[0..4].copy_from_slice(&(-0x400i32).to_le_bytes());
        let n = 4usize;
        cell_page[n..n + 2].copy_from_slice(&NK_SIG.to_le_bytes());
        cell_page[n + NK_STABLE_COUNT..n + NK_STABLE_COUNT + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        cell_page[n + NK_STABLE_LIST..n + NK_STABLE_LIST + 4]
            .copy_from_slice(&0x80u32.to_le_bytes());

        // li list at 0x80:
        let lc = 0x80usize;
        cell_page[lc..lc + 4].copy_from_slice(&(-0x80i32).to_le_bytes());
        cell_page[lc + 4..lc + 6].copy_from_slice(&0x696Cu16.to_le_bytes()); // "li"
        cell_page[lc + 6..lc + 8].copy_from_slice(&1u16.to_le_bytes());
        cell_page[lc + 8..lc + 12].copy_from_slice(&0x100u32.to_le_bytes());

        // Child NK at 0x100 named "Spooler":
        let cc = 0x100usize;
        cell_page[cc..cc + 4].copy_from_slice(&(-0x100i32).to_le_bytes());
        let cn = cc + 4;
        cell_page[cn..cn + 2].copy_from_slice(&NK_SIG.to_le_bytes());
        let svc_name = b"Spooler";
        cell_page[cn + NK_NAME_LEN..cn + NK_NAME_LEN + 2]
            .copy_from_slice(&(svc_name.len() as u16).to_le_bytes());
        cell_page[cn + NK_NAME_DATA..cn + NK_NAME_DATA + svc_name.len()].copy_from_slice(svc_name);

        let isf = IsfBuilder::new().add_struct("_HHIVE", 0x600).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(cell_page_vaddr, cell_page_paddr, flags::WRITABLE)
            .write_phys(cell_page_paddr, &cell_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let names = enum_direct_subkeys(&reader, hive_vaddr, "");
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "Spooler");
    }

    /// find_key_cell: empty path string returns Some(root_cell) immediately
    /// (no path components to iterate).
    #[test]
    fn find_key_cell_empty_path_returns_root() {
        use memf_core::test_builders::{flags, PageTableBuilder};

        let hive_vaddr: u64 = 0xFFFF_8000_00C0_0000;
        let hive_paddr: u64 = 0x00C0_0000;
        let cell_page_vaddr = hive_vaddr.wrapping_add(HBIN_START);
        let cell_page_paddr: u64 = 0x00C1_0000;

        let mut hive_page = [0u8; 4096];
        // root_cell_index = 0x100
        let root_idx: u32 = 0x100;
        hive_page[ROOT_CELL_OFFSET as usize..ROOT_CELL_OFFSET as usize + 4]
            .copy_from_slice(&root_idx.to_le_bytes());

        let cell_page = [0u8; 4096];

        let isf = IsfBuilder::new().add_struct("_HHIVE", 0x600).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(cell_page_vaddr, cell_page_paddr, flags::WRITABLE)
            .write_phys(cell_page_paddr, &cell_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // Empty path: no components to iterate → returns Some(root_cell_index=0x100)
        let result = find_key_cell(&reader, hive_vaddr, "");
        assert_eq!(result, Some(0x100), "empty path returns root cell index");
    }

    // ── walk_svc_diff with a real SCM service list ─────────────────────

    /// ISF builder that includes _SERVICE_RECORD, _LIST_ENTRY, _UNICODE_STRING.
    fn make_svc_diff_reader(
        ptb: PageTableBuilder,
    ) -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        // _SERVICE_RECORD field offsets (matching service.rs tests).
        const SR_SERVICE_LIST: u64 = 0x00;
        const SR_SERVICE_NAME: u64 = 0x10;
        const SR_DISPLAY_NAME: u64 = 0x18;
        const SR_CURRENT_STATE: u64 = 0x20;
        const SR_SERVICE_TYPE: u64 = 0x24;
        const SR_START_TYPE: u64 = 0x28;
        const SR_IMAGE_PATH: u64 = 0x30;
        const SR_OBJECT_NAME: u64 = 0x38;
        const SR_PROCESS_ID: u64 = 0x40;

        let isf = IsfBuilder::new()
            .add_struct("_SERVICE_RECORD", 0x80)
            .add_field(
                "_SERVICE_RECORD",
                "ServiceList",
                SR_SERVICE_LIST,
                "_LIST_ENTRY",
            )
            .add_field("_SERVICE_RECORD", "ServiceName", SR_SERVICE_NAME, "pointer")
            .add_field("_SERVICE_RECORD", "DisplayName", SR_DISPLAY_NAME, "pointer")
            .add_field(
                "_SERVICE_RECORD",
                "CurrentState",
                SR_CURRENT_STATE,
                "unsigned int",
            )
            .add_field(
                "_SERVICE_RECORD",
                "ServiceType",
                SR_SERVICE_TYPE,
                "unsigned int",
            )
            .add_field(
                "_SERVICE_RECORD",
                "StartType",
                SR_START_TYPE,
                "unsigned int",
            )
            .add_field("_SERVICE_RECORD", "ImagePath", SR_IMAGE_PATH, "pointer")
            .add_field("_SERVICE_RECORD", "ObjectName", SR_OBJECT_NAME, "pointer")
            .add_field(
                "_SERVICE_RECORD",
                "ProcessId",
                SR_PROCESS_ID,
                "unsigned int",
            )
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer")
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// Encode a string as UTF-16LE bytes.
    fn utf16le_bytes(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// walk_svc_diff: one SCM service ("EvilSvc", AutoStart) not in registry
    /// → in_scm=true, in_registry=false, is_suspicious=true.
    ///
    /// Covers walk_svc_diff lines 84-93 (SCM map built) and 129-149 (SCM loop).
    #[test]
    fn walk_svc_diff_scm_service_not_in_registry_is_suspicious() {
        use memf_core::test_builders::{flags, PageTableBuilder};

        // Virtual addresses (paddr must be < 0x00FF_FFFF for SyntheticPhysMem).
        let head_vaddr: u64 = 0xFFFF_8000_00D0_0000;
        let head_paddr: u64 = 0x00D0_0000;
        let sr_vaddr: u64 = 0xFFFF_8000_00D1_0000;
        let sr_paddr: u64 = 0x00D1_0000;
        let str_vaddr: u64 = 0xFFFF_8000_00D2_0000;
        let str_paddr: u64 = 0x00D2_0000;

        // Encode "EvilSvc" as UTF-16LE for the ServiceName string buffer.
        let name_utf16 = utf16le_bytes("EvilSvc");
        let name_len = name_utf16.len() as u16;

        // str_page layout:
        //   [0x000..0x010]: _UNICODE_STRING for ServiceName
        //     [0..2]  = length (bytes)
        //     [2..4]  = max length
        //     [8..16] = Buffer pointer → str_vaddr + 0x100
        //   [0x100..]: UTF-16LE "EvilSvc"
        let mut str_page = vec![0u8; 0x200];
        str_page[0x00..0x02].copy_from_slice(&name_len.to_le_bytes());
        str_page[0x02..0x04].copy_from_slice(&(name_len + 2).to_le_bytes());
        let buf_vaddr = str_vaddr + 0x100;
        str_page[0x08..0x10].copy_from_slice(&buf_vaddr.to_le_bytes());
        str_page[0x100..0x100 + name_utf16.len()].copy_from_slice(&name_utf16);

        // head_page: LIST_ENTRY that acts as sentinel/head.
        //   head.Flink = sr_vaddr  (points to SERVICE_RECORD.ServiceList)
        //   head.Blink = sr_vaddr
        let mut head_page = vec![0u8; 0x100];
        head_page[0x00..0x08].copy_from_slice(&sr_vaddr.to_le_bytes()); // Flink
        head_page[0x08..0x10].copy_from_slice(&sr_vaddr.to_le_bytes()); // Blink

        // sr_page: _SERVICE_RECORD at offset 0.
        //   [0x00..0x08] ServiceList.Flink = head_vaddr (sentinel → stop)
        //   [0x08..0x10] ServiceList.Blink = head_vaddr
        //   [0x10..0x18] ServiceName pointer = str_vaddr
        //   [0x18..0x20] DisplayName pointer = 0 (empty)
        //   [0x20..0x24] CurrentState = 4 (Running)
        //   [0x24..0x28] ServiceType  = 0x10 (WIN32_OWN_PROCESS)
        //   [0x28..0x2C] StartType    = 2 (AutoStart)
        //   [0x30..0x38] ImagePath ptr = 0 (empty)
        //   [0x38..0x40] ObjectName ptr = 0 (empty)
        //   [0x40..0x44] ProcessId    = 1234
        let mut sr_page = vec![0u8; 0x100];
        sr_page[0x00..0x08].copy_from_slice(&head_vaddr.to_le_bytes()); // Flink → sentinel
        sr_page[0x08..0x10].copy_from_slice(&head_vaddr.to_le_bytes()); // Blink
        sr_page[0x10..0x18].copy_from_slice(&str_vaddr.to_le_bytes()); // ServiceName
        sr_page[0x20..0x24].copy_from_slice(&4u32.to_le_bytes()); // CurrentState Running
        sr_page[0x24..0x28].copy_from_slice(&0x10u32.to_le_bytes()); // ServiceType
        sr_page[0x28..0x2C].copy_from_slice(&2u32.to_le_bytes()); // StartType AutoStart
        sr_page[0x40..0x44].copy_from_slice(&1234u32.to_le_bytes()); // ProcessId

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_page)
            .map_4k(sr_vaddr, sr_paddr, flags::WRITABLE)
            .write_phys(sr_paddr, &sr_page)
            .map_4k(str_vaddr, str_paddr, flags::WRITABLE)
            .write_phys(str_paddr, &str_page);

        let reader = make_svc_diff_reader(ptb);

        // system_hive_addr = 0 → no registry entries.
        // SCM has "EvilSvc" (AutoStart=2) not in registry → suspicious.
        let result = walk_svc_diff(&reader, head_vaddr, 0).unwrap();
        assert!(!result.is_empty(), "should find SCM-only service");
        let entry = result.iter().find(|e| e.service_name == "EvilSvc");
        assert!(entry.is_some(), "should find EvilSvc");
        let entry = entry.unwrap();
        assert!(entry.in_scm, "EvilSvc should be in SCM");
        assert!(!entry.in_registry, "EvilSvc should not be in registry");
        assert!(
            entry.is_suspicious,
            "SCM-only AutoStart service is suspicious"
        );
        assert_eq!(entry.start_type, 2, "start_type from SCM = AutoStart=2");
    }

    /// walk_svc_diff: registry-only AutoStart service not in SCM → suspicious.
    ///
    /// Covers walk_svc_diff lines 101-106 (service_subkeys populated),
    /// lines 110-122 (for loop over subkeys with read_registry_values),
    /// and lines 153-168 (registry-only entries loop).
    #[test]
    fn walk_svc_diff_registry_only_auto_start_service_is_suspicious() {
        use memf_core::test_builders::{flags, PageTableBuilder};

        let hive_vaddr: u64 = 0xFFFF_8000_00E0_0000;
        let hive_paddr: u64 = 0x00E0_0000;
        let cell_vaddr_base: u64 = hive_vaddr + 0x1000; // HBIN_START
        let cell_paddr_base: u64 = 0x00E1_0000;

        let mut cp = vec![0u8; 0x1000];

        fn w32(buf: &mut Vec<u8>, off: usize, val: u32) {
            buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
        }
        fn w16(buf: &mut Vec<u8>, off: usize, val: u16) {
            buf[off..off + 2].copy_from_slice(&val.to_le_bytes());
        }

        // Root cell at idx=0
        w32(&mut cp, 0, 0xFFFF_FF80u32);
        w16(&mut cp, 4, NK_SIG);
        w32(&mut cp, 4 + NK_STABLE_COUNT, 1u32);
        w32(&mut cp, 4 + NK_STABLE_LIST, 0x80u32);

        // lf list at idx=0x80
        w32(&mut cp, 0x80, 0xFFFF_FF80u32);
        w16(&mut cp, 0x84, 0x666Cu16);
        w16(&mut cp, 0x86, 1u16);
        w32(&mut cp, 0x88, 0x100u32);

        // CurrentControlSet NK at idx=0x100
        let ccs_name = b"CurrentControlSet";
        w32(&mut cp, 0x100, 0xFFFF_FF00u32);
        w16(&mut cp, 0x104, NK_SIG);
        w32(&mut cp, 0x104 + NK_STABLE_COUNT, 1u32);
        w32(&mut cp, 0x104 + NK_STABLE_LIST, 0x180u32);
        w16(&mut cp, 0x104 + NK_NAME_LEN, ccs_name.len() as u16);
        cp[0x104 + NK_NAME_DATA..0x104 + NK_NAME_DATA + ccs_name.len()].copy_from_slice(ccs_name);

        // lf list at idx=0x180
        w32(&mut cp, 0x180, 0xFFFF_FF80u32);
        w16(&mut cp, 0x184, 0x666Cu16);
        w16(&mut cp, 0x186, 1u16);
        w32(&mut cp, 0x188, 0x200u32);

        // Services NK at idx=0x200
        let svc_name = b"Services";
        w32(&mut cp, 0x200, 0xFFFF_FF00u32);
        w16(&mut cp, 0x204, NK_SIG);
        w32(&mut cp, 0x204 + NK_STABLE_COUNT, 1u32);
        w32(&mut cp, 0x204 + NK_STABLE_LIST, 0x280u32);
        w16(&mut cp, 0x204 + NK_NAME_LEN, svc_name.len() as u16);
        cp[0x204 + NK_NAME_DATA..0x204 + NK_NAME_DATA + svc_name.len()].copy_from_slice(svc_name);

        // lf list at idx=0x280
        w32(&mut cp, 0x280, 0xFFFF_FF80u32);
        w16(&mut cp, 0x284, 0x666Cu16);
        w16(&mut cp, 0x286, 1u16);
        w32(&mut cp, 0x288, 0x300u32);

        // BackdoorSvc NK at idx=0x300
        let bd_name = b"BackdoorSvc";
        w32(&mut cp, 0x300, 0xFFFF_FF00u32);
        w16(&mut cp, 0x304, NK_SIG);
        w32(&mut cp, 0x304 + NK_STABLE_COUNT, 0u32);
        w32(&mut cp, 0x304 + 0x24, 1u32); // value_count = 1
        w32(&mut cp, 0x304 + 0x28, 0x380u32); // values_list cell = 0x380
        w16(&mut cp, 0x304 + NK_NAME_LEN, bd_name.len() as u16);
        cp[0x304 + NK_NAME_DATA..0x304 + NK_NAME_DATA + bd_name.len()].copy_from_slice(bd_name);

        // Values list cell at idx=0x380
        w32(&mut cp, 0x380, 0xFFFF_FF80u32);
        w32(&mut cp, 0x384, 0x400u32);

        // VK cell at idx=0x400: "Start" = "2" (REG_SZ inline)
        let start_name = b"Start";
        w32(&mut cp, 0x400, 0xFFFF_FF80u32);
        w16(&mut cp, 0x404, 0x6B76u16);
        w16(&mut cp, 0x406, start_name.len() as u16);
        w32(&mut cp, 0x408, 0x8000_0002u32); // inline, 2 bytes
        w32(&mut cp, 0x40C, 0x0000_0032u32); // inline data = '2' in UTF-16LE
        w32(&mut cp, 0x410, 1u32); // type = REG_SZ
        cp[0x404 + 0x14..0x404 + 0x14 + start_name.len()].copy_from_slice(start_name);

        let hive_page = vec![0u8; 0x1000];

        let ptb = PageTableBuilder::new()
            .map_4k(hive_vaddr, hive_paddr, flags::WRITABLE)
            .write_phys(hive_paddr, &hive_page)
            .map_4k(cell_vaddr_base, cell_paddr_base, flags::WRITABLE)
            .write_phys(cell_paddr_base, &cp);

        let reader = make_svc_diff_reader(ptb);
        let result = walk_svc_diff(&reader, 0, hive_vaddr).unwrap();

        assert!(!result.is_empty(), "should find registry-only service");
        let entry = result.iter().find(|e| e.service_name == "BackdoorSvc");
        assert!(entry.is_some(), "should find BackdoorSvc");
        let entry = entry.unwrap();
        assert!(!entry.in_scm, "BackdoorSvc should not be in SCM");
        assert!(entry.in_registry, "BackdoorSvc should be in registry");
        assert_eq!(entry.start_type, 2, "start_type should be 2 (AutoStart)");
        assert!(
            entry.is_suspicious,
            "registry-only AutoStart service is suspicious"
        );
    }
}
