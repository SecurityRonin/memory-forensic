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
    hive_addr.wrapping_add(HBIN_START).wrapping_add(cell_index as u64)
}

fn read_cell<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, vaddr: u64) -> Option<Vec<u8>> {
    reader.read_bytes(vaddr + 4, 4096).ok()
}

fn key_node_name(data: &[u8]) -> String {
    if data.len() < NK_NAME_DATA {
        return String::new();
    }
    let len = u16::from_le_bytes(
        data[NK_NAME_LEN..NK_NAME_LEN + 2].try_into().unwrap_or([0; 2]),
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
        let count = u32::from_le_bytes(
            data[NK_STABLE_COUNT..NK_STABLE_COUNT + 4].try_into().ok()?,
        ) as usize;
        if count == 0 {
            return None;
        }
        let list_cell = u32::from_le_bytes(
            data[NK_STABLE_LIST..NK_STABLE_LIST + 4].try_into().ok()?,
        );
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
            let child_cell =
                u32::from_le_bytes(list_data[off..off + 4].try_into().ok()?);
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
    let list_cell = u32::from_le_bytes(
        match data[NK_STABLE_LIST..NK_STABLE_LIST + 4].try_into() {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        },
    );
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
        let child_cell =
            match list_data[off..off + 4].try_into().ok().map(u32::from_le_bytes) {
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
}
