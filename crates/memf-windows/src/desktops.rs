//! Windows Desktop and Window Station enumeration.
//!
//! Window stations and desktops are security boundaries in Windows.
//! Each session has one or more window stations, and each window station
//! contains one or more desktops. Malware sometimes creates hidden desktops
//! to run GUI payloads invisibly — enumerating desktops reveals these
//! hidden execution contexts.
//!
//! Key forensic indicators:
//! - Non-standard window station names (not `WinSta0` or `Service-0x0-*`)
//! - Non-standard desktop names on the interactive station
//! - Desktops on unexpected interactive stations

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;

/// Maximum number of window stations to enumerate (safety limit).
const MAX_WINSTATIONS: usize = 256;

/// Maximum number of desktops per window station (safety limit).
const MAX_DESKTOPS_PER_STATION: usize = 64;

/// Standard desktop names on the interactive window station.
const STANDARD_DESKTOPS: &[&str] = &["Default", "Winlogon", "Disconnect", "Screen-saver"];

/// Information about a window station recovered from kernel memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WindowStationInfo {
    /// Virtual address of the window station object.
    pub address: u64,
    /// Window station name (e.g. `WinSta0`).
    pub name: String,
    /// Session ID this station belongs to.
    pub session_id: u32,
    /// Whether this is the interactive station (`WinSta0`).
    pub is_interactive: bool,
    /// Number of desktops attached to this station.
    pub desktop_count: u32,
    /// Whether this station looks suspicious.
    pub is_suspicious: bool,
}

/// Information about a desktop recovered from kernel memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DesktopInfo {
    /// Virtual address of the desktop object.
    pub address: u64,
    /// Desktop name (e.g. "Default", "Winlogon").
    pub name: String,
    /// Name of the owning window station.
    pub winstation_name: String,
    /// Size of the desktop heap in bytes.
    pub heap_size: u64,
    /// Number of threads attached to this desktop.
    pub thread_count: u32,
    /// Whether this desktop looks suspicious.
    pub is_suspicious: bool,
}

/// Classify a window station name as suspicious.
///
/// Returns `true` for non-standard window station names.
/// Standard names are `WinSta0` (interactive) and `Service-0x0-*` (service stations).
pub fn classify_winstation(name: &str) -> bool {
    if name.is_empty() {
        return true;
    }

    // WinSta0 is the interactive window station — always benign.
    if name == "WinSta0" {
        return false;
    }

    // Service window stations follow the pattern "Service-0x0-XXXXX$".
    if name.starts_with("Service-0x0-") {
        return false;
    }

    // Anything else is non-standard and suspicious.
    true
}

/// Classify a desktop name as suspicious.
///
/// Returns `true` when:
/// - The desktop has a non-standard name on `WinSta0` (standard names are
///   `Default`, `Winlogon`, `Disconnect`, `Screen-saver`)
/// - Any desktop on a non-`WinSta0` interactive station
/// - Empty desktop name (always suspicious)
pub fn classify_desktop(name: &str, winstation: &str) -> bool {
    // Empty desktop name is always suspicious.
    if name.is_empty() {
        return true;
    }

    if winstation == "WinSta0" {
        // On the interactive station, only standard desktop names are benign.
        return !STANDARD_DESKTOPS.contains(&name);
    }

    // For non-WinSta0 stations, service desktops are generally benign.
    false
}

/// Read a u64 pointer from memory, returning 0 on failure.
fn read_ptr<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, addr: u64) -> u64 {
    match reader.read_bytes(addr, 8) {
        Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        _ => 0,
    }
}

/// Read a u32 value from memory, returning 0 on failure.
fn read_u32<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, addr: u64) -> u32 {
    match reader.read_bytes(addr, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => 0,
    }
}

/// Walk the desktop list for a single window station.
fn walk_station_desktops<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ws_name: &str,
    first_desk: u64,
    desk_name_off: u64,
    desk_heap_off: u64,
    desk_next_off: u64,
    desk_thread_count_off: u64,
) -> Vec<DesktopInfo> {
    let mut desktops = Vec::new();
    let mut current_desk = first_desk;
    let mut seen = std::collections::HashSet::new();

    while current_desk != 0 && desktops.len() < MAX_DESKTOPS_PER_STATION {
        if !seen.insert(current_desk) {
            break;
        }

        let desk_name =
            read_unicode_string(reader, current_desk + desk_name_off).unwrap_or_default();
        let heap_size = read_ptr(reader, current_desk + desk_heap_off);
        let thread_count = read_u32(reader, current_desk + desk_thread_count_off);
        let is_suspicious = classify_desktop(&desk_name, ws_name);

        desktops.push(DesktopInfo {
            address: current_desk,
            name: desk_name,
            winstation_name: ws_name.to_owned(),
            heap_size,
            thread_count,
            is_suspicious,
        });

        current_desk = read_ptr(reader, current_desk + desk_next_off);
    }

    desktops
}

/// Enumerate window stations and desktops from kernel memory.
///
/// Walks the `grpWinStaList` linked list to find `_WINSTATION_OBJECT` structures,
/// then walks each station's desktop list. Returns `(Vec<WindowStationInfo>, Vec<DesktopInfo>)`.
///
/// Returns `Ok((Vec::new(), Vec::new()))` if the `grpWinStaList` symbol is missing.
pub fn walk_desktops<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<(Vec<WindowStationInfo>, Vec<DesktopInfo>)> {
    let Some(list_head) = reader.symbols().symbol_address("grpWinStaList") else {
        return Ok((Vec::new(), Vec::new()));
    };

    // Resolve structure offsets for _WINSTATION_OBJECT.
    let ws_name_off = reader
        .symbols()
        .field_offset("_WINSTATION_OBJECT", "Name")
        .unwrap_or(0x10);

    let ws_session_id_off = reader
        .symbols()
        .field_offset("_WINSTATION_OBJECT", "dwSessionId")
        .unwrap_or(0x20);

    let ws_next_off = reader
        .symbols()
        .field_offset("_WINSTATION_OBJECT", "rpwinstaNext")
        .unwrap_or(0x28);

    let ws_rpdesk_list_off = reader
        .symbols()
        .field_offset("_WINSTATION_OBJECT", "rpdeskList")
        .unwrap_or(0x30);

    // Resolve structure offsets for desktop objects.
    let desk_name_off = reader
        .symbols()
        .field_offset("tagDESKTOP", "Name")
        .unwrap_or(0x10);

    let desk_heap_off = reader
        .symbols()
        .field_offset("tagDESKTOP", "pheapDesktop")
        .unwrap_or(0x18);

    let desk_next_off = reader
        .symbols()
        .field_offset("tagDESKTOP", "rpdeskNext")
        .unwrap_or(0x20);

    let desk_thread_count_off = reader
        .symbols()
        .field_offset("tagDESKTOP", "dwThreadCount")
        .unwrap_or(0x28);

    // Read the first window station pointer from grpWinStaList.
    let first_ws = read_ptr(reader, list_head);
    if first_ws == 0 {
        return Ok((Vec::new(), Vec::new()));
    }

    let mut stations = Vec::new();
    let mut all_desktops = Vec::new();
    let mut current_ws = first_ws;
    let mut seen_ws = std::collections::HashSet::new();

    while current_ws != 0 && stations.len() < MAX_WINSTATIONS {
        if !seen_ws.insert(current_ws) {
            break;
        }

        let ws_name = read_unicode_string(reader, current_ws + ws_name_off).unwrap_or_default();
        let session_id = read_u32(reader, current_ws + ws_session_id_off);
        let is_interactive = ws_name == "WinSta0";
        let is_suspicious = classify_winstation(&ws_name);

        let first_desk = read_ptr(reader, current_ws + ws_rpdesk_list_off);
        let desktops = walk_station_desktops(
            reader,
            &ws_name,
            first_desk,
            desk_name_off,
            desk_heap_off,
            desk_next_off,
            desk_thread_count_off,
        );

        let desktop_count = desktops.len() as u32;

        stations.push(WindowStationInfo {
            address: current_ws,
            name: ws_name,
            session_id,
            is_interactive,
            desktop_count,
            is_suspicious,
        });

        all_desktops.extend(desktops);

        current_ws = read_ptr(reader, current_ws + ws_next_off);
    }

    Ok((stations, all_desktops))
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ---------------------------------------------------------------
    // classify_winstation tests
    // ---------------------------------------------------------------

    /// WinSta0 is the interactive station — always benign.
    #[test]
    fn classify_winstation_winsta0_benign() {
        assert!(!classify_winstation("WinSta0"));
    }

    /// Service window stations (Service-0x0-*) are benign.
    #[test]
    fn classify_winstation_service_benign() {
        assert!(!classify_winstation("Service-0x0-3e7$"));
    }

    /// Non-standard window station names are suspicious.
    #[test]
    fn classify_winstation_hidden_suspicious() {
        assert!(classify_winstation("HiddenStation"));
    }

    // ---------------------------------------------------------------
    // classify_desktop tests
    // ---------------------------------------------------------------

    /// "Default" desktop on WinSta0 is benign.
    #[test]
    fn classify_desktop_default_benign() {
        assert!(!classify_desktop("Default", "WinSta0"));
    }

    /// "Winlogon" desktop on WinSta0 is benign.
    #[test]
    fn classify_desktop_winlogon_benign() {
        assert!(!classify_desktop("Winlogon", "WinSta0"));
    }

    /// Non-standard desktop name on WinSta0 is suspicious.
    #[test]
    fn classify_desktop_hidden_on_winsta0_suspicious() {
        assert!(classify_desktop("HiddenDesktop", "WinSta0"));
    }

    /// Empty desktop name is suspicious.
    #[test]
    fn classify_desktop_empty_name_suspicious() {
        assert!(classify_desktop("", "WinSta0"));
    }

    // ---------------------------------------------------------------
    // walk_desktops tests
    // ---------------------------------------------------------------

    /// No grpWinStaList symbol -> empty Vecs.
    #[test]
    fn walk_desktops_no_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("_WINSTATION_OBJECT", 0x100)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let (stations, desktops) = walk_desktops(&reader).unwrap();
        assert!(stations.is_empty());
        assert!(desktops.is_empty());
    }
}
