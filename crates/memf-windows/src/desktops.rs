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

    /// "Disconnect" desktop on WinSta0 is benign (standard name).
    #[test]
    fn classify_desktop_disconnect_benign() {
        assert!(!classify_desktop("Disconnect", "WinSta0"));
    }

    /// "Screen-saver" desktop on WinSta0 is benign (standard name).
    #[test]
    fn classify_desktop_screen_saver_benign() {
        assert!(!classify_desktop("Screen-saver", "WinSta0"));
    }

    /// Any desktop on a service station (non-WinSta0) is benign.
    #[test]
    fn classify_desktop_on_service_station_benign() {
        assert!(!classify_desktop("Default", "Service-0x0-3e7$"));
        assert!(!classify_desktop("HiddenDesktop", "Service-0x0-3e7$"));
    }

    /// Empty name on a non-WinSta0 station is still suspicious.
    #[test]
    fn classify_desktop_empty_name_on_service_station_suspicious() {
        assert!(classify_desktop("", "Service-0x0-3e7$"));
    }

    // ── classify_winstation additional cases ─────────────────────────

    /// Empty window station name is suspicious.
    #[test]
    fn classify_winstation_empty_suspicious() {
        assert!(classify_winstation(""));
    }

    /// Service station with various suffixes is benign.
    #[test]
    fn classify_winstation_various_service_names_benign() {
        assert!(!classify_winstation("Service-0x0-3e7$"));
        assert!(!classify_winstation("Service-0x0-3e4$"));
        assert!(!classify_winstation("Service-0x0-1f4$"));
    }

    /// Names that look like service stations but aren't are suspicious.
    #[test]
    fn classify_winstation_fake_service_prefix_suspicious() {
        assert!(classify_winstation("Service-0x1-3e7$")); // 0x1 not 0x0
        assert!(classify_winstation("service-0x0-3e7$")); // lowercase 's'
    }

    // ── Serialization tests ──────────────────────────────────────────

    #[test]
    fn window_station_info_serializes() {
        let info = WindowStationInfo {
            address: 0xFFFF_9A00_1234_0000,
            name: "WinSta0".to_string(),
            session_id: 1,
            is_interactive: true,
            desktop_count: 3,
            is_suspicious: false,
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"name\":\"WinSta0\""));
        assert!(json.contains("\"session_id\":1"));
        assert!(json.contains("\"is_interactive\":true"));
        assert!(json.contains("\"desktop_count\":3"));
        assert!(json.contains("\"is_suspicious\":false"));
    }

    #[test]
    fn desktop_info_serializes() {
        let info = DesktopInfo {
            address: 0xFFFF_9A00_ABCD_0000,
            name: "HiddenDesktop".to_string(),
            winstation_name: "WinSta0".to_string(),
            heap_size: 0x0010_0000,
            thread_count: 5,
            is_suspicious: true,
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"name\":\"HiddenDesktop\""));
        assert!(json.contains("\"winstation_name\":\"WinSta0\""));
        assert!(json.contains("\"thread_count\":5"));
        assert!(json.contains("\"is_suspicious\":true"));
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

    /// grpWinStaList present and mapped, but the pointer at list_head is 0 →
    /// exercises the walk body past the symbol check, returns empty.
    #[test]
    fn walk_desktops_symbol_present_first_ws_zero() {
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};

        let list_vaddr: u64 = 0xFFFF_8000_00A0_0000;
        let list_paddr: u64 = 0x00A0_0000;

        let isf = IsfBuilder::new()
            .add_symbol("grpWinStaList", list_vaddr)
            .add_struct("_WINSTATION_OBJECT", 0x100)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Map a page at list_vaddr with first 8 bytes = 0 (null first_ws pointer).
        let page = [0u8; 4096];

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(list_vaddr, list_paddr, flags::WRITABLE)
            .write_phys(list_paddr, &page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let (stations, desktops) = walk_desktops(&reader).unwrap_or_default();
        assert!(stations.is_empty(), "null first_ws should yield no stations");
        assert!(desktops.is_empty(), "null first_ws should yield no desktops");
    }

    /// Helper: build ISF with grpWinStaList symbol and required structs including _UNICODE_STRING.
    /// Layout chosen to avoid field overlap:
    ///   _WINSTATION_OBJECT.Name   @ 0x10 (_UNICODE_STRING = 16 bytes: 0x10..0x20)
    ///   _WINSTATION_OBJECT.dwSessionId @ 0x20
    ///   _WINSTATION_OBJECT.rpwinstaNext @ 0x28
    ///   _WINSTATION_OBJECT.rpdeskList   @ 0x30
    ///
    ///   tagDESKTOP.Name        @ 0x10 (_UNICODE_STRING = 16 bytes: 0x10..0x20)
    ///   tagDESKTOP.pheapDesktop @ 0x20  (placed AFTER the Name _UNICODE_STRING)
    ///   tagDESKTOP.rpdeskNext   @ 0x28
    ///   tagDESKTOP.dwThreadCount @ 0x30
    fn make_winsta_isf(list_vaddr: u64) -> memf_symbols::isf::IsfResolver {
        use memf_symbols::test_builders::IsfBuilder;
        use memf_symbols::isf::IsfResolver;
        let isf = IsfBuilder::windows_kernel_preset()
            .add_symbol("grpWinStaList", list_vaddr)
            .add_struct("_WINSTATION_OBJECT", 0x100)
            .add_field("_WINSTATION_OBJECT", "Name", 0x10, "_UNICODE_STRING")
            .add_field("_WINSTATION_OBJECT", "dwSessionId", 0x20, "unsigned long")
            .add_field("_WINSTATION_OBJECT", "rpwinstaNext", 0x28, "pointer")
            .add_field("_WINSTATION_OBJECT", "rpdeskList", 0x30, "pointer")
            .add_struct("tagDESKTOP", 0x100)
            .add_field("tagDESKTOP", "Name", 0x10, "_UNICODE_STRING")
            .add_field("tagDESKTOP", "pheapDesktop", 0x20, "pointer")
            .add_field("tagDESKTOP", "rpdeskNext", 0x28, "pointer")
            .add_field("tagDESKTOP", "dwThreadCount", 0x30, "unsigned long")
            .build_json();
        IsfResolver::from_value(&isf).unwrap()
    }

    /// Helper: write a _UNICODE_STRING block into a page buffer.
    /// Layout: Length(u16) at off, MaxLength(u16) at off+2, Buffer(u64) at off+8.
    /// The UTF-16LE string data is placed at str_off within the same page.
    fn write_unistr_in_page(page: &mut Vec<u8>, off: usize, text: &str, str_off: usize, base_vaddr: u64) {
        let utf16: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let len = utf16.len() as u16;
        page[str_off..str_off + utf16.len()].copy_from_slice(&utf16);
        page[off..off + 2].copy_from_slice(&len.to_le_bytes());      // Length
        page[off + 2..off + 4].copy_from_slice(&len.to_le_bytes());  // MaxLength
        let buf_vaddr = base_vaddr + str_off as u64;
        page[off + 8..off + 16].copy_from_slice(&buf_vaddr.to_le_bytes()); // Buffer
    }

    /// walk_desktops: station with one desktop in the linked list.
    /// Exercises walk_station_desktops and the desktop-info push path.
    #[test]
    fn walk_desktops_station_with_one_desktop() {
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};

        // Addresses (all physical < 0x00FF_FFFF per 16 MB limit)
        let list_vaddr: u64  = 0xFFFF_8000_00C0_0000;
        let list_paddr: u64  = 0x00C0_0000;
        let ws_vaddr: u64    = 0xFFFF_8000_00C1_0000;
        let ws_paddr: u64    = 0x00C1_0000;
        let desk_vaddr: u64  = 0xFFFF_8000_00C2_0000;
        let desk_paddr: u64  = 0x00C2_0000;

        let resolver = make_winsta_isf(list_vaddr);

        // list page: first 8 bytes = ws_vaddr
        let mut list_page = vec![0u8; 4096];
        list_page[0..8].copy_from_slice(&ws_vaddr.to_le_bytes());

        // ws page: _UNICODE_STRING at 0x10 (Name), session_id at 0x20, rpdeskList at 0x30
        let mut ws_page = vec![0u8; 4096];
        write_unistr_in_page(&mut ws_page, 0x10, "WinSta0", 0x200, ws_vaddr);
        ws_page[0x20..0x24].copy_from_slice(&1u32.to_le_bytes()); // session_id
        ws_page[0x30..0x38].copy_from_slice(&desk_vaddr.to_le_bytes()); // rpdeskList

        // desk page: _UNICODE_STRING at 0x10 (Name, occupies 0x10..0x20),
        //            pheapDesktop at 0x20, rpdeskNext at 0x28, dwThreadCount at 0x30.
        let mut desk_page = vec![0u8; 4096];
        write_unistr_in_page(&mut desk_page, 0x10, "Default", 0x200, desk_vaddr);
        let heap_size: u64 = 0x0010_0000;
        desk_page[0x20..0x28].copy_from_slice(&heap_size.to_le_bytes()); // pheapDesktop
        desk_page[0x30..0x34].copy_from_slice(&3u32.to_le_bytes());       // dwThreadCount

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(list_vaddr, list_paddr, flags::WRITABLE)
            .map_4k(ws_vaddr, ws_paddr, flags::WRITABLE)
            .map_4k(desk_vaddr, desk_paddr, flags::WRITABLE)
            .write_phys(list_paddr, &list_page)
            .write_phys(ws_paddr, &ws_page)
            .write_phys(desk_paddr, &desk_page)
            .build();

        let vas = memf_core::vas::VirtualAddressSpace::new(mem, cr3, memf_core::vas::TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let (stations, desktops) = walk_desktops(&reader).unwrap();
        assert_eq!(stations.len(), 1, "should find exactly one window station");
        let ws = &stations[0];
        assert_eq!(ws.name, "WinSta0");
        assert_eq!(ws.session_id, 1);
        assert!(ws.is_interactive);
        assert!(!ws.is_suspicious, "WinSta0 should not be suspicious");
        assert_eq!(ws.desktop_count, 1);

        assert_eq!(desktops.len(), 1, "should find exactly one desktop");
        let desk = &desktops[0];
        assert_eq!(desk.name, "Default");
        assert_eq!(desk.winstation_name, "WinSta0");
        assert_eq!(desk.heap_size, heap_size);
        assert_eq!(desk.thread_count, 3);
        assert!(!desk.is_suspicious, "'Default' on WinSta0 is standard");
    }

    /// walk_desktops: suspicious desktop (non-standard name on WinSta0).
    #[test]
    fn walk_desktops_suspicious_desktop_flagged() {
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};

        let list_vaddr: u64  = 0xFFFF_8000_00D0_0000;
        let list_paddr: u64  = 0x00D0_0000;
        let ws_vaddr: u64    = 0xFFFF_8000_00D1_0000;
        let ws_paddr: u64    = 0x00D1_0000;
        let desk_vaddr: u64  = 0xFFFF_8000_00D2_0000;
        let desk_paddr: u64  = 0x00D2_0000;

        let resolver = make_winsta_isf(list_vaddr);

        let mut list_page = vec![0u8; 4096];
        list_page[0..8].copy_from_slice(&ws_vaddr.to_le_bytes());

        let mut ws_page = vec![0u8; 4096];
        write_unistr_in_page(&mut ws_page, 0x10, "WinSta0", 0x200, ws_vaddr);
        ws_page[0x30..0x38].copy_from_slice(&desk_vaddr.to_le_bytes());

        let mut desk_page = vec![0u8; 4096];
        write_unistr_in_page(&mut desk_page, 0x10, "HiddenDesktop", 0x200, desk_vaddr);

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(list_vaddr, list_paddr, flags::WRITABLE)
            .map_4k(ws_vaddr, ws_paddr, flags::WRITABLE)
            .map_4k(desk_vaddr, desk_paddr, flags::WRITABLE)
            .write_phys(list_paddr, &list_page)
            .write_phys(ws_paddr, &ws_page)
            .write_phys(desk_paddr, &desk_page)
            .build();

        let vas = memf_core::vas::VirtualAddressSpace::new(mem, cr3, memf_core::vas::TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let (_stations, desktops) = walk_desktops(&reader).unwrap();
        assert_eq!(desktops.len(), 1);
        assert!(desktops[0].is_suspicious, "HiddenDesktop on WinSta0 must be flagged");
    }

    /// grpWinStaList present, first_ws non-zero and mapped, but all fields zero →
    /// exercises the station walk loop (reads ws_name, session_id, desktop list).
    #[test]
    fn walk_desktops_symbol_with_mapped_ws_zero_fields() {
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};

        let list_vaddr: u64 = 0xFFFF_8000_00B0_0000;
        let list_paddr: u64 = 0x00B0_0000;
        let ws_vaddr: u64 = 0xFFFF_8000_00B1_0000;
        let ws_paddr: u64 = 0x00B1_0000;

        let isf = IsfBuilder::new()
            .add_symbol("grpWinStaList", list_vaddr)
            .add_struct("_WINSTATION_OBJECT", 0x100)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // list_vaddr page: first 8 bytes = ws_vaddr (non-null first station).
        let mut list_page = [0u8; 4096];
        list_page[0..8].copy_from_slice(&ws_vaddr.to_le_bytes());

        // ws_vaddr page: all zeroes → ws_name = "", session_id = 0, rpwinstaNext = 0 (stop).
        // rpdeskList (at default offset 0x30) = 0 → no desktops.
        let ws_page = [0u8; 4096];

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(list_vaddr, list_paddr, flags::WRITABLE)
            .map_4k(ws_vaddr, ws_paddr, flags::WRITABLE)
            .write_phys(list_paddr, &list_page)
            .write_phys(ws_paddr, &ws_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let (stations, desktops) = walk_desktops(&reader).unwrap_or_default();
        // Should get exactly 1 station (with empty name) and no desktops.
        assert_eq!(stations.len(), 1, "should find exactly one station");
        assert!(desktops.is_empty(), "no desktops (rpdeskList == 0)");
        // Empty name is suspicious.
        assert!(stations[0].is_suspicious);
        assert_eq!(stations[0].session_id, 0);
        assert_eq!(stations[0].desktop_count, 0);
    }
}
