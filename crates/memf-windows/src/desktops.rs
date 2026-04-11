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
    if name.eq_ignore_ascii_case("WinSta0") {
        return false;
    }
    if name.to_lowercase().starts_with("service-0x0-") {
        return false;
    }
    true
}

/// Classify a desktop name as suspicious.
///
/// Returns `true` (suspicious) when the desktop name is empty (unnamed desktop
/// is anomalous) or the desktop is on the interactive station (`WinSta0`) but
/// has a non-standard name (standard names are `Default`, `Winlogon`,
/// `Disconnect`, `Screen-saver`).  Desktops on service stations (non-`WinSta0`)
/// are considered benign.
pub fn classify_desktop(name: &str, winstation: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    if !winstation.eq_ignore_ascii_case("WinSta0") {
        return false;
    }
    !STANDARD_DESKTOPS
        .iter()
        .any(|&s| s.eq_ignore_ascii_case(name))
}

/// Read a u64 pointer from memory, returning 0 on failure.
fn read_ptr<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, addr: u64) -> u64 {
    reader
        .read_bytes(addr, 8)
        .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap()))
        .unwrap_or(0)
}

/// Read a u32 value from memory, returning 0 on failure.
fn read_u32<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, addr: u64) -> u32 {
    reader
        .read_bytes(addr, 4)
        .map(|b| u32::from_le_bytes(b[..4].try_into().unwrap()))
        .unwrap_or(0)
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
    let mut desk_addr = first_desk;
    let mut count = 0;

    while desk_addr != 0 && count < MAX_DESKTOPS_PER_STATION {
        count += 1;

        let name = read_unicode_string(reader, desk_addr + desk_name_off)
            .unwrap_or_default();
        let heap_size = read_ptr(reader, desk_addr + desk_heap_off);
        let thread_count = read_u32(reader, desk_addr + desk_thread_count_off);
        let is_suspicious = classify_desktop(&name, ws_name);

        desktops.push(DesktopInfo {
            address: desk_addr,
            name,
            winstation_name: ws_name.to_string(),
            heap_size,
            thread_count,
            is_suspicious,
        });

        desk_addr = read_ptr(reader, desk_addr + desk_next_off);
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
    let list_sym = reader.symbols().symbol_address("grpWinStaList");
    let Some(list_sym) = list_sym else {
        return Ok((Vec::new(), Vec::new()));
    };

    let first_ws = read_ptr(reader, list_sym);
    if first_ws == 0 {
        return Ok((Vec::new(), Vec::new()));
    }

    // Field offsets for _WINSTATION_OBJECT
    let ws_name_off = reader
        .symbols()
        .field_offset("_WINSTATION_OBJECT", "Name")
        .unwrap_or(0x10) as u64;
    let ws_session_off = reader
        .symbols()
        .field_offset("_WINSTATION_OBJECT", "dwSessionId")
        .unwrap_or(0x20) as u64;
    let ws_next_off = reader
        .symbols()
        .field_offset("_WINSTATION_OBJECT", "rpwinstaNext")
        .unwrap_or(0x28) as u64;
    let ws_desk_off = reader
        .symbols()
        .field_offset("_WINSTATION_OBJECT", "rpdeskList")
        .unwrap_or(0x30) as u64;

    // Field offsets for tagDESKTOP
    let desk_name_off = reader
        .symbols()
        .field_offset("tagDESKTOP", "Name")
        .unwrap_or(0x10) as u64;
    let desk_heap_off = reader
        .symbols()
        .field_offset("tagDESKTOP", "pheapDesktop")
        .unwrap_or(0x20) as u64;
    let desk_next_off = reader
        .symbols()
        .field_offset("tagDESKTOP", "rpdeskNext")
        .unwrap_or(0x28) as u64;
    let desk_thread_count_off = reader
        .symbols()
        .field_offset("tagDESKTOP", "dwThreadCount")
        .unwrap_or(0x30) as u64;

    let mut stations = Vec::new();
    let mut all_desktops = Vec::new();
    let mut ws_count = 0;
    let mut ws_addr = first_ws;

    while ws_addr != 0 && ws_count < MAX_WINSTATIONS {
        ws_count += 1;

        let name = read_unicode_string(reader, ws_addr + ws_name_off).unwrap_or_default();
        let session_id = read_u32(reader, ws_addr + ws_session_off);
        let first_desk = read_ptr(reader, ws_addr + ws_desk_off);

        let desktops = walk_station_desktops(
            reader,
            &name,
            first_desk,
            desk_name_off,
            desk_heap_off,
            desk_next_off,
            desk_thread_count_off,
        );
        let desktop_count = desktops.len() as u32;
        let is_interactive = name.eq_ignore_ascii_case("WinSta0");
        let is_suspicious = classify_winstation(&name);

        stations.push(WindowStationInfo {
            address: ws_addr,
            name,
            session_id,
            is_interactive,
            desktop_count,
            is_suspicious,
        });
        all_desktops.extend(desktops);

        ws_addr = read_ptr(reader, ws_addr + ws_next_off);
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

    use memf_core::test_builders::flags;
    use memf_core::test_builders::SyntheticPhysMem;

    // ---------------------------------------------------------------
    // classify_winstation tests
    // ---------------------------------------------------------------

    /// WinSta0 is the interactive station — always benign.
    #[test]
    fn classify_winstation_winsta0_benign() {
        assert!(!classify_winstation("WinSta0"));
        assert!(!classify_winstation("WINSTA0")); // case-insensitive
    }

    /// Service window stations (Service-0x0-*) are benign.
    #[test]
    fn classify_winstation_service_benign() {
        assert!(!classify_winstation("Service-0x0-3e7"));
        assert!(!classify_winstation("Service-0x0-3e4"));
    }

    /// Non-standard window station names are suspicious.
    #[test]
    fn classify_winstation_hidden_suspicious() {
        assert!(classify_winstation("HiddenStation"));
        assert!(classify_winstation("MalwareWinSta"));
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
        assert!(classify_desktop("", "Service-0x0-3e7"));
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
        assert!(!classify_desktop("AnyName", "Service-0x0-3e7"));
        assert!(!classify_desktop("MalDesktop", "Service-0x0-3e4"));
    }

    /// Empty name on a non-WinSta0 station is still suspicious.
    #[test]
    fn classify_desktop_empty_name_on_service_station_suspicious() {
        assert!(classify_desktop("", "Service-0x0-3e7"));
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
        assert!(!classify_winstation("Service-0x0-3e7"));
        assert!(!classify_winstation("Service-0x0-abc123"));
    }

    /// Names that look like service stations but aren't are suspicious.
    #[test]
    fn classify_winstation_fake_service_prefix_suspicious() {
        assert!(classify_winstation("Service-0x1-3e7")); // 0x1, not 0x0
        assert!(classify_winstation("svc-0x0-abc")); // wrong prefix
    }

    // ── Serialization tests ──────────────────────────────────────────

    #[test]
    fn window_station_info_serializes() {
        let info = WindowStationInfo {
            address: 0x1000,
            name: "WinSta0".to_string(),
            session_id: 1,
            is_interactive: true,
            desktop_count: 2,
            is_suspicious: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("WinSta0"));
        assert!(json.contains("\"is_interactive\":true"));
    }

    #[test]
    fn desktop_info_serializes() {
        let info = DesktopInfo {
            address: 0x2000,
            name: "Default".to_string(),
            winstation_name: "WinSta0".to_string(),
            heap_size: 0x100000,
            thread_count: 5,
            is_suspicious: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("Default"));
        assert!(json.contains("WinSta0"));
    }

    // ---------------------------------------------------------------
    // walk_desktops tests
    // ---------------------------------------------------------------

    fn make_empty_desk_reader() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("_WINSTATION_OBJECT", 64)
            .add_struct("tagDESKTOP", 64)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// No grpWinStaList symbol -> empty Vecs.
    #[test]
    fn walk_desktops_no_symbol() {
        let reader = make_empty_desk_reader();
        let (stations, desktops) = walk_desktops(&reader).unwrap();
        assert!(stations.is_empty());
        assert!(desktops.is_empty());
    }

    /// grpWinStaList present and mapped, but the pointer at list_head is 0 →
    /// exercises the walk body past the symbol check, returns empty.
    #[test]
    fn walk_desktops_symbol_present_first_ws_zero() {
        const SYM_VADDR: u64 = 0xFFFF_8000_0080_0000;
        const SYM_PADDR: u64 = 0x0080_0000;
        let isf = IsfBuilder::new()
            .add_struct("_WINSTATION_OBJECT", 64)
            .add_struct("tagDESKTOP", 64)
            .add_symbol("grpWinStaList", SYM_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&0u64.to_le_bytes());
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(SYM_VADDR, SYM_PADDR, flags::WRITABLE)
            .write_phys(SYM_PADDR, &sym_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let (stations, desktops) = walk_desktops(&reader).unwrap();
        assert!(stations.is_empty());
        assert!(desktops.is_empty());
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
    fn make_winsta_isf(list_vaddr: u64) -> IsfResolver {
        let isf = IsfBuilder::new()
            .add_struct("_WINSTATION_OBJECT", 64)
            .add_field("_WINSTATION_OBJECT", "Name", 0x10, "_UNICODE_STRING")
            .add_field("_WINSTATION_OBJECT", "dwSessionId", 0x20, "unsigned long")
            .add_field("_WINSTATION_OBJECT", "rpwinstaNext", 0x28, "pointer")
            .add_field("_WINSTATION_OBJECT", "rpdeskList", 0x30, "pointer")
            .add_struct("tagDESKTOP", 64)
            .add_field("tagDESKTOP", "Name", 0x10, "_UNICODE_STRING")
            .add_field("tagDESKTOP", "pheapDesktop", 0x20, "pointer")
            .add_field("tagDESKTOP", "rpdeskNext", 0x28, "pointer")
            .add_field("tagDESKTOP", "dwThreadCount", 0x30, "unsigned long")
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            .add_symbol("grpWinStaList", list_vaddr)
            .build_json();
        IsfResolver::from_value(&isf).unwrap()
    }

    /// Helper: write a _UNICODE_STRING block into a page buffer.
    /// Layout: Length(u16) at off, MaxLength(u16) at off+2, Buffer(u64) at off+8.
    /// The UTF-16LE string data is placed at str_off within the same page.
    fn write_unistr_in_page(page: &mut Vec<u8>, off: usize, text: &str, str_off: usize, base_vaddr: u64) {
        let utf16: Vec<u8> = text.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let byte_len = utf16.len() as u16;
        let buf_vaddr = base_vaddr + str_off as u64;
        page[off..off + 2].copy_from_slice(&byte_len.to_le_bytes());
        page[off + 2..off + 4].copy_from_slice(&byte_len.to_le_bytes());
        page[off + 8..off + 16].copy_from_slice(&buf_vaddr.to_le_bytes());
        page[str_off..str_off + utf16.len()].copy_from_slice(&utf16);
    }

    /// walk_desktops: station with one desktop in the linked list.
    /// Exercises walk_station_desktops and the desktop-info push path.
    #[test]
    fn walk_desktops_station_with_one_desktop() {
        const SYM_VADDR:  u64 = 0xFFFF_8000_0079_0000;
        const SYM_PADDR:  u64 = 0x0079_0000;
        const WS_VADDR:   u64 = 0xFFFF_8000_0078_0000;
        const WS_PADDR:   u64 = 0x0078_0000;
        const DESK_VADDR: u64 = 0xFFFF_8000_0077_0000;
        const DESK_PADDR: u64 = 0x0077_0000;

        let isf = IsfBuilder::new()
            .add_struct("_WINSTATION_OBJECT", 64)
            .add_field("_WINSTATION_OBJECT", "Name", 0x10, "_UNICODE_STRING")
            .add_field("_WINSTATION_OBJECT", "dwSessionId", 0x20, "unsigned long")
            .add_field("_WINSTATION_OBJECT", "rpwinstaNext", 0x28, "pointer")
            .add_field("_WINSTATION_OBJECT", "rpdeskList", 0x30, "pointer")
            .add_struct("tagDESKTOP", 64)
            .add_field("tagDESKTOP", "Name", 0x10, "_UNICODE_STRING")
            .add_field("tagDESKTOP", "pheapDesktop", 0x20, "pointer")
            .add_field("tagDESKTOP", "rpdeskNext", 0x28, "pointer")
            .add_field("tagDESKTOP", "dwThreadCount", 0x30, "unsigned long")
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            .add_symbol("grpWinStaList", SYM_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&WS_VADDR.to_le_bytes());

        // WS page: Name="WinSta0" @ 0x10, session_id=1 @ 0x20, next=0, desk=DESK_VADDR
        let mut ws_page = vec![0u8; 4096];
        write_unistr_in_page(&mut ws_page, 0x10, "WinSta0", 0x200, WS_VADDR);
        ws_page[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
        ws_page[0x28..0x30].copy_from_slice(&0u64.to_le_bytes()); // next = 0
        ws_page[0x30..0x38].copy_from_slice(&DESK_VADDR.to_le_bytes());

        // Desk page: Name="Default" @ 0x10, heap=0x100000 @ 0x20, next=0, threads=3
        let mut desk_page = vec![0u8; 4096];
        write_unistr_in_page(&mut desk_page, 0x10, "Default", 0x200, DESK_VADDR);
        desk_page[0x20..0x28].copy_from_slice(&0x100000u64.to_le_bytes());
        desk_page[0x28..0x30].copy_from_slice(&0u64.to_le_bytes()); // next = 0
        desk_page[0x30..0x34].copy_from_slice(&3u32.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(SYM_VADDR, SYM_PADDR, flags::WRITABLE)
            .write_phys(SYM_PADDR, &sym_page)
            .map_4k(WS_VADDR, WS_PADDR, flags::WRITABLE)
            .write_phys(WS_PADDR, &ws_page)
            .map_4k(DESK_VADDR, DESK_PADDR, flags::WRITABLE)
            .write_phys(DESK_PADDR, &desk_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let (stations, desktops) = walk_desktops(&reader).unwrap();
        assert_eq!(stations.len(), 1);
        assert_eq!(stations[0].name, "WinSta0");
        assert!(stations[0].is_interactive);
        assert!(!stations[0].is_suspicious);
        assert_eq!(stations[0].desktop_count, 1);
        assert_eq!(desktops.len(), 1);
        assert_eq!(desktops[0].name, "Default");
        assert!(!desktops[0].is_suspicious);
        assert_eq!(desktops[0].thread_count, 3);
    }

    /// walk_desktops: suspicious desktop (non-standard name on WinSta0).
    #[test]
    fn walk_desktops_suspicious_desktop_flagged() {
        const SYM_VADDR:  u64 = 0xFFFF_8000_0075_0000;
        const SYM_PADDR:  u64 = 0x0075_0000;
        const WS_VADDR:   u64 = 0xFFFF_8000_0074_0000;
        const WS_PADDR:   u64 = 0x0074_0000;
        const DESK_VADDR: u64 = 0xFFFF_8000_0073_0000;
        const DESK_PADDR: u64 = 0x0073_0000;

        let isf = IsfBuilder::new()
            .add_struct("_WINSTATION_OBJECT", 64)
            .add_field("_WINSTATION_OBJECT", "Name", 0x10, "_UNICODE_STRING")
            .add_field("_WINSTATION_OBJECT", "dwSessionId", 0x20, "unsigned long")
            .add_field("_WINSTATION_OBJECT", "rpwinstaNext", 0x28, "pointer")
            .add_field("_WINSTATION_OBJECT", "rpdeskList", 0x30, "pointer")
            .add_struct("tagDESKTOP", 64)
            .add_field("tagDESKTOP", "Name", 0x10, "_UNICODE_STRING")
            .add_field("tagDESKTOP", "pheapDesktop", 0x20, "pointer")
            .add_field("tagDESKTOP", "rpdeskNext", 0x28, "pointer")
            .add_field("tagDESKTOP", "dwThreadCount", 0x30, "unsigned long")
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            .add_symbol("grpWinStaList", SYM_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&WS_VADDR.to_le_bytes());

        let mut ws_page = vec![0u8; 4096];
        write_unistr_in_page(&mut ws_page, 0x10, "WinSta0", 0x200, WS_VADDR);
        ws_page[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
        ws_page[0x30..0x38].copy_from_slice(&DESK_VADDR.to_le_bytes());

        let mut desk_page = vec![0u8; 4096];
        write_unistr_in_page(&mut desk_page, 0x10, "HiddenDesk", 0x200, DESK_VADDR);
        desk_page[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(SYM_VADDR, SYM_PADDR, flags::WRITABLE)
            .write_phys(SYM_PADDR, &sym_page)
            .map_4k(WS_VADDR, WS_PADDR, flags::WRITABLE)
            .write_phys(WS_PADDR, &ws_page)
            .map_4k(DESK_VADDR, DESK_PADDR, flags::WRITABLE)
            .write_phys(DESK_PADDR, &desk_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let (_, desktops) = walk_desktops(&reader).unwrap();
        assert_eq!(desktops.len(), 1);
        assert_eq!(desktops[0].name, "HiddenDesk");
        assert!(desktops[0].is_suspicious);
    }

    /// grpWinStaList present, first_ws non-zero and mapped, but all fields zero →
    /// exercises the station walk loop (reads ws_name, session_id, desktop list).
    #[test]
    fn walk_desktops_symbol_with_mapped_ws_zero_fields() {
        const SYM_VADDR: u64 = 0xFFFF_8000_0071_0000;
        const SYM_PADDR: u64 = 0x0071_0000;
        const WS_VADDR:  u64 = 0xFFFF_8000_0070_0000;
        const WS_PADDR:  u64 = 0x0070_0000;

        let isf = IsfBuilder::new()
            .add_struct("_WINSTATION_OBJECT", 64)
            .add_field("_WINSTATION_OBJECT", "Name", 0x10, "_UNICODE_STRING")
            .add_field("_WINSTATION_OBJECT", "dwSessionId", 0x20, "unsigned long")
            .add_field("_WINSTATION_OBJECT", "rpwinstaNext", 0x28, "pointer")
            .add_field("_WINSTATION_OBJECT", "rpdeskList", 0x30, "pointer")
            .add_struct("tagDESKTOP", 64)
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            .add_symbol("grpWinStaList", SYM_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&WS_VADDR.to_le_bytes());

        // all zeros in ws_page → name="", session=0, next=0, desk=0
        let ws_page = vec![0u8; 4096];

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(SYM_VADDR, SYM_PADDR, flags::WRITABLE)
            .write_phys(SYM_PADDR, &sym_page)
            .map_4k(WS_VADDR, WS_PADDR, flags::WRITABLE)
            .write_phys(WS_PADDR, &ws_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let (stations, desktops) = walk_desktops(&reader).unwrap();
        // One station with empty name → is_suspicious=true
        assert_eq!(stations.len(), 1);
        assert!(stations[0].is_suspicious);
        assert_eq!(stations[0].name, "");
        assert!(desktops.is_empty());
    }
}
