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

/// Information about a window station recovered from kernel memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WindowStationInfo {
    /// Virtual address of the window station object.
    pub address: u64,
    /// Window station name (e.g. "WinSta0").
    pub name: String,
    /// Session ID this station belongs to.
    pub session_id: u32,
    /// Whether this is the interactive station (WinSta0).
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
    todo!()
}

/// Classify a desktop name as suspicious.
///
/// Returns `true` when:
/// - The desktop has a non-standard name on `WinSta0` (standard names are
///   `Default`, `Winlogon`, `Disconnect`, `Screen-saver`)
/// - Any desktop on a non-`WinSta0` interactive station
pub fn classify_desktop(name: &str, winstation: &str) -> bool {
    todo!()
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
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
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

    /// No grpWinStaList symbol → empty Vecs.
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
