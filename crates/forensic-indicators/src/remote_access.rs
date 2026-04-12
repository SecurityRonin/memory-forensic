/// TeamViewer registry indicator paths.
/// Source: lolrmm-registry-paths-complete.md §TeamViewer (16 paths)
pub const TEAMVIEWER_PATHS: &[&str] = &[
    r"SOFTWARE\TeamViewer",
    r"SYSTEM\CurrentControlSet\Services\TeamViewer",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TeamViewer",
];

/// AnyDesk registry indicator paths.
/// Source: lolrmm-registry-paths-complete.md §AnyDesk (8 paths)
pub const ANYDESK_PATHS: &[&str] = &[
    r"SOFTWARE\Clients\Media\AnyDesk",
    r"SYSTEM\CurrentControlSet\Services\AnyDesk",
    r"SOFTWARE\Classes\.anydesk\shell\open\command",
    r"SOFTWARE\Classes\AnyDesk\shell\open\command",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\AnyDesk",
    r"DRIVERS\DriverDatabase\DeviceIds\USBPRINT\AnyDesk",
    r"DRIVERS\DriverDatabase\DeviceIds\WSDPRINT\AnyDesk",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\AnyDesk Printer",
];

/// Splashtop registry indicator paths.
/// Source: lolrmm-registry-paths-complete.md §Splashtop (11 paths)
pub const SPLASHTOP_PATHS: &[&str] = &[
    r"SOFTWARE\WOW6432Node\Splashtop Inc.",
    r"SYSTEM\CurrentControlSet\Services\SplashtopRemoteService",
    r"SYSTEM\CurrentControlSet\Control\SafeBoot\Network\SplashtopRemoteService",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Splashtop Software Updater",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Splashtop-Splashtop Streamer-Remote Session/Operational",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Splashtop-Splashtop Streamer-Status/Operational",
    r"Software\Splashtop Inc.",
];

/// Atera registry indicator paths.
/// Source: lolrmm-registry-paths-complete.md §Atera (9 paths)
pub const ATERA_PATHS: &[&str] = &[
    r"SOFTWARE\ATERA Networks\AlphaAgent",
    r"SOFTWARE\ATERA Networks",
    r"SYSTEM\CurrentControlSet\Services\AteraAgent",
    r"SYSTEM\ControlSet\Services\EventLog\Application\AlphaAgent",
    r"SYSTEM\ControlSet\Services\EventLog\Application\AteraAgent",
    r"SOFTWARE\Microsoft\Tracing\AteraAgent_RASAPI32",
    r"SOFTWARE\Microsoft\Tracing\AteraAgent_RASMANCS",
];

/// GoToAssist / GoTo Resolve registry indicator paths.
/// Source: lolrmm-registry-paths-complete.md §GoToAssist (1 path)
pub const GOTOASSIST_PATHS: &[&str] = &[
    r"SOFTWARE\GoTo Resolve Unattended",
    r"SOFTWARE\Citrix\GoToMyPc",
    r"WOW6432Node\Citrix\GoToMyPc",
];

/// Action1 RMM registry indicator paths.
/// Source: lolrmm-registry-paths-complete.md §Action1 (3 paths)
pub const ACTION1_PATHS: &[&str] = &[
    r"System\CurrentControlSet\Services\A1Agent",
    r"SOFTWARE\WOW6432Node\Action1",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\Windows Error Reporting\LocalDumps\action1_agent.exe",
];

/// ManageEngine ServiceDesk Plus registry indicator paths.
/// Source: lolrmm-registry-paths-complete.md §ManageEngine (1 path)
pub const MANAGEENGINE_PATHS: &[&str] = &[
    r"SOFTWARE\ManageEngine",
    r"SOFTWARE\AdventNet\ManageEngine",
];

/// All LOLRMM remote access tool paths combined (for bulk scanning).
pub const ALL_LOLRMM_PATHS: &[&str] = &[
    // TEAMVIEWER_PATHS
    r"SOFTWARE\TeamViewer",
    r"SYSTEM\CurrentControlSet\Services\TeamViewer",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TeamViewer",
    // ANYDESK_PATHS
    r"SOFTWARE\Clients\Media\AnyDesk",
    r"SYSTEM\CurrentControlSet\Services\AnyDesk",
    r"SOFTWARE\Classes\.anydesk\shell\open\command",
    r"SOFTWARE\Classes\AnyDesk\shell\open\command",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\AnyDesk",
    r"DRIVERS\DriverDatabase\DeviceIds\USBPRINT\AnyDesk",
    r"DRIVERS\DriverDatabase\DeviceIds\WSDPRINT\AnyDesk",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\AnyDesk Printer",
    // SPLASHTOP_PATHS
    r"SOFTWARE\WOW6432Node\Splashtop Inc.",
    r"SYSTEM\CurrentControlSet\Services\SplashtopRemoteService",
    r"SYSTEM\CurrentControlSet\Control\SafeBoot\Network\SplashtopRemoteService",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Splashtop Software Updater",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Splashtop-Splashtop Streamer-Remote Session/Operational",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Splashtop-Splashtop Streamer-Status/Operational",
    r"Software\Splashtop Inc.",
    // ATERA_PATHS
    r"SOFTWARE\ATERA Networks\AlphaAgent",
    r"SOFTWARE\ATERA Networks",
    r"SYSTEM\CurrentControlSet\Services\AteraAgent",
    r"SYSTEM\ControlSet\Services\EventLog\Application\AlphaAgent",
    r"SYSTEM\ControlSet\Services\EventLog\Application\AteraAgent",
    r"SOFTWARE\Microsoft\Tracing\AteraAgent_RASAPI32",
    r"SOFTWARE\Microsoft\Tracing\AteraAgent_RASMANCS",
    // GOTOASSIST_PATHS
    r"SOFTWARE\GoTo Resolve Unattended",
    r"SOFTWARE\Citrix\GoToMyPc",
    r"WOW6432Node\Citrix\GoToMyPc",
    // ACTION1_PATHS
    r"System\CurrentControlSet\Services\A1Agent",
    r"SOFTWARE\WOW6432Node\Action1",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\Windows Error Reporting\LocalDumps\action1_agent.exe",
    // MANAGEENGINE_PATHS
    r"SOFTWARE\ManageEngine",
    r"SOFTWARE\AdventNet\ManageEngine",
];

/// Returns true if the given registry path matches a known LOLRMM remote access tool
/// indicator (case-insensitive contains match).
pub fn is_remote_access_tool_path(_path: &str) -> bool {
    todo!("implement is_remote_access_tool_path")
}

/// Returns the tool name if the path matches a known LOLRMM remote access tool,
/// or None if not recognized.
pub fn identify_remote_access_tool(_path: &str) -> Option<&'static str> {
    todo!("implement identify_remote_access_tool")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn teamviewer_paths_not_empty() {
        assert!(!TEAMVIEWER_PATHS.is_empty(), "TEAMVIEWER_PATHS must not be empty");
    }

    #[test]
    fn anydesk_paths_not_empty() {
        assert!(!ANYDESK_PATHS.is_empty(), "ANYDESK_PATHS must not be empty");
    }

    #[test]
    fn all_lolrmm_paths_not_empty() {
        assert!(!ALL_LOLRMM_PATHS.is_empty(), "ALL_LOLRMM_PATHS must not be empty");
    }

    #[test]
    fn is_remote_access_tool_path_teamviewer_matches() {
        assert!(
            is_remote_access_tool_path(r"SOFTWARE\TeamViewer\ConnectionHistory"),
            "TeamViewer path must match"
        );
    }

    #[test]
    fn is_remote_access_tool_path_case_insensitive() {
        assert!(
            is_remote_access_tool_path(r"software\teamviewer"),
            "Match must be case-insensitive"
        );
    }

    #[test]
    fn is_remote_access_tool_path_unrelated_returns_false() {
        assert!(
            !is_remote_access_tool_path(r"SOFTWARE\Microsoft\Office"),
            "Unrelated path must not match"
        );
    }

    #[test]
    fn identify_remote_access_tool_teamviewer() {
        assert_eq!(
            identify_remote_access_tool(r"SOFTWARE\TeamViewer\ConnectionHistory"),
            Some("TeamViewer"),
            "Should identify TeamViewer"
        );
    }

    #[test]
    fn identify_remote_access_tool_anydesk() {
        assert_eq!(
            identify_remote_access_tool(r"SYSTEM\CurrentControlSet\Services\AnyDesk"),
            Some("AnyDesk"),
            "Should identify AnyDesk"
        );
    }

    #[test]
    fn identify_remote_access_tool_unknown_returns_none() {
        assert_eq!(
            identify_remote_access_tool(r"SOFTWARE\Microsoft\Windows"),
            None,
            "Unknown path should return None"
        );
    }
}
