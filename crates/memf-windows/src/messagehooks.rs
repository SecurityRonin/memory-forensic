//! Windows message hook detection (`SetWindowsHookEx`).
//!
//! `SetWindowsHookEx()` installs message hooks that intercept keyboard/mouse
//! events — used by keyloggers and credential stealers. The win32k subsystem
//! maintains hook chains via `_HOOK` structures linked from `_DESKTOP` objects.
//!
//! This module enumerates installed message hooks from kernel memory and
//! classifies them as suspicious based on hook type and owning module.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;

/// Maximum number of hooks to enumerate (safety limit).
const MAX_HOOKS: usize = 4096;

/// Number of hook types in the aphkStart array (WH_MSGFILTER=-1 through WH_MOUSE_LL=14).
const HOOK_TYPE_COUNT: usize = 16;

/// Information about a Windows message hook recovered from kernel memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MessageHookInfo {
    /// Virtual address of the hook object.
    pub address: u64,
    /// Hook type name (e.g., `WH_KEYBOARD_LL`, `WH_MOUSE_LL`).
    pub hook_type: String,
    /// Process ID that installed the hook.
    pub owner_pid: u32,
    /// Address of the hook procedure.
    pub hook_proc_addr: u64,
    /// DLL containing the hook procedure.
    pub module_name: String,
    /// Whether this hook looks suspicious (heuristic flag).
    pub is_suspicious: bool,
}

/// Map a raw hook type value to its symbolic name.
///
/// Hook type values range from -1 (`WH_MSGFILTER`) to 14 (`WH_MOUSE_LL`).
/// The kernel stores these as `u32` where -1 is `0xFFFF_FFFF`.
pub fn hook_type_name(raw: u32) -> String {
    match raw {
        0xFFFF_FFFF => "WH_MSGFILTER".into(),
        0 => "WH_JOURNALRECORD".into(),
        1 => "WH_JOURNALPLAYBACK".into(),
        2 => "WH_KEYBOARD".into(),
        3 => "WH_GETMESSAGE".into(),
        4 => "WH_CALLWNDPROC".into(),
        5 => "WH_CBT".into(),
        6 => "WH_SYSMSGFILTER".into(),
        7 => "WH_MOUSE".into(),
        9 => "WH_DEBUG".into(),
        10 => "WH_SHELL".into(),
        11 => "WH_FOREGROUNDIDLE".into(),
        12 => "WH_CALLWNDPROCRET".into(),
        13 => "WH_KEYBOARD_LL".into(),
        14 => "WH_MOUSE_LL".into(),
        other => format!("WH_UNKNOWN({other})"),
    }
}

/// Classify a message hook as suspicious based on hook type and module.
///
/// Returns `true` when the hook matches common keylogger/stealer patterns:
/// - `WH_KEYBOARD_LL` or `WH_MOUSE_LL` from non-system modules
/// - Any hook from temp, appdata, or downloads directories
/// - Empty module name (injected or unknown origin)
///
/// Known benign Windows modules: `user32.dll`, `imm32.dll`, `msctf.dll`.
pub fn classify_message_hook(hook_type: &str, module: &str) -> bool {
    // Empty module name means unknown origin — always suspicious.
    if module.is_empty() {
        return true;
    }

    let lower_module = module.to_ascii_lowercase();

    // Any hook from temp, appdata, or downloads directories is suspicious
    // regardless of hook type.
    const SUSPICIOUS_PATHS: &[&str] = &["\\temp\\", "\\appdata\\", "\\downloads\\"];

    for path in SUSPICIOUS_PATHS {
        if lower_module.contains(path) {
            return true;
        }
    }

    // Known benign Windows system modules that commonly install hooks.
    const BENIGN_MODULES: &[&str] = &["user32.dll", "imm32.dll", "msctf.dll"];

    let is_system_module = BENIGN_MODULES
        .iter()
        .any(|m| lower_module == *m || lower_module.ends_with(&format!("\\{m}")));

    // WH_KEYBOARD_LL or WH_MOUSE_LL from non-system modules are suspicious
    // (primary keylogger/mouse-logger vector).
    if (hook_type == "WH_KEYBOARD_LL" || hook_type == "WH_MOUSE_LL") && !is_system_module {
        return true;
    }

    false
}

/// Enumerate Windows message hooks from kernel memory.
///
/// Walks the win32k desktop hook chains starting from the `grpWinStaList`
/// symbol. For each window station, iterates desktops and reads the
/// `aphkStart` array of hook chain heads.
///
/// Returns `Ok(Vec::new())` if the required symbols are not present.
pub fn walk_message_hooks<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<MessageHookInfo>> {
    // Resolve grpWinStaList — the head of the window station linked list.
    let winsta_list_head = match reader.symbols().symbol_address("grpWinStaList") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    // Struct/field offsets for traversal.
    let winsta_next_off = reader
        .symbols()
        .field_offset("_WINSTATION_OBJECT", "rpwinstaNext")
        .unwrap_or(0x10);

    let winsta_desktop_off = reader
        .symbols()
        .field_offset("_WINSTATION_OBJECT", "rpdeskList")
        .unwrap_or(0x18);

    let desktop_next_off = reader
        .symbols()
        .field_offset("_DESKTOP", "rpdeskNext")
        .unwrap_or(0x10);

    let desktop_hooks_off = reader
        .symbols()
        .field_offset("_DESKTOP", "pDeskInfo")
        .unwrap_or(0x20);

    let deskinfo_aphk_off = reader
        .symbols()
        .field_offset("tagDESKTOPINFO", "aphkStart")
        .unwrap_or(0x18);

    let hook_next_off = reader
        .symbols()
        .field_offset("_HOOK", "phkNext")
        .unwrap_or(0x18);

    let hook_ihook_off = reader
        .symbols()
        .field_offset("_HOOK", "iHook")
        .unwrap_or(0x00);

    let hook_offpfn_off = reader
        .symbols()
        .field_offset("_HOOK", "offPfn")
        .unwrap_or(0x08);

    let hook_ihmod_off = reader
        .symbols()
        .field_offset("_HOOK", "ihmod")
        .unwrap_or(0x10);

    let hook_ptihooked_off = reader
        .symbols()
        .field_offset("_HOOK", "ptiHooked")
        .unwrap_or(0x28);

    // _THREADINFO → _EPROCESS → UniqueProcessId chain for PID extraction.
    let threadinfo_eprocess_off = reader
        .symbols()
        .field_offset("tagTHREADINFO", "pEThread")
        .unwrap_or(0x00);

    let ethread_process_off = reader
        .symbols()
        .field_offset("_ETHREAD", "ThreadsProcess")
        .unwrap_or(0x220);

    let pid_off = reader
        .symbols()
        .field_offset("_EPROCESS", "UniqueProcessId")
        .unwrap_or(0x440);

    // Read head pointer from grpWinStaList (pointer to first _WINSTATION_OBJECT).
    let first_winsta = match reader.read_bytes(winsta_list_head, 8) {
        Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        _ => return Ok(Vec::new()),
    };

    if first_winsta == 0 {
        return Ok(Vec::new());
    }

    let mut hooks = Vec::new();
    let mut winsta_addr = first_winsta;
    let mut seen_winstations = std::collections::HashSet::new();

    // Walk window stations.
    while winsta_addr != 0 && hooks.len() < MAX_HOOKS {
        if !seen_winstations.insert(winsta_addr) {
            break; // Cycle detection.
        }

        // Read first desktop pointer from this window station.
        let first_desktop = match reader.read_bytes(winsta_addr + winsta_desktop_off, 8) {
            Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            _ => 0,
        };

        let mut desktop_addr = first_desktop;
        let mut seen_desktops = std::collections::HashSet::new();

        // Walk desktops within this window station.
        while desktop_addr != 0 && hooks.len() < MAX_HOOKS {
            if !seen_desktops.insert(desktop_addr) {
                break; // Cycle detection.
            }

            // Read pDeskInfo pointer.
            let deskinfo_addr = match reader.read_bytes(desktop_addr + desktop_hooks_off, 8) {
                Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                _ => 0,
            };

            if deskinfo_addr != 0 {
                // Iterate aphkStart[0..HOOK_TYPE_COUNT] — array of pointers to _HOOK chain heads.
                for idx in 0..HOOK_TYPE_COUNT {
                    let aphk_entry_addr = deskinfo_addr + deskinfo_aphk_off + (idx as u64 * 8);

                    let hook_head = match reader.read_bytes(aphk_entry_addr, 8) {
                        Ok(bytes) if bytes.len() == 8 => {
                            u64::from_le_bytes(bytes[..8].try_into().unwrap())
                        }
                        _ => continue,
                    };

                    if hook_head == 0 {
                        continue;
                    }

                    // Walk the hook chain for this type.
                    let mut hook_addr = hook_head;
                    let mut seen_hooks = std::collections::HashSet::new();

                    while hook_addr != 0 && hooks.len() < MAX_HOOKS {
                        if !seen_hooks.insert(hook_addr) {
                            break; // Cycle detection.
                        }

                        // Read iHook (hook type as u32).
                        let raw_type: u32 = match reader.read_bytes(hook_addr + hook_ihook_off, 4) {
                            Ok(bytes) if bytes.len() == 4 => {
                                u32::from_le_bytes(bytes[..4].try_into().unwrap())
                            }
                            _ => idx as u32,
                        };

                        let hook_type = hook_type_name(raw_type);

                        // Read offPfn (hook procedure address).
                        let hook_proc_addr = match reader.read_bytes(hook_addr + hook_offpfn_off, 8)
                        {
                            Ok(bytes) if bytes.len() == 8 => {
                                u64::from_le_bytes(bytes[..8].try_into().unwrap())
                            }
                            _ => 0,
                        };

                        // Read ihmod (module index) — used as a proxy; the actual
                        // module name comes from the module table. We read the
                        // _UNICODE_STRING at this offset if it looks like a pointer.
                        let module_name = match reader.read_bytes(hook_addr + hook_ihmod_off, 8) {
                            Ok(bytes) if bytes.len() == 8 => {
                                let mod_ptr = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                                if mod_ptr > 0xFFFF {
                                    // Attempt to read as a UNICODE_STRING.
                                    read_unicode_string(reader, mod_ptr).unwrap_or_default()
                                } else {
                                    String::new()
                                }
                            }
                            _ => String::new(),
                        };

                        // Extract owner PID via ptiHooked → pEThread → EPROCESS → PID.
                        let owner_pid = match reader.read_bytes(hook_addr + hook_ptihooked_off, 8) {
                            Ok(bytes) if bytes.len() == 8 => {
                                let ti_ptr = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                                if ti_ptr != 0 {
                                    extract_pid_from_threadinfo(
                                        reader,
                                        ti_ptr,
                                        threadinfo_eprocess_off,
                                        ethread_process_off,
                                        pid_off,
                                    )
                                } else {
                                    0
                                }
                            }
                            _ => 0,
                        };

                        let is_suspicious = classify_message_hook(&hook_type, &module_name);

                        hooks.push(MessageHookInfo {
                            address: hook_addr,
                            hook_type,
                            owner_pid,
                            hook_proc_addr,
                            module_name,
                            is_suspicious,
                        });

                        // Follow phkNext to the next hook in the chain.
                        hook_addr = match reader.read_bytes(hook_addr + hook_next_off, 8) {
                            Ok(bytes) if bytes.len() == 8 => {
                                u64::from_le_bytes(bytes[..8].try_into().unwrap())
                            }
                            _ => break,
                        };
                    }
                }
            }

            // Follow rpdeskNext to the next desktop.
            desktop_addr = match reader.read_bytes(desktop_addr + desktop_next_off, 8) {
                Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                _ => break,
            };
        }

        // Follow rpwinstaNext to the next window station.
        winsta_addr = match reader.read_bytes(winsta_addr + winsta_next_off, 8) {
            Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            _ => break,
        };
    }

    Ok(hooks)
}

/// Extract a PID from a `tagTHREADINFO` pointer by chasing through
/// `pEThread` → `ThreadsProcess` → `UniqueProcessId`.
fn extract_pid_from_threadinfo<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    threadinfo_addr: u64,
    threadinfo_eprocess_off: u64,
    ethread_process_off: u64,
    pid_off: u64,
) -> u32 {
    // Read pEThread pointer.
    let ethread = match reader.read_bytes(threadinfo_addr + threadinfo_eprocess_off, 8) {
        Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        _ => return 0,
    };

    if ethread == 0 {
        return 0;
    }

    // Read ThreadsProcess → _EPROCESS pointer.
    let eprocess = match reader.read_bytes(ethread + ethread_process_off, 8) {
        Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        _ => return 0,
    };

    if eprocess == 0 {
        return 0;
    }

    // Read UniqueProcessId.
    match reader.read_bytes(eprocess + pid_off, 8) {
        Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()) as u32,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ── classify_message_hook tests ──────────────────────────────────────

    /// WH_KEYBOARD_LL from a custom DLL is suspicious.
    #[test]
    fn classify_keyboard_ll_custom_dll_suspicious() {
        assert!(classify_message_hook("WH_KEYBOARD_LL", "keylogger.dll"));
    }

    /// WH_KEYBOARD_LL from user32.dll is benign.
    #[test]
    fn classify_keyboard_ll_user32_benign() {
        assert!(!classify_message_hook("WH_KEYBOARD_LL", "user32.dll"));
    }

    /// WH_MOUSE_LL from a temp directory is suspicious.
    #[test]
    fn classify_mouse_ll_temp_dir_suspicious() {
        assert!(classify_message_hook(
            "WH_MOUSE_LL",
            "C:\\Users\\victim\\AppData\\Local\\Temp\\evil.dll"
        ));
    }

    /// WH_CBT from a known system module (msctf.dll) is benign.
    #[test]
    fn classify_cbt_system_module_benign() {
        assert!(!classify_message_hook("WH_CBT", "msctf.dll"));
    }

    /// Any hook from an AppData path is suspicious.
    #[test]
    fn classify_any_hook_appdata_suspicious() {
        assert!(classify_message_hook(
            "WH_SHELL",
            "C:\\Users\\user\\AppData\\Roaming\\malware\\hook.dll"
        ));
    }

    /// Empty module name is suspicious (unknown origin).
    #[test]
    fn classify_empty_module_suspicious() {
        assert!(classify_message_hook("WH_KEYBOARD", ""));
    }

    // ── hook_type_name tests ─────────────────────────────────────────────

    /// Known hook type values map to correct symbolic names.
    #[test]
    fn hook_type_name_known_values() {
        assert_eq!(hook_type_name(0xFFFF_FFFF), "WH_MSGFILTER");
        assert_eq!(hook_type_name(0), "WH_JOURNALRECORD");
        assert_eq!(hook_type_name(1), "WH_JOURNALPLAYBACK");
        assert_eq!(hook_type_name(2), "WH_KEYBOARD");
        assert_eq!(hook_type_name(3), "WH_GETMESSAGE");
        assert_eq!(hook_type_name(4), "WH_CALLWNDPROC");
        assert_eq!(hook_type_name(5), "WH_CBT");
        assert_eq!(hook_type_name(6), "WH_SYSMSGFILTER");
        assert_eq!(hook_type_name(7), "WH_MOUSE");
        assert_eq!(hook_type_name(9), "WH_DEBUG");
        assert_eq!(hook_type_name(10), "WH_SHELL");
        assert_eq!(hook_type_name(11), "WH_FOREGROUNDIDLE");
        assert_eq!(hook_type_name(12), "WH_CALLWNDPROCRET");
        assert_eq!(hook_type_name(13), "WH_KEYBOARD_LL");
        assert_eq!(hook_type_name(14), "WH_MOUSE_LL");
        assert_eq!(hook_type_name(99), "WH_UNKNOWN(99)");
    }

    // ── hook_type_name edge cases ────────────────────────────────────────

    /// hook_type 8 has no entry and returns WH_UNKNOWN(8).
    #[test]
    fn hook_type_name_missing_8() {
        // Value 8 is not in the table.
        assert_eq!(hook_type_name(8), "WH_UNKNOWN(8)");
    }

    /// Very large raw type value returns WH_UNKNOWN.
    #[test]
    fn hook_type_name_large_value() {
        assert_eq!(hook_type_name(0xDEAD_BEEF), "WH_UNKNOWN(3735928559)");
    }

    // ── classify_message_hook additional coverage ────────────────────────

    /// WH_MOUSE_LL from a known system module is benign.
    #[test]
    fn classify_mouse_ll_user32_benign() {
        assert!(!classify_message_hook("WH_MOUSE_LL", "user32.dll"));
        assert!(!classify_message_hook("WH_MOUSE_LL", "imm32.dll"));
    }

    /// WH_GETMESSAGE from an unrelated custom DLL is not suspicious
    /// (only LL hooks are flagged from non-system modules).
    #[test]
    fn classify_getmessage_custom_dll_benign() {
        assert!(!classify_message_hook("WH_GETMESSAGE", "accessibility.dll"));
    }

    /// Module path with \\downloads\\ is suspicious regardless of hook type.
    #[test]
    fn classify_downloads_path_suspicious() {
        assert!(classify_message_hook(
            "WH_CBT",
            "C:\\Users\\user\\Downloads\\evil.dll"
        ));
    }

    /// Module name that ends with a system module name (path-qualified) is benign.
    #[test]
    fn classify_path_qualified_system_module_benign() {
        // Ends with \user32.dll — should match BENIGN_MODULES.
        assert!(!classify_message_hook(
            "WH_KEYBOARD_LL",
            "C:\\Windows\\System32\\user32.dll"
        ));
        assert!(!classify_message_hook(
            "WH_KEYBOARD_LL",
            "C:\\Windows\\SysWOW64\\imm32.dll"
        ));
    }

    // ── walk_message_hooks tests ─────────────────────────────────────────

    /// No grpWinStaList symbol present → returns empty Vec.
    #[test]
    fn walk_message_hooks_no_symbol() {
        let isf = IsfBuilder::new().add_struct("_HOOK", 0x80).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_message_hooks(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// Walker with grpWinStaList symbol but unreadable memory returns empty.
    #[test]
    fn walk_message_hooks_unreadable_winsta_list() {
        let isf = IsfBuilder::new()
            .add_struct("_HOOK", 0x80)
            .add_symbol("grpWinStaList", 0xFFFF_8000_DEAD_0000u64)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        // No memory mapped → read fails → empty.
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_message_hooks(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// Walker with grpWinStaList pointing to zero first_winsta returns empty.
    #[test]
    fn walk_message_hooks_zero_first_winsta() {
        use memf_core::test_builders::flags;

        let sym_vaddr: u64 = 0xFFFF_8000_3000_0000;
        let sym_paddr: u64 = 0x0070_0000;

        // 8 bytes at sym_vaddr = 0 (null pointer to first window station).
        let mut page = vec![0u8; 4096];
        page[0..8].copy_from_slice(&0u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("_HOOK", 0x80)
            .add_symbol("grpWinStaList", sym_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, flags::WRITABLE)
            .write_phys(sym_paddr, &page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        // first_winsta == 0 → empty.
        let result = walk_message_hooks(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// walker with grpWinStaList → non-zero winsta → zero desktop list → empty.
    #[test]
    fn walk_message_hooks_nonzero_winsta_zero_desktop() {
        let sym_vaddr: u64 = 0xFFFF_8000_3100_0000;
        let sym_paddr: u64 = 0x0073_0000;
        let winsta_vaddr: u64 = 0xFFFF_8000_3200_0000;
        let winsta_paddr: u64 = 0x0074_0000;

        // sym page: 8 bytes = winsta_vaddr.
        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&winsta_vaddr.to_le_bytes());

        // winsta page: all zeros → first_desktop = 0 (at winsta + 0x18).
        // rpwinstaNext at winsta + 0x10 = 0 → loop ends.
        let winsta_page = vec![0u8; 4096];

        let isf = IsfBuilder::new()
            .add_struct("_HOOK", 0x80)
            .add_symbol("grpWinStaList", sym_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, flags::WRITABLE)
            .map_4k(winsta_vaddr, winsta_paddr, flags::WRITABLE)
            .write_phys(sym_paddr, &sym_page)
            .write_phys(winsta_paddr, &winsta_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_message_hooks(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// classify: WH_SHELL from downloads path is suspicious.
    #[test]
    fn classify_shell_hook_downloads_suspicious() {
        assert!(classify_message_hook(
            "WH_SHELL",
            "C:\\Users\\victim\\Downloads\\hook.dll"
        ));
    }

    /// classify: WH_CBT from imm32.dll is benign.
    #[test]
    fn classify_cbt_imm32_benign() {
        assert!(!classify_message_hook("WH_CBT", "imm32.dll"));
    }

    /// classify: WH_MOUSE_LL from msctf.dll is benign.
    #[test]
    fn classify_mouse_ll_msctf_benign() {
        assert!(!classify_message_hook("WH_MOUSE_LL", "msctf.dll"));
    }

    /// classify: path-qualified imm32.dll is benign for WH_KEYBOARD_LL.
    #[test]
    fn classify_path_qualified_imm32_benign() {
        assert!(!classify_message_hook(
            "WH_KEYBOARD_LL",
            "C:\\Windows\\System32\\imm32.dll"
        ));
    }

    /// hook_type_name: value 15 → unknown.
    #[test]
    fn hook_type_name_value_15_unknown() {
        assert_eq!(hook_type_name(15), "WH_UNKNOWN(15)");
    }

    /// HOOK_TYPE_COUNT and MAX_HOOKS constants are reasonable.
    #[test]
    fn hook_constants_sensible() {
        assert_eq!(HOOK_TYPE_COUNT, 16);
        assert!(MAX_HOOKS > 0);
        assert!(MAX_HOOKS <= 65536);
    }

    /// MessageHookInfo serializes to JSON.
    #[test]
    fn message_hook_info_serializes() {
        let hook = MessageHookInfo {
            address: 0xFFFF_8000_1234_0000,
            hook_type: "WH_KEYBOARD_LL".to_string(),
            owner_pid: 1234,
            hook_proc_addr: 0xDEAD_BEEF_0000,
            module_name: "keylogger.dll".to_string(),
            is_suspicious: true,
        };
        let json = serde_json::to_string(&hook).unwrap();
        assert!(json.contains("WH_KEYBOARD_LL"));
        assert!(json.contains("keylogger.dll"));
        assert!(json.contains("is_suspicious"));
    }

    /// extract_pid_from_threadinfo: ethread_ptr == 0 → returns 0.
    #[test]
    fn extract_pid_zero_ethread_returns_zero() {
        let (cr3, mem) = PageTableBuilder::new().build();
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        // threadinfo page: at offset 0 (threadinfo_eprocess_off=0) → 0 (ethread null).
        // extract_pid_from_threadinfo returns 0 when ethread == 0.
        let result = extract_pid_from_threadinfo(&reader, 0xFFFF_8000_DEAD_0000, 0, 0x220, 0x440);
        assert_eq!(result, 0, "unreadable threadinfo → 0");
    }

    /// extract_pid_from_threadinfo: ethread reads ok (non-zero), eprocess reads ok,
    /// PID reads ok → returns correct PID.
    #[test]
    fn extract_pid_from_threadinfo_valid_chain() {
        let threadinfo_vaddr: u64 = 0xFFFF_8000_4000_0000;
        let threadinfo_paddr: u64 = 0x0040_0000;
        let ethread_vaddr: u64 = 0xFFFF_8000_4100_0000;
        let ethread_paddr: u64 = 0x0041_0000;
        let eprocess_vaddr: u64 = 0xFFFF_8000_4200_0000;
        let eprocess_paddr: u64 = 0x0042_0000;

        let expected_pid: u64 = 9999;
        // threadinfo_eprocess_off = 0 → ethread_vaddr at threadinfo+0
        // ethread_process_off = 0x08 → eprocess_vaddr at ethread+0x08
        // pid_off = 0x10 → pid at eprocess+0x10

        let mut threadinfo_page = vec![0u8; 4096];
        threadinfo_page[0..8].copy_from_slice(&ethread_vaddr.to_le_bytes());

        let mut ethread_page = vec![0u8; 4096];
        ethread_page[0x08..0x10].copy_from_slice(&eprocess_vaddr.to_le_bytes());

        let mut eprocess_page = vec![0u8; 4096];
        eprocess_page[0x10..0x18].copy_from_slice(&expected_pid.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(threadinfo_vaddr, threadinfo_paddr, flags::WRITABLE)
            .map_4k(ethread_vaddr, ethread_paddr, flags::WRITABLE)
            .map_4k(eprocess_vaddr, eprocess_paddr, flags::WRITABLE)
            .write_phys(threadinfo_paddr, &threadinfo_page)
            .write_phys(ethread_paddr, &ethread_page)
            .write_phys(eprocess_paddr, &eprocess_page)
            .build();

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let pid = extract_pid_from_threadinfo(&reader, threadinfo_vaddr, 0, 0x08, 0x10);
        assert_eq!(pid, expected_pid as u32, "should extract PID {expected_pid}");
    }

    /// walker: winsta → desktop → deskinfo → one hook in aphkStart[0] → one hook returned.
    ///
    /// This exercises the inner aphk loop, hook chain traversal, and hook field reads.
    /// The hook has ihmod <= 0xFFFF so module_name = "" → classify_message_hook → suspicious.
    #[test]
    fn walk_message_hooks_one_hook_inner_loop() {
        // Memory layout (all on separate 4K pages, physical addrs < 16MB):
        //   sym_page   → 8 bytes: winsta_vaddr
        //   winsta_page → at +0x10: 0 (no next winsta), at +0x18: desktop_vaddr
        //   desktop_page → at +0x10: 0 (no next desktop), at +0x20: deskinfo_vaddr
        //   deskinfo_page → at +0x18: hook_vaddr (aphkStart[0])
        //   hook_page  → at +0x00: 13u32 (WH_KEYBOARD_LL), +0x08: hook_proc,
        //                           +0x10: 0u64 (ihmod ≤ 0xFFFF, so module = ""),
        //                           +0x18: 0 (phkNext = null, chain ends),
        //                           +0x28: 0 (ptiHooked = null → owner_pid = 0)

        let sym_vaddr: u64 = 0xFFFF_8000_5000_0000;
        let sym_paddr: u64 = 0x0050_0000;
        let winsta_vaddr: u64 = 0xFFFF_8000_5100_0000;
        let winsta_paddr: u64 = 0x0051_0000;
        let desktop_vaddr: u64 = 0xFFFF_8000_5200_0000;
        let desktop_paddr: u64 = 0x0052_0000;
        let deskinfo_vaddr: u64 = 0xFFFF_8000_5300_0000;
        let deskinfo_paddr: u64 = 0x0053_0000;
        let hook_vaddr: u64 = 0xFFFF_8000_5400_0000;
        let hook_paddr: u64 = 0x0054_0000;

        let hook_proc_addr: u64 = 0xDEAD_CAFE_0000;

        // sym_page: pointer to winsta
        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&winsta_vaddr.to_le_bytes());

        // winsta_page: rpwinstaNext (offset 0x10) = 0, rpdeskList (offset 0x18) = desktop_vaddr
        let mut winsta_page = vec![0u8; 4096];
        winsta_page[0x10..0x18].copy_from_slice(&0u64.to_le_bytes()); // no next
        winsta_page[0x18..0x20].copy_from_slice(&desktop_vaddr.to_le_bytes());

        // desktop_page: rpdeskNext (offset 0x10) = 0, pDeskInfo (offset 0x20) = deskinfo_vaddr
        let mut desktop_page = vec![0u8; 4096];
        desktop_page[0x10..0x18].copy_from_slice(&0u64.to_le_bytes()); // no next
        desktop_page[0x20..0x28].copy_from_slice(&deskinfo_vaddr.to_le_bytes());

        // deskinfo_page: aphkStart[0] (offset 0x18) = hook_vaddr
        let mut deskinfo_page = vec![0u8; 4096];
        deskinfo_page[0x18..0x20].copy_from_slice(&hook_vaddr.to_le_bytes());
        // aphkStart[1..15] = 0 (no other hooks)

        // hook_page:
        //   iHook (offset 0x00, u32): 13 = WH_KEYBOARD_LL
        //   offPfn (offset 0x08, u64): hook_proc_addr
        //   ihmod (offset 0x10, u64): 0 (≤ 0xFFFF → module_name = "")
        //   phkNext (offset 0x18, u64): 0 (chain ends)
        //   ptiHooked (offset 0x28, u64): 0 (owner_pid = 0)
        let mut hook_page = vec![0u8; 4096];
        hook_page[0x00..0x04].copy_from_slice(&13u32.to_le_bytes()); // WH_KEYBOARD_LL
        hook_page[0x08..0x10].copy_from_slice(&hook_proc_addr.to_le_bytes());
        hook_page[0x10..0x18].copy_from_slice(&0u64.to_le_bytes()); // ihmod=0
        hook_page[0x18..0x20].copy_from_slice(&0u64.to_le_bytes()); // phkNext=null
        hook_page[0x28..0x30].copy_from_slice(&0u64.to_le_bytes()); // ptiHooked=null

        let isf = IsfBuilder::new()
            .add_struct("_HOOK", 0x80)
            .add_symbol("grpWinStaList", sym_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sym_vaddr, sym_paddr, flags::WRITABLE)
            .map_4k(winsta_vaddr, winsta_paddr, flags::WRITABLE)
            .map_4k(desktop_vaddr, desktop_paddr, flags::WRITABLE)
            .map_4k(deskinfo_vaddr, deskinfo_paddr, flags::WRITABLE)
            .map_4k(hook_vaddr, hook_paddr, flags::WRITABLE)
            .write_phys(sym_paddr, &sym_page)
            .write_phys(winsta_paddr, &winsta_page)
            .write_phys(desktop_paddr, &desktop_page)
            .write_phys(deskinfo_paddr, &deskinfo_page)
            .write_phys(hook_paddr, &hook_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let hooks = walk_message_hooks(&reader).unwrap();
        assert_eq!(hooks.len(), 1, "expected exactly 1 hook, got {}", hooks.len());
        let h = &hooks[0];
        assert_eq!(h.address, hook_vaddr, "hook address mismatch");
        assert_eq!(h.hook_type, "WH_KEYBOARD_LL", "hook type mismatch");
        assert_eq!(h.hook_proc_addr, hook_proc_addr, "hook proc addr mismatch");
        assert_eq!(h.owner_pid, 0, "owner_pid should be 0 (null ptiHooked)");
        // Empty module name → suspicious
        assert!(h.is_suspicious, "WH_KEYBOARD_LL with empty module should be suspicious");
    }

    /// extract_pid_from_threadinfo: ethread non-null, eprocess non-null, PID reads ok.
    /// Verifies the full chain when ethread ptr returned is valid but ThreadsProcess = 0.
    #[test]
    fn extract_pid_zero_eprocess_returns_zero() {
        let threadinfo_vaddr: u64 = 0xFFFF_8000_6000_0000;
        let threadinfo_paddr: u64 = 0x0060_0000;
        let ethread_vaddr: u64 = 0xFFFF_8000_6100_0000;
        let ethread_paddr: u64 = 0x0061_0000;

        // threadinfo: at +0 → ethread_vaddr
        let mut threadinfo_page = vec![0u8; 4096];
        threadinfo_page[0..8].copy_from_slice(&ethread_vaddr.to_le_bytes());

        // ethread: at +0x08 → 0 (eprocess = null)
        let mut ethread_page = vec![0u8; 4096];
        ethread_page[0x08..0x10].copy_from_slice(&0u64.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(threadinfo_vaddr, threadinfo_paddr, flags::WRITABLE)
            .map_4k(ethread_vaddr, ethread_paddr, flags::WRITABLE)
            .write_phys(threadinfo_paddr, &threadinfo_page)
            .write_phys(ethread_paddr, &ethread_page)
            .build();

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let pid = extract_pid_from_threadinfo(&reader, threadinfo_vaddr, 0, 0x08, 0x10);
        assert_eq!(pid, 0, "null eprocess → 0");
    }
}
