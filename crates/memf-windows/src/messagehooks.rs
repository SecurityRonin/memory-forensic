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
    const SUSPICIOUS_PATHS: &[&str] = &[
        "\\temp\\",
        "\\appdata\\",
        "\\downloads\\",
    ];

    for path in SUSPICIOUS_PATHS {
        if lower_module.contains(path) {
            return true;
        }
    }

    // Known benign Windows system modules that commonly install hooks.
    const BENIGN_MODULES: &[&str] = &[
        "user32.dll",
        "imm32.dll",
        "msctf.dll",
    ];

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
                Ok(bytes) if bytes.len() == 8 => {
                    u64::from_le_bytes(bytes[..8].try_into().unwrap())
                }
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
                        let raw_type: u32 =
                            match reader.read_bytes(hook_addr + hook_ihook_off, 4) {
                                Ok(bytes) if bytes.len() == 4 => {
                                    u32::from_le_bytes(bytes[..4].try_into().unwrap())
                                }
                                _ => idx as u32,
                            };

                        let hook_type = hook_type_name(raw_type);

                        // Read offPfn (hook procedure address).
                        let hook_proc_addr =
                            match reader.read_bytes(hook_addr + hook_offpfn_off, 8) {
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
                                let mod_ptr =
                                    u64::from_le_bytes(bytes[..8].try_into().unwrap());
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
                        let owner_pid =
                            match reader.read_bytes(hook_addr + hook_ptihooked_off, 8) {
                                Ok(bytes) if bytes.len() == 8 => {
                                    let ti_ptr =
                                        u64::from_le_bytes(bytes[..8].try_into().unwrap());
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
                Ok(bytes) if bytes.len() == 8 => {
                    u64::from_le_bytes(bytes[..8].try_into().unwrap())
                }
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
        Ok(bytes) if bytes.len() == 8 => {
            u64::from_le_bytes(bytes[..8].try_into().unwrap()) as u32
        }
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

    // ── walk_message_hooks tests ─────────────────────────────────────────

    /// No grpWinStaList symbol present → returns empty Vec.
    #[test]
    fn walk_message_hooks_no_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("_HOOK", 0x80)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_message_hooks(&reader).unwrap();
        assert!(result.is_empty());
    }
}
