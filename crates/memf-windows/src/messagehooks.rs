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
    todo!()
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
