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
    // WH_MSGFILTER = -1 (0xFFFFFFFF), WH_MIN = 0, ..., WH_MOUSE_LL = 14
    // No entry for type 8 (reserved/not defined in standard headers)
    match raw {
        0xFFFF_FFFF => "WH_MSGFILTER".to_string(),
        0  => "WH_JOURNALRECORD".to_string(),
        1  => "WH_JOURNALPLAYBACK".to_string(),
        2  => "WH_KEYBOARD".to_string(),
        3  => "WH_GETMESSAGE".to_string(),
        4  => "WH_CALLWNDPROC".to_string(),
        5  => "WH_CBT".to_string(),
        6  => "WH_SYSMSGFILTER".to_string(),
        7  => "WH_MOUSE".to_string(),
        9  => "WH_DEBUG".to_string(),
        10 => "WH_SHELL".to_string(),
        11 => "WH_FOREGROUNDIDLE".to_string(),
        12 => "WH_CALLWNDPROCRET".to_string(),
        13 => "WH_KEYBOARD_LL".to_string(),
        14 => "WH_MOUSE_LL".to_string(),
        n  => format!("WH_UNKNOWN({n})"),
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
    const BENIGN_MODULES: &[&str] = &["user32.dll", "imm32.dll", "msctf.dll"];

    if module.is_empty() {
        return true;
    }

    let lower_module = module.to_lowercase();

    // Any hook from temp/appdata/downloads is suspicious regardless of type
    if lower_module.contains("\\temp\\")
        || lower_module.contains("\\appdata\\")
        || lower_module.contains("\\downloads\\")
    {
        return true;
    }

    // Check if module ends with a known benign module name
    let is_benign_module = BENIGN_MODULES
        .iter()
        .any(|&m| lower_module.ends_with(m));

    if is_benign_module {
        return false;
    }

    // WH_KEYBOARD_LL or WH_MOUSE_LL from non-system modules is suspicious
    if hook_type == "WH_KEYBOARD_LL" || hook_type == "WH_MOUSE_LL" {
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
    let list_sym = reader.symbols().symbol_address("grpWinStaList");
    let Some(list_sym) = list_sym else {
        return Ok(Vec::new());
    };

    // Read the first winsta pointer from the symbol
    let first_ws: u64 = match reader.read_bytes(list_sym, 8) {
        Ok(b) => u64::from_le_bytes(b[..8].try_into().unwrap()),
        Err(_) => return Ok(Vec::new()),
    };
    if first_ws == 0 {
        return Ok(Vec::new());
    }

    // Field offsets for _WINSTATION_OBJECT
    let ws_next_off = reader
        .symbols()
        .field_offset("_WINSTATION_OBJECT", "rpwinstaNext")
        .unwrap_or(0x28) as u64;
    let ws_desk_off = reader
        .symbols()
        .field_offset("_WINSTATION_OBJECT", "rpdeskList")
        .unwrap_or(0x30) as u64;

    // Field offsets for tagDESKTOP
    let desk_next_off = reader
        .symbols()
        .field_offset("tagDESKTOP", "rpdeskNext")
        .unwrap_or(0x28) as u64;
    let desk_aphk_off = reader
        .symbols()
        .field_offset("tagDESKTOP", "aphkStart")
        .unwrap_or(0x38) as u64;

    // Field offsets for _HOOK
    let hook_next_off  = reader.symbols().field_offset("_HOOK", "phkNext").unwrap_or(0x00) as u64;
    let hook_type_off  = reader.symbols().field_offset("_HOOK", "iHook").unwrap_or(0x08) as u64;
    let hook_proc_off  = reader.symbols().field_offset("_HOOK", "pfn").unwrap_or(0x10) as u64;
    let hook_ihmod_off = reader.symbols().field_offset("_HOOK", "ihmod").unwrap_or(0x18) as u64;
    let hook_pti_off   = reader.symbols().field_offset("_HOOK", "pti").unwrap_or(0x20) as u64;

    // Field offsets for PID chain from tagTHREADINFO
    let threadinfo_eprocess_off = reader
        .symbols()
        .field_offset("tagTHREADINFO", "pEThread")
        .unwrap_or(0x00) as u64;
    let ethread_process_off = reader
        .symbols()
        .field_offset("_ETHREAD", "ThreadsProcess")
        .unwrap_or(0x220) as u64;
    let pid_off = reader
        .symbols()
        .field_offset("_EPROCESS", "UniqueProcessId")
        .unwrap_or(0x440) as u64;

    let mut results = Vec::new();
    let mut hook_count = 0usize;

    let mut ws_addr = first_ws;
    while ws_addr != 0 {
        // Walk desktops of this station
        let first_desk: u64 = match reader.read_bytes(ws_addr + ws_desk_off, 8) {
            Ok(b) => u64::from_le_bytes(b[..8].try_into().unwrap()),
            Err(_) => 0,
        };

        let mut desk_addr = first_desk;
        while desk_addr != 0 {
            // Walk aphkStart array
            for i in 0..HOOK_TYPE_COUNT {
                let slot_addr = desk_addr + desk_aphk_off + i as u64 * 8;
                let head_hook: u64 = match reader.read_bytes(slot_addr, 8) {
                    Ok(b) => u64::from_le_bytes(b[..8].try_into().unwrap()),
                    Err(_) => 0,
                };

                let mut hook_addr = head_hook;
                let mut seen = std::collections::HashSet::new();
                while hook_addr != 0 && hook_count < MAX_HOOKS {
                    if !seen.insert(hook_addr) {
                        break;
                    }
                    hook_count += 1;

                    // Read hook type
                    let i_hook_raw: u32 = reader
                        .read_bytes(hook_addr + hook_type_off, 4)
                        .map(|b| u32::from_le_bytes(b[..4].try_into().unwrap()))
                        .unwrap_or(0xFFFF_FFFF);
                    let hook_type = hook_type_name(i_hook_raw);

                    // Read proc address
                    let hook_proc_addr: u64 = reader
                        .read_bytes(hook_addr + hook_proc_off, 8)
                        .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap()))
                        .unwrap_or(0);

                    // Read ihmod to determine module origin (<=0xFFFF → injected/unknown)
                    let ihmod: i32 = reader
                        .read_bytes(hook_addr + hook_ihmod_off, 4)
                        .map(|b| i32::from_le_bytes(b[..4].try_into().unwrap()))
                        .unwrap_or(-1);
                    let module_name = if ihmod > 0 {
                        // Try to read module name via _UNICODE_STRING at ihmod offset
                        let uni_addr = hook_addr + hook_ihmod_off + 8;
                        read_unicode_string(reader, uni_addr).unwrap_or_default()
                    } else {
                        String::new()
                    };

                    // Extract owner PID via tagTHREADINFO chain
                    let pti: u64 = reader
                        .read_bytes(hook_addr + hook_pti_off, 8)
                        .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap()))
                        .unwrap_or(0);
                    let owner_pid = extract_pid_from_threadinfo(
                        reader,
                        pti,
                        threadinfo_eprocess_off,
                        ethread_process_off,
                        pid_off,
                    );

                    let is_suspicious = classify_message_hook(&hook_type, &module_name);
                    results.push(MessageHookInfo {
                        address: hook_addr,
                        hook_type,
                        owner_pid,
                        hook_proc_addr,
                        module_name,
                        is_suspicious,
                    });

                    // Follow phkNext
                    hook_addr = match reader.read_bytes(hook_addr + hook_next_off, 8) {
                        Ok(b) => u64::from_le_bytes(b[..8].try_into().unwrap()),
                        Err(_) => 0,
                    };
                }
            }

            // Next desktop
            desk_addr = match reader.read_bytes(desk_addr + desk_next_off, 8) {
                Ok(b) => u64::from_le_bytes(b[..8].try_into().unwrap()),
                Err(_) => 0,
            };
        }

        // Next window station
        ws_addr = match reader.read_bytes(ws_addr + ws_next_off, 8) {
            Ok(b) => u64::from_le_bytes(b[..8].try_into().unwrap()),
            Err(_) => 0,
        };
    }

    Ok(results)
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
    if threadinfo_addr == 0 {
        return 0;
    }
    let ethread: u64 = reader
        .read_bytes(threadinfo_addr + threadinfo_eprocess_off, 8)
        .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap()))
        .unwrap_or(0);
    if ethread == 0 {
        return 0;
    }
    let eprocess: u64 = reader
        .read_bytes(ethread + ethread_process_off, 8)
        .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap()))
        .unwrap_or(0);
    if eprocess == 0 {
        return 0;
    }
    reader
        .read_bytes(eprocess + pid_off, 8)
        .map(|b| u64::from_le_bytes(b[..8].try_into().unwrap()) as u32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ── classify_message_hook tests ──────────────────────────────────────

    /// WH_KEYBOARD_LL from a custom DLL is suspicious.
    #[test]
    fn classify_keyboard_ll_custom_dll_suspicious() {
        assert!(classify_message_hook("WH_KEYBOARD_LL", "evil_logger.dll"));
    }

    /// WH_KEYBOARD_LL from user32.dll is benign.
    #[test]
    fn classify_keyboard_ll_user32_benign() {
        assert!(!classify_message_hook("WH_KEYBOARD_LL", "user32.dll"));
    }

    /// WH_MOUSE_LL from a temp directory is suspicious.
    #[test]
    fn classify_mouse_ll_temp_dir_suspicious() {
        assert!(classify_message_hook("WH_MOUSE_LL", r"C:\Users\user\AppData\Local\Temp\payload.dll"));
    }

    /// WH_CBT from a known system module (msctf.dll) is benign.
    #[test]
    fn classify_cbt_system_module_benign() {
        assert!(!classify_message_hook("WH_CBT", "msctf.dll"));
    }

    /// Any hook from an AppData path is suspicious.
    #[test]
    fn classify_any_hook_appdata_suspicious() {
        assert!(classify_message_hook("WH_CBT", r"C:\Users\user\AppData\Roaming\mal.dll"));
    }

    /// Empty module name is suspicious (unknown origin).
    #[test]
    fn classify_empty_module_suspicious() {
        assert!(classify_message_hook("WH_CBT", ""));
    }

    // ── hook_type_name tests ─────────────────────────────────────────────

    /// Known hook type values map to correct symbolic names.
    #[test]
    fn hook_type_name_known_values() {
        assert_eq!(hook_type_name(0xFFFF_FFFF), "WH_MSGFILTER");
        assert_eq!(hook_type_name(2), "WH_KEYBOARD");
        assert_eq!(hook_type_name(13), "WH_KEYBOARD_LL");
        assert_eq!(hook_type_name(14), "WH_MOUSE_LL");
        assert_eq!(hook_type_name(10), "WH_SHELL");
    }

    // ── hook_type_name edge cases ────────────────────────────────────────

    /// hook_type 8 has no entry and returns WH_UNKNOWN(8).
    #[test]
    fn hook_type_name_missing_8() {
        assert_eq!(hook_type_name(8), "WH_UNKNOWN(8)");
    }

    /// Very large raw type value returns WH_UNKNOWN.
    #[test]
    fn hook_type_name_large_value() {
        assert!(hook_type_name(999).starts_with("WH_UNKNOWN("));
    }

    // ── classify_message_hook additional coverage ────────────────────────

    /// WH_MOUSE_LL from a known system module is benign.
    #[test]
    fn classify_mouse_ll_user32_benign() {
        assert!(!classify_message_hook("WH_MOUSE_LL", "user32.dll"));
    }

    /// WH_GETMESSAGE from an unrelated custom DLL is not suspicious
    /// (only LL hooks are flagged from non-system modules).
    #[test]
    fn classify_getmessage_custom_dll_benign() {
        assert!(!classify_message_hook("WH_GETMESSAGE", "custom.dll"));
    }

    /// Module path with \\downloads\\ is suspicious regardless of hook type.
    #[test]
    fn classify_downloads_path_suspicious() {
        assert!(classify_message_hook("WH_GETMESSAGE", r"C:\Users\user\Downloads\hook.dll"));
    }

    /// Module name that ends with a system module name (path-qualified) is benign.
    #[test]
    fn classify_path_qualified_system_module_benign() {
        assert!(!classify_message_hook("WH_KEYBOARD_LL", r"C:\Windows\System32\user32.dll"));
    }

    // ── walk_message_hooks tests ─────────────────────────────────────────

    fn make_empty_hooks_reader() -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("_WINSTATION_OBJECT", 64)
            .add_field("_WINSTATION_OBJECT", "rpwinstaNext", 0x28, "pointer")
            .add_field("_WINSTATION_OBJECT", "rpdeskList", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// No grpWinStaList symbol present → returns empty Vec.
    #[test]
    fn walk_message_hooks_no_symbol() {
        let reader = make_empty_hooks_reader();
        let result = walk_message_hooks(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// Walker with grpWinStaList symbol but unreadable memory returns empty.
    #[test]
    fn walk_message_hooks_unreadable_winsta_list() {
        let isf = IsfBuilder::new()
            .add_struct("_WINSTATION_OBJECT", 64)
            .add_symbol("grpWinStaList", 0xFFFF_8000_0099_0000)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_message_hooks(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// Walker with grpWinStaList pointing to zero first_winsta returns empty.
    #[test]
    fn walk_message_hooks_zero_first_winsta() {
        const SYM_VADDR: u64 = 0xFFFF_8000_0098_0000;
        const SYM_PADDR: u64 = 0x0098_0000;
        let isf = IsfBuilder::new()
            .add_struct("_WINSTATION_OBJECT", 64)
            .add_symbol("grpWinStaList", SYM_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&0u64.to_le_bytes()); // first_ws = 0
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(SYM_VADDR, SYM_PADDR, flags::WRITABLE)
            .write_phys(SYM_PADDR, &sym_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_message_hooks(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// walker with grpWinStaList → non-zero winsta → zero desktop list → empty.
    #[test]
    fn walk_message_hooks_nonzero_winsta_zero_desktop() {
        const SYM_VADDR: u64 = 0xFFFF_8000_0097_0000;
        const SYM_PADDR: u64 = 0x0097_0000;
        const WS_VADDR:  u64 = 0xFFFF_8000_0096_0000;
        const WS_PADDR:  u64 = 0x0096_0000;

        let isf = IsfBuilder::new()
            .add_struct("_WINSTATION_OBJECT", 64)
            .add_field("_WINSTATION_OBJECT", "rpwinstaNext", 0x28, "pointer")
            .add_field("_WINSTATION_OBJECT", "rpdeskList", 0x30, "pointer")
            .add_symbol("grpWinStaList", SYM_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&WS_VADDR.to_le_bytes());

        let mut ws_page = vec![0u8; 4096];
        // rpwinstaNext = 0 (stop), rpdeskList = 0 (no desktops)
        ws_page[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
        ws_page[0x30..0x38].copy_from_slice(&0u64.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(SYM_VADDR, SYM_PADDR, flags::WRITABLE)
            .write_phys(SYM_PADDR, &sym_page)
            .map_4k(WS_VADDR, WS_PADDR, flags::WRITABLE)
            .write_phys(WS_PADDR, &ws_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_message_hooks(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// classify: WH_SHELL from downloads path is suspicious.
    #[test]
    fn classify_shell_hook_downloads_suspicious() {
        assert!(classify_message_hook("WH_SHELL", r"C:\Users\user\Downloads\shell_hook.dll"));
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
        assert!(!classify_message_hook("WH_KEYBOARD_LL", r"C:\Windows\System32\imm32.dll"));
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
        assert!(MAX_HOOKS >= 256);
    }

    /// MessageHookInfo serializes to JSON.
    #[test]
    fn message_hook_info_serializes() {
        let info = MessageHookInfo {
            address: 0xDEAD_BEEF,
            hook_type: "WH_KEYBOARD_LL".to_string(),
            owner_pid: 1234,
            hook_proc_addr: 0x1000,
            module_name: "evil.dll".to_string(),
            is_suspicious: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("WH_KEYBOARD_LL"));
        assert!(json.contains("evil.dll"));
        assert!(json.contains("1234"));
    }

    /// extract_pid_from_threadinfo: ethread_ptr == 0 → returns 0.
    #[test]
    fn extract_pid_zero_ethread_returns_zero() {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        // threadinfo_addr=0 → returns 0
        let pid = extract_pid_from_threadinfo(&reader, 0, 0, 0, 0);
        assert_eq!(pid, 0);
    }

    /// extract_pid_from_threadinfo: ethread reads ok (non-zero), eprocess reads ok,
    /// PID reads ok → returns correct PID.
    #[test]
    fn extract_pid_from_threadinfo_valid_chain() {
        const TI_VADDR:  u64 = 0xFFFF_8000_0094_0000;
        const TI_PADDR:  u64 = 0x0094_0000;
        const ETH_VADDR: u64 = 0xFFFF_8000_0093_0000;
        const ETH_PADDR: u64 = 0x0093_0000;
        const EPS_VADDR: u64 = 0xFFFF_8000_0092_0000;
        const EPS_PADDR: u64 = 0x0092_0000;

        // threadinfo_eprocess_off = 0, ethread_process_off = 0x10, pid_off = 0x20
        let mut ti_page = vec![0u8; 4096];
        ti_page[0..8].copy_from_slice(&ETH_VADDR.to_le_bytes());

        let mut eth_page = vec![0u8; 4096];
        eth_page[0x10..0x18].copy_from_slice(&EPS_VADDR.to_le_bytes());

        let mut eps_page = vec![0u8; 4096];
        eps_page[0x20..0x28].copy_from_slice(&0x4567u64.to_le_bytes());

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(TI_VADDR, TI_PADDR, flags::WRITABLE)
            .write_phys(TI_PADDR, &ti_page)
            .map_4k(ETH_VADDR, ETH_PADDR, flags::WRITABLE)
            .write_phys(ETH_PADDR, &eth_page)
            .map_4k(EPS_VADDR, EPS_PADDR, flags::WRITABLE)
            .write_phys(EPS_PADDR, &eps_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let pid = extract_pid_from_threadinfo(&reader, TI_VADDR, 0, 0x10, 0x20);
        assert_eq!(pid, 0x4567);
    }

    /// walker: winsta → desktop → deskinfo → one hook in aphkStart[0] → one hook returned.
    ///
    /// This exercises the inner aphk loop, hook chain traversal, and hook field reads.
    /// The hook has ihmod <= 0xFFFF so module_name = "" → classify_message_hook → suspicious.
    #[test]
    fn walk_message_hooks_one_hook_inner_loop() {
        const SYM_VADDR:  u64 = 0xFFFF_8000_0090_0000;
        const SYM_PADDR:  u64 = 0x0090_0000;
        const WS_VADDR:   u64 = 0xFFFF_8000_0091_0000;
        const WS_PADDR:   u64 = 0x0091_0000;
        const DESK_VADDR: u64 = 0xFFFF_8000_0092_0000;
        const DESK_PADDR: u64 = 0x0092_0000;
        const HOOK_VADDR: u64 = 0xFFFF_8000_0093_0000;
        const HOOK_PADDR: u64 = 0x0093_0000;

        // aphkStart offset = 0x38, phkNext=0, iHook=0x08, pfn=0x10, ihmod=0x18, pti=0x20
        let isf = IsfBuilder::new()
            .add_struct("_WINSTATION_OBJECT", 64)
            .add_field("_WINSTATION_OBJECT", "rpwinstaNext", 0x28, "pointer")
            .add_field("_WINSTATION_OBJECT", "rpdeskList", 0x30, "pointer")
            .add_struct("tagDESKTOP", 256)
            .add_field("tagDESKTOP", "rpdeskNext", 0x28, "pointer")
            .add_field("tagDESKTOP", "aphkStart", 0x38, "pointer")
            .add_struct("_HOOK", 64)
            .add_field("_HOOK", "phkNext", 0x00, "pointer")
            .add_field("_HOOK", "iHook", 0x08, "unsigned long")
            .add_field("_HOOK", "pfn", 0x10, "pointer")
            .add_field("_HOOK", "ihmod", 0x18, "long")
            .add_field("_HOOK", "pti", 0x20, "pointer")
            .add_symbol("grpWinStaList", SYM_VADDR)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let mut sym_page = vec![0u8; 4096];
        sym_page[0..8].copy_from_slice(&WS_VADDR.to_le_bytes());

        let mut ws_page = vec![0u8; 4096];
        ws_page[0x28..0x30].copy_from_slice(&0u64.to_le_bytes()); // rpwinstaNext = 0
        ws_page[0x30..0x38].copy_from_slice(&DESK_VADDR.to_le_bytes()); // rpdeskList

        let mut desk_page = vec![0u8; 4096];
        desk_page[0x28..0x30].copy_from_slice(&0u64.to_le_bytes()); // rpdeskNext = 0
        // aphkStart[0] = HOOK_VADDR
        desk_page[0x38..0x40].copy_from_slice(&HOOK_VADDR.to_le_bytes());

        let mut hook_page = vec![0u8; 4096];
        hook_page[0x00..0x08].copy_from_slice(&0u64.to_le_bytes()); // phkNext = 0 (end)
        hook_page[0x08..0x0c].copy_from_slice(&13u32.to_le_bytes()); // iHook = WH_KEYBOARD_LL
        hook_page[0x10..0x18].copy_from_slice(&0xDEAD_BEEFu64.to_le_bytes()); // pfn
        hook_page[0x18..0x1c].copy_from_slice(&(-1i32).to_le_bytes()); // ihmod = -1 → no module
        hook_page[0x20..0x28].copy_from_slice(&0u64.to_le_bytes()); // pti = 0

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(SYM_VADDR, SYM_PADDR, flags::WRITABLE)
            .write_phys(SYM_PADDR, &sym_page)
            .map_4k(WS_VADDR, WS_PADDR, flags::WRITABLE)
            .write_phys(WS_PADDR, &ws_page)
            .map_4k(DESK_VADDR, DESK_PADDR, flags::WRITABLE)
            .write_phys(DESK_PADDR, &desk_page)
            .map_4k(HOOK_VADDR, HOOK_PADDR, flags::WRITABLE)
            .write_phys(HOOK_PADDR, &hook_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let hooks = walk_message_hooks(&reader).unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].hook_type, "WH_KEYBOARD_LL");
        assert_eq!(hooks[0].hook_proc_addr, 0xDEAD_BEEF);
        assert!(hooks[0].is_suspicious); // empty module → suspicious
    }

    /// extract_pid_from_threadinfo: ethread non-null, eprocess non-null, PID reads ok.
    /// Verifies the full chain when ethread ptr returned is valid but ThreadsProcess = 0.
    #[test]
    fn extract_pid_zero_eprocess_returns_zero() {
        const TI_VADDR: u64 = 0xFFFF_8000_0088_0000;
        const TI_PADDR: u64 = 0x0088_0000;
        const ET_VADDR: u64 = 0xFFFF_8000_0087_0000;
        const ET_PADDR: u64 = 0x0087_0000;

        // ethread.ThreadsProcess = 0 at offset 0x10
        let mut ti_page = vec![0u8; 4096];
        ti_page[0..8].copy_from_slice(&ET_VADDR.to_le_bytes()); // pEThread at off 0

        let mut et_page = vec![0u8; 4096];
        et_page[0x10..0x18].copy_from_slice(&0u64.to_le_bytes()); // ThreadsProcess = 0

        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(TI_VADDR, TI_PADDR, flags::WRITABLE)
            .write_phys(TI_PADDR, &ti_page)
            .map_4k(ET_VADDR, ET_PADDR, flags::WRITABLE)
            .write_phys(ET_PADDR, &et_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let pid = extract_pid_from_threadinfo(&reader, TI_VADDR, 0, 0x10, 0x20);
        assert_eq!(pid, 0);
    }
}
