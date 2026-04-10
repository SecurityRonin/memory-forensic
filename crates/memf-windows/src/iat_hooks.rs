//! Import Address Table (IAT) hook detection.
//!
//! Detects IAT hooking where malware patches the Import Address Table of a
//! DLL/EXE to redirect API calls. Each IAT entry should point into the target
//! DLL's address range. If it points elsewhere (especially to RWX memory or
//! unknown modules), it is a hook.
//!
//! MITRE ATT&CK: T1056 / T1547

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{dll, Result};

/// Maximum number of hooks to collect per process before stopping.
const MAX_HOOKS: usize = 4096;

/// Maximum number of import descriptors to parse per module.
const MAX_IMPORT_DESCRIPTORS: usize = 1024;

/// Maximum number of thunk entries per import descriptor.
const MAX_THUNKS: usize = 8192;

/// Information about a single detected IAT hook.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IatHookInfo {
    /// Process ID owning the hooked module.
    pub pid: u32,
    /// Process name from `_EPROCESS.ImageFileName`.
    pub process_name: String,
    /// Module whose IAT was patched (e.g. `"ntdll.dll"`).
    pub hooked_module: String,
    /// Imported function name that was hooked (e.g. `"NtCreateFile"`).
    pub hooked_function: String,
    /// Virtual address of the IAT slot that was patched.
    pub iat_address: u64,
    /// Name of the DLL that *should* service this import.
    pub original_target: String,
    /// Address the IAT slot actually points to (the hook destination).
    pub hook_target: u64,
    /// Module name that contains `hook_target`, or `""` if unknown.
    pub hook_module: String,
    /// Whether this hook is considered suspicious.
    pub is_suspicious: bool,
}

/// Classify whether an IAT entry is suspicious.
///
/// An entry is suspicious if:
/// - `hook_target` falls outside the expected module's address range, **or**
/// - `hook_module` is empty or `"unknown"` (unresolvable destination).
///
/// A zero `hook_target` is **not** suspicious -- it indicates a NULL /
/// not-yet-resolved import thunk and is common for delay-loaded DLLs.
pub fn classify_iat_hook(
    hook_target: u64,
    expected_module_base: u64,
    expected_module_size: u32,
    hook_module: &str,
) -> bool {
    if hook_target == 0 {
        return false;
    }

    let end = expected_module_base.saturating_add(u64::from(expected_module_size));

    if hook_target < expected_module_base || hook_target >= end {
        return true;
    }

    let normalized = hook_module.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized == "unknown" {
        return true;
    }

    false
}

/// Walk the IAT of all loaded DLLs for a given process and detect hooks.
///
/// `eprocess_addr` is the virtual address of the `_EPROCESS` structure.
/// The function switches to the process address space (via
/// `_KPROCESS.DirectoryTableBase`) and walks
/// `PEB -> PEB_LDR_DATA -> InLoadOrderModuleList`. For each DLL it parses
/// the PE Import Directory and compares each IAT entry against the expected
/// target DLL's address range.
///
/// Returns a vector of [`IatHookInfo`] for every detected hook.
/// At most [`MAX_HOOKS`] entries are returned per process.
pub fn walk_iat_hooks<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
    eprocess_addr: u64,
    pid: u32,
    process_name: &str,
) -> Result<Vec<IatHookInfo>> {
    let peb_addr: u64 = reader.read_field(eprocess_addr, "_EPROCESS", "Peb")?;
    if peb_addr == 0 {
        return Ok(Vec::new());
    }

    let cr3: u64 = reader.read_field(eprocess_addr, "_KPROCESS", "DirectoryTableBase")?;
    if cr3 == 0 {
        return Ok(Vec::new());
    }
    let proc_reader = reader.with_cr3(cr3);

    let dlls = match dll::walk_dlls(&proc_reader, peb_addr) {
        Ok(d) => d,
        Err(_) => return Ok(Vec::new()),
    };

    let module_ranges: Vec<(u64, u64, String)> = dlls
        .iter()
        .filter(|d| d.base_addr != 0 && d.size != 0)
        .map(|d| {
            (
                d.base_addr,
                d.base_addr.saturating_add(d.size),
                d.name.clone(),
            )
        })
        .collect();

    let mut hooks = Vec::new();

    for dll_info in &dlls {
        if dll_info.base_addr == 0 {
            continue;
        }
        if hooks.len() >= MAX_HOOKS {
            break;
        }

        let module_hooks = parse_module_imports(
            &proc_reader,
            dll_info.base_addr,
            &dll_info.name,
            &module_ranges,
            pid,
            process_name,
            MAX_HOOKS.saturating_sub(hooks.len()),
        );
        hooks.extend(module_hooks);
    }

    hooks.truncate(MAX_HOOKS);
    Ok(hooks)
}

fn resolve_module(addr: u64, module_ranges: &[(u64, u64, String)]) -> String {
    for (base, end, name) in module_ranges {
        if addr >= *base && addr < *end {
            return name.clone();
        }
    }
    String::new()
}

fn find_module_range(name: &str, module_ranges: &[(u64, u64, String)]) -> Option<(u64, u32)> {
    let lower = name.trim().to_ascii_lowercase();
    for (base, end, mod_name) in module_ranges {
        if mod_name.to_ascii_lowercase() == lower {
            let size = end.saturating_sub(*base);
            return Some((*base, size as u32));
        }
    }
    None
}

fn read_ascii_string<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, vaddr: u64) -> String {
    match reader.read_bytes(vaddr, 256) {
        Ok(bytes) => {
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            String::from_utf8_lossy(&bytes[..end]).into_owned()
        }
        Err(_) => String::new(),
    }
}

fn le_u16(buf: &[u8], off: usize) -> u16 {
    if off + 2 > buf.len() {
        return 0;
    }
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn le_u32(buf: &[u8], off: usize) -> u32 {
    if off + 4 > buf.len() {
        return 0;
    }
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn le_u64(buf: &[u8], off: usize) -> u64 {
    if off + 8 > buf.len() {
        return 0;
    }
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

#[allow(clippy::too_many_arguments)]
fn parse_module_imports<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    image_base: u64,
    module_name: &str,
    module_ranges: &[(u64, u64, String)],
    pid: u32,
    process_name: &str,
    remaining: usize,
) -> Vec<IatHookInfo> {
    let Ok(header) = reader.read_bytes(image_base, 1024) else {
        return Vec::new();
    };

    if header.len() < 0x40 || header[0] != 0x4D || header[1] != 0x5A {
        return Vec::new();
    }

    let e_lfanew = le_u32(&header, 0x3C) as usize;
    if e_lfanew == 0 || e_lfanew + 4 > header.len() {
        return Vec::new();
    }

    if header.get(e_lfanew) != Some(&b'P')
        || header.get(e_lfanew + 1) != Some(&b'E')
        || header.get(e_lfanew + 2) != Some(&0)
        || header.get(e_lfanew + 3) != Some(&0)
    {
        return Vec::new();
    }

    let coff_off = e_lfanew + 4;
    if coff_off + 20 > header.len() {
        return Vec::new();
    }

    let opt_off = coff_off + 20;
    if opt_off + 2 > header.len() {
        return Vec::new();
    }

    let opt_magic = le_u16(&header, opt_off);
    let is_pe32plus = opt_magic == 0x020B;

    let import_dir_off = if is_pe32plus {
        opt_off + 120
    } else {
        opt_off + 104
    };

    let (import_rva, import_size) = if import_dir_off + 8 <= header.len() {
        (
            le_u32(&header, import_dir_off),
            le_u32(&header, import_dir_off + 4),
        )
    } else {
        let Ok(ext) = reader.read_bytes(image_base + import_dir_off as u64, 8) else {
            return Vec::new();
        };
        if ext.len() < 8 {
            return Vec::new();
        }
        (le_u32(&ext, 0), le_u32(&ext, 4))
    };

    if import_rva == 0 || import_size == 0 {
        return Vec::new();
    }

    parse_import_descriptors(
        reader,
        image_base,
        import_rva,
        import_size,
        is_pe32plus,
        module_name,
        module_ranges,
        pid,
        process_name,
        remaining,
    )
}

#[allow(clippy::too_many_arguments)]
fn parse_import_descriptors<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    image_base: u64,
    import_rva: u32,
    import_size: u32,
    is_pe32plus: bool,
    module_name: &str,
    module_ranges: &[(u64, u64, String)],
    pid: u32,
    process_name: &str,
    remaining: usize,
) -> Vec<IatHookInfo> {
    let mut results = Vec::new();
    let import_vaddr = image_base.wrapping_add(u64::from(import_rva));

    let read_size = (import_size as usize).min(MAX_IMPORT_DESCRIPTORS * 20);
    let Ok(import_data) = reader.read_bytes(import_vaddr, read_size) else {
        return results;
    };

    let thunk_size: usize = if is_pe32plus { 8 } else { 4 };

    let mut desc_off = 0;
    while desc_off + 20 <= import_data.len() {
        if results.len() >= remaining {
            break;
        }

        let ilt_rva = le_u32(&import_data, desc_off);
        let name_rva = le_u32(&import_data, desc_off + 12);
        let iat_rva = le_u32(&import_data, desc_off + 16);

        if ilt_rva == 0 && name_rva == 0 && iat_rva == 0 {
            break;
        }

        desc_off += 20;

        if iat_rva == 0 {
            continue;
        }

        let original_target = if name_rva != 0 {
            read_ascii_string(reader, image_base.wrapping_add(u64::from(name_rva)))
        } else {
            String::new()
        };

        let (expected_base, expected_size) =
            find_module_range(&original_target, module_ranges).unwrap_or((0, 0));

        let ilt_rva_effective = if ilt_rva != 0 { ilt_rva } else { iat_rva };

        let iat_vaddr = image_base.wrapping_add(u64::from(iat_rva));
        let ilt_vaddr = image_base.wrapping_add(u64::from(ilt_rva_effective));

        let max_bytes = MAX_THUNKS * thunk_size;
        let Ok(iat_bytes) = reader.read_bytes(iat_vaddr, max_bytes) else {
            continue;
        };
        let ilt_bytes = if ilt_rva != 0 && ilt_rva != iat_rva {
            reader.read_bytes(ilt_vaddr, max_bytes).ok()
        } else {
            None
        };

        let mut thunk_idx = 0;
        while thunk_idx < MAX_THUNKS {
            if results.len() >= remaining {
                break;
            }

            let byte_off = thunk_idx * thunk_size;
            if byte_off + thunk_size > iat_bytes.len() {
                break;
            }

            let iat_entry = if is_pe32plus {
                le_u64(&iat_bytes, byte_off)
            } else {
                u64::from(le_u32(&iat_bytes, byte_off))
            };

            if iat_entry == 0 {
                break;
            }

            thunk_idx += 1;

            let func_name = read_import_name(
                reader,
                &ilt_bytes,
                byte_off,
                thunk_size,
                is_pe32plus,
                image_base,
            );

            let hook_module_name = resolve_module(iat_entry, module_ranges);

            let is_suspicious = if expected_base != 0 && expected_size != 0 {
                classify_iat_hook(iat_entry, expected_base, expected_size, &hook_module_name)
            } else {
                false
            };

            if is_suspicious {
                results.push(IatHookInfo {
                    pid,
                    process_name: process_name.to_string(),
                    hooked_module: module_name.to_string(),
                    hooked_function: func_name,
                    iat_address: iat_vaddr + byte_off as u64,
                    original_target: original_target.clone(),
                    hook_target: iat_entry,
                    hook_module: hook_module_name,
                    is_suspicious,
                });
            }
        }
    }

    results
}

fn read_import_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ilt_bytes: &Option<Vec<u8>>,
    byte_off: usize,
    thunk_size: usize,
    is_pe32plus: bool,
    image_base: u64,
) -> String {
    let ilt_entry = if let Some(ref ilt) = ilt_bytes {
        if byte_off + thunk_size <= ilt.len() {
            if is_pe32plus {
                le_u64(ilt, byte_off)
            } else {
                u64::from(le_u32(ilt, byte_off))
            }
        } else {
            return String::new();
        }
    } else {
        return String::new();
    };

    if ilt_entry == 0 {
        return String::new();
    }

    let ordinal_flag = if is_pe32plus {
        ilt_entry & (1u64 << 63) != 0
    } else {
        ilt_entry & (1u64 << 31) != 0
    };

    if ordinal_flag {
        let ordinal = (ilt_entry & 0xFFFF) as u16;
        return format!("Ordinal#{ordinal}");
    }

    let name_rva = (ilt_entry & 0x7FFF_FFFF) as u32;

    if name_rva == 0 {
        return String::new();
    }

    let name_vaddr = image_base.wrapping_add(u64::from(name_rva)).wrapping_add(2);
    read_ascii_string(reader, name_vaddr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_target_in_module_benign() {
        let base: u64 = 0x7FF8_0000_0000;
        let size: u32 = 0x10_0000;
        let target = base + 0x1234;
        assert!(
            !classify_iat_hook(target, base, size, "kernel32.dll"),
            "target inside module range should not be suspicious"
        );
    }

    #[test]
    fn classify_target_outside_module_suspicious() {
        let base: u64 = 0x7FF8_0000_0000;
        let size: u32 = 0x10_0000;
        let target = base + u64::from(size) + 0x1000;
        assert!(
            classify_iat_hook(target, base, size, "kernel32.dll"),
            "target outside module range should be suspicious"
        );
    }

    #[test]
    fn classify_unknown_hook_module_suspicious() {
        let base: u64 = 0x7FF8_0000_0000;
        let size: u32 = 0x10_0000;
        let target = base + 0x500;
        assert!(
            classify_iat_hook(target, base, size, ""),
            "empty hook_module should be suspicious even if target is in range"
        );
        assert!(
            classify_iat_hook(target, base, size, "unknown"),
            "hook_module 'unknown' should be suspicious"
        );
    }

    #[test]
    fn classify_zero_target_benign() {
        let base: u64 = 0x7FF8_0000_0000;
        let size: u32 = 0x10_0000;
        assert!(
            !classify_iat_hook(0, base, size, ""),
            "zero hook target should not be suspicious (delay-load)"
        );
    }

    #[test]
    fn walk_no_peb_returns_empty() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let eproc_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let eproc_paddr: u64 = 0x0090_0000;

        let mut eproc_data = vec![0u8; 8192];
        eproc_data[0x28..0x30].copy_from_slice(&0x1AB000u64.to_le_bytes());
        eproc_data[0x550..0x558].copy_from_slice(&0u64.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr + 0x1000, eproc_paddr + 0x1000, flags::WRITABLE)
            .write_phys(eproc_paddr, &eproc_data[..4096])
            .write_phys(eproc_paddr + 0x1000, &eproc_data[4096..])
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_iat_hooks(&reader, eproc_vaddr, 4, "System").unwrap();
        assert!(
            results.is_empty(),
            "process with no PEB should return empty hook list"
        );
    }

    /// Walk body: PEB is non-zero but CR3 (DirectoryTableBase) is 0 → returns empty.
    /// This exercises the cr3 == 0 guard in the walk body.
    #[test]
    fn walk_iat_hooks_nonzero_peb_zero_cr3_empty() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let eproc_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let eproc_paddr: u64 = 0x0070_0000;

        let mut eproc_data = vec![0u8; 8192];
        // _EPROCESS.Peb at offset 0x550 — write a non-zero PEB address.
        eproc_data[0x550..0x558].copy_from_slice(&0x0000_7FF0_0000u64.to_le_bytes());
        // _KPROCESS.DirectoryTableBase at offset 0x28 — write 0 (no cr3).
        eproc_data[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr + 0x1000, eproc_paddr + 0x1000, flags::WRITABLE)
            .write_phys(eproc_paddr, &eproc_data[..4096])
            .write_phys(eproc_paddr + 0x1000, &eproc_data[4096..])
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let results = walk_iat_hooks(&reader, eproc_vaddr, 4, "test.exe").unwrap_or_default();
        assert!(results.is_empty(), "zero CR3 should return empty hook list");
    }

    #[test]
    fn iat_hook_serializes() {
        let hook = IatHookInfo {
            pid: 1234,
            process_name: "malware.exe".into(),
            hooked_module: "ntdll.dll".into(),
            hooked_function: "NtCreateFile".into(),
            iat_address: 0x7FF8_0000_1000,
            original_target: "ntdll.dll".into(),
            hook_target: 0xDEAD_BEEF_0000,
            hook_module: "evil.dll".into(),
            is_suspicious: true,
        };

        let json = serde_json::to_string(&hook).expect("IatHookInfo should serialize to JSON");
        assert!(
            json.contains("malware.exe"),
            "JSON should contain process name"
        );
        assert!(
            json.contains("NtCreateFile"),
            "JSON should contain function name"
        );
        assert!(json.contains("evil.dll"), "JSON should contain hook module");
    }

    // ── Helper function coverage ──────────────────────────────────────

    /// le_u16 returns 0 when the offset is out of bounds.
    #[test]
    fn le_u16_oob_returns_zero() {
        assert_eq!(le_u16(&[0x01, 0x02], 1), 0); // needs 2 bytes from offset 1 but only 1 available
        assert_eq!(le_u16(&[], 0), 0);
    }

    /// le_u16 reads correctly within bounds.
    #[test]
    fn le_u16_reads_correctly() {
        assert_eq!(le_u16(&[0x34, 0x12, 0xFF], 0), 0x1234);
        assert_eq!(le_u16(&[0x00, 0x78, 0x56], 1), 0x5678);
    }

    /// le_u32 returns 0 when out of bounds.
    #[test]
    fn le_u32_oob_returns_zero() {
        assert_eq!(le_u32(&[0x01, 0x02, 0x03], 0), 0); // needs 4 bytes
        assert_eq!(le_u32(&[], 0), 0);
    }

    /// le_u32 reads correctly within bounds.
    #[test]
    fn le_u32_reads_correctly() {
        let buf = [0x78u8, 0x56, 0x34, 0x12];
        assert_eq!(le_u32(&buf, 0), 0x1234_5678);
    }

    /// le_u64 returns 0 when out of bounds.
    #[test]
    fn le_u64_oob_returns_zero() {
        assert_eq!(le_u64(&[0u8; 7], 0), 0);
        assert_eq!(le_u64(&[], 0), 0);
    }

    /// le_u64 reads correctly within bounds.
    #[test]
    fn le_u64_reads_correctly() {
        let buf: [u8; 8] = [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
        assert_eq!(le_u64(&buf, 0), 0x0102_0304_0506_0708);
    }

    /// classify_iat_hook with hook_target exactly at module base is benign.
    #[test]
    fn classify_iat_hook_at_exact_base_benign() {
        let base: u64 = 0x7FF8_0000_0000;
        let size: u32 = 0x10_0000;
        // target == base is inside range [base, base+size)
        assert!(!classify_iat_hook(base, base, size, "kernel32.dll"));
    }

    /// classify_iat_hook with hook_target at exactly end is suspicious (end is exclusive).
    #[test]
    fn classify_iat_hook_at_end_exclusive_suspicious() {
        let base: u64 = 0x7FF8_0000_0000;
        let size: u32 = 0x10_0000;
        let end = base + u64::from(size);
        assert!(classify_iat_hook(end, base, size, "kernel32.dll"));
    }

    /// classify_iat_hook with "unknown" trimmed/cased variants.
    #[test]
    fn classify_iat_hook_unknown_with_whitespace() {
        let base: u64 = 0x7FF8_0000_0000;
        let size: u32 = 0x10_0000;
        let target = base + 0x100;
        // Whitespace-trimmed "unknown" is still suspicious.
        assert!(classify_iat_hook(target, base, size, "  UNKNOWN  "));
    }

    /// Zero expected_module_base + zero size: target inside [0,0) is never inside —
    /// but classify_iat_hook with non-zero hook target still checks range (0..0 is
    /// always outside, so result is suspicious).
    #[test]
    fn classify_iat_hook_zero_base_and_size_suspicious() {
        // Any non-zero hook_target is >= base (0) but the range is [0..0) which is
        // empty. The hook_target (e.g. 0x1000) >= end (0), so it IS >= end → suspicious.
        // Actually 0x1000 >= 0 (base) but 0x1000 >= 0 (end) → outside → suspicious.
        assert!(classify_iat_hook(0x1000, 0, 0, "ntdll.dll"));
    }

    // ── resolve_module and find_module_range coverage ─────────────────

    /// resolve_module returns the module name whose range contains the addr.
    #[test]
    fn resolve_module_returns_correct_name() {
        let ranges: Vec<(u64, u64, String)> = vec![
            (0x1000_0000, 0x1010_0000, "ntdll.dll".to_string()),
            (0x2000_0000, 0x2020_0000, "kernel32.dll".to_string()),
        ];
        assert_eq!(resolve_module(0x1005_0000, &ranges), "ntdll.dll");
        assert_eq!(resolve_module(0x2010_0000, &ranges), "kernel32.dll");
    }

    /// resolve_module returns empty string when no range contains the addr.
    #[test]
    fn resolve_module_no_match_returns_empty() {
        let ranges: Vec<(u64, u64, String)> = vec![
            (0x1000_0000, 0x1010_0000, "ntdll.dll".to_string()),
        ];
        // Address below the range
        assert_eq!(resolve_module(0x0FFF_FFFF, &ranges), "");
        // Address at or above end (exclusive)
        assert_eq!(resolve_module(0x1010_0000, &ranges), "");
        // Empty ranges
        assert_eq!(resolve_module(0x1005_0000, &[]), "");
    }

    /// resolve_module returns the first matching module when ranges overlap.
    #[test]
    fn resolve_module_first_match_wins() {
        let ranges: Vec<(u64, u64, String)> = vec![
            (0x1000_0000, 0x2000_0000, "first.dll".to_string()),
            (0x1000_0000, 0x2000_0000, "second.dll".to_string()),
        ];
        assert_eq!(resolve_module(0x1500_0000, &ranges), "first.dll");
    }

    /// find_module_range returns base and size for a matching module name.
    #[test]
    fn find_module_range_found() {
        let ranges: Vec<(u64, u64, String)> = vec![
            (0x7FF8_0000_0000, 0x7FF8_0010_0000, "KERNEL32.DLL".to_string()),
        ];
        // Case-insensitive lookup
        let result = find_module_range("kernel32.dll", &ranges);
        assert!(result.is_some());
        let (base, size) = result.unwrap();
        assert_eq!(base, 0x7FF8_0000_0000);
        assert_eq!(size, 0x0010_0000);
    }

    /// find_module_range returns None when the name is not present.
    #[test]
    fn find_module_range_not_found() {
        let ranges: Vec<(u64, u64, String)> = vec![
            (0x7FF8_0000_0000, 0x7FF8_0010_0000, "kernel32.dll".to_string()),
        ];
        assert!(find_module_range("ntdll.dll", &ranges).is_none());
        assert!(find_module_range("kernel32.dll", &[]).is_none());
    }

    /// find_module_range trims whitespace from the query name.
    #[test]
    fn find_module_range_trims_whitespace() {
        let ranges: Vec<(u64, u64, String)> = vec![
            (0x1000, 0x2000, "ntdll.dll".to_string()),
        ];
        let result = find_module_range("  ntdll.dll  ", &ranges);
        assert!(result.is_some());
    }

    /// parse_module_imports rejects headers that are too short (< 0x40 bytes).
    #[test]
    fn parse_module_imports_short_header_returns_empty() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Map only 0x10 bytes — too short for a DOS header (< 0x40).
        let image_base: u64 = 0x0010_0000;
        let image_paddr: u64 = 0x0010_0000;
        let short_header = vec![0x4D, 0x5A, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // "MZ" + 6 zeros

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(image_base, image_paddr, flags::WRITABLE)
            .write_phys(image_paddr, &short_header)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let ranges: Vec<(u64, u64, String)> = vec![];
        let result = parse_module_imports(&reader, image_base, "test.dll", &ranges, 1, "test", 100);
        assert!(result.is_empty(), "short header (<0x40) should return empty");
    }

    /// parse_module_imports rejects a header without PE\0\0 signature.
    #[test]
    fn parse_module_imports_bad_pe_signature_returns_empty() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let image_base: u64 = 0x0011_0000;
        let image_paddr: u64 = 0x0011_0000;

        // DOS header: MZ at [0], e_lfanew at [0x3C] = 0x40 (within 1024 bytes)
        let mut header = vec![0u8; 1024];
        header[0] = 0x4D; // M
        header[1] = 0x5A; // Z
        header[0x3C] = 0x40; // e_lfanew = 64
        // At offset 0x40: write "XX\0\0" instead of "PE\0\0"
        header[0x40] = b'X';
        header[0x41] = b'X';
        header[0x42] = 0;
        header[0x43] = 0;

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(image_base, image_paddr, flags::WRITABLE)
            .write_phys(image_paddr, &header[..4096.min(header.len())])
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let ranges: Vec<(u64, u64, String)> = vec![];
        let result = parse_module_imports(&reader, image_base, "test.dll", &ranges, 1, "test", 100);
        assert!(result.is_empty(), "bad PE signature should return empty");
    }

    /// parse_module_imports rejects when import_rva == 0.
    #[test]
    fn parse_module_imports_zero_import_rva_returns_empty() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let image_base: u64 = 0x0012_0000;
        let image_paddr: u64 = 0x0012_0000;

        // Build a minimal valid PE32+ header with import_rva = 0.
        let mut header = vec![0u8; 1024];
        // DOS header
        header[0] = 0x4D; // M
        header[1] = 0x5A; // Z
        let e_lfanew: u32 = 0x40;
        header[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        // PE signature
        header[0x40] = b'P';
        header[0x41] = b'E';
        header[0x42] = 0;
        header[0x43] = 0;
        // COFF header (20 bytes) starts at 0x44
        // Optional header starts at 0x44 + 20 = 0x58
        // opt_magic = 0x020B (PE32+) at 0x58
        header[0x58] = 0x0B;
        header[0x59] = 0x02;
        // import_dir for PE32+: opt_off + 120 = 0x58 + 0x78 = 0xD0
        // import_rva = 0, import_size = 0 (zeros already)

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(image_base, image_paddr, flags::WRITABLE)
            .write_phys(image_paddr, &header)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let ranges: Vec<(u64, u64, String)> = vec![];
        let result = parse_module_imports(&reader, image_base, "test.dll", &ranges, 1, "test", 100);
        assert!(result.is_empty(), "zero import_rva should return empty");
    }
}
