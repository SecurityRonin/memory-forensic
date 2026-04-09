//! Driver IRP dispatch table hook detection (Windows).
//!
//! Each loaded Windows kernel driver has a `_DRIVER_OBJECT` containing a
//! `MajorFunction` array of 28 function pointers — one per IRP major
//! function code. Rootkits replace these pointers to intercept I/O
//! operations (disk reads, network, filesystem). A hooked IRP handler
//! points outside the driver's own module address range.
//!
//! Equivalent to Volatility's `driverirp` plugin. MITRE ATT&CK T1014.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use serde::Serialize;

use crate::driver;
use crate::Result;

/// Maximum number of drivers we'll iterate before bailing out.
const MAX_DRIVERS: usize = 4096;

/// Number of IRP major function slots in a `_DRIVER_OBJECT`.
const IRP_MJ_COUNT: usize = 28;

/// Information about a single IRP dispatch table entry for a driver.
#[derive(Debug, Clone, Serialize)]
pub struct DriverIrpHookInfo {
    /// Base name of the driver module (e.g. `ntoskrnl.exe`).
    pub driver_name: String,
    /// Base address where the driver image is loaded.
    pub driver_base: u64,
    /// Size of the driver image in bytes.
    pub driver_size: u32,
    /// IRP major function index (0..27).
    pub irp_index: u8,
    /// Human-readable IRP name (e.g. `IRP_MJ_CREATE`).
    pub irp_name: String,
    /// Address of the IRP handler function pointer.
    pub handler_addr: u64,
    /// Name of the module that contains the handler address.
    pub handler_module: String,
    /// Whether this handler is considered hooked (points outside the driver's own range).
    pub is_hooked: bool,
}

/// Map an IRP major function index to its human-readable name.
///
/// Returns `"IRP_MJ_UNKNOWN"` for indices outside the known range.
pub fn irp_name(index: u8) -> &'static str {
    match index {
        0 => "IRP_MJ_CREATE",
        1 => "IRP_MJ_CREATE_NAMED_PIPE",
        2 => "IRP_MJ_CLOSE",
        3 => "IRP_MJ_READ",
        4 => "IRP_MJ_WRITE",
        5 => "IRP_MJ_QUERY_INFORMATION",
        6 => "IRP_MJ_SET_INFORMATION",
        7 => "IRP_MJ_QUERY_EA",
        8 => "IRP_MJ_SET_EA",
        9 => "IRP_MJ_FLUSH_BUFFERS",
        10 => "IRP_MJ_QUERY_VOLUME_INFORMATION",
        11 => "IRP_MJ_SET_VOLUME_INFORMATION",
        12 => "IRP_MJ_DIRECTORY_CONTROL",
        13 => "IRP_MJ_FILE_SYSTEM_CONTROL",
        14 => "IRP_MJ_DEVICE_CONTROL",
        15 => "IRP_MJ_INTERNAL_DEVICE_CONTROL",
        16 => "IRP_MJ_SHUTDOWN",
        17 => "IRP_MJ_LOCK_CONTROL",
        18 => "IRP_MJ_CLEANUP",
        19 => "IRP_MJ_CREATE_MAILSLOT",
        20 => "IRP_MJ_QUERY_SECURITY",
        21 => "IRP_MJ_SET_SECURITY",
        22 => "IRP_MJ_POWER",
        23 => "IRP_MJ_SYSTEM_CONTROL",
        24 => "IRP_MJ_DEVICE_CHANGE",
        25 => "IRP_MJ_QUERY_QUOTA",
        26 => "IRP_MJ_SET_QUOTA",
        27 => "IRP_MJ_PNP",
        _ => "IRP_MJ_UNKNOWN",
    }
}

/// Classify whether an IRP handler address is hooked.
///
/// A handler is considered hooked if it is non-null **and** falls outside
/// the driver's own module range `[driver_base, driver_base + driver_size)`.
pub fn classify_irp_hook(handler_addr: u64, driver_base: u64, driver_size: u32) -> bool {
    if handler_addr == 0 {
        return false;
    }
    let end = driver_base.wrapping_add(u64::from(driver_size));
    handler_addr < driver_base || handler_addr >= end
}

/// Resolve which module contains `addr`, returning its name or `"<unknown>"`.
fn resolve_module(addr: u64, modules: &[crate::WinDriverInfo]) -> String {
    modules
        .iter()
        .find(|m| addr >= m.base_addr && addr < m.base_addr + m.size)
        .map_or_else(|| "<unknown>".to_string(), |m| m.name.clone())
}

/// Check a single driver object's IRP dispatch table and emit
/// [`DriverIrpHookInfo`] entries for every non-null slot.
fn check_driver_object<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    driver_obj_addr: u64,
    modules: &[crate::WinDriverInfo],
) -> Result<Vec<DriverIrpHookInfo>> {
    let driver_base: u64 =
        reader.read_field(driver_obj_addr, "_DRIVER_OBJECT", "DriverStart")?;
    let driver_size: u32 =
        reader.read_field(driver_obj_addr, "_DRIVER_OBJECT", "DriverSize")?;

    let driver_name_offset = reader
        .symbols()
        .field_offset("_DRIVER_OBJECT", "DriverName")
        .ok_or_else(|| crate::Error::Walker("missing _DRIVER_OBJECT.DriverName offset".into()))?;
    let driver_name = crate::unicode::read_unicode_string(
        reader,
        driver_obj_addr.wrapping_add(driver_name_offset),
    )
    .unwrap_or_default();

    let mf_offset = reader
        .symbols()
        .field_offset("_DRIVER_OBJECT", "MajorFunction")
        .ok_or_else(|| {
            crate::Error::Walker("missing _DRIVER_OBJECT.MajorFunction offset".into())
        })?;
    let mf_base = driver_obj_addr.wrapping_add(mf_offset);
    let mf_bytes = reader.read_bytes(mf_base, IRP_MJ_COUNT * 8)?;

    let mut results = Vec::new();
    for i in 0..IRP_MJ_COUNT {
        let byte_off = i * 8;
        let handler_addr =
            u64::from_le_bytes(mf_bytes[byte_off..byte_off + 8].try_into().expect("8 bytes"));
        if handler_addr == 0 {
            continue;
        }
        let handler_module = resolve_module(handler_addr, modules);
        // A handler is hooked only if it is outside the driver's own range
        // AND does not resolve to any known loaded module.
        let is_hooked = classify_irp_hook(handler_addr, driver_base, driver_size)
            && handler_module == "<unknown>";
        results.push(DriverIrpHookInfo {
            driver_name: driver_name.clone(),
            driver_base,
            driver_size,
            irp_index: i as u8,
            irp_name: irp_name(i as u8).to_string(),
            handler_addr,
            handler_module,
            is_hooked,
        });
    }
    Ok(results)
}

/// Walk all loaded drivers and check their IRP dispatch tables for hooks.
///
/// `driver_list_head` is the virtual address of `PsLoadedModuleList`.
///
/// The walker enumerates all loaded kernel modules for name resolution,
/// then walks the module list entries. Because `_KLDR_DATA_TABLE_ENTRY`
/// does not contain a direct pointer to `_DRIVER_OBJECT`, this walker
/// returns an empty vec when driver objects cannot be discovered. Use
/// [`check_driver_irp_hooks`] when you already have driver object
/// addresses (e.g. from object directory enumeration).
pub fn walk_driver_irp<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    driver_list_head: u64,
) -> Result<Vec<DriverIrpHookInfo>> {
    let modules = driver::walk_drivers(reader, driver_list_head)?;

    let entries = reader.walk_list_with(
        driver_list_head,
        "_LIST_ENTRY",
        "Flink",
        "_KLDR_DATA_TABLE_ENTRY",
        "InLoadOrderLinks",
    )?;

    let results = Vec::new();
    let limit = entries.len().min(MAX_DRIVERS);

    for entry_addr in entries.into_iter().take(limit) {
        let _dll_base: u64 =
            match reader.read_field(entry_addr, "_KLDR_DATA_TABLE_ENTRY", "DllBase") {
                Ok(v) => v,
                Err(_) => continue,
            };
        // Without object directory access we cannot locate the _DRIVER_OBJECT.
        let _ = &modules;
    }

    Ok(results)
}

/// Check a list of known `_DRIVER_OBJECT` addresses for IRP dispatch hooks.
///
/// Primary entry point when driver object addresses are already known
/// (e.g. from object directory enumeration or pool tag scanning).
pub fn check_driver_irp_hooks<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    driver_obj_addrs: &[u64],
    known_modules: &[crate::WinDriverInfo],
) -> Result<Vec<DriverIrpHookInfo>> {
    let mut results = Vec::new();
    let limit = driver_obj_addrs.len().min(MAX_DRIVERS);
    for &addr in driver_obj_addrs.iter().take(limit) {
        match check_driver_object(reader, addr, known_modules) {
            Ok(entries) => results.extend(entries),
            Err(_) => continue,
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── irp_name tests ─────────────────────────────────────────────

    #[test]
    fn irp_name_create() {
        assert_eq!(irp_name(0), "IRP_MJ_CREATE");
    }

    #[test]
    fn irp_name_device_control() {
        assert_eq!(irp_name(14), "IRP_MJ_DEVICE_CONTROL");
    }

    #[test]
    fn irp_name_pnp() {
        assert_eq!(irp_name(27), "IRP_MJ_PNP");
    }

    #[test]
    fn irp_name_unknown() {
        assert_eq!(irp_name(28), "IRP_MJ_UNKNOWN");
        assert_eq!(irp_name(255), "IRP_MJ_UNKNOWN");
    }

    // ── classify_irp_hook tests ────────────────────────────────────

    #[test]
    fn classify_in_range_benign() {
        // Handler inside [base, base+size) → not hooked
        let base: u64 = 0xFFFFF800_02000000;
        let size: u32 = 0x40000;
        let handler = base + 0x1000;
        assert!(!classify_irp_hook(handler, base, size));
    }

    #[test]
    fn classify_outside_range_hooked() {
        // Handler outside [base, base+size) → hooked
        let base: u64 = 0xFFFFF800_02000000;
        let size: u32 = 0x40000;
        let handler: u64 = 0xFFFF_C900_DEAD_0000;
        assert!(classify_irp_hook(handler, base, size));
    }

    #[test]
    fn classify_null_benign() {
        // Null handler → not hooked (unused slot)
        let base: u64 = 0xFFFFF800_02000000;
        let size: u32 = 0x40000;
        assert!(!classify_irp_hook(0, base, size));
    }

    #[test]
    fn classify_at_boundary_start() {
        // Handler exactly at base → benign
        let base: u64 = 0xFFFFF800_02000000;
        let size: u32 = 0x40000;
        assert!(!classify_irp_hook(base, base, size));
    }

    #[test]
    fn classify_at_boundary_end() {
        // Handler at base+size → hooked (exclusive upper bound)
        let base: u64 = 0xFFFFF800_02000000;
        let size: u32 = 0x40000;
        let end = base + u64::from(size);
        assert!(classify_irp_hook(end, base, size));
    }

    #[test]
    fn classify_just_before_base_hooked() {
        // Handler one byte before base → hooked
        let base: u64 = 0xFFFFF800_02000000;
        let size: u32 = 0x40000;
        assert!(classify_irp_hook(base - 1, base, size));
    }

    // ── walk_driver_irp tests ─────────────────────────────────────

    #[test]
    fn walk_empty_list_returns_empty() {
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let vaddr_base = 0xFFFF_8000_0000_0000u64;
        let paddr_base = 0x10_0000u64;
        let mut page = vec![0u8; 4096];
        page[0..8].copy_from_slice(&vaddr_base.to_le_bytes());
        page[8..16].copy_from_slice(&vaddr_base.to_le_bytes());

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr_base, paddr_base, flags::WRITABLE)
            .write_phys(paddr_base, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_driver_irp(&reader, vaddr_base).unwrap();
        assert!(result.is_empty());
    }

    // ── check_driver_irp_hooks tests ──────────────────────────────

    fn utf16le_bytes(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn build_unicode_string_at(buf: &mut [u8], offset: usize, length: u16, buffer_ptr: u64) {
        buf[offset..offset + 2].copy_from_slice(&length.to_le_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&length.to_le_bytes());
        buf[offset + 8..offset + 16].copy_from_slice(&buffer_ptr.to_le_bytes());
    }

    #[test]
    fn check_detects_hooked_irp() {
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let drv_obj_vaddr: u64 = 0xFFFF_8000_0050_0000;
        let drv_obj_paddr: u64 = 0x0050_0000;
        let strings_vaddr: u64 = 0xFFFF_8000_0050_1000;
        let strings_paddr: u64 = 0x0051_0000;

        let mut page = vec![0u8; 4096];
        let mut string_data = vec![0u8; 4096];

        let driver_base: u64 = 0xFFFFF800_02000000;
        let driver_size: u32 = 0x40000;
        page[0x18..0x20].copy_from_slice(&driver_base.to_le_bytes());
        page[0x20..0x24].copy_from_slice(&driver_size.to_le_bytes());

        let name_str = "\\Driver\\ACPI";
        let name_utf16 = utf16le_bytes(name_str);
        let name_len = name_utf16.len() as u16;
        string_data[0..name_utf16.len()].copy_from_slice(&name_utf16);
        build_unicode_string_at(&mut page, 0x38, name_len, strings_vaddr);

        let ntoskrnl_base: u64 = 0xFFFFF800_00000000;
        let clean_target: u64 = ntoskrnl_base + 0x1000;
        page[0x70..0x78].copy_from_slice(&clean_target.to_le_bytes());

        let hooked_target: u64 = 0xFFFF_C900_DEAD_0000;
        page[0x78..0x80].copy_from_slice(&hooked_target.to_le_bytes());

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(drv_obj_vaddr, drv_obj_paddr, flags::WRITABLE)
            .map_4k(strings_vaddr, strings_paddr, flags::WRITABLE)
            .write_phys(drv_obj_paddr, &page)
            .write_phys(strings_paddr, &string_data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let known_modules = vec![
            crate::WinDriverInfo {
                name: "ntoskrnl.exe".into(),
                full_path: r"\SystemRoot\system32\ntoskrnl.exe".into(),
                base_addr: ntoskrnl_base,
                size: 0x800000,
                vaddr: 0,
            },
            crate::WinDriverInfo {
                name: "ACPI.sys".into(),
                full_path: r"\SystemRoot\system32\ACPI.sys".into(),
                base_addr: driver_base,
                size: u64::from(driver_size),
                vaddr: 0,
            },
        ];

        let hooks = check_driver_irp_hooks(&reader, &[drv_obj_vaddr], &known_modules).unwrap();
        assert_eq!(hooks.len(), 2);

        let create = &hooks[0];
        assert_eq!(create.irp_index, 0);
        assert_eq!(create.irp_name, "IRP_MJ_CREATE");
        assert_eq!(create.handler_addr, clean_target);
        assert_eq!(create.handler_module, "ntoskrnl.exe");
        assert!(!create.is_hooked);

        let hooked = &hooks[1];
        assert_eq!(hooked.irp_index, 1);
        assert_eq!(hooked.irp_name, "IRP_MJ_CREATE_NAMED_PIPE");
        assert_eq!(hooked.handler_addr, hooked_target);
        assert_eq!(hooked.handler_module, "<unknown>");
        assert!(hooked.is_hooked);
        assert_eq!(hooked.driver_name, "\\Driver\\ACPI");
        assert_eq!(hooked.driver_base, driver_base);
        assert_eq!(hooked.driver_size, driver_size);
    }

    #[test]
    fn check_clean_driver_no_hooks() {
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let drv_obj_vaddr: u64 = 0xFFFF_8000_0050_0000;
        let drv_obj_paddr: u64 = 0x0050_0000;
        let mut page = vec![0u8; 4096];

        let driver_base: u64 = 0xFFFFF800_02000000;
        let driver_size: u32 = 0x40000;
        page[0x18..0x20].copy_from_slice(&driver_base.to_le_bytes());
        page[0x20..0x24].copy_from_slice(&driver_size.to_le_bytes());

        let clean_target: u64 = driver_base + 0x100;
        page[0x70..0x78].copy_from_slice(&clean_target.to_le_bytes());

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(drv_obj_vaddr, drv_obj_paddr, flags::WRITABLE)
            .write_phys(drv_obj_paddr, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let known_modules = vec![crate::WinDriverInfo {
            name: "ACPI.sys".into(),
            full_path: r"\SystemRoot\system32\ACPI.sys".into(),
            base_addr: driver_base,
            size: u64::from(driver_size),
            vaddr: 0,
        }];

        let hooks = check_driver_irp_hooks(&reader, &[drv_obj_vaddr], &known_modules).unwrap();
        assert_eq!(hooks.len(), 1);
        assert!(!hooks[0].is_hooked);
        assert_eq!(hooks[0].handler_module, "ACPI.sys");
    }

    #[test]
    fn check_empty_driver_obj_list() {
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let vaddr_base = 0xFFFF_8000_0000_0000u64;
        let paddr_base = 0x10_0000u64;
        let page = vec![0u8; 4096];

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr_base, paddr_base, flags::WRITABLE)
            .write_phys(paddr_base, &page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = check_driver_irp_hooks(&reader, &[], &[]).unwrap();
        assert!(result.is_empty());
    }

    // ── serialization test ─────────────────────────────────────────

    #[test]
    fn driver_irp_hook_info_serializes() {
        let info = DriverIrpHookInfo {
            driver_name: "test.sys".into(),
            driver_base: 0xFFFFF800_02000000,
            driver_size: 0x40000,
            irp_index: 3,
            irp_name: "IRP_MJ_READ".into(),
            handler_addr: 0xFFFF_C900_DEAD_0000,
            handler_module: "evil.sys".into(),
            is_hooked: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("IRP_MJ_READ"));
        assert!(json.contains("evil.sys"));
        assert!(json.contains("\"is_hooked\":true"));
    }
}
