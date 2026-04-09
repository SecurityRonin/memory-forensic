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

/// Walk all loaded drivers and check their IRP dispatch tables for hooks.
///
/// `driver_list_head` is the virtual address of `PsLoadedModuleList`.
///
/// For each driver, reads the `_DRIVER_OBJECT` and its `MajorFunction[0..28]`
/// array, classifying each handler pointer against the driver's own module
/// range. Handlers that fall outside are flagged as hooked.
pub fn walk_driver_irp<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
    _driver_list_head: u64,
) -> Result<Vec<DriverIrpHookInfo>> {
    todo!("walk_driver_irp: implement IRP dispatch table walking")
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

    // ── walk_driver_irp placeholder test ───────────────────────────

    #[test]
    #[should_panic(expected = "walk_driver_irp")]
    fn walk_todo_panics() {
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let vaddr_base = 0xFFFF_8000_0000_0000u64;
        let paddr_base = 0x10_0000u64;
        let mut page = vec![0u8; 4096];
        // Empty list: sentinel points to itself.
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

        // Should panic with todo!
        let _ = walk_driver_irp(&reader, vaddr_base);
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
