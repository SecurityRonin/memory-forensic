//! Windows system information extraction.
//!
//! Reads OS version, build number, service pack, and system metadata from
//! kernel memory structures. Equivalent to Volatility's `windows.info` plugin.
//! Resolves global symbols: `NtBuildNumber`, `NtBuildLab`, `CmNtCSDVersion`,
//! `NtMajorVersion`, `NtMinorVersion`, `KeNumberProcessors`, and
//! `KdDebuggerDataBlock`.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use serde::Serialize;

/// Windows system information extracted from kernel memory.
#[derive(Debug, Clone, Serialize)]
pub struct SystemInfo {
    /// NT major version (e.g. 10 for Windows 10/11).
    pub major_version: u32,
    /// NT minor version (e.g. 0 for Windows 10).
    pub minor_version: u32,
    /// Build number from `NtBuildNumber` (high bit masked off).
    pub build_number: u32,
    /// Build lab string from `NtBuildLab` (null-terminated ASCII).
    pub build_lab: String,
    /// Service pack string derived from `CmNtCSDVersion`.
    pub service_pack: String,
    /// Number of logical processors from `KeNumberProcessors`.
    pub num_processors: u32,
    /// System time from `KdDebuggerDataBlock` (Windows FILETIME).
    pub system_time: u64,
    /// Product type string: "Workstation", "Domain Controller", "Server", or "Unknown".
    pub product_type: String,
}

/// Map an NT product type code to a human-readable name.
///
/// NT product type values:
/// - 1 = VER_NT_WORKSTATION
/// - 2 = VER_NT_DOMAIN_CONTROLLER
/// - 3 = VER_NT_SERVER
pub fn product_type_name(product_type: u32) -> String {
    match product_type {
        1 => "Workstation".into(),
        2 => "Domain Controller".into(),
        3 => "Server".into(),
        _ => "Unknown".into(),
    }
}

/// Extract Windows system information from kernel memory.
///
/// Looks up global kernel symbols (`NtBuildNumber`, `NtMajorVersion`, etc.)
/// to reconstruct the OS version and build metadata. Returns `Ok(None)` if
/// the essential `NtBuildNumber` symbol is not found (e.g. non-Windows image).
///
/// Optional fields degrade gracefully: if a symbol is missing, a default
/// value is used (0 for integers, empty string for strings).
pub fn walk_sysinfo<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Option<SystemInfo>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── product_type_name classifier tests ──

    #[test]
    fn product_type_workstation() {
        assert_eq!(product_type_name(1), "Workstation");
    }

    #[test]
    fn product_type_domain_controller() {
        assert_eq!(product_type_name(2), "Domain Controller");
    }

    #[test]
    fn product_type_server() {
        assert_eq!(product_type_name(3), "Server");
    }

    #[test]
    fn product_type_unknown() {
        assert_eq!(product_type_name(0), "Unknown");
        assert_eq!(product_type_name(99), "Unknown");
    }

    // ── serialization test ──

    #[test]
    fn system_info_serializes() {
        let info = SystemInfo {
            major_version: 10,
            minor_version: 0,
            build_number: 19041,
            build_lab: "19041.1.amd64fre.vb_release.191206-1406".into(),
            service_pack: "Service Pack 0".into(),
            num_processors: 4,
            system_time: 132_500_000_000_000_000,
            product_type: "Workstation".into(),
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["major_version"], 10);
        assert_eq!(json["build_number"], 19041);
        assert_eq!(json["product_type"], "Workstation");
        assert_eq!(json["num_processors"], 4);
    }

    // ── walker test ──

    #[test]
    fn walker_no_symbol_returns_none() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Build a reader with NO NtBuildNumber symbol
        let isf = IsfBuilder::new()
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer");

        let json = isf.build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();

        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let ptb = PageTableBuilder::new().map_4k(vaddr, paddr, flags::WRITABLE);
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_sysinfo(&reader).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn walker_with_build_number_returns_info() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // NtBuildNumber address in kernel virtual space
        let build_num_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let build_num_paddr: u64 = 0x0090_0000;

        // NtMajorVersion
        let major_vaddr: u64 = 0xFFFF_8000_0020_1000;
        let major_paddr: u64 = 0x0091_0000;

        // NtMinorVersion
        let minor_vaddr: u64 = 0xFFFF_8000_0020_2000;
        let minor_paddr: u64 = 0x0092_0000;

        // NtBuildLab
        let build_lab_vaddr: u64 = 0xFFFF_8000_0020_3000;
        let build_lab_paddr: u64 = 0x0093_0000;

        // CmNtCSDVersion
        let csd_vaddr: u64 = 0xFFFF_8000_0020_4000;
        let csd_paddr: u64 = 0x0094_0000;

        // KeNumberProcessors
        let nproc_vaddr: u64 = 0xFFFF_8000_0020_5000;
        let nproc_paddr: u64 = 0x0095_0000;

        let isf = IsfBuilder::new()
            .add_symbol("NtBuildNumber", build_num_vaddr)
            .add_symbol("NtMajorVersion", major_vaddr)
            .add_symbol("NtMinorVersion", minor_vaddr)
            .add_symbol("NtBuildLab", build_lab_vaddr)
            .add_symbol("CmNtCSDVersion", csd_vaddr)
            .add_symbol("KeNumberProcessors", nproc_vaddr);

        let json = isf.build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();

        // Build number 19041 with high bit set (checked build flag)
        let raw_build: u32 = 0xF000_0000 | 19041;
        let build_lab_str = b"19041.1.amd64fre.vb_release\0";
        // CmNtCSDVersion: SP major = 2 -> (2 << 8)
        let csd_version: u32 = 2 << 8;

        let ptb = PageTableBuilder::new()
            .map_4k(build_num_vaddr, build_num_paddr, flags::WRITABLE)
            .write_phys(build_num_paddr, &raw_build.to_le_bytes())
            .map_4k(major_vaddr, major_paddr, flags::WRITABLE)
            .write_phys(major_paddr, &10u32.to_le_bytes())
            .map_4k(minor_vaddr, minor_paddr, flags::WRITABLE)
            .write_phys(minor_paddr, &0u32.to_le_bytes())
            .map_4k(build_lab_vaddr, build_lab_paddr, flags::WRITABLE)
            .write_phys(build_lab_paddr, build_lab_str)
            .map_4k(csd_vaddr, csd_paddr, flags::WRITABLE)
            .write_phys(csd_paddr, &csd_version.to_le_bytes())
            .map_4k(nproc_vaddr, nproc_paddr, flags::WRITABLE)
            .write_phys(nproc_paddr, &8u32.to_le_bytes());

        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_sysinfo(&reader).unwrap();
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.build_number, 19041);
        assert_eq!(info.major_version, 10);
        assert_eq!(info.minor_version, 0);
        assert_eq!(info.build_lab, "19041.1.amd64fre.vb_release");
        assert_eq!(info.service_pack, "Service Pack 2");
        assert_eq!(info.num_processors, 8);
    }
}
