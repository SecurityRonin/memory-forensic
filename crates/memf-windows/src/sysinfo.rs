//! Windows system information extraction.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use serde::Serialize;

/// Windows system information extracted from kernel memory.
#[derive(Debug, Clone, Serialize)]
pub struct SystemInfo {
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub build_lab: String,
    pub service_pack: String,
    pub num_processors: u32,
    pub system_time: u64,
    pub product_type: String,
}

pub fn product_type_name(product_type: u32) -> String {
    match product_type {
        1 => "Workstation".into(),
        2 => "Domain Controller".into(),
        3 => "Server".into(),
        _ => "Unknown".into(),
    }
}

pub fn walk_sysinfo<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Option<SystemInfo>> {
    let symbols = reader.symbols();

    let build_num_vaddr = match symbols.symbol_address("NtBuildNumber") {
        Some(addr) => addr,
        None => return Ok(None),
    };

    let build_number = {
        let bytes = reader.read_bytes(build_num_vaddr, 4)?;
        let raw = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        raw & 0x0000_FFFF
    };

    let major_version = read_u32_symbol(reader, symbols, "NtMajorVersion").unwrap_or(0);
    let minor_version = read_u32_symbol(reader, symbols, "NtMinorVersion").unwrap_or(0);

    let build_lab = match symbols.symbol_address("NtBuildLab") {
        Some(addr) => reader.read_string(addr, 128).unwrap_or_default(),
        None => String::new(),
    };

    let service_pack = match symbols.symbol_address("CmNtCSDVersion") {
        Some(addr) => {
            let bytes = reader.read_bytes(addr, 4).unwrap_or_else(|_| vec![0; 4]);
            let csd = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let sp_major = (csd >> 8) & 0xFF;
            format!("Service Pack {sp_major}")
        }
        None => String::new(),
    };

    let num_processors = read_u32_symbol(reader, symbols, "KeNumberProcessors").unwrap_or(0);

    let (system_time, product_type) = match symbols.symbol_address("KdDebuggerDataBlock") {
        Some(addr) => {
            let sys_time = reader
                .read_bytes(addr.wrapping_add(0x14), 8)
                .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
                .unwrap_or(0);
            let prod_type = reader
                .read_bytes(addr.wrapping_add(0x264), 4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                .unwrap_or(0);
            (sys_time, product_type_name(prod_type))
        }
        None => (0, "Unknown".into()),
    };

    Ok(Some(SystemInfo {
        major_version,
        minor_version,
        build_number,
        build_lab,
        service_pack,
        num_processors,
        system_time,
        product_type,
    }))
}

fn read_u32_symbol<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    symbols: &dyn memf_symbols::SymbolResolver,
    name: &str,
) -> Option<u32> {
    let addr = symbols.symbol_address(name)?;
    let bytes = reader.read_bytes(addr, 4).ok()?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn walker_no_symbol_returns_none() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

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
    fn walker_with_kd_debugger_data_block() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let build_num_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let build_num_paddr: u64 = 0x0030_0000;
        let kd_vaddr: u64 = 0xFFFF_8000_0031_0000;
        let kd_paddr: u64 = 0x0031_0000;

        let mut kd_page = vec![0u8; 4096];
        let sys_time: u64 = 0x01D8_DEAD_BEEF_0000;
        kd_page[0x14..0x1C].copy_from_slice(&sys_time.to_le_bytes());
        kd_page[0x264..0x268].copy_from_slice(&3u32.to_le_bytes());

        let raw_build: u32 = 19041;
        let mut build_page = vec![0u8; 4096];
        build_page[0..4].copy_from_slice(&raw_build.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_symbol("NtBuildNumber", build_num_vaddr)
            .add_symbol("KdDebuggerDataBlock", kd_vaddr);
        let json = isf.build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(build_num_vaddr, build_num_paddr, flags::WRITABLE)
            .write_phys(build_num_paddr, &build_page)
            .map_4k(kd_vaddr, kd_paddr, flags::WRITABLE)
            .write_phys(kd_paddr, &kd_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_sysinfo(&reader).unwrap();
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.build_number, 19041);
        assert_eq!(info.system_time, sys_time);
        assert_eq!(info.product_type, "Server");
    }

    #[test]
    fn walker_kd_debugger_domain_controller() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let build_num_vaddr: u64 = 0xFFFF_8000_0040_0000;
        let build_num_paddr: u64 = 0x0040_0000;
        let kd_vaddr: u64 = 0xFFFF_8000_0041_0000;
        let kd_paddr: u64 = 0x0041_0000;

        let mut kd_page = vec![0u8; 4096];
        kd_page[0x264..0x268].copy_from_slice(&2u32.to_le_bytes());

        let raw_build: u32 = 17763;
        let mut build_page = vec![0u8; 4096];
        build_page[0..4].copy_from_slice(&raw_build.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_symbol("NtBuildNumber", build_num_vaddr)
            .add_symbol("KdDebuggerDataBlock", kd_vaddr);
        let json = isf.build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(build_num_vaddr, build_num_paddr, flags::WRITABLE)
            .write_phys(build_num_paddr, &build_page)
            .map_4k(kd_vaddr, kd_paddr, flags::WRITABLE)
            .write_phys(kd_paddr, &kd_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let info = walk_sysinfo(&reader).unwrap().unwrap();
        assert_eq!(info.product_type, "Domain Controller");
        assert_eq!(info.build_number, 17763);
    }

    #[test]
    fn walker_kd_debugger_workstation() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let build_num_vaddr: u64 = 0xFFFF_8000_0050_0000;
        let build_num_paddr: u64 = 0x0050_0000;
        let kd_vaddr: u64 = 0xFFFF_8000_0051_0000;
        let kd_paddr: u64 = 0x0051_0000;

        let mut kd_page = vec![0u8; 4096];
        kd_page[0x264..0x268].copy_from_slice(&1u32.to_le_bytes());

        let mut build_page = vec![0u8; 4096];
        build_page[0..4].copy_from_slice(&22000u32.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_symbol("NtBuildNumber", build_num_vaddr)
            .add_symbol("KdDebuggerDataBlock", kd_vaddr);
        let json = isf.build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(build_num_vaddr, build_num_paddr, flags::WRITABLE)
            .write_phys(build_num_paddr, &build_page)
            .map_4k(kd_vaddr, kd_paddr, flags::WRITABLE)
            .write_phys(kd_paddr, &kd_page)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let info = walk_sysinfo(&reader).unwrap().unwrap();
        assert_eq!(info.product_type, "Workstation");
    }

    #[test]
    fn walker_with_build_number_returns_info() {
        use memf_core::object_reader::ObjectReader;
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let build_num_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let build_num_paddr: u64 = 0x0090_0000;
        let major_vaddr: u64 = 0xFFFF_8000_0020_1000;
        let major_paddr: u64 = 0x0091_0000;
        let minor_vaddr: u64 = 0xFFFF_8000_0020_2000;
        let minor_paddr: u64 = 0x0092_0000;
        let build_lab_vaddr: u64 = 0xFFFF_8000_0020_3000;
        let build_lab_paddr: u64 = 0x0093_0000;
        let csd_vaddr: u64 = 0xFFFF_8000_0020_4000;
        let csd_paddr: u64 = 0x0094_0000;
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

        let raw_build: u32 = 0xF000_0000 | 19041;
        let build_lab_str = b"19041.1.amd64fre.vb_release\0";
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
