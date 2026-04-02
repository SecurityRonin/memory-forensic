use anyhow::{bail, Context, Result};
use memf_format::{DumpMetadata, PhysicalMemoryProvider};
use memf_symbols::SymbolResolver;

/// Detected operating system profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsProfile {
    Linux,
    Windows,
    MacOs,
}

impl std::fmt::Display for OsProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Linux => write!(f, "Linux"),
            Self::Windows => write!(f, "Windows"),
            Self::MacOs => write!(f, "macOS"),
        }
    }
}

/// Analysis context with OS-specific parameters.
#[allow(dead_code)] // kaslr_offset will be used for KASLR-adjusted symbol display
pub struct AnalysisContext {
    pub os: OsProfile,
    pub cr3: u64,
    pub kaslr_offset: u64,
    pub ps_active_process_head: Option<u64>,
    pub ps_loaded_module_list: Option<u64>,
}

/// Detect the operating system from dump metadata and symbols.
pub fn detect_os(
    metadata: Option<&DumpMetadata>,
    symbols: &dyn SymbolResolver,
) -> Result<OsProfile> {
    // 1. Windows crash dumps always have machine_type + cr3
    if let Some(meta) = metadata {
        if meta.machine_type.is_some() && meta.cr3.is_some() {
            return Ok(OsProfile::Windows);
        }
    }
    // 2. Linux symbols contain init_task
    if symbols.symbol_address("init_task").is_some() {
        return Ok(OsProfile::Linux);
    }
    // 3. Windows symbols contain _EPROCESS
    if symbols.struct_size("_EPROCESS").is_some() {
        return Ok(OsProfile::Windows);
    }
    // 4. macOS symbols contain allproc
    if symbols.symbol_address("allproc").is_some() {
        return Ok(OsProfile::MacOs);
    }
    bail!("cannot determine OS from dump metadata or symbols; provide --os linux|windows")
}

/// x86_64 kernel virtual address base (`__START_KERNEL_map`).
const KERNEL_MAP_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// Extract the kernel page table root (CR3) physical address.
pub fn extract_cr3(
    os: OsProfile,
    metadata: Option<&DumpMetadata>,
    symbols: &dyn SymbolResolver,
    provider: &dyn PhysicalMemoryProvider,
) -> Result<u64> {
    match os {
        OsProfile::Windows => metadata
            .and_then(|m| m.cr3)
            .context("Windows dump missing CR3 in metadata; provide --cr3"),
        OsProfile::Linux => {
            let swapper_vaddr = symbols
                .symbol_address("swapper_pg_dir")
                .context("symbol 'swapper_pg_dir' not found; provide --cr3")?;
            let kaslr_offset =
                memf_linux::kaslr::detect_kaslr_offset(provider, symbols).unwrap_or(0);
            // Physical = virtual + KASLR_offset - __START_KERNEL_map
            let cr3 = swapper_vaddr
                .wrapping_add(kaslr_offset)
                .wrapping_sub(KERNEL_MAP_BASE);
            Ok(cr3)
        }
        OsProfile::MacOs => {
            bail!("macOS CR3 extraction not yet implemented; provide --cr3")
        }
    }
}

/// Build a full analysis context from dump metadata, symbols, and physical memory.
pub fn build_analysis_context(
    metadata: Option<&DumpMetadata>,
    symbols: &dyn SymbolResolver,
    provider: &dyn PhysicalMemoryProvider,
) -> Result<AnalysisContext> {
    let os = detect_os(metadata, symbols)?;
    let cr3 = extract_cr3(os, metadata, symbols, provider)?;
    let kaslr_offset = if os == OsProfile::Linux {
        memf_linux::kaslr::detect_kaslr_offset(provider, symbols).unwrap_or(0)
    } else {
        0
    };
    Ok(AnalysisContext {
        os,
        cr3,
        kaslr_offset,
        ps_active_process_head: metadata.and_then(|m| m.ps_active_process_head),
        ps_loaded_module_list: metadata.and_then(|m| m.ps_loaded_module_list),
    })
}

/// Parse a hex address string (with or without "0x" prefix).
pub fn parse_hex_addr(s: &str) -> Result<u64> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(s, 16).context(format!("invalid hex address: {s}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_format::{DumpMetadata, MachineType};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_resolver(builder: &IsfBuilder) -> Box<dyn SymbolResolver> {
        Box::new(IsfResolver::from_value(&builder.build_json()).unwrap())
    }

    #[test]
    fn detect_os_windows_from_metadata() {
        let meta = DumpMetadata {
            cr3: Some(0x1ab000),
            machine_type: Some(MachineType::Amd64),
            ..Default::default()
        };
        let resolver = make_resolver(&IsfBuilder::new());
        let os = detect_os(Some(&meta), resolver.as_ref()).unwrap();
        assert_eq!(os, OsProfile::Windows);
    }

    #[test]
    fn detect_os_linux_from_symbols() {
        let resolver = make_resolver(&IsfBuilder::linux_process_preset());
        let os = detect_os(None, resolver.as_ref()).unwrap();
        assert_eq!(os, OsProfile::Linux);
    }

    #[test]
    fn detect_os_windows_from_symbols() {
        let resolver = make_resolver(&IsfBuilder::windows_kernel_preset());
        let os = detect_os(None, resolver.as_ref()).unwrap();
        assert_eq!(os, OsProfile::Windows);
    }

    #[test]
    fn detect_os_unknown_is_error() {
        let resolver = make_resolver(&IsfBuilder::new());
        let result = detect_os(None, resolver.as_ref());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cannot determine OS"));
    }

    #[test]
    fn detect_os_macos_from_symbols() {
        let resolver =
            make_resolver(&IsfBuilder::new().add_symbol("allproc", 0xFFFF_FF80_0000_1000));
        let os = detect_os(None, resolver.as_ref()).unwrap();
        assert_eq!(os, OsProfile::MacOs);
    }

    #[test]
    fn extract_cr3_windows_from_metadata() {
        let meta = DumpMetadata {
            cr3: Some(0x1ab000),
            machine_type: Some(MachineType::Amd64),
            ..Default::default()
        };
        let resolver = make_resolver(&IsfBuilder::new());
        let dump = memf_format::test_builders::LimeBuilder::new()
            .add_range(0, &[0u8; 64])
            .build();
        let provider = memf_format::lime::LimeProvider::from_bytes(&dump).unwrap();
        let cr3 = extract_cr3(
            OsProfile::Windows,
            Some(&meta),
            resolver.as_ref(),
            &provider,
        )
        .unwrap();
        assert_eq!(cr3, 0x1ab000);
    }

    #[test]
    fn extract_cr3_windows_missing_metadata_is_error() {
        let resolver = make_resolver(&IsfBuilder::new());
        let dump = memf_format::test_builders::LimeBuilder::new()
            .add_range(0, &[0u8; 64])
            .build();
        let provider = memf_format::lime::LimeProvider::from_bytes(&dump).unwrap();
        let result = extract_cr3(OsProfile::Windows, None, resolver.as_ref(), &provider);
        assert!(result.is_err());
    }

    #[test]
    fn extract_cr3_macos_is_error() {
        let resolver = make_resolver(&IsfBuilder::new());
        let dump = memf_format::test_builders::LimeBuilder::new()
            .add_range(0, &[0u8; 64])
            .build();
        let provider = memf_format::lime::LimeProvider::from_bytes(&dump).unwrap();
        let result = extract_cr3(OsProfile::MacOs, None, resolver.as_ref(), &provider);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("macOS"));
    }

    #[test]
    fn parse_hex_addr_with_prefix() {
        assert_eq!(parse_hex_addr("0x1ab000").unwrap(), 0x1ab000);
    }

    #[test]
    fn parse_hex_addr_without_prefix() {
        assert_eq!(parse_hex_addr("1ab000").unwrap(), 0x1ab000);
    }

    #[test]
    fn parse_hex_addr_uppercase_prefix() {
        assert_eq!(parse_hex_addr("0XDEAD").unwrap(), 0xDEAD);
    }

    #[test]
    fn parse_hex_addr_invalid() {
        assert!(parse_hex_addr("not_hex").is_err());
    }

    #[test]
    fn os_profile_display() {
        assert_eq!(format!("{}", OsProfile::Linux), "Linux");
        assert_eq!(format!("{}", OsProfile::Windows), "Windows");
        assert_eq!(format!("{}", OsProfile::MacOs), "macOS");
    }
}
