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
pub struct AnalysisContext {
    pub os: OsProfile,
    pub cr3: u64,
    pub kaslr_offset: u64,
    pub ps_active_process_head: Option<u64>,
    pub ps_loaded_module_list: Option<u64>,
}

/// Detect the operating system from dump metadata and symbols.
pub fn detect_os(
    _metadata: Option<&DumpMetadata>,
    _symbols: &dyn SymbolResolver,
) -> Result<OsProfile> {
    todo!()
}

/// Extract the kernel page table root (CR3) physical address.
pub fn extract_cr3(
    _os: OsProfile,
    _metadata: Option<&DumpMetadata>,
    _symbols: &dyn SymbolResolver,
    _provider: &dyn PhysicalMemoryProvider,
) -> Result<u64> {
    todo!()
}

/// Build a full analysis context from dump metadata, symbols, and physical memory.
pub fn build_analysis_context(
    _metadata: Option<&DumpMetadata>,
    _symbols: &dyn SymbolResolver,
    _provider: &dyn PhysicalMemoryProvider,
) -> Result<AnalysisContext> {
    todo!()
}

/// Parse a hex address string (with or without "0x" prefix).
pub fn parse_hex_addr(_s: &str) -> Result<u64> {
    todo!()
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
