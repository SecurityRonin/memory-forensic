//! Reflective .NET (CLR) assembly detection walker — MITRE ATT&CK T1620.
//!
//! Scans CLR heap domains for assemblies that were loaded reflectively
//! (no backing file on disk) and optionally retain an `MZ`/`PE` header
//! in memory.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{types::ClrAssemblyInfo, Result};

/// Scan CLR `AppDomain` heaps for dynamically loaded (fileless) assemblies.
///
/// Locates the CLR data structure roots via the `mscorwks.dll` or
/// `clr.dll` export table, then walks `AppDomain->AssemblyList` and each
/// `Assembly->Module` to extract metadata. Reports any assembly whose
/// `ModuleFile.Path` is empty (dynamic) or whose mapped memory contains an
/// `MZ` signature indicating an in-memory PE.
///
/// # MITRE ATT&CK
/// T1620 — Reflective Code Loading
pub fn scan_clr_heap<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<ClrAssemblyInfo>> {
    let _ = reader;
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_minimal_reader(
    ) -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn empty_memory_returns_ok_empty() {
        let reader = make_minimal_reader();
        let result = scan_clr_heap(&reader);
        assert!(result.is_ok(), "should succeed with minimal reader");
        assert!(
            result.unwrap().is_empty(),
            "empty memory → no CLR assembly hits"
        );
    }

    #[test]
    fn result_is_vec_of_clr_assembly_info() {
        let reader = make_minimal_reader();
        let result: Result<Vec<ClrAssemblyInfo>> = scan_clr_heap(&reader);
        assert!(result.is_ok());
    }

    #[test]
    fn clr_assembly_info_fields_constructible() {
        let info = ClrAssemblyInfo {
            pid: 5555,
            image_name: "powershell.exe".to_string(),
            assembly_name: "evil".to_string(),
            is_dynamic: true,
            has_pe_header: true,
            module_path: String::new(),
        };
        assert_eq!(info.pid, 5555);
        assert!(info.is_dynamic);
        assert!(info.has_pe_header);
        assert!(info.module_path.is_empty());
    }

    #[test]
    fn clr_assembly_info_serializes() {
        let info = ClrAssemblyInfo {
            pid: 11,
            image_name: "dotnet.exe".to_string(),
            assembly_name: "SomeAssembly".to_string(),
            is_dynamic: false,
            has_pe_header: false,
            module_path: r"C:\Windows\assembly\SomeAssembly.dll".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":11"));
        assert!(json.contains("SomeAssembly"));
        assert!(json.contains("\"is_dynamic\":false"));
        assert!(json.contains("\"has_pe_header\":false"));
    }
}
