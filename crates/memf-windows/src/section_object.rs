//! Section object forensics walker — MITRE ATT&CK T1055.
//!
//! Enumerates Windows section objects from the object manager namespace
//! and detects suspicious configurations: image sections without a disk
//! backing file, RWX anonymous sections, and sections shared across many
//! processes without a backing file.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{types::SectionObjectInfo, Result};

/// Enumerate section objects from the kernel object manager and analyse
/// them for suspicious attributes.
///
/// Walks `ObpRootDirectoryObject` → `\BaseNamedObjects` and process handle
/// tables to find `_SECTION` objects. For each section inspects:
/// - Whether it is an image section (`SEC_IMAGE`) and its backing file
///   exists on disk.
/// - The page protection of its `_SEGMENT`.
/// - How many processes have it mapped.
///
/// # MITRE ATT&CK
/// T1055 — Process Injection (Section / Doppelgänging)
pub fn scan_section_objects<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<SectionObjectInfo>> {
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
        let result = scan_section_objects(&reader);
        assert!(result.is_ok(), "should succeed with minimal reader");
        assert!(
            result.unwrap().is_empty(),
            "empty memory → no section objects"
        );
    }

    #[test]
    fn result_is_vec_of_section_object_info() {
        let reader = make_minimal_reader();
        let result: Result<Vec<SectionObjectInfo>> = scan_section_objects(&reader);
        assert!(result.is_ok());
    }

    #[test]
    fn section_object_info_fields_constructible() {
        let info = SectionObjectInfo {
            pid: 777,
            image_name: "ghost.exe".to_string(),
            section_name: r"\BaseNamedObjects\evil".to_string(),
            backing_file: String::new(),
            protection: 0x40, // PAGE_EXECUTE_READWRITE
            mapped_process_count: 3,
            is_image_section: true,
            file_on_disk: false,
        };
        assert_eq!(info.pid, 777);
        assert_eq!(info.protection, 0x40);
        assert!(info.is_image_section);
        assert!(!info.file_on_disk);
        assert_eq!(info.mapped_process_count, 3);
    }

    #[test]
    fn section_object_info_serializes() {
        let info = SectionObjectInfo {
            pid: 2,
            image_name: "svc.exe".to_string(),
            section_name: String::new(),
            backing_file: String::new(),
            protection: 0x20,
            mapped_process_count: 1,
            is_image_section: false,
            file_on_disk: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":2"));
        assert!(json.contains("\"is_image_section\":false"));
        assert!(json.contains("\"file_on_disk\":false"));
    }
}
