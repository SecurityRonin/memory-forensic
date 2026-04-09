//! Cross-view kernel module detection for Linux.
//!
//! Detects hidden kernel modules by cross-referencing multiple views of
//! loaded modules: the kernel module list (`modules` symbol), kobj/sysfs
//! entries, and memory-mapped regions. Rootkits that unlink from one list
//! but not others can be detected by discrepancies between views.
//! Equivalent to Volatility's `linux.check_modules` cross-view approach.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Cross-view module visibility entry.
///
/// Each entry represents a kernel module found in at least one view,
/// with flags indicating which views contain it. A module missing from
/// any view but present in others is classified as hidden/suspicious.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ModXviewEntry {
    /// Module name from the kernel `module.name` field.
    pub name: String,
    /// Base virtual address of the module's core section.
    pub base_addr: u64,
    /// Size of the module's core section in bytes.
    pub size: u32,
    /// Whether the module was found in the `modules` linked list.
    pub in_module_list: bool,
    /// Whether the module was found in the kobj/sysfs entries.
    pub in_kobj_list: bool,
    /// Whether the module's memory range is mapped and valid.
    pub in_memory_map: bool,
    /// Whether this module is hidden/suspicious (missing from at least
    /// one view while present in another).
    pub is_hidden: bool,
}

/// Classify module visibility across three kernel views.
///
/// Returns `true` (hidden/suspicious) if the module is missing from any
/// view but present in at least one. All-false means the module was not
/// found at all (not suspicious — just absent). All-true means benign.
pub fn classify_module_visibility(
    in_module_list: bool,
    in_kobj_list: bool,
    in_memory_map: bool,
) -> bool {
    let present_count = [in_module_list, in_kobj_list, in_memory_map]
        .iter()
        .filter(|&&v| v)
        .count();

    // Hidden if present in at least one view but not all three
    present_count > 0 && present_count < 3
}

/// Walk and cross-reference kernel module views for hidden module detection.
///
/// Collects modules from three views:
/// 1. **Module list** — the `modules` linked list (`LIST_HEAD`)
/// 2. **Kobj list** — `mkobj.kobj.entry` linkage in sysfs
/// 3. **Memory map** — `module_core`/`module_init` address range validity
///
/// Each unique module is checked against all views and classified.
/// Returns `Ok(Vec::new())` if the `modules` symbol is not found
/// (graceful degradation).
pub fn walk_modxview<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
) -> Result<Vec<ModXviewEntry>> {
    todo!("walk_modxview implementation")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_all_visible_benign() {
        assert!(!classify_module_visibility(true, true, true));
    }

    #[test]
    fn classify_missing_from_list_suspicious() {
        // Present in kobj and memory, but missing from module list
        assert!(classify_module_visibility(false, true, true));
    }

    #[test]
    fn classify_missing_from_kobj_suspicious() {
        // Present in module list and memory, but missing from kobj
        assert!(classify_module_visibility(true, false, true));
    }

    #[test]
    fn classify_all_missing_not_suspicious() {
        // Not found anywhere — not suspicious, just absent
        assert!(!classify_module_visibility(false, false, false));
    }

    #[test]
    fn walk_no_symbol_returns_empty() {
        use memf_core::test_builders::PageTableBuilder;
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        // Build a reader with no `modules` symbol
        let isf = IsfBuilder::new()
            .add_struct("module", 64)
            .add_field("module", "name", 0, "char")
            .add_field("module", "list", 8, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_modxview(&reader);
        // With todo!(), this will panic — but after GREEN it should return Ok(vec![])
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn modxview_entry_serializes() {
        let entry = ModXviewEntry {
            name: "test_module".to_string(),
            base_addr: 0xFFFF_8000_0000_1000,
            size: 4096,
            in_module_list: true,
            in_kobj_list: true,
            in_memory_map: false,
            is_hidden: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("test_module"));
        assert!(json.contains("\"is_hidden\":true"));
    }
}
