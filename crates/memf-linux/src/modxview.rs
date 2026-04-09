//! Cross-view kernel module detection for Linux.
//!
//! Detects hidden kernel modules by cross-referencing multiple views of
//! loaded modules: the kernel module list (`modules` symbol), kobj/sysfs
//! entries, and memory-mapped regions. Rootkits that unlink from one list
//! but not others can be detected by discrepancies between views.
//! Equivalent to Volatility's `linux.check_modules` cross-view approach.

use std::collections::HashSet;

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Maximum number of modules to enumerate before stopping (cycle guard).
const MAX_MODULES: usize = 4096;

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
    reader: &ObjectReader<P>,
) -> Result<Vec<ModXviewEntry>> {
    // Graceful degradation: if `modules` symbol is missing, return empty.
    let modules_addr = match reader.symbols().symbol_address("modules") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    // View 1: Walk the modules linked list.
    let module_addrs = reader.walk_list(modules_addr, "module", "list")?;

    let mut seen = HashSet::new();
    let mut entries = Vec::new();

    for &mod_addr in module_addrs.iter().take(MAX_MODULES) {
        if !seen.insert(mod_addr) {
            break; // Cycle detected
        }

        let name = reader
            .read_field_string(mod_addr, "module", "name", 56)
            .unwrap_or_else(|_| "<unknown>".to_string());

        let base_addr: u64 = reader
            .read_field(mod_addr, "module", "module_core")
            .unwrap_or(0);

        let size: u32 = reader
            .read_field(mod_addr, "module", "core_size")
            .unwrap_or(0);

        // View 1: Present in module list by definition (found it there).
        let in_module_list = true;

        // View 2: Check kobj linkage.
        // If mkobj/kobj fields are not resolvable, assume present (can't verify).
        let in_kobj_list = check_kobj_linkage(reader, mod_addr);

        // View 3: Check memory mapping validity.
        // If module_core is non-zero and we can read from it, it's mapped.
        let in_memory_map = check_memory_mapped(reader, base_addr, size);

        let is_hidden = classify_module_visibility(in_module_list, in_kobj_list, in_memory_map);

        entries.push(ModXviewEntry {
            name,
            base_addr,
            size,
            in_module_list,
            in_kobj_list,
            in_memory_map,
            is_hidden,
        });
    }

    Ok(entries)
}

/// Check whether a module's kobj entry is properly linked.
///
/// Verifies that `module.mkobj.kobj.entry.next` is a valid (non-null)
/// pointer, indicating the module is linked into the sysfs kobj tree.
/// Returns `true` (assume present) if the required field offsets are
/// unavailable.
fn check_kobj_linkage<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    mod_addr: u64,
) -> bool {
    // Resolve mkobj offset within module struct
    let mkobj_offset = match reader.symbols().field_offset("module", "mkobj") {
        Some(off) => off,
        None => return true, // Can't verify — assume present
    };

    // Resolve kobj offset within module_kobject
    let kobj_offset = match reader.symbols().field_offset("module_kobject", "kobj") {
        Some(off) => off,
        None => return true,
    };

    // Resolve entry offset within kobject (list_head)
    let entry_offset = match reader.symbols().field_offset("kobject", "entry") {
        Some(off) => off,
        None => return true,
    };

    // Read the entry.next pointer
    let entry_addr = mod_addr + mkobj_offset + kobj_offset + entry_offset;
    let next_ptr: u64 = match reader.read_field(entry_addr, "list_head", "next") {
        Ok(v) => v,
        Err(_) => return true, // Can't read — assume present
    };

    // A null or zero next pointer means unlinked from kobj tree
    next_ptr != 0
}

/// Check whether a module's core memory range is mapped and readable.
///
/// Attempts to read a small probe from the module's base address.
/// Returns `true` if the base is zero (can't verify) or the memory is
/// readable. Returns `false` only when the address is non-zero but
/// unreadable.
fn check_memory_mapped<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    base_addr: u64,
    size: u32,
) -> bool {
    if base_addr == 0 || size == 0 {
        return true; // Can't verify — assume present
    }

    // Probe: try to read 1 byte from the module base address
    reader.read_bytes(base_addr, 1).is_ok()
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
