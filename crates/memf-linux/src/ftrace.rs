//! Ftrace hook detection from kernel memory.
//!
//! Detects malicious ftrace hooks by walking the `ftrace_ops_list` global
//! linked list.  Each `ftrace_ops` entry records a `func` function pointer
//! that is called for every instrumented kernel function.  A `func` pointer
//! that lies outside the kernel text range (`_stext`..`_etext`) is a strong
//! indicator of a rootkit hook.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about a single ftrace_ops entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FtraceHookInfo {
    /// Virtual address of the `ftrace_ops` struct.
    pub address: u64,
    /// `ftrace_ops.func` — the hook function pointer.
    pub func: u64,
    /// Resolved symbol name if available, otherwise hex string.
    pub func_name: String,
    /// `ftrace_ops.flags` field.
    pub flags: u32,
    /// True when `func` lies outside `_stext`..`_etext`.
    pub is_suspicious: bool,
}

/// Walk `ftrace_ops_list` and return all registered ftrace hooks.
///
/// Returns `Ok(Vec::new())` when the `ftrace_ops_list` symbol is absent.
pub fn walk_ftrace_hooks<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<FtraceHookInfo>> {
    let _ = reader;
    Ok(Vec::new())
}

/// Classify whether a `func` pointer is suspicious given the kernel text range.
pub fn classify_ftrace_hook(func: u64, stext: u64, etext: u64) -> bool {
    func < stext || func >= etext
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_no_symbol_reader() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn no_symbol_returns_empty() {
        let reader = make_no_symbol_reader();
        let result = walk_ftrace_hooks(&reader).unwrap();
        assert!(result.is_empty(), "no ftrace_ops_list symbol → empty vec");
    }

    #[test]
    fn classify_in_kernel_benign() {
        let stext = 0xFFFF_FFFF_8100_0000_u64;
        let etext = 0xFFFF_FFFF_8200_0000_u64;
        let func = 0xFFFF_FFFF_8150_0000_u64; // inside kernel text
        assert!(
            !classify_ftrace_hook(func, stext, etext),
            "in-kernel func should be benign"
        );
    }

    #[test]
    fn classify_out_of_kernel_suspicious() {
        let stext = 0xFFFF_FFFF_8100_0000_u64;
        let etext = 0xFFFF_FFFF_8200_0000_u64;
        let func = 0xFFFF_C900_0000_0000_u64; // outside kernel text → suspicious
        assert!(
            classify_ftrace_hook(func, stext, etext),
            "out-of-kernel func should be suspicious"
        );
    }

    // RED test: walk_ftrace_hooks with a real symbol and mapped ops should return entries.
    #[test]
    fn walk_ftrace_hooks_with_symbol_returns_entries() {
        use memf_core::test_builders::flags;

        // Layout of ftrace_ops (simplified):
        //   0x00: func (pointer, 8 bytes)
        //   0x08: list.next (pointer, 8 bytes) — points to next ops or back to list head
        //   0x10: list.prev (pointer, 8 bytes)
        //   0x18: flags (u32, 4 bytes)
        //
        // We create one ops entry.  ftrace_ops_list symbol points to the list head
        // (a list_head whose .next points to our ops.list).
        //
        // For simplicity we make a self-referential list: ops.list.next = list_head_addr
        // so the walk terminates after one entry.

        let list_head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let list_head_paddr: u64 = 0x0080_0000;
        let ops_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let ops_paddr: u64 = 0x0081_0000;

        // ftrace_ops.list is at offset 8 within ftrace_ops.
        // ftrace_ops_list (list_head) .next points to &ops.list = ops_vaddr + 8.
        // ops.list.next points back to list_head_vaddr (sentinel) so walk stops.

        let func_ptr: u64 = 0xFFFF_FFFF_8150_0000; // in-kernel
        let ops_flags: u32 = 0x0001;

        // Build list head page: [next=ops_vaddr+8, prev=ops_vaddr+8]
        let mut list_head_data = [0u8; 0x1000];
        list_head_data[0..8].copy_from_slice(&(ops_vaddr + 8).to_le_bytes());
        list_head_data[8..16].copy_from_slice(&(ops_vaddr + 8).to_le_bytes());

        // Build ops page:
        //   +0x00: func ptr
        //   +0x08: list.next = list_head_vaddr (sentinel → stop)
        //   +0x10: list.prev
        //   +0x18: flags
        let mut ops_data = [0u8; 0x1000];
        ops_data[0x00..0x08].copy_from_slice(&func_ptr.to_le_bytes());
        ops_data[0x08..0x10].copy_from_slice(&list_head_vaddr.to_le_bytes());
        ops_data[0x10..0x18].copy_from_slice(&list_head_vaddr.to_le_bytes());
        ops_data[0x18..0x1C].copy_from_slice(&ops_flags.to_le_bytes());

        let stext: u64 = 0xFFFF_FFFF_8100_0000;
        let etext: u64 = 0xFFFF_FFFF_8200_0000;

        let isf = IsfBuilder::new()
            .add_struct("ftrace_ops", 64)
            .add_field("ftrace_ops", "func", 0, "pointer")
            .add_field("ftrace_ops", "list", 8, "list_head")
            .add_field("ftrace_ops", "flags", 0x18, "unsigned int")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("ftrace_ops_list", list_head_vaddr)
            .add_symbol("_stext", stext)
            .add_symbol("_etext", etext)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mut mem) = PageTableBuilder::new()
            .map_4k(list_head_vaddr, list_head_paddr, flags::PRESENT | flags::WRITABLE)
            .map_4k(ops_vaddr, ops_paddr, flags::PRESENT | flags::WRITABLE)
            .build();
        mem.write_bytes(list_head_paddr, &list_head_data);
        mem.write_bytes(ops_paddr, &ops_data);

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let hooks = walk_ftrace_hooks(&reader).unwrap();
        assert_eq!(hooks.len(), 1, "should find one ftrace hook");
        assert_eq!(hooks[0].func, func_ptr);
        assert!(!hooks[0].is_suspicious, "in-kernel func should be benign");
    }
}
