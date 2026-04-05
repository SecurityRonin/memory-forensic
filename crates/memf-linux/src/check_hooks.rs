//! Linux kernel inline hook detector.
//!
//! Checks the first bytes of key kernel functions for JMP/CALL
//! trampolines that indicate inline hooking. Reads the function
//! prologue and checks for x86_64 patterns like:
//!   - `0xE9` (relative JMP)
//!   - `0xFF 0x25` (absolute indirect JMP)
//!   - `0x48 0xB8 ... 0xFF 0xE0` (MOV RAX, imm64; JMP RAX)

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, KernelHookInfo, Result};

/// Number of prologue bytes to read from each function.
const PROLOGUE_SIZE: usize = 16;

/// Well-known kernel functions to check for inline hooks.
const FUNCTIONS_TO_CHECK: &[&str] = &[
    "sys_read",
    "sys_write",
    "sys_open",
    "sys_close",
    "vfs_read",
    "vfs_write",
    "tcp4_seq_show",
    "filldir",
    "filldir64",
];

/// Check key kernel functions for inline hooks.
///
/// Reads the first [`PROLOGUE_SIZE`] bytes of each function in
/// [`FUNCTIONS_TO_CHECK`] and looks for JMP/CALL trampoline patterns.
pub fn check_inline_hooks<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<KernelHookInfo>> {
    todo!()
}

/// Analyze a function prologue for hook patterns.
///
/// Returns `(hook_type, target)` if a hook is detected, or `("none", None)`.
fn analyze_prologue(bytes: &[u8], func_addr: u64) -> (String, Option<u64>) {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags as ptflags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_test_reader(
        data: &[u8],
        func_vaddr: u64,
        func_paddr: u64,
        stext: u64,
        etext: u64,
        func_symbols: &[(&str, u64)],
    ) -> ObjectReader<SyntheticPhysMem> {
        let mut builder = IsfBuilder::new()
            .add_struct("task_struct", 64)
            .add_field("task_struct", "pid", 0, "int")
            .add_symbol("_stext", stext)
            .add_symbol("_etext", etext);

        for &(name, addr) in func_symbols {
            builder = builder.add_symbol(name, addr);
        }

        let isf = builder.build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(func_vaddr, func_paddr, ptflags::WRITABLE)
            .write_phys(func_paddr, data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn clean_function_no_hook() {
        // Normal function prologue: push rbp; mov rbp, rsp; sub rsp, 0x20
        let mut prologue = vec![0u8; 4096];
        prologue[0] = 0x55; // push rbp
        prologue[1] = 0x48; // REX.W
        prologue[2] = 0x89; // mov
        prologue[3] = 0xE5; // rbp, rsp

        let func_vaddr: u64 = 0xFFFF_8000_0001_0000;
        let func_paddr: u64 = 0x0080_0000;
        let stext: u64 = 0xFFFF_8000_0000_0000;
        let etext: u64 = 0xFFFF_8000_00FF_FFFF;

        let reader = make_test_reader(
            &prologue,
            func_vaddr,
            func_paddr,
            stext,
            etext,
            &[("sys_read", func_vaddr)],
        );
        let results = check_inline_hooks(&reader).unwrap();

        assert_eq!(results.len(), 1);
        assert!(!results[0].suspicious);
        assert_eq!(results[0].symbol, "sys_read");
        assert_eq!(results[0].hook_type, "none");
    }

    #[test]
    fn detects_relative_jmp_hook() {
        // Hooked: E9 xx xx xx xx (relative JMP)
        let mut prologue = vec![0u8; 4096];
        prologue[0] = 0xE9; // JMP rel32
        prologue[1..5].copy_from_slice(&0x1000i32.to_le_bytes());

        let func_vaddr: u64 = 0xFFFF_8000_0001_0000;
        let func_paddr: u64 = 0x0080_0000;
        let stext: u64 = 0xFFFF_8000_0000_0000;
        let etext: u64 = 0xFFFF_8000_00FF_FFFF;

        let reader = make_test_reader(
            &prologue,
            func_vaddr,
            func_paddr,
            stext,
            etext,
            &[("sys_read", func_vaddr)],
        );
        let results = check_inline_hooks(&reader).unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].suspicious);
        assert_eq!(results[0].hook_type, "jmp_rel32");
        assert!(results[0].target.is_some());
    }

    #[test]
    fn detects_movabs_jmp_rax_hook() {
        // Hooked: 48 B8 <8 bytes> FF E0 (MOV RAX, imm64; JMP RAX)
        let mut prologue = vec![0u8; 4096];
        prologue[0] = 0x48; // REX.W
        prologue[1] = 0xB8; // MOV RAX, imm64
        let target: u64 = 0xFFFF_C900_DEAD_BEEF;
        prologue[2..10].copy_from_slice(&target.to_le_bytes());
        prologue[10] = 0xFF; // JMP
        prologue[11] = 0xE0; // RAX

        let func_vaddr: u64 = 0xFFFF_8000_0001_0000;
        let func_paddr: u64 = 0x0080_0000;
        let stext: u64 = 0xFFFF_8000_0000_0000;
        let etext: u64 = 0xFFFF_8000_00FF_FFFF;

        let reader = make_test_reader(
            &prologue,
            func_vaddr,
            func_paddr,
            stext,
            etext,
            &[("sys_read", func_vaddr)],
        );
        let results = check_inline_hooks(&reader).unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].suspicious);
        assert_eq!(results[0].hook_type, "mov_rax_jmp");
        assert_eq!(results[0].target, Some(target));
    }

    #[test]
    fn analyze_prologue_normal() {
        let bytes = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0, 0, 0, 0, 0, 0, 0, 0];
        let (hook_type, target) = analyze_prologue(&bytes, 0xFFFF_8000_0001_0000);
        assert_eq!(hook_type, "none");
        assert_eq!(target, None);
    }

    #[test]
    fn skips_missing_symbols() {
        // If sys_read symbol is missing, just skip it (no error)
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 64)
            .add_field("task_struct", "pid", 0, "int")
            .add_symbol("_stext", 0xFFFF_8000_0000_0000)
            .add_symbol("_etext", 0xFFFF_8000_00FF_FFFF)
            // No function symbols
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = check_inline_hooks(&reader).unwrap();
        assert!(results.is_empty());
    }
}
