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
#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
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
        todo!()
    }

    #[test]
    fn clean_function_no_hook() {
        todo!()
    }

    #[test]
    fn detects_relative_jmp_hook() {
        todo!()
    }

    #[test]
    fn detects_movabs_jmp_rax_hook() {
        todo!()
    }

    #[test]
    fn analyze_prologue_normal() {
        todo!()
    }

    #[test]
    fn detects_indirect_jmp_hook() {
        todo!()
    }

    #[test]
    fn skips_symbol_with_unreadable_prologue() {
        todo!()
    }

    #[test]
    fn detects_rel_jmp_hook_outside_text_region() {
        todo!()
    }

    #[test]
    fn analyze_prologue_short_bytes_returns_none() {
        todo!()
    }

    #[test]
    fn skips_missing_symbols() {
        todo!()
    }
}
