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
///
/// `ftrace_ops` layout (simplified, x86-64):
///   +0x00: func (pointer) — the hook callback
///   +0x08: list (list_head) — embedded linked list
///   +0x18: flags (u32)
pub fn walk_ftrace_hooks<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<FtraceHookInfo>> {
        todo!()
    }

/// Classify whether a `func` pointer is suspicious given the kernel text range.
pub fn classify_ftrace_hook(func: u64, stext: u64, etext: u64) -> bool {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_no_symbol_reader() -> ObjectReader<SyntheticPhysMem> {
        todo!()
    }

    #[test]
    fn no_symbol_returns_empty() {
        todo!()
    }

    #[test]
    fn classify_in_kernel_benign() {
        todo!()
    }

    #[test]
    fn classify_out_of_kernel_suspicious() {
        todo!()
    }

    // RED test: walk_ftrace_hooks with a real symbol and mapped ops should return entries.
    #[test]
    fn walk_ftrace_hooks_with_symbol_returns_entries() {
        todo!()
    }
}
