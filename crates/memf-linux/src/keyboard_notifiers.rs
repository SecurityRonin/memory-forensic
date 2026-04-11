//! Keyboard notifier chain forensics — keylogger detection.
//!
//! Walks the `keyboard_notifier_list` (`raw_notifier_head`) linked list of
//! `notifier_block` structures.  Each entry records a `notifier_call`
//! function pointer.  A pointer outside the kernel text range indicates a
//! potential keylogger injected by a rootkit.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about a single `notifier_block` on the keyboard notifier chain.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KeyboardNotifierInfo {
    /// Virtual address of the `notifier_block`.
    pub address: u64,
    /// `notifier_block.notifier_call` — function pointer.
    pub notifier_call: u64,
    /// `notifier_block.priority`.
    pub priority: i32,
    /// True when `notifier_call` lies outside `_stext`..`_etext`.
    pub is_suspicious: bool,
}

/// Walk `keyboard_notifier_list` and return all registered notifier blocks.
///
/// Returns `Ok(Vec::new())` when the `keyboard_notifier_list` symbol is absent.
///
/// `raw_notifier_head` layout:
///   +0: head (pointer to first `notifier_block`, or NULL)
///
/// `notifier_block` layout:
///   +0:  notifier_call (pointer)
///   +8:  next (pointer to next notifier_block, or NULL)
///   +16: priority (i32)
pub fn walk_keyboard_notifiers<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<KeyboardNotifierInfo>> {
        todo!()
    }

/// Classify a notifier_call pointer as suspicious if outside kernel text.
pub fn classify_notifier(notifier_call: u64, stext: u64, etext: u64) -> bool {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
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

    // RED test: walk with a symbol and one notifier_block in memory returns an entry.
    #[test]
    fn walk_keyboard_notifiers_with_symbol_returns_entry() {
        todo!()
    }
}
