//! Linux network protocol handler (`seq_afinfo`) hook detector.
//!
//! Linux rootkits commonly replace the `seq_show` function pointer in
//! `tcp_seq_afinfo`, `udp_seq_afinfo`, and similar protocol handler
//! structures to hide network connections from `/proc/net/tcp` and
//! `/proc/net/udp`. This module reads those structs from memory and
//! compares each `seq_ops` function pointer against the kernel text
//! range (`_stext`..`_etext`) to detect hooks.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Protocol handler symbols to check, paired with human-readable names.
const AFINFO_SYMBOLS: &[(&str, &str)] = &[
    ("tcp_seq_afinfo", "tcp"),
    ("udp_seq_afinfo", "udp"),
    ("tcp6_seq_afinfo", "tcp6"),
    ("udp6_seq_afinfo", "udp6"),
    ("raw_seq_afinfo", "raw"),
];

/// Function pointer field names within the `seq_operations` struct.
const SEQ_OPS_FIELDS: &[&str] = &["show", "start", "next", "stop"];

/// Information about a network protocol handler with potential hooks.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AfInfoHookInfo {
    /// Protocol name, e.g. "tcp", "udp", "tcp6", "udp6", "raw".
    pub protocol: String,
    /// Kernel symbol name, e.g. "tcp_seq_afinfo".
    pub struct_name: String,
    /// Field path that was checked, e.g. "seq_ops.show".
    pub field: String,
    /// Virtual address the function pointer targets.
    pub hook_address: u64,
    /// Expected module (should be kernel text).
    pub expected_module: String,
    /// Where the hook actually points.
    pub actual_module: String,
    /// Whether this function pointer is considered hooked.
    pub is_hooked: bool,
}

/// Classify whether a function pointer in a `seq_afinfo` struct is hooked.
///
/// - Address of `0` is not considered hooked (null/unset pointer).
/// - Address within `[kernel_start, kernel_end]` is benign (kernel text).
/// - Address outside that range is suspicious (hooked).
pub fn classify_afinfo_hook(hook_addr: u64, kernel_start: u64, kernel_end: u64) -> bool {
        todo!()
    }

/// Walk network protocol handler structs and check for hooks.
///
/// Looks up `tcp_seq_afinfo`, `udp_seq_afinfo`, `tcp6_seq_afinfo`,
/// `udp6_seq_afinfo`, and `raw_seq_afinfo` symbols. For each, reads
/// the `seq_ops` function pointers (`show`, `start`, `next`, `stop`)
/// and compares against the kernel text range.
///
/// Returns `Ok(Vec::new())` if no afinfo symbols are found (graceful
/// degradation).
pub fn walk_check_afinfo<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<AfInfoHookInfo>> {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags as ptflags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // -----------------------------------------------------------------------
    // classify_afinfo_hook unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn hook_outside_kernel_suspicious() {
        todo!()
    }

    #[test]
    fn hook_inside_kernel_benign() {
        todo!()
    }

    #[test]
    fn hook_zero_benign() {
        todo!()
    }

    #[test]
    fn classify_multiple_protocols() {
        todo!()
    }

    // -----------------------------------------------------------------------
    // AfInfoHookInfo struct tests
    // -----------------------------------------------------------------------

    #[test]
    fn afinfo_hook_info_serializes() {
        todo!()
    }

    // -----------------------------------------------------------------------
    // walk_check_afinfo integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn walk_check_afinfo_no_symbols_returns_empty() {
        todo!()
    }

    #[test]
    fn walk_check_afinfo_detects_hooked_seq_ops() {
        todo!()
    }
}
