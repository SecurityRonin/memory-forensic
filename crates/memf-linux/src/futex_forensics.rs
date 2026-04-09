//! Futex forensics for Linux memory forensics.
//!
//! Walks the kernel `futex_queues` hash table to enumerate all pending
//! futex wait entries. Cross-process futexes from unexpected address ranges
//! and abnormally high waiter counts are flagged as suspicious.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about a futex entry found in the kernel futex hash table.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FutexInfo {
    /// Virtual address of the futex key.
    pub key_address: u64,
    /// PID of the process owning the futex.
    pub owner_pid: u32,
    /// Number of waiters on this futex.
    pub waiter_count: u32,
    /// Futex type: "private" or "shared".
    pub futex_type: String,
    /// True when this futex matches attack patterns (confusion attack or DoS).
    pub is_suspicious: bool,
}

/// Classify whether a futex entry is suspicious.
pub fn classify_futex(_key_address: u64, _owner_pid: u32, _waiter_count: u32) -> bool {
    todo!("classify_futex not yet implemented")
}

/// Walk the kernel futex hash table and return all pending futex entries.
///
/// Returns `Ok(Vec::new())` when the `futex_queues` symbol or required ISF
/// offsets are absent (graceful degradation).
pub fn walk_futex_table<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
) -> Result<Vec<FutexInfo>> {
    todo!("walk_futex_table not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
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
    fn classify_high_waiter_count_suspicious() {
        assert!(
            classify_futex(0x7FFF_0000_0000, 500, 1001),
            "high waiter count must be suspicious"
        );
    }

    #[test]
    fn classify_normal_futex_benign() {
        assert!(
            !classify_futex(0x7F00_0000_1000, 1234, 3),
            "normal futex must not be suspicious"
        );
    }

    #[test]
    fn walk_futex_no_symbol_returns_empty() {
        let reader = make_no_symbol_reader();
        let result = walk_futex_table(&reader).unwrap();
        assert!(result.is_empty(), "no futex_queues symbol → empty vec expected");
    }
}
