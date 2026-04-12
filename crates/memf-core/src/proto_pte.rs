//! Prototype PTE resolution for shared memory sections.

/// Resolves prototype PTEs to their backing physical address.
///
/// In Windows, when a PTE has bit 10 set (not-present), it indicates the page
/// is shared via a prototype PTE. Implementations of this trait decode the raw
/// PTE value and return the resolved physical address of the backing page.
pub trait PrototypePteSource: Send + Sync {
    /// Given the raw non-present PTE value (with bit 10 set), return the
    /// resolved physical address of the backing page, or `None` if unavailable.
    fn resolve(&self, pte_value: u64) -> Option<u64>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_builders::MockPrototypePteSource;

    #[test]
    fn mock_source_returns_mapped_address() {
        let source = MockPrototypePteSource::new(vec![(1 << 10, 0x00A0_0000)]);
        assert_eq!(source.resolve(1 << 10), Some(0x00A0_0000));
    }

    #[test]
    fn mock_source_returns_none_for_unmapped() {
        let source = MockPrototypePteSource::new(vec![]);
        assert_eq!(source.resolve(1 << 10), None);
    }
}
