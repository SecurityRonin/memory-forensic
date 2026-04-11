//! Linux network connection walker.
//!
//! Enumerates TCP connections by scanning the kernel's `tcp_hashinfo.ehash`
//! hash table. Each bucket contains a `hlist_nulls` chain of `sock` structs.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{ConnectionInfo, ConnectionState, Error, Protocol, Result};

/// Walk Linux TCP connections via `tcp_hashinfo.ehash`.
pub fn walk_connections<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<ConnectionInfo>> {
        todo!()
    }

fn read_inet_sock<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    sk_addr: u64,
) -> Result<ConnectionInfo> {
        todo!()
    }

fn ipv4_to_string(addr: u32) -> String {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_net_reader(data: &[u8], vaddr: u64, paddr: u64) -> ObjectReader<SyntheticPhysMem> {
        todo!()
    }

    #[test]
    fn walk_single_connection() {
        todo!()
    }

    #[test]
    fn empty_hash_table() {
        todo!()
    }

    #[test]
    fn ipv4_formatting() {
        todo!()
    }
}
