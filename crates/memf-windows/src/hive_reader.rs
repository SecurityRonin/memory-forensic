//! winreg-core [`CellReader`] backend over an in-memory kernel hive.
//!
//! memf's HMAP cell-map translation ([`cell_index_to_va`]) resolves a registry
//! cell index to the virtual address of its `_HCELL` size header within a live,
//! non-contiguous in-memory hive. winreg-core's [`CellReader`] trait wants the
//! same thing expressed as offset → `(CellHeader, body)`. This adapter bridges
//! the two: it lets winreg-core's shared `Key`/`Value`/`SubkeyIndex` navigation
//! walk a hive straight out of the memory image, reusing the audited nk/vk/lf
//! decoders instead of memf's parallel reimplementation.
//!
//! A winreg-core [`CellOffset`] and a memf cell index are the *same* 32-bit
//! value — both are hive-bins-relative — so no remapping is needed: the offset
//! is fed directly to [`cell_index_to_va`].

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use winreg_core::cell_reader::CellReader;
use winreg_core::error::{HiveError, Result as HiveResult};
use winreg_format::cells::{CellHeader, CellOffset};

/// A winreg-core [`CellReader`] that resolves cells through memf's HMAP cell map.
///
/// Borrows the [`ObjectReader`] and the `_CMHIVE`/`_HHIVE` virtual address
/// (`hhive_addr`) that [`cell_index_to_va`] requires — the same VA the existing
/// memf registry walkers pass, *not* the `_HBASE_BLOCK` pointer.
pub struct MemfHiveReader<'r, P: PhysicalMemoryProvider> {
    reader: &'r ObjectReader<P>,
    hhive_addr: u64,
}

impl<'r, P: PhysicalMemoryProvider> MemfHiveReader<'r, P> {
    /// Build a backend for the hive whose `_CMHIVE`/`_HHIVE` lives at
    /// `hhive_addr`. This is the VA the HMAP cell-index translation walks; it is
    /// `RegistryHive::base_addr`, never the base-block pointer.
    pub fn new(reader: &'r ObjectReader<P>, hhive_addr: u64) -> Self {
        Self { reader, hhive_addr }
    }
}

impl<P: PhysicalMemoryProvider> CellReader for MemfHiveReader<'_, P> {
    /// Resolve a hive-bins-relative [`CellOffset`] (= memf cell index) through
    /// the HMAP to the `_HCELL` size header, then read the header and body.
    ///
    /// Unlike the flat-file backend this does **not** reject unallocated cells:
    /// a live in-memory hive is allocation-agnostic, and the shared navigation
    /// only ever follows offsets the hive itself recorded.
    fn read_cell_raw(&self, _offset: CellOffset) -> HiveResult<(CellHeader, Vec<u8>)> {
        // RED stub — not yet implemented.
        let _ = (self.reader, self.hhive_addr);
        Err(HiveError::NullOffset)
    }
}
