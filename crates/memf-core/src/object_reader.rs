//! High-level kernel object reading using symbol resolution.
// Stub -- implemented in Task 11.

use std::marker::PhantomData;

use memf_format::PhysicalMemoryProvider;

/// Reads kernel objects from a physical memory dump using symbol information.
///
/// Combines a [`PhysicalMemoryProvider`] with page table walking and symbol
/// resolution to provide high-level access to kernel data structures.
pub struct ObjectReader<P: PhysicalMemoryProvider> {
    _marker: PhantomData<P>,
}
