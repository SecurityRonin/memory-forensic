//! Process hollowing detection.
//!
//! Detects process hollowing by reading the PE header at each process's
//! `PEB.ImageBaseAddress` and checking for:
//! 1. Missing MZ magic (`0x4D5A`) — image unmapped or overwritten
//! 2. Missing PE signature (`PE\0\0`) — corrupt or replaced header
//! 3. `SizeOfImage` mismatch between PE header and LDR module entry
//!
//! These indicators reveal when malware creates a legitimate process in a
//! suspended state, unmaps its image, and replaces it with malicious code.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{process, Result, WinHollowingInfo};

/// Check all running processes for signs of process hollowing.
///
/// For each process with a non-null PEB, switches to the process's CR3
/// and reads the PE header at `PEB.ImageBaseAddress`. Compares the PE
/// `SizeOfImage` against the first entry in `InLoadOrderModuleList`.
///
/// Returns one `WinHollowingInfo` per process (including clean ones).
/// Check the `suspicious` field to filter findings.
pub fn check_hollowing<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<WinHollowingInfo>> {
        todo!()
    }

/// Read and validate the PE header at the given virtual address.
///
/// Returns `(has_mz, has_pe, size_of_image)`.
/// If the memory is unreadable, returns `(false, false, 0)`.
fn read_pe_header<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    image_base: u64,
) -> (bool, bool, u32) {
        todo!()
    }

/// Get the image size from the first entry in `InLoadOrderModuleList`.
///
/// The first entry typically represents the process's main executable.
/// Returns 0 if the LDR data is unreadable.
fn ldr_first_image_size<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, peb_addr: u64) -> u64 {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn utf16le(s: &str) -> Vec<u8> {
        todo!()
    }

    /// Build a minimal valid PE header at a given offset in a buffer.
    /// Returns the expected SizeOfImage value.
    fn write_pe_header(buf: &mut [u8], offset: usize, size_of_image: u32) -> u32 {
        todo!()
    }

    /// Set up a single-process memory layout for hollowing tests.
    /// Returns (cr3, mem, ps_head_vaddr).
    fn build_single_process_memory(
        pid: u64,
        name: &str,
        peb_paddr: u64,
        image_base_vaddr: u64,
        image_base_paddr: u64,
        image_data: &[u8],
        ldr_size: u64,
    ) -> (u64, memf_core::test_builders::SyntheticPhysMem, u64) {
        todo!()
    }

    #[test]
    fn legitimate_process_not_flagged() {
        todo!()
    }

    #[test]
    fn hollowed_process_no_mz_flagged() {
        todo!()
    }

    #[test]
    fn hollowed_process_size_mismatch_flagged() {
        todo!()
    }

    #[test]
    fn system_process_skipped_no_peb() {
        todo!()
    }

    #[test]
    fn mz_present_but_pe_missing_flagged() {
        todo!()
    }

    /// read_pe_header: MZ present but header is exactly 0x40 bytes —
    /// e_lfanew could be within the buffer but the PE sig is at the boundary.
    /// Exercises the `header.len() < pe_off + 4` extended-read branch.
    #[test]
    fn read_pe_header_pe_beyond_512_bytes_extended_read() {
        todo!()
    }

    /// ldr_first_image_size: InLoadOrderModuleList.Flink == list head (empty list) → returns 0.
    /// Exercises the `first_entry == list_head` guard in ldr_first_image_size.
    #[test]
    fn ldr_first_image_size_empty_ldr_list_returns_zero() {
        todo!()
    }

    /// WinHollowingInfo serializes correctly.
    #[test]
    fn win_hollowing_info_serializes() {
        todo!()
    }
}
