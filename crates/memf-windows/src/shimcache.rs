//! Windows AppCompatCache (Shimcache) extraction from kernel memory.
//!
//! The Application Compatibility Cache tracks recently executed programs
//! and is a key forensic artifact for proving execution history. Windows
//! maintains this cache in kernel memory via the `g_ShimCache` symbol,
//! which points to an `_RTL_AVL_TABLE` (Win8+) or linked list (Win7)
//! of `_SHIM_CACHE_ENTRY` structures.
//!
//! Each entry records the full executable path, last-modification
//! timestamp (FILETIME), an execution flag (InsertFlag), and the size
//! of any associated shim data. The position in the cache indicates
//! recency — position 0 is the most recently cached entry.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;

/// Maximum number of shimcache entries to iterate (safety limit).
const MAX_SHIMCACHE_ENTRIES: usize = 4096;

/// A single Application Compatibility Cache (Shimcache) entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShimcacheEntry {
    /// Full executable path (e.g., `\??\C:\Windows\System32\cmd.exe`).
    pub path: String,
    /// FILETIME of the file's last modification timestamp.
    pub last_modified: u64,
    /// Whether the InsertFlag indicates the program was executed.
    pub exec_flag: bool,
    /// Size of shim data associated with this entry.
    pub data_size: u32,
    /// Position in the cache (0 = most recent).
    pub position: u32,
}

/// Walk the AppCompatCache (Shimcache) from kernel memory.
///
/// Locates the `g_ShimCache` symbol, which points to an RTL_AVL_TABLE
/// containing `_SHIM_CACHE_ENTRY` nodes. Each node holds a
/// `_UNICODE_STRING` path, a FILETIME timestamp, an insert/exec flag,
/// and shim data size.
///
/// Returns an empty `Vec` if the required symbols are not present
/// (graceful degradation).
///
/// # Errors
///
/// Returns an error if memory reads fail after the symbol has been
/// located and validated.
pub fn walk_shimcache<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<ShimcacheEntry>> {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// Build an ISF with the shimcache structures but no g_ShimCache symbol.
    fn shimcache_isf_no_symbol() -> IsfBuilder {
        todo!()
    }

    /// Build an ISF with the shimcache structures AND the g_ShimCache symbol.
    fn shimcache_isf_with_symbol(symbol_addr: u64) -> IsfBuilder {
        todo!()
    }

    /// Encode a Rust &str as UTF-16LE bytes.
    fn encode_utf16le(s: &str) -> Vec<u8> {
        todo!()
    }

    // ── No symbol → empty Vec ───────────────────────────────────────

    /// No g_ShimCache symbol → empty Vec (not an error).
    #[test]
    fn walk_shimcache_no_symbol() {
        todo!()
    }

    // ── Single entry with path + timestamp ──────────────────────────

    // Memory layout:
    //   g_ShimCache pointer @ PTR_VADDR → HEADER_VADDR
    //
    //   _SHIM_CACHE_HEADER @ HEADER_VADDR:
    //     NumEntries = 1
    //     ListHead.Flink @ +0x8 → ENTRY0_VADDR
    //
    //   _SHIM_CACHE_ENTRY @ ENTRY0_VADDR:
    //     ListEntry.Flink @ +0x0 → HEADER_VADDR + 0x8 (back to list head)
    //     Path @ +0x10 (_UNICODE_STRING → "\\??\\C:\\Windows\\System32\\cmd.exe")
    //     LastModified @ +0x20 = 0x01D9_ABCD_1234_5678
    //     InsertFlag @ +0x28 = 0 (not executed)
    //     DataSize @ +0x2C = 0

    const PTR_VADDR: u64 = 0xFFFF_8000_0010_0000;
    const PTR_PADDR: u64 = 0x0080_0000;
    const HEADER_VADDR: u64 = 0xFFFF_8000_0020_0000;
    const HEADER_PADDR: u64 = 0x0090_0000;
    const ENTRY0_VADDR: u64 = 0xFFFF_8000_0030_0000;
    const ENTRY0_PADDR: u64 = 0x00A0_0000;
    const PATH0_BUF_VADDR: u64 = 0xFFFF_8000_0030_1000;
    const PATH0_BUF_PADDR: u64 = 0x00A1_0000;

    fn build_single_entry_reader(insert_flag: u32) -> ObjectReader<SyntheticPhysMem> {
        todo!()
    }

    /// One entry with path + timestamp → correct ShimcacheEntry.
    #[test]
    fn walk_shimcache_single_entry() {
        todo!()
    }

    // ── Exec flag set → exec_flag = true ────────────────────────────

    /// Entry with InsertFlag set → exec_flag = true.
    #[test]
    fn shimcache_exec_flag() {
        todo!()
    }
}
