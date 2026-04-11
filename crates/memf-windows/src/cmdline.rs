//! Windows process command line extraction.
//!
//! Reads command lines from `_EPROCESS` -> `_PEB` ->
//! `_RTL_USER_PROCESS_PARAMETERS.CommandLine` for each process.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;
use crate::{Error, Result, WinCmdlineInfo};

/// Walk all processes and extract their command lines.
///
/// For each process with a non-null PEB, reads
/// `PEB.ProcessParameters.CommandLine`. Kernel processes (PEB = 0)
/// are skipped.
pub fn walk_cmdlines<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<WinCmdlineInfo>> {
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

    /// Encode a Rust &str as UTF-16LE bytes.
    fn utf16le_bytes(s: &str) -> Vec<u8> {
        todo!()
    }

    /// Build a _UNICODE_STRING in a byte buffer.
    fn build_unicode_string_at(buf: &mut [u8], offset: usize, length: u16, buffer_ptr: u64) {
        todo!()
    }

    fn make_win_reader(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        todo!()
    }

    // Offsets from windows_kernel_preset:
    const EPROCESS_PID: u64 = 0x440;
    const EPROCESS_LINKS: u64 = 0x448;
    const EPROCESS_PPID: u64 = 0x540;
    const EPROCESS_PEB: u64 = 0x550;
    const EPROCESS_IMAGE_NAME: u64 = 0x5A8;
    const EPROCESS_CREATE_TIME: u64 = 0x430;
    const EPROCESS_EXIT_TIME: u64 = 0x438;
    const KPROCESS_DTB: u64 = 0x28;
    // PEB offsets
    const PEB_PROCESS_PARAMETERS: u64 = 0x20;
    // _RTL_USER_PROCESS_PARAMETERS offsets
    const PARAMS_COMMAND_LINE: u64 = 0x70;

    #[test]
    fn extracts_cmdline_from_process() {
        todo!()
    }

    #[test]
    fn skips_kernel_processes_no_peb() {
        todo!()
    }

    #[test]
    fn handles_empty_cmdline() {
        todo!()
    }
}
