//! Windows process environment variable extraction.
//!
//! Reads environment blocks from `_EPROCESS` -> `_PEB` ->
//! `_RTL_USER_PROCESS_PARAMETERS.Environment`. The environment block
//! is a UTF-16LE encoded sequence of `KEY=VALUE\0` pairs terminated
//! by a double null.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Result, WinEnvVarInfo};

/// Maximum bytes to read from an environment block.
const MAX_ENV_SIZE: usize = 32768;

/// Walk all processes and extract their environment variables.
///
/// For each process with a non-null PEB, reads the environment
/// block from `PEB.ProcessParameters.Environment`. Kernel processes
/// (PEB = 0) are skipped.
pub fn walk_envvars<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<WinEnvVarInfo>> {
        todo!()
    }

/// Parse a UTF-16LE environment block into key-value pairs.
///
/// The block is a sequence of `KEY=VALUE\0` strings terminated by
/// a double null (`\0\0`).
fn parse_env_block(raw: &[u8]) -> Vec<(String, String)> {
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

    fn utf16le_bytes(s: &str) -> Vec<u8> {
        todo!()
    }

    fn make_win_reader(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        todo!()
    }

    /// Build a UTF-16LE environment block from key-value pairs.
    fn build_env_block(pairs: &[(&str, &str)]) -> Vec<u8> {
        todo!()
    }

    const EPROCESS_PID: u64 = 0x440;
    const EPROCESS_LINKS: u64 = 0x448;
    const EPROCESS_PPID: u64 = 0x540;
    const EPROCESS_PEB: u64 = 0x550;
    const EPROCESS_IMAGE_NAME: u64 = 0x5A8;
    const EPROCESS_CREATE_TIME: u64 = 0x430;
    const EPROCESS_EXIT_TIME: u64 = 0x438;
    const KPROCESS_DTB: u64 = 0x28;
    const PEB_PROCESS_PARAMETERS: u64 = 0x20;
    const PARAMS_ENVIRONMENT: u64 = 0x80;

    #[test]
    fn parse_env_block_basic() {
        todo!()
    }

    #[test]
    fn parse_env_block_empty() {
        todo!()
    }

    #[test]
    fn extracts_envvars_from_process() {
        todo!()
    }

    #[test]
    fn skips_kernel_processes_no_peb() {
        todo!()
    }
}
