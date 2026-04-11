//! SSH key extraction from sshd process memory.
//!
//! Scans sshd process heap and mapped memory for SSH public key material
//! (e.g. `ssh-rsa`, `ssh-ed25519`). During incident response this reveals
//! lateral movement paths and compromised credentials by recovering keys
//! that were present in the SSH daemon's address space at the time of
//! the memory capture.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, Result, SshKeyInfo, SshKeyType, VmaFlags};

/// SSH key type prefixes to scan for.
const SSH_KEY_PREFIXES: &[(&str, SshKeyType)] = &[
    ("ssh-rsa ", SshKeyType::Rsa),
    ("ssh-ed25519 ", SshKeyType::Ed25519),
    ("ssh-dss ", SshKeyType::Dsa),
    ("ecdsa-sha2-nistp256 ", SshKeyType::Ecdsa256),
    ("ecdsa-sha2-nistp384 ", SshKeyType::Ecdsa384),
    ("ecdsa-sha2-nistp521 ", SshKeyType::Ecdsa521),
];

/// Maximum key line length (bytes) before we stop reading.
const MAX_KEY_LINE: usize = 8192;

/// Maximum VMA region size to scan (16 MiB safety limit).
const MAX_VMA_SCAN: u64 = 16 * 1024 * 1024;

/// Extract SSH public keys from sshd process memory.
///
/// Walks the process list to find `sshd` processes, then scans their
/// readable VMAs for SSH key prefix strings. When a prefix is found,
/// extracts the full key line (up to newline/null, max 8 KiB) and
/// parses the key type, base64 data, and optional comment.
///
/// Results are deduplicated by `(pid, key_data)`.
pub fn extract_ssh_keys<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<SshKeyInfo>> {
        todo!()
    }

/// Check if a task is sshd and, if so, scan its VMAs for SSH keys.
fn scan_sshd_keys<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
    results: &mut Vec<SshKeyInfo>,
    seen: &mut std::collections::HashSet<(u64, String)>,
) {
        todo!()
    }

/// Scan a memory region for SSH key prefixes.
fn scan_region_for_keys<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    pid: u64,
    start: u64,
    size: u64,
    results: &mut Vec<SshKeyInfo>,
    seen: &mut std::collections::HashSet<(u64, String)>,
) {
        todo!()
    }

/// Find the first occurrence of `needle` in `haystack`.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        todo!()
    }

/// Parse a key line into `(key_type, full_key_data, comment)`.
///
/// The key line format is: `<type> <base64> [comment]`
fn parse_key_line(line: &str) -> Option<(SshKeyType, String, String)> {
        todo!()
    }

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags as ptflags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_test_reader(
        data: &[u8],
        vaddr: u64,
        paddr: u64,
        extra_mappings: &[(u64, u64, &[u8])],
    ) -> ObjectReader<SyntheticPhysMem> {
        todo!()
    }

    #[test]
    fn ssh_key_type_from_prefix() {
        todo!()
    }

    #[test]
    fn ssh_key_type_display() {
        todo!()
    }

    #[test]
    fn extract_ssh_keys_no_sshd() {
        todo!()
    }

    #[test]
    fn extracts_ed25519_key_from_sshd_heap() {
        todo!()
    }

    #[test]
    fn extracts_rsa_key_without_comment() {
        todo!()
    }

    #[test]
    fn deduplicates_identical_keys() {
        todo!()
    }

    #[test]
    fn parse_key_line_ed25519_with_comment() {
        todo!()
    }

    #[test]
    fn parse_key_line_rsa_no_comment() {
        todo!()
    }

    #[test]
    fn parse_key_line_invalid() {
        todo!()
    }

    #[test]
    fn missing_init_task_symbol() {
        todo!()
    }
}
