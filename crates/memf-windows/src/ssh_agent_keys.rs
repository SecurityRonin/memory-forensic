//! SSH agent private key forensics walker.
//!
//! When a private key is loaded into an SSH agent (`ssh-add`), the agent
//! decrypts it and holds the plaintext key material in heap memory for the
//! lifetime of the agent process. This walker recovers those in-memory keys
//! from `ssh-agent.exe` (Windows OpenSSH) and `pageant.exe` (PuTTY Pageant).
//!
//! # Detection approach
//!
//! Keys in SSH agent memory follow SSH wire format (RFC 4251): a 4-byte
//! big-endian length prefix followed by the key type ASCII string
//! (`ssh-rsa`, `ssh-ed25519`, `ecdsa-sha2-nistp256`, etc.). This walker
//! scans for those magic byte sequences and captures the surrounding blob.
//! PEM-armoured private key headers are also detected as a secondary signal.
//!
//! # Attribution
//!
//! Technique documented by:
//!   NetSPI, "Stealing Unencrypted SSH-Agent Keys from Memory" (2014)
//!   <https://blog.netspi.com/stealing-unencrypted-ssh-agent-keys-from-memory/>
//!   (Independently re-implemented in Rust for read-only forensic analysis)
//!
//! # Forensic guarantee
//!
//! Read-only. No live process access, no Win32 API calls, no state modification.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{
    types::SshAgentKeyInfo,
    Result,
};

/// SSH agent process names to scan.
pub const SSH_AGENT_PROCESSES: &[&str] = &["ssh-agent.exe", "pageant.exe"];

/// Maximum bytes read from a single VAD region.
const MAX_REGION_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Walk committed, writable heap regions of `ssh-agent.exe` and `pageant.exe`
/// processes and extract any SSH private key material found in memory.
pub fn walk_ssh_agent_keys<P: PhysicalMemoryProvider + Clone>(
    _reader: &ObjectReader<P>,
    _ps_head_vaddr: u64,
) -> Result<Vec<SshAgentKeyInfo>> {
    // GREEN: not yet implemented — stub returns empty.
    Ok(Vec::new())
}

/// Scan a raw byte slice for SSH private key material.
///
/// Returns `SshAgentKeyInfo` items with `pid: 0` and `process_name` empty;
/// the caller fills those in after the call.
///
/// This is a stub — returns empty until the GREEN implementation.
pub(crate) fn scan_ssh_agent_region(_data: &[u8]) -> Vec<SshAgentKeyInfo> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_empty_returns_nothing() {
        assert!(scan_ssh_agent_region(b"").is_empty());
    }

    #[test]
    fn scan_random_bytes_returns_nothing() {
        let data = vec![0xAAu8; 256];
        assert!(scan_ssh_agent_region(&data).is_empty());
    }

    #[test]
    fn scan_detects_ssh_rsa_wire_format() {
        // \x00\x00\x00\x07 + "ssh-rsa" + fake key material
        let mut data = Vec::new();
        data.extend_from_slice(b"\x00\x00\x00\x07ssh-rsa");
        data.extend_from_slice(&[0xAA; 128]); // fake key bytes
        let results = scan_ssh_agent_region(&data);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key_type, "ssh-rsa");
        assert_eq!(results[0].region_offset, 0);
        assert!(!results[0].key_blob.is_empty());
    }

    #[test]
    fn scan_detects_ed25519_wire_format() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x00\x00\x00\x0bssh-ed25519");
        data.extend_from_slice(&[0xBB; 64]);
        let results = scan_ssh_agent_region(&data);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key_type, "ssh-ed25519");
    }

    #[test]
    fn scan_detects_pem_openssh_private_key() {
        let pem = b"-----BEGIN OPENSSH PRIVATE KEY-----\nfakebase64data\n-----END OPENSSH PRIVATE KEY-----\n";
        let results = scan_ssh_agent_region(pem);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key_type, "pem-openssh");
        assert!(results[0].key_blob.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----"));
    }

    #[test]
    fn scan_detects_pem_rsa_private_key() {
        let pem = b"-----BEGIN RSA PRIVATE KEY-----\nfakebase64data\n-----END RSA PRIVATE KEY-----\n";
        let results = scan_ssh_agent_region(pem);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key_type, "pem-rsa");
    }

    #[test]
    fn scan_multiple_keys_in_region() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x00\x00\x00\x07ssh-rsa");
        data.extend_from_slice(&[0xAA; 64]);
        data.extend_from_slice(b"\x00\x00\x00\x0bssh-ed25519");
        data.extend_from_slice(&[0xBB; 32]);
        let results = scan_ssh_agent_region(&data);
        assert_eq!(results.len(), 2);
        let types: Vec<_> = results.iter().map(|r| r.key_type.as_str()).collect();
        assert!(types.contains(&"ssh-rsa"));
        assert!(types.contains(&"ssh-ed25519"));
    }
}
