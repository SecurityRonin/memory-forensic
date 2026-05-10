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

/// Maximum bytes captured for an SSH wire-format key blob.
const MAX_WIRE_BLOB: usize = 4096;

/// Maximum bytes captured for a PEM key block.
const MAX_PEM_BLOB: usize = 8192;

/// SSH wire-format magic sequences: (bytes, key_type_name).
///
/// Each entry is the 4-byte big-endian length prefix concatenated with the
/// key-type ASCII string as specified in RFC 4251.
const SSH_KEY_SIGS: &[(&[u8], &str)] = &[
    (b"\x00\x00\x00\x07ssh-rsa",            "ssh-rsa"),
    (b"\x00\x00\x00\x13ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256"),
    (b"\x00\x00\x00\x13ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384"),
    (b"\x00\x00\x00\x13ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521"),
    (b"\x00\x00\x00\x0bssh-ed25519",         "ssh-ed25519"),
];

/// PEM header patterns: (begin_marker, key_type_name).
const PEM_SIGS: &[(&[u8], &str)] = &[
    (b"-----BEGIN OPENSSH PRIVATE KEY-----", "pem-openssh"),
    (b"-----BEGIN RSA PRIVATE KEY-----",     "pem-rsa"),
    (b"-----BEGIN EC PRIVATE KEY-----",      "pem-ec"),
    (b"-----BEGIN DSA PRIVATE KEY-----",     "pem-dsa"),
];

/// Walk committed, writable heap regions of `ssh-agent.exe` and `pageant.exe`
/// processes and extract any SSH private key material found in memory.
pub fn walk_ssh_agent_keys<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
    ps_head_vaddr: u64,
) -> Result<Vec<SshAgentKeyInfo>> {
    let wr = crate::heap_walker::for_each_heap_region(
        reader,
        ps_head_vaddr,
        |proc| {
            SSH_AGENT_PROCESSES
                .iter()
                .any(|s| proc.image_name.eq_ignore_ascii_case(s))
        },
        |bytes, proc| {
            scan_ssh_agent_region(bytes)
                .into_iter()
                .map(|mut item| {
                    item.pid = proc.pid;
                    item.image_name.clone_from(&proc.image_name);
                    item
                })
                .collect()
        },
        |info: &SshAgentKeyInfo| {
            let prefix_len = info.key_blob.len().min(32);
            (info.pid, info.key_type.clone(), info.key_blob[..prefix_len].to_vec())
        },
    )?;
    Ok(wr.items)
}

/// Scan a raw byte slice for SSH private key material.
///
/// Returns `SshAgentKeyInfo` items with `pid: 0` and `image_name` empty;
/// the caller (`walk_ssh_agent_keys`) fills those in after the call.
pub(crate) fn scan_ssh_agent_region(data: &[u8]) -> Vec<SshAgentKeyInfo> {
    let mut results = Vec::new();

    // --- SSH wire-format scan ---
    for &(sig, name) in SSH_KEY_SIGS {
        let sig_len = sig.len();
        if data.len() < sig_len {
            continue;
        }
        for window_start in 0..=(data.len() - sig_len) {
            if &data[window_start..window_start + sig_len] == sig {
                let blob_start = window_start + sig_len;
                let blob_end = (blob_start + MAX_WIRE_BLOB).min(data.len());
                results.push(SshAgentKeyInfo {
                    pid: 0,
                    image_name: String::new(),
                    key_type: name.to_string(),
                    key_blob: data[blob_start..blob_end].to_vec(),
                    region_offset: window_start,
                });
            }
        }
    }

    // --- PEM header scan ---
    for &(sig, name) in PEM_SIGS {
        let sig_len = sig.len();
        if data.len() < sig_len {
            continue;
        }
        for window_start in 0..=(data.len() - sig_len) {
            if &data[window_start..window_start + sig_len] == sig {
                let blob_end = (window_start + MAX_PEM_BLOB).min(data.len());
                results.push(SshAgentKeyInfo {
                    pid: 0,
                    image_name: String::new(),
                    key_type: name.to_string(),
                    key_blob: data[window_start..blob_end].to_vec(),
                    region_offset: window_start,
                });
            }
        }
    }

    results
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

    #[test]
    fn output_type_has_image_name_field() {
        // Compile-time check: field must be named image_name, not process_name.
        let info = SshAgentKeyInfo {
            pid: 1,
            image_name: "ssh-agent.exe".to_string(),
            key_type: "ssh-ed25519".to_string(),
            key_blob: vec![0u8; 32],
            region_offset: 0,
        };
        assert_eq!(info.image_name, "ssh-agent.exe");
    }
}
