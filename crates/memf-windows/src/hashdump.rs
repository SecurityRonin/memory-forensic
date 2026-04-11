//! Windows SAM NTLM hash extraction from memory dumps.
//!
//! Goes beyond `sam.rs` (which enumerates user accounts and metadata) by
//! actually decrypting the boot key from the SYSTEM hive and using it to
//! decrypt the password hashes stored in the SAM hive's V values.
//!
//! The decryption pipeline is:
//! 1. Extract the boot key from `SYSTEM\CurrentControlSet\Control\Lsa`
//!    (JD, Skew1, GBG, Data class names, scrambled)
//! 2. Decrypt the hashed boot key from `SAM\SAM\Domains\Account` (F value)
//! 3. For each user in `SAM\SAM\Domains\Account\Users\{RID}`: read V value,
//!    extract LM and NT hash offsets, decrypt with DES using RID as key
//!
//! This enables offline credential analysis for:
//! - Identifying blank/default passwords (incident response)
//! - Detecting pass-the-hash attack targets
//! - Correlating compromised credentials across systems

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

/// Maximum number of user entries to enumerate (safety limit).
const MAX_USERS: usize = 4096;

/// Well-known empty/blank NT hash (NTLM of empty string).
const EMPTY_NT_HASH: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";

/// Well-known empty LM hash.
const EMPTY_LM_HASH: &str = "aad3b435b51404eeaad3b435b51404ee";

/// Boot key scramble order used by Windows to permute the class-name bytes.
const BOOT_KEY_SCRAMBLE: [usize; 16] = [
    0x08, 0x05, 0x04, 0x02, 0x0B, 0x09, 0x0D, 0x03, 0x00, 0x06, 0x01, 0x0C, 0x0E, 0x0A, 0x0F, 0x07,
];

/// SYSTEM hive LSA subkey names whose class names form the boot key.
const LSA_KEY_NAMES: [&str; 4] = ["JD", "Skew1", "GBG", "Data"];

/// An extracted NTLM hash entry from the SAM hive.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HashdumpEntry {
    /// User account name.
    pub username: String,
    /// Relative Identifier (RID) — unique per-user on the local machine.
    pub rid: u32,
    /// LM hash as lowercase hex string (or `EMPTY_LM_HASH` for empty).
    pub lm_hash: String,
    /// NT hash as lowercase hex string (or `EMPTY_NT_HASH` for empty).
    pub nt_hash: String,
    /// Whether this entry looks suspicious based on hash heuristics.
    pub is_suspicious: bool,
}

/// Classify a hashdump entry as suspicious.
///
/// Returns `true` for entries matching patterns that warrant investigation:
/// - Empty/blank NT hash (password is empty)
/// - Well-known default or admin hashes
/// - Machine accounts (`$` suffix) with non-standard hashes
pub fn classify_hashdump(username: &str, nt_hash: &str) -> bool {
        todo!()
    }

/// Extract NTLM password hashes from SAM and SYSTEM registry hives in memory.
///
/// Takes both the SAM and SYSTEM hive virtual addresses. The SYSTEM hive is
/// needed to extract the boot key used to decrypt the SAM hashes.
///
/// Returns an empty `Vec` if either hive address is 0 or required registry
/// paths/symbols are missing.
pub fn walk_hashdump<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    sam_hive_addr: u64,
    system_hive_addr: u64,
) -> crate::Result<Vec<HashdumpEntry>> {
        todo!()
    }

/// Extract the boot key from the SYSTEM hive's LSA subkeys.
///
/// The boot key is assembled from the class names of four registry keys
/// under `SYSTEM\CurrentControlSet\Control\Lsa`: JD, Skew1, GBG, Data.
/// The raw bytes are then scrambled using a fixed permutation order.
fn extract_boot_key<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    root_addr: u64,
) -> Vec<u8> {
        todo!()
    }

/// Decrypt the hashed boot key from the SAM Account\F value.
///
/// The F value contains the domain account metadata. Starting at offset 0x70,
/// there is an RC4-encrypted (or AES on newer systems) structure that, when
/// decrypted with the boot key, yields the hashed boot key used to decrypt
/// individual user hashes.
///
/// For simplicity and reliability across Windows versions, we support the
/// older MD5+RC4 format (revision 2) and return a best-effort key for the
/// AES format (revision 3).
fn decrypt_hashed_boot_key(f_data: &[u8], boot_key: &[u8]) -> Vec<u8> {
        todo!()
    }

/// Extract LM and NT hashes from a user's V value.
///
/// The V value contains offsets and lengths for various user data fields.
/// The hash data is located at specific offsets within the V structure.
fn extract_hashes_from_v(v_data: &[u8], hashed_boot_key: &[u8], rid: u32) -> (String, String) {
        todo!()
    }

/// Resolve a username for a RID from the Names subkey.
fn resolve_username_for_rid<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    names_key: u64,
    target_rid: u32,
) -> String {
        todo!()
    }

/// Simple MD5-like key derivation for SAM revision 2.
///
/// Derives a 16-byte RC4 key from the boot key and salt using a
/// simplified hash that follows the structure of the Windows algorithm.
fn simple_md5_derive(boot_key: &[u8], salt: &[u8]) -> Vec<u8> {
        todo!()
    }

/// Minimal MD5 implementation (RFC 1321) for SAM key derivation.
fn md5_hash(message: &[u8]) -> Vec<u8> {
        todo!()
    }

/// RC4 stream cipher (used by SAM revision 2).
fn rc4_crypt(key: &[u8], data: &[u8]) -> Vec<u8> {
        todo!()
    }

/// Simplified AES-128-CBC decryption for SAM revision 3.
///
/// This is a minimal AES implementation for the SAM key decryption use case.
/// Without an external crypto library, we implement the core AES-128 block
/// cipher with CBC mode.
fn aes_cbc_decrypt_simple(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
        todo!()
    }

/// AES S-box.
const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// AES inverse S-box.
const AES_INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// AES round constant.
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// AES-128 key expansion: produce 11 round keys (176 bytes).
fn aes128_key_expansion(key: &[u8]) -> Vec<[u8; 16]> {
        todo!()
    }

/// AES-128 single block decryption.
fn aes128_decrypt_block(cipher: &[u8; 16], round_keys: &[[u8; 16]]) -> [u8; 16] {
    let mut state = *cipher;

    // Initial round key addition (round 10)
    xor_block(&mut state, &round_keys[10]);

    // Rounds 9..1
    for round in (1..10).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        xor_block(&mut state, &round_keys[round]);
        inv_mix_columns(&mut state);
    }

    // Final round (round 0)
    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    xor_block(&mut state, &round_keys[0]);

    state
}

fn xor_block(state: &mut [u8; 16], key: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= key[i];
    }
}

fn inv_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = AES_INV_SBOX[*b as usize];
    }
}

fn inv_shift_rows(state: &mut [u8; 16]) {
    // AES state is column-major: state[row + 4*col]
    // Row 1: shift right by 1
    let tmp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = tmp;

    // Row 2: shift right by 2
    state.swap(2, 10);
    state.swap(6, 14);

    // Row 3: shift right by 3 (= left by 1)
    let tmp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = tmp;
}

/// Galois field multiplication for AES.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
        todo!()
    }

fn inv_mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let s0 = state[col * 4];
        let s1 = state[col * 4 + 1];
        let s2 = state[col * 4 + 2];
        let s3 = state[col * 4 + 3];

        state[col * 4] = gf_mul(0x0e, s0) ^ gf_mul(0x0b, s1) ^ gf_mul(0x0d, s2) ^ gf_mul(0x09, s3);
        state[col * 4 + 1] =
            gf_mul(0x09, s0) ^ gf_mul(0x0e, s1) ^ gf_mul(0x0b, s2) ^ gf_mul(0x0d, s3);
        state[col * 4 + 2] =
            gf_mul(0x0d, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0e, s2) ^ gf_mul(0x0b, s3);
        state[col * 4 + 3] =
            gf_mul(0x0b, s0) ^ gf_mul(0x0d, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0e, s3);
    }
}

// ---------------------------------------------------------------------------
// Internal helpers — registry hive navigation (mirrors sam.rs patterns)
// ---------------------------------------------------------------------------

/// Read a cell address from the flat storage base + cell offset.
fn read_cell_addr<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    cell_off: u32,
) -> u64 {
        todo!()
    }

/// Find a subkey by name under a parent `_CM_KEY_NODE`.
fn find_subkey_by_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    parent_addr: u64,
    target_name: &str,
) -> u64 {
        todo!()
    }

/// Read the class name of a `_CM_KEY_NODE` (used for boot key extraction).
/// Returns the raw bytes of the class name, or an empty vec on failure.
fn read_key_class_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    key_addr: u64,
) -> Vec<u8> {
        todo!()
    }

/// Read the named value data from a registry key's value list.
/// Returns the raw data bytes, or an empty vec on failure.
fn read_value_data<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    key_addr: u64,
    target_name: &str,
) -> Vec<u8> {
        todo!()
    }

/// Resolve a hive's flat base address for cell offset calculations.
fn resolve_flat_base<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, hive_addr: u64) -> u64 {
        todo!()
    }

/// Resolve the root cell address of a hive.
fn resolve_root_cell<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    flat_base: u64,
) -> u64 {
        todo!()
    }

/// Format a byte slice as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
        todo!()
    }

/// Perform a single DES block encryption (used for RID-based hash decryption).
/// This is a minimal DES implementation for the specific SAM hash use case.
/// Windows uses two DES keys derived from the RID to decrypt the 16-byte hash.
#[allow(dead_code)]
fn des_ecb_encrypt(key: &[u8; 8], data: &[u8; 8]) -> [u8; 8] {
    // DES Initial Permutation table
    const IP: [u8; 64] = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14,
        6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11,
        3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    ];

    // DES Final Permutation (IP^-1)
    const FP: [u8; 64] = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62,
        30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19,
        59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
    ];

    // DES Expansion permutation
    const E: [u8; 48] = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17,
        18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
    ];

    // DES P-box permutation
    const P: [u8; 32] = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25,
    ];

    // DES S-boxes
    const SBOXES: [[u8; 64]; 8] = [
        [
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6,
            12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2,
            4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
        ],
        [
            15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0,
            1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1,
            3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
        ],
        [
            10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8,
            5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13,
            0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
        ],
        [
            7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7,
            2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6,
            10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
        ],
        [
            2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0,
            15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7,
            1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
        ],
        [
            12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1,
            13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12,
            9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
        ],
        [
            4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3,
            5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8,
            1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
        ],
        [
            13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5,
            6, 2, 0, 14, 9, 11, 7, 0, 1, 3, 13, 4, 14, 10, 15, 5, 2, 12, 11, 9, 6, 8, 2, 1, 14, 7,
            4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
        ],
    ];

    // DES key schedule: PC-1 and PC-2 permutations, shift schedule
    const PC1: [u8; 56] = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3,
        60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45,
        37, 29, 21, 13, 5, 28, 20, 12, 4,
    ];

    const PC2: [u8; 48] = [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41,
        52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
    ];

    const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

    // Helper: get bit n (1-indexed) from a byte slice
    fn get_bit(data: &[u8], pos: u8) -> u8 {
        todo!()
    }

    // Helper: set bit n (1-indexed) in a byte slice
    fn set_bit(data: &mut [u8], pos: u8, val: u8) {
        todo!()
    }

    // Generate 16 round subkeys
    let mut cd = [0u8; 7]; // 56 bits
    for i in 0..56u8 {
        let bit = get_bit(key, PC1[i as usize]);
        let byte_idx = (i / 8) as usize;
        let bit_idx = 7 - (i % 8);
        if bit == 1 {
            cd[byte_idx] |= 1 << bit_idx;
        }
    }

    // Split into C (28 bits) and D (28 bits)
    let mut c: u32 = 0;
    let mut d: u32 = 0;
    for i in 0..28u8 {
        let byte_idx = (i / 8) as usize;
        let bit_idx = 7 - (i % 8);
        if (cd[byte_idx] >> bit_idx) & 1 == 1 {
            c |= 1 << (27 - i);
        }
    }
    for i in 0..28u8 {
        let src = i + 28;
        let byte_idx = (src / 8) as usize;
        let bit_idx = 7 - (src % 8);
        if (cd[byte_idx] >> bit_idx) & 1 == 1 {
            d |= 1 << (27 - i);
        }
    }

    let mut subkeys = [[0u8; 6]; 16];
    for round in 0..16 {
        let shift = SHIFTS[round] as u32;
        c = ((c << shift) | (c >> (28 - shift))) & 0x0FFF_FFFF;
        d = ((d << shift) | (d >> (28 - shift))) & 0x0FFF_FFFF;

        // Combine C and D into 56-bit value for PC-2
        let mut cd56 = [0u8; 7];
        for i in 0..28u8 {
            if (c >> (27 - i)) & 1 == 1 {
                let byte_idx = (i / 8) as usize;
                let bit_idx = 7 - (i % 8);
                cd56[byte_idx] |= 1 << bit_idx;
            }
        }
        for i in 0..28u8 {
            let pos = i + 28;
            if (d >> (27 - i)) & 1 == 1 {
                let byte_idx = (pos / 8) as usize;
                let bit_idx = 7 - (pos % 8);
                cd56[byte_idx] |= 1 << bit_idx;
            }
        }

        // Apply PC-2
        for i in 0..48u8 {
            let src_pos = PC2[i as usize]; // 1-indexed into cd56
            let bit = get_bit(&cd56, src_pos);
            let byte_idx = (i / 8) as usize;
            let bit_idx = 7 - (i % 8);
            if bit == 1 {
                subkeys[round][byte_idx] |= 1 << bit_idx;
            }
        }
    }

    // Initial Permutation
    let mut block = [0u8; 8];
    for i in 0..64u8 {
        let bit = get_bit(data, IP[i as usize]);
        set_bit(&mut block, i + 1, bit);
    }

    // Split into L and R (32 bits each)
    let mut l: u32 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
    let mut r: u32 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);

    // 16 Feistel rounds
    for round in 0..16 {
        let old_l = l;
        l = r;

        // Expand R to 48 bits using E
        let r_bytes = r.to_be_bytes();
        let mut expanded = [0u8; 6];
        for i in 0..48u8 {
            let bit = get_bit(&r_bytes, E[i as usize]);
            let byte_idx = (i / 8) as usize;
            let bit_idx = 7 - (i % 8);
            if bit == 1 {
                expanded[byte_idx] |= 1 << bit_idx;
            }
        }

        // XOR with subkey
        for i in 0..6 {
            expanded[i] ^= subkeys[round][i];
        }

        // S-box substitution: 48 bits → 32 bits
        let mut sbox_out: u32 = 0;
        for s in 0..8 {
            let bit_offset = s * 6;
            let mut val: u8 = 0;
            for b in 0..6u8 {
                let byte_idx = ((bit_offset + b) / 8) as usize;
                let bit_idx = 7 - ((bit_offset + b) % 8);
                if byte_idx < 6 && (expanded[byte_idx] >> bit_idx) & 1 == 1 {
                    val |= 1 << (5 - b);
                }
            }
            let row = ((val >> 5) & 1) << 1 | (val & 1);
            let col = (val >> 1) & 0x0F;
            let sbox_val = SBOXES[s as usize][(row as usize) * 16 + (col as usize)];
            sbox_out |= (sbox_val as u32) << (4 * (7 - s));
        }

        // P-box permutation
        let sbox_bytes = sbox_out.to_be_bytes();
        let mut p_out: u32 = 0;
        for i in 0..32u8 {
            let bit = get_bit(&sbox_bytes, P[i as usize]);
            if bit == 1 {
                p_out |= 1 << (31 - i);
            }
        }

        r = old_l ^ p_out;
    }

    // Combine R and L (note the swap)
    let mut preoutput = [0u8; 8];
    preoutput[0..4].copy_from_slice(&r.to_be_bytes());
    preoutput[4..8].copy_from_slice(&l.to_be_bytes());

    // Final Permutation
    let mut output = [0u8; 8];
    for i in 0..64u8 {
        let bit = get_bit(&preoutput, FP[i as usize]);
        set_bit(&mut output, i + 1, bit);
    }

    output
}

/// Convert a RID into two 8-byte DES keys (7 bytes expanded to 8 with parity).
fn rid_to_des_keys(rid: u32) -> ([u8; 8], [u8; 8]) {
    let rid_bytes = rid.to_le_bytes();

    // First key: bytes 0,1,2,3,0,1,2
    let s1 = [
        rid_bytes[0],
        rid_bytes[1],
        rid_bytes[2],
        rid_bytes[3],
        rid_bytes[0],
        rid_bytes[1],
        rid_bytes[2],
    ];

    // Second key: bytes 3,0,1,2,3,0,1
    let s2 = [
        rid_bytes[3],
        rid_bytes[0],
        rid_bytes[1],
        rid_bytes[2],
        rid_bytes[3],
        rid_bytes[0],
        rid_bytes[1],
    ];

    (str_to_key(&s1), str_to_key(&s2))
}

/// Expand a 7-byte value into an 8-byte DES key with parity bits.
fn str_to_key(s: &[u8; 7]) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[0] = s[0] >> 1;
    key[1] = ((s[0] & 0x01) << 6) | (s[1] >> 2);
    key[2] = ((s[1] & 0x03) << 5) | (s[2] >> 3);
    key[3] = ((s[2] & 0x07) << 4) | (s[3] >> 4);
    key[4] = ((s[3] & 0x0F) << 3) | (s[4] >> 5);
    key[5] = ((s[4] & 0x1F) << 2) | (s[5] >> 6);
    key[6] = ((s[5] & 0x3F) << 1) | (s[6] >> 7);
    key[7] = s[6] & 0x7F;

    // Set parity bits
    for b in &mut key {
        *b = (*b << 1) & 0xFE;
        // odd parity
        let ones = b.count_ones();
        if ones % 2 == 0 {
            *b |= 1;
        }
    }

    key
}

/// DES-decrypt a single 8-byte block (DES-ECB decrypt = encrypt with reversed subkeys).
fn des_ecb_decrypt(key: &[u8; 8], data: &[u8; 8]) -> [u8; 8] {
    // For decryption we reverse the subkey order. Rather than duplicating
    // the full DES implementation, we reuse encrypt and note that
    // DES decryption with the same key schedule reversed is equivalent.
    // However, our encrypt builds subkeys internally. We implement decrypt
    // by building subkeys then reversing. For simplicity and correctness,
    // we replicate the structure.

    // Actually, the SAM hash "decryption" in Windows uses DES *encrypt*
    // (not decrypt) with the RID-derived keys to transform the obfuscated
    // hash back to the actual hash. This is because the obfuscation step
    // used DES encrypt, and the same operation reverses the XOR/permutation
    // used in the SAM's own obfuscation layer.
    //
    // In the classic hashdump approach:
    //   actual_hash = DES_ECB_decrypt(rid_key, encrypted_hash)
    //
    // We implement true DES decrypt by reversing the round key schedule.

    // This is a copy of `des_ecb_encrypt` with subkey order reversed.
    // (Tables are identical, only the subkey application order changes.)

    const IP: [u8; 64] = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14,
        6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11,
        3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    ];
    const FP: [u8; 64] = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62,
        30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19,
        59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
    ];
    const E_TABLE: [u8; 48] = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17,
        18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
    ];
    const P_TABLE: [u8; 32] = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25,
    ];
    const SBOXES: [[u8; 64]; 8] = [
        [
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6,
            12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2,
            4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
        ],
        [
            15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0,
            1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1,
            3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
        ],
        [
            10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8,
            5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13,
            0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
        ],
        [
            7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7,
            2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6,
            10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
        ],
        [
            2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0,
            15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7,
            1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
        ],
        [
            12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1,
            13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12,
            9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
        ],
        [
            4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3,
            5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8,
            1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
        ],
        [
            13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5,
            6, 2, 0, 14, 9, 11, 7, 0, 1, 3, 13, 4, 14, 10, 15, 5, 2, 12, 11, 9, 6, 8, 2, 1, 14, 7,
            4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
        ],
    ];
    const PC1: [u8; 56] = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3,
        60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45,
        37, 29, 21, 13, 5, 28, 20, 12, 4,
    ];
    const PC2: [u8; 48] = [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41,
        52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
    ];
    const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

    fn get_bit(data: &[u8], pos: u8) -> u8 {
        todo!()
    }

    fn set_bit(data: &mut [u8], pos: u8, val: u8) {
        todo!()
    }

    // Generate subkeys (same as encrypt)
    let mut cd = [0u8; 7];
    for i in 0..56u8 {
        let bit = get_bit(key, PC1[i as usize]);
        let byte_idx = (i / 8) as usize;
        let bit_idx = 7 - (i % 8);
        if bit == 1 {
            cd[byte_idx] |= 1 << bit_idx;
        }
    }

    let mut c: u32 = 0;
    let mut d: u32 = 0;
    for i in 0..28u8 {
        let byte_idx = (i / 8) as usize;
        let bit_idx = 7 - (i % 8);
        if (cd[byte_idx] >> bit_idx) & 1 == 1 {
            c |= 1 << (27 - i);
        }
    }
    for i in 0..28u8 {
        let src = i + 28;
        let byte_idx = (src / 8) as usize;
        let bit_idx = 7 - (src % 8);
        if (cd[byte_idx] >> bit_idx) & 1 == 1 {
            d |= 1 << (27 - i);
        }
    }

    let mut subkeys = [[0u8; 6]; 16];
    for round in 0..16 {
        let shift = SHIFTS[round] as u32;
        c = ((c << shift) | (c >> (28 - shift))) & 0x0FFF_FFFF;
        d = ((d << shift) | (d >> (28 - shift))) & 0x0FFF_FFFF;

        let mut cd56 = [0u8; 7];
        for i in 0..28u8 {
            if (c >> (27 - i)) & 1 == 1 {
                let byte_idx = (i / 8) as usize;
                let bit_idx = 7 - (i % 8);
                cd56[byte_idx] |= 1 << bit_idx;
            }
        }
        for i in 0..28u8 {
            let pos = i + 28;
            if (d >> (27 - i)) & 1 == 1 {
                let byte_idx = (pos / 8) as usize;
                let bit_idx = 7 - (pos % 8);
                cd56[byte_idx] |= 1 << bit_idx;
            }
        }

        for i in 0..48u8 {
            let src_pos = PC2[i as usize];
            let bit = get_bit(&cd56, src_pos);
            let byte_idx = (i / 8) as usize;
            let bit_idx = 7 - (i % 8);
            if bit == 1 {
                subkeys[round][byte_idx] |= 1 << bit_idx;
            }
        }
    }

    // REVERSE subkey order for decryption
    subkeys.reverse();

    // Initial Permutation
    let mut block = [0u8; 8];
    for i in 0..64u8 {
        let bit = get_bit(data, IP[i as usize]);
        set_bit(&mut block, i + 1, bit);
    }

    let mut l: u32 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
    let mut r: u32 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);

    for round in 0..16 {
        let old_l = l;
        l = r;

        let r_bytes = r.to_be_bytes();
        let mut expanded = [0u8; 6];
        for i in 0..48u8 {
            let bit = get_bit(&r_bytes, E_TABLE[i as usize]);
            let byte_idx = (i / 8) as usize;
            let bit_idx = 7 - (i % 8);
            if bit == 1 {
                expanded[byte_idx] |= 1 << bit_idx;
            }
        }

        for i in 0..6 {
            expanded[i] ^= subkeys[round][i];
        }

        let mut sbox_out: u32 = 0;
        for s in 0..8u8 {
            let bit_offset = s * 6;
            let mut val: u8 = 0;
            for b in 0..6u8 {
                let byte_idx = ((bit_offset + b) / 8) as usize;
                let bit_idx = 7 - ((bit_offset + b) % 8);
                if byte_idx < 6 && (expanded[byte_idx] >> bit_idx) & 1 == 1 {
                    val |= 1 << (5 - b);
                }
            }
            let row = ((val >> 5) & 1) << 1 | (val & 1);
            let col = (val >> 1) & 0x0F;
            let sbox_val = SBOXES[s as usize][(row as usize) * 16 + (col as usize)];
            sbox_out |= (sbox_val as u32) << (4 * (7 - s));
        }

        let sbox_bytes = sbox_out.to_be_bytes();
        let mut p_out: u32 = 0;
        for i in 0..32u8 {
            let bit = get_bit(&sbox_bytes, P_TABLE[i as usize]);
            if bit == 1 {
                p_out |= 1 << (31 - i);
            }
        }

        r = old_l ^ p_out;
    }

    let mut preoutput = [0u8; 8];
    preoutput[0..4].copy_from_slice(&r.to_be_bytes());
    preoutput[4..8].copy_from_slice(&l.to_be_bytes());

    let mut output = [0u8; 8];
    for i in 0..64u8 {
        let bit = get_bit(&preoutput, FP[i as usize]);
        set_bit(&mut output, i + 1, bit);
    }

    output
}

/// Decrypt a 16-byte SAM hash using two DES keys derived from the RID.
fn decrypt_sam_hash_with_rid(encrypted: &[u8], rid: u32) -> Vec<u8> {
        todo!()
    }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ---------------------------------------------------------------
    // Classifier tests
    // ---------------------------------------------------------------

    /// Empty NT hash (blank password) is suspicious.
    #[test]
    fn classify_empty_nt_hash_suspicious() {
        todo!()
    }

    /// Normal (non-empty, non-known-bad) hash is not suspicious.
    #[test]
    fn classify_normal_hash_benign() {
        todo!()
    }

    /// Machine account with empty hash is suspicious (blank password case).
    #[test]
    fn classify_machine_account_empty_hash() {
        todo!()
    }

    /// Machine account with normal hash is not suspicious.
    #[test]
    fn classify_machine_account_normal_hash() {
        todo!()
    }

    /// Known bad hash ("password") is suspicious.
    #[test]
    fn classify_known_bad_hash_suspicious() {
        todo!()
    }

    /// Empty username returns false (graceful).
    #[test]
    fn classify_empty_username_benign() {
        todo!()
    }

    /// Empty hash string returns false (graceful).
    #[test]
    fn classify_empty_hash_string_benign() {
        todo!()
    }

    /// Blank password hash with different casing still detected.
    #[test]
    fn classify_blank_password_case_insensitive() {
        todo!()
    }

    // ---------------------------------------------------------------
    // Walker tests
    // ---------------------------------------------------------------

    /// No hive addresses → empty Vec.
    #[test]
    fn walk_hashdump_no_hive() {
        todo!()
    }

    // ---------------------------------------------------------------
    // DES / key derivation unit tests
    // ---------------------------------------------------------------

    /// `str_to_key` produces 8-byte key with parity bits set.
    #[test]
    fn str_to_key_parity() {
        todo!()
    }

    /// `rid_to_des_keys` produces two distinct keys.
    #[test]
    fn rid_to_des_keys_distinct() {
        todo!()
    }

    /// `hex_encode` works correctly.
    #[test]
    fn hex_encode_correct() {
        todo!()
    }

    /// DES encrypt then decrypt round-trips correctly.
    #[test]
    fn des_round_trip() {
        todo!()
    }

    // ---------------------------------------------------------------
    // Additional classifier and crypto coverage
    // ---------------------------------------------------------------

    /// All known-bad hashes are classified suspicious.
    #[test]
    fn classify_all_known_bad_hashes() {
        todo!()
    }

    /// HashdumpEntry serializes to JSON correctly.
    #[test]
    fn hashdump_entry_serializes() {
        todo!()
    }

    /// decrypt_hashed_boot_key returns empty for short F data.
    #[test]
    fn decrypt_hashed_boot_key_short_f_data() {
        todo!()
    }

    /// decrypt_hashed_boot_key returns empty for wrong boot_key length.
    #[test]
    fn decrypt_hashed_boot_key_wrong_key_len() {
        todo!()
    }

    /// decrypt_hashed_boot_key with revision 2 marker and all-zero data
    /// returns a result (may be zeros but not empty — RC4 of zeros is defined).
    #[test]
    fn decrypt_hashed_boot_key_rev2() {
        todo!()
    }

    /// decrypt_hashed_boot_key with revision 3 marker (AES path).
    #[test]
    fn decrypt_hashed_boot_key_rev3() {
        todo!()
    }

    /// decrypt_hashed_boot_key with unknown revision returns empty.
    #[test]
    fn decrypt_hashed_boot_key_unknown_revision() {
        todo!()
    }

    /// extract_hashes_from_v with too-short V data returns empty hashes.
    #[test]
    fn extract_hashes_from_v_short_data() {
        todo!()
    }

    /// extract_hashes_from_v with empty hashed_boot_key returns empty hashes.
    #[test]
    fn extract_hashes_from_v_empty_boot_key() {
        todo!()
    }

    /// extract_hashes_from_v with zero offsets in V data returns empty hashes.
    #[test]
    fn extract_hashes_from_v_zero_offsets() {
        todo!()
    }

    /// rc4_crypt with empty key returns data unchanged.
    #[test]
    fn rc4_crypt_empty_key() {
        todo!()
    }

    /// rc4_crypt is self-inverse (XOR-based stream cipher).
    #[test]
    fn rc4_crypt_self_inverse() {
        todo!()
    }

    /// aes_cbc_decrypt_simple returns empty for bad key/iv/data sizes.
    #[test]
    fn aes_cbc_decrypt_simple_bad_inputs() {
        todo!()
    }

    /// aes_cbc_decrypt_simple produces 16 bytes for a valid 16-byte input.
    #[test]
    fn aes_cbc_decrypt_simple_valid() {
        todo!()
    }

    /// md5_hash produces 16-byte output.
    #[test]
    fn md5_hash_produces_16_bytes() {
        todo!()
    }

    /// md5_hash("") has a known RFC 1321 value.
    #[test]
    fn md5_hash_empty_string() {
        todo!()
    }

    /// simple_md5_derive produces 16 bytes.
    #[test]
    fn simple_md5_derive_produces_16_bytes() {
        todo!()
    }

    /// decrypt_sam_hash_with_rid produces 16 bytes.
    #[test]
    fn decrypt_sam_hash_with_rid_produces_16_bytes() {
        todo!()
    }

    /// BOOT_KEY_SCRAMBLE has 16 elements all in range 0..16.
    #[test]
    fn boot_key_scramble_valid() {
        todo!()
    }

    /// LSA_KEY_NAMES has exactly 4 elements.
    #[test]
    fn lsa_key_names_count() {
        todo!()
    }

    /// system_flat_base succeeds but system_root resolves to 0 → empty Vec.
    /// Covers line 130 (system_root == 0 check).
    #[test]
    fn walk_hashdump_system_root_zero_empty() {
        todo!()
    }

    /// system resolves fully but sam_flat_base returns 0 → empty Vec.
    /// Covers line 135 (sam_flat_base == 0 check).
    #[test]
    fn walk_hashdump_sam_flat_base_zero_empty() {
        todo!()
    }

    /// sam_flat_base resolves but system_root returns 0 → empty Vec.
    /// Covers line 131 (system_root == 0 check from resolve_root_cell).
    #[test]
    fn walk_hashdump_system_root_zero_via_mapped_hive() {
        todo!()
    }

    /// Non-zero hive addresses but unreadable memory → empty Vec.
    #[test]
    fn walk_hashdump_unreadable_hive() {
        todo!()
    }

    // ── Additional coverage: internal helpers ────────────────────────

    /// gf_mul(0, x) = 0 for all x.
    #[test]
    fn gf_mul_zero_operand() {
        todo!()
    }

    /// gf_mul(1, x) = x (multiplicative identity).
    #[test]
    fn gf_mul_identity() {
        todo!()
    }

    /// gf_mul(2, 0x80) should reduce by 0x1b (polynomial).
    #[test]
    fn gf_mul_reduction() {
        todo!()
    }

    /// aes128_key_expansion produces exactly 11 round keys of 16 bytes each.
    #[test]
    fn aes128_key_expansion_count() {
        todo!()
    }

    /// inv_sub_bytes is the inverse of sub_bytes (round-trip via AES_SBOX → INV_SBOX).
    #[test]
    fn inv_sub_bytes_round_trip() {
        todo!()
    }

    /// inv_shift_rows applied twice returns original state (period 2 for rows 1 and 3).
    #[test]
    fn inv_shift_rows_twice_returns_original() {
        todo!()
    }

    /// hex_encode with multi-byte input.
    #[test]
    fn hex_encode_multi_byte() {
        todo!()
    }

    /// classify_hashdump: case-insensitive hash comparison works.
    #[test]
    fn classify_hashdump_case_insensitive_hashes() {
        todo!()
    }

    /// extract_hashes_from_v with nt_length == 4 returns EMPTY_NT_HASH.
    #[test]
    fn extract_hashes_from_v_nt_length_four_empty_marker() {
        todo!()
    }

    /// resolve_flat_base returns 0 when hive_addr is unmapped.
    #[test]
    fn resolve_flat_base_unmapped_returns_zero() {
        todo!()
    }

    /// resolve_root_cell returns 0 when hive_addr is unmapped.
    #[test]
    fn resolve_root_cell_unmapped_returns_zero() {
        todo!()
    }

    /// read_value_data returns empty when key_addr is unmapped.
    #[test]
    fn read_value_data_unmapped_returns_empty() {
        todo!()
    }

    /// read_key_class_name returns empty when key_addr is unmapped.
    #[test]
    fn read_key_class_name_unmapped_returns_empty() {
        todo!()
    }

    // ── Additional coverage: decrypt_hashed_boot_key edge cases ─────

    /// decrypt_hashed_boot_key rev2 with F data = 0x80 bytes (exact minimum,
    /// but not 0xA0) returns empty because the rev2 branch needs 0xA0 bytes.
    #[test]
    fn decrypt_hashed_boot_key_rev2_too_short_for_encrypted_data() {
        todo!()
    }

    /// decrypt_hashed_boot_key rev3 with F data exactly 0x88 bytes (< 0x98) → empty.
    #[test]
    fn decrypt_hashed_boot_key_rev3_too_short() {
        todo!()
    }

    /// extract_hashes_from_v with nt_length >= 20 but offset out of bounds.
    #[test]
    fn extract_hashes_from_v_nt_offset_out_of_bounds() {
        todo!()
    }

    /// decrypt_sam_hash_with_rid with empty input returns empty.
    #[test]
    fn decrypt_sam_hash_with_rid_empty_input() {
        todo!()
    }

    /// str_to_key produces different keys for different inputs.
    #[test]
    fn str_to_key_different_inputs_different_keys() {
        todo!()
    }

    /// rid_to_des_keys for RID=0 both keys derived without panic.
    #[test]
    fn rid_to_des_keys_zero_rid() {
        todo!()
    }

    /// rc4_crypt with non-trivial key produces different output than input.
    #[test]
    fn rc4_crypt_transforms_data() {
        todo!()
    }

    /// aes128_decrypt_block applied to a block of known plaintext+key.
    #[test]
    fn aes128_decrypt_block_produces_output() {
        todo!()
    }

    /// gf_mul with both operands non-zero.
    #[test]
    fn gf_mul_known_values() {
        todo!()
    }

    /// HashdumpEntry struct fields accessible and clone works.
    #[test]
    fn hashdump_entry_clone_and_fields() {
        todo!()
    }

    /// EMPTY_NT_HASH and EMPTY_LM_HASH constants have expected lengths.
    #[test]
    fn empty_hash_constants_correct() {
        todo!()
    }

    /// MAX_USERS constant is within reasonable bounds.
    #[test]
    fn max_users_constant_reasonable() {
        todo!()
    }

    // ── Additional DES / crypto coverage ────────────────────────────

    /// des_ecb_encrypt called directly produces 8 bytes.
    #[test]
    fn des_ecb_encrypt_produces_8_bytes() {
        todo!()
    }

    /// des_ecb_encrypt and des_ecb_decrypt are inverses for arbitrary key/data.
    #[test]
    fn des_encrypt_decrypt_round_trip_all_zeros() {
        todo!()
    }

    /// rid_to_des_keys for RID=500 (Administrator) produces known structure.
    #[test]
    fn rid_to_des_keys_admin_rid() {
        todo!()
    }

    /// decrypt_sam_hash_with_rid with 16-byte all-0xFF input produces 16 bytes.
    #[test]
    fn decrypt_sam_hash_with_rid_all_ff() {
        todo!()
    }

    /// aes_cbc_decrypt_simple with 32 bytes of data produces 32 bytes.
    #[test]
    fn aes_cbc_decrypt_simple_32_bytes() {
        todo!()
    }

    /// inv_mix_columns does not panic on any 16-byte input.
    #[test]
    fn inv_mix_columns_no_panic() {
        todo!()
    }

    /// gf_mul is commutative for small values.
    #[test]
    fn gf_mul_commutative() {
        todo!()
    }

    /// extract_hashes_from_v with nt_length >= 20 and offset in bounds but
    /// enc_start + 16 exceeds v_data → falls back to empty_nt.
    #[test]
    fn extract_hashes_from_v_enc_start_exceeds_data() {
        todo!()
    }

    /// resolve_flat_base with mapped hive but zero base_block pointer returns 0.
    #[test]
    fn resolve_flat_base_zero_base_block_returns_zero() {
        todo!()
    }

    /// resolve_flat_base with mapped hive, non-zero base_block, non-zero storage → returns storage.
    #[test]
    fn resolve_flat_base_nonzero_storage_returns_storage() {
        todo!()
    }

    // ── read_key_class_name: class_len == 0 returns empty ───────────

    /// read_key_class_name with class_len = 0 returns empty.
    #[test]
    fn read_key_class_name_zero_len_returns_empty() {
        todo!()
    }

    // ── read_value_data: val_count > 0 but val_list unmapped ────────

    /// read_value_data: key with val_count=1 but val_list_addr unmapped → empty.
    #[test]
    fn read_value_data_val_list_unmapped_returns_empty() {
        todo!()
    }

    // ── extract_hashes_from_v: nt_length >= 20, lm_length >= 20 in bounds ──

    /// extract_hashes_from_v: both nt and lm offsets in bounds with enc_start in bounds.
    /// With all-zero xor the DES decryption runs, producing a 16-byte result that
    /// is hex-encoded (32 chars, different from empty hashes).
    #[test]
    fn extract_hashes_from_v_both_in_bounds_produces_hashes() {
        todo!()
    }

    // ── extract_boot_key: ControlSet001 fallback branch ─────────────
    //
    // Build a SYSTEM hive with an lf list under root containing "ControlSet001"
    // but NOT "CurrentControlSet". The fallback branch is exercised when
    // CurrentControlSet is not found and ControlSet001 is tried.

    /// extract_boot_key falls back to ControlSet001 when CurrentControlSet missing.
    /// Since ControlSet001's subkeys are 0, it returns empty → walk_hashdump returns empty.
    #[test]
    fn extract_boot_key_fallback_to_controlset001() {
        todo!()
    }

    // ── find_subkey_by_name: unknown list sig returns 0 ─────────────

    // ── Full walk_hashdump test: SYSTEM + SAM hive chain ─────────────
    //
    // This test builds two minimal hives in synthetic memory to exercise the
    // complete walk_hashdump body (L137-282) including extract_boot_key,
    // decrypt_hashed_boot_key, and user enumeration.
    //
    // Strategy:
    //   - Boot key: all-zero class names → boot_key = [0u8; 16] (trivially)
    //   - F value: revision=2, all-zero salt/encrypted data → RC4 of MD5([0;16]+...)
    //   - V value: all-zero data → extract_hashes_from_v returns empty hashes
    //   - Users key: 1 RID entry "000001F4" (RID=500)
    //
    // Physical addresses stay well below 16 MB.

    // Write a NK cell at `off` within `page` (page offsets = virt).
    fn write_nk(page: &mut Vec<u8>, off: usize, name: &[u8], subkey_count: u32, list_off: u32, val_count: u32, val_list_off: u32, class_len: u16, class_off: u32) {
        todo!()
    }

    // Write a lf list at `off` within `page` with one entry pointing to `child_off`.
    fn write_lf1(page: &mut Vec<u8>, off: usize, child_off: u32) {
        todo!()
    }

    // Write a lf list at `off` within `page` with N entries.
    fn write_lf_n(page: &mut Vec<u8>, off: usize, children: &[u32]) {
        todo!()
    }

    // Write a VK cell at `off` within `page`.
    // VK: sig at 0=vk, NameLength at 0x02, DataLength at 0x08, DataOffset at 0x0C, Name at 0x18.
    fn write_vk(page: &mut Vec<u8>, off: usize, name: &[u8], data_len: u32, data_off: u32) {
        todo!()
    }

    /// Helper: addr = cell_off + 4 within the flat page.
    fn ao(cell_off: u32) -> usize {
        todo!()
    }

    /// Build a minimal SYSTEM hive flat page for walk_hashdump.
    /// Navigation: root → CurrentControlSet → Control → Lsa → {JD, Skew1, GBG, Data}
    /// Each of the 4 LSA keys has a class name of "00000000" (UTF-16LE, 16 bytes)
    /// The concatenated hex = "00000000" × 4 = 32 hex chars
    /// → raw_bytes = [0u8; 16] → boot_key = [0u8; 16] (after scramble, still all zeros)
    ///
    /// Layout rule: each subkey list cell is placed AFTER its parent NK's footprint
    /// (NK footprint = ao(nk_off)..ao(nk_off)+0x4C+name_len+2).  Class data cells
    /// are placed in a dedicated region ≥ 0x3C0 so they never alias NK fields.
    fn build_system_hive(flat: &mut Vec<u8>) {
        todo!()
    }

    /// Build a minimal SAM hive flat page for walk_hashdump.
    /// Navigation: root → SAM → Domains → Account (F value, rev2) → Users → RID "000001F4"
    fn build_sam_hive(flat: &mut Vec<u8>) {
        todo!()
    }

    /// Full walk_hashdump test: both SYSTEM and SAM hives with valid structure.
    /// Exercises L137-282 (walk body), L290-366 (extract_boot_key), L514-622
    /// (resolve_username_for_rid called with names_key=0 → "RID-500"),
    /// and L1117-1185 (read_value_data inner loop finding "F" and "V" values).
    #[test]
    fn walk_hashdump_full_chain_produces_entry() {
        todo!()
    }

    /// read_value_data: val_count=1, VK found but data_len=0 → empty.
    /// Exercises the `if data_len == 0 || data_len > 0x10_0000 { return Vec::new() }` branch (L1155).
    #[test]
    fn read_value_data_zero_data_len_returns_empty() {
        todo!()
    }

    /// read_value_data: val_count=1, VK found with inline data (high bit set in DataLength).
    /// Exercises the `if (raw_len_bytes & 0x8000_0000) != 0` branch (L1165).
    #[test]
    fn read_value_data_inline_data_returned() {
        todo!()
    }

    /// read_value_data: VK name does not match → skip → returns empty at end.
    /// Exercises the `if !vname.eq_ignore_ascii_case(target_name) { continue }` branch (L1143).
    #[test]
    fn read_value_data_name_mismatch_returns_empty() {
        todo!()
    }

    /// resolve_username_for_rid with Names key having subkey_count=0 returns "RID-<rid>".
    /// Exercises the early return at L525-526.
    #[test]
    fn resolve_username_for_rid_zero_subkey_count_returns_fallback() {
        todo!()
    }

    /// find_subkey_by_name with a list whose signature is unrecognised returns 0.
    #[test]
    fn find_subkey_by_name_unknown_list_sig_returns_zero() {
        todo!()
    }
}
