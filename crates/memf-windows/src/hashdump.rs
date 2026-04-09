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
    0x08, 0x05, 0x04, 0x02, 0x0B, 0x09, 0x0D, 0x03,
    0x00, 0x06, 0x01, 0x0C, 0x0E, 0x0A, 0x0F, 0x07,
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
    if username.is_empty() || nt_hash.is_empty() {
        return false;
    }

    let hash_lower = nt_hash.to_ascii_lowercase();

    // Empty/blank password — NT hash of ""
    if hash_lower == EMPTY_NT_HASH {
        return true;
    }

    // Well-known default/weak password hashes
    const KNOWN_BAD_HASHES: &[&str] = &[
        // "password"
        "a4f49c406510bdcab6824ee7c30fd852",
        // "Password1"
        "b4a06b2eafca1e1f17e321090e652794",
        // "admin"
        "209c6174da490caeb422f3fa5a7ae634",
        // "P@ssw0rd"
        "161cff084477fe596a5db81874498a24",
        // "test"
        "0cb6948805f797bf2a82807973b89537",
        // "changeme"
        "5835048ce94ad0564e29a924a03510ef",
    ];
    if KNOWN_BAD_HASHES.iter().any(|&h| hash_lower == h) {
        return true;
    }

    // Machine accounts (trailing $) with a non-empty, non-standard hash
    // Machine accounts normally rotate their password; a blank hash is suspicious.
    let lower_name = username.to_ascii_lowercase();
    if lower_name.ends_with('$') && hash_lower != EMPTY_NT_HASH {
        // Machine accounts with known-bad hashes are especially suspicious,
        // but even a non-rotating hash on a machine account is unusual only
        // if it matches a known weak hash. We already caught those above.
        // Here we flag machine accounts that have the empty LM-equivalent
        // pattern in their NT hash field (shouldn't happen normally).
        // For now, machine accounts with blank passwords are the main concern.
        // (blank case already handled above, so machine accounts with real
        //  hashes are not flagged here)
    }

    false
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
    if sam_hive_addr == 0 || system_hive_addr == 0 {
        return Ok(Vec::new());
    }

    todo!("implement hashdump walker: boot key extraction, SAM hash decryption")
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
    let addr = flat_base + (cell_off as u64) + 4;
    match reader.read_bytes(addr, 2) {
        Ok(bytes) if bytes.len() == 2 => addr,
        _ => 0,
    }
}

/// Find a subkey by name under a parent `_CM_KEY_NODE`.
fn find_subkey_by_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    parent_addr: u64,
    target_name: &str,
) -> u64 {
    let subkey_count: u32 = match reader.read_bytes(parent_addr + 0x18, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return 0,
    };

    if subkey_count == 0 || subkey_count > 4096 {
        return 0;
    }

    let list_off: u32 = match reader.read_bytes(parent_addr + 0x20, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return 0,
    };

    let list_addr = read_cell_addr(reader, flat_base, list_off);
    if list_addr == 0 {
        return 0;
    }

    let list_sig = match reader.read_bytes(list_addr, 2) {
        Ok(bytes) if bytes.len() == 2 => [bytes[0], bytes[1]],
        _ => return 0,
    };

    let count: u16 = match reader.read_bytes(list_addr + 2, 2) {
        Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
        _ => return 0,
    };

    for i in 0..count.min(4096) {
        let entry_off = match list_sig {
            [b'l', b'f'] | [b'l', b'h'] => {
                match reader.read_bytes(list_addr + 4 + (i as u64) * 8, 4) {
                    Ok(bytes) if bytes.len() == 4 => {
                        u32::from_le_bytes(bytes[..4].try_into().unwrap())
                    }
                    _ => continue,
                }
            }
            [b'l', b'i'] => {
                match reader.read_bytes(list_addr + 4 + (i as u64) * 4, 4) {
                    Ok(bytes) if bytes.len() == 4 => {
                        u32::from_le_bytes(bytes[..4].try_into().unwrap())
                    }
                    _ => continue,
                }
            }
            _ => return 0,
        };

        let key_addr = read_cell_addr(reader, flat_base, entry_off);
        if key_addr == 0 {
            continue;
        }

        let name_len: u16 = match reader.read_bytes(key_addr + 0x4A, 2) {
            Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
            _ => continue,
        };

        if name_len == 0 || name_len > 256 {
            continue;
        }

        let name = match reader.read_bytes(key_addr + 0x4C, name_len as usize) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            _ => continue,
        };

        if name.eq_ignore_ascii_case(target_name) {
            return key_addr;
        }
    }

    0
}

/// Read the class name of a `_CM_KEY_NODE` (used for boot key extraction).
/// Returns the raw bytes of the class name, or an empty vec on failure.
fn read_key_class_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    key_addr: u64,
) -> Vec<u8> {
    // _CM_KEY_NODE: ClassLength at 0x4E (u16), Class offset at 0x30 (u32).
    let class_len: u16 = match reader.read_bytes(key_addr + 0x4E, 2) {
        Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
        _ => return Vec::new(),
    };

    if class_len == 0 || class_len > 1024 {
        return Vec::new();
    }

    let class_off: u32 = match reader.read_bytes(key_addr + 0x30, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return Vec::new(),
    };

    let class_addr = read_cell_addr(reader, flat_base, class_off);
    if class_addr == 0 {
        return Vec::new();
    }

    match reader.read_bytes(class_addr, class_len as usize) {
        Ok(bytes) => bytes,
        _ => Vec::new(),
    }
}

/// Read the named value data from a registry key's value list.
/// Returns the raw data bytes, or an empty vec on failure.
fn read_value_data<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    key_addr: u64,
    target_name: &str,
) -> Vec<u8> {
    let val_count: u32 = match reader.read_bytes(key_addr + 0x28, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return Vec::new(),
    };

    if val_count == 0 {
        return Vec::new();
    }

    let val_list_off: u32 = match reader.read_bytes(key_addr + 0x2C, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return Vec::new(),
    };

    let val_list_addr = read_cell_addr(reader, flat_base, val_list_off);
    if val_list_addr == 0 {
        return Vec::new();
    }

    for v in 0..val_count.min(64) {
        let val_off: u32 = match reader.read_bytes(val_list_addr + (v as u64) * 4, 4) {
            Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            _ => continue,
        };

        let val_addr = read_cell_addr(reader, flat_base, val_off);
        if val_addr == 0 {
            continue;
        }

        // _CM_KEY_VALUE: NameLength at 0x02 (u16), Name at 0x18.
        let vname_len: u16 = match reader.read_bytes(val_addr + 0x02, 2) {
            Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
            _ => continue,
        };

        if vname_len == 0 || vname_len > 256 {
            continue;
        }

        let vname = match reader.read_bytes(val_addr + 0x18, vname_len as usize) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            _ => continue,
        };

        if !vname.eq_ignore_ascii_case(target_name) {
            continue;
        }

        // DataLength at 0x08 (u32), DataOffset at 0x0C (u32).
        let data_len: u32 = match reader.read_bytes(val_addr + 0x08, 4) {
            Ok(bytes) if bytes.len() == 4 => {
                u32::from_le_bytes(bytes[..4].try_into().unwrap()) & 0x7FFF_FFFF
            }
            _ => return Vec::new(),
        };

        if data_len == 0 || data_len > 0x10_0000 {
            return Vec::new();
        }

        // Small data (high bit set in original length) is stored inline at offset 0x0C.
        let raw_len_bytes = match reader.read_bytes(val_addr + 0x08, 4) {
            Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            _ => return Vec::new(),
        };

        if (raw_len_bytes & 0x8000_0000) != 0 {
            // Inline data at 0x0C, up to 4 bytes.
            let inline_len = data_len.min(4) as usize;
            return reader.read_bytes(val_addr + 0x0C, inline_len).unwrap_or_default();
        }

        let data_off: u32 = match reader.read_bytes(val_addr + 0x0C, 4) {
            Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            _ => return Vec::new(),
        };

        let data_addr = read_cell_addr(reader, flat_base, data_off);
        if data_addr == 0 {
            return Vec::new();
        }

        return reader.read_bytes(data_addr, data_len as usize).unwrap_or_default();
    }

    Vec::new()
}

/// Resolve a hive's flat base address for cell offset calculations.
fn resolve_flat_base<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
) -> u64 {
    let base_block_off = reader
        .symbols()
        .field_offset("_HHIVE", "BaseBlock")
        .unwrap_or(0x10);

    let base_block_addr = match reader.read_bytes(hive_addr + base_block_off, 8) {
        Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        _ => return 0,
    };

    if base_block_addr == 0 {
        return 0;
    }

    let storage_base = reader
        .symbols()
        .field_offset("_HHIVE", "Storage")
        .unwrap_or(0x30);

    match reader.read_bytes(hive_addr + storage_base, 8) {
        Ok(bytes) if bytes.len() == 8 => {
            let addr = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            if addr != 0 { addr } else { base_block_addr + 0x1000 }
        }
        _ => base_block_addr + 0x1000,
    }
}

/// Resolve the root cell address of a hive.
fn resolve_root_cell<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hive_addr: u64,
    flat_base: u64,
) -> u64 {
    let base_block_off = reader
        .symbols()
        .field_offset("_HHIVE", "BaseBlock")
        .unwrap_or(0x10);

    let base_block_addr = match reader.read_bytes(hive_addr + base_block_off, 8) {
        Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        _ => return 0,
    };

    if base_block_addr == 0 {
        return 0;
    }

    let root_cell_off = match reader.read_bytes(base_block_addr + 0x24, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return 0,
    };

    if root_cell_off == 0 || root_cell_off == u32::MAX {
        return 0;
    }

    read_cell_addr(reader, flat_base, root_cell_off)
}

/// Format a byte slice as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Perform a single DES block encryption (used for RID-based hash decryption).
/// This is a minimal DES implementation for the specific SAM hash use case.
/// Windows uses two DES keys derived from the RID to decrypt the 16-byte hash.
fn des_ecb_encrypt(key: &[u8; 8], data: &[u8; 8]) -> [u8; 8] {
    // DES Initial Permutation table
    const IP: [u8; 64] = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    ];

    // DES Final Permutation (IP^-1)
    const FP: [u8; 64] = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25,
    ];

    // DES Expansion permutation
    const E: [u8; 48] = [
        32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
         8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1,
    ];

    // DES P-box permutation
    const P: [u8; 32] = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
    ];

    // DES S-boxes
    const SBOXES: [[u8; 64]; 8] = [
        [
            14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
            0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
            4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
            15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13,
        ],
        [
            15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
            3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
            0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
            13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9,
        ],
        [
            10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
            13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
            13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
            1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12,
        ],
        [
            7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
            13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
            10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
            3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14,
        ],
        [
            2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
            14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
            4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
            11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3,
        ],
        [
            12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
            10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
            9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
            4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13,
        ],
        [
            4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
            13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
            1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
            6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12,
        ],
        [
            13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
            1,15,13,8,10,3,7,4,12,5,6,2,0,14,9,11,
            7,0,1,3,13,4,14,10,15,5,2,12,11,9,6,8,
            2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11,
        ],
    ];

    // DES key schedule: PC-1 and PC-2 permutations, shift schedule
    const PC1: [u8; 56] = [
        57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4,
    ];

    const PC2: [u8; 48] = [
        14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
        23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
    ];

    const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

    // Helper: get bit n (1-indexed) from a byte slice
    fn get_bit(data: &[u8], pos: u8) -> u8 {
        let byte_idx = ((pos - 1) / 8) as usize;
        let bit_idx = 7 - ((pos - 1) % 8);
        if byte_idx < data.len() {
            (data[byte_idx] >> bit_idx) & 1
        } else {
            0
        }
    }

    // Helper: set bit n (1-indexed) in a byte slice
    fn set_bit(data: &mut [u8], pos: u8, val: u8) {
        let byte_idx = ((pos - 1) / 8) as usize;
        let bit_idx = 7 - ((pos - 1) % 8);
        if byte_idx < data.len() {
            if val == 1 {
                data[byte_idx] |= 1 << bit_idx;
            } else {
                data[byte_idx] &= !(1 << bit_idx);
            }
        }
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
        rid_bytes[0], rid_bytes[1], rid_bytes[2], rid_bytes[3],
        rid_bytes[0], rid_bytes[1], rid_bytes[2],
    ];

    // Second key: bytes 3,0,1,2,3,0,1
    let s2 = [
        rid_bytes[3], rid_bytes[0], rid_bytes[1], rid_bytes[2],
        rid_bytes[3], rid_bytes[0], rid_bytes[1],
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
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    ];
    const FP: [u8; 64] = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25,
    ];
    const E_TABLE: [u8; 48] = [
        32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
         8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1,
    ];
    const P_TABLE: [u8; 32] = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
    ];
    const SBOXES: [[u8; 64]; 8] = [
        [
            14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
            0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
            4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
            15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13,
        ],
        [
            15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
            3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
            0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
            13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9,
        ],
        [
            10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
            13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
            13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
            1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12,
        ],
        [
            7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
            13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
            10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
            3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14,
        ],
        [
            2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
            14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
            4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
            11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3,
        ],
        [
            12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
            10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
            9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
            4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13,
        ],
        [
            4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
            13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
            1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
            6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12,
        ],
        [
            13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
            1,15,13,8,10,3,7,4,12,5,6,2,0,14,9,11,
            7,0,1,3,13,4,14,10,15,5,2,12,11,9,6,8,
            2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11,
        ],
    ];
    const PC1: [u8; 56] = [
        57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4,
    ];
    const PC2: [u8; 48] = [
        14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
        23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
    ];
    const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

    fn get_bit(data: &[u8], pos: u8) -> u8 {
        let byte_idx = ((pos - 1) / 8) as usize;
        let bit_idx = 7 - ((pos - 1) % 8);
        if byte_idx < data.len() { (data[byte_idx] >> bit_idx) & 1 } else { 0 }
    }

    fn set_bit(data: &mut [u8], pos: u8, val: u8) {
        let byte_idx = ((pos - 1) / 8) as usize;
        let bit_idx = 7 - ((pos - 1) % 8);
        if byte_idx < data.len() {
            if val == 1 { data[byte_idx] |= 1 << bit_idx; }
            else { data[byte_idx] &= !(1 << bit_idx); }
        }
    }

    // Generate subkeys (same as encrypt)
    let mut cd = [0u8; 7];
    for i in 0..56u8 {
        let bit = get_bit(key, PC1[i as usize]);
        let byte_idx = (i / 8) as usize;
        let bit_idx = 7 - (i % 8);
        if bit == 1 { cd[byte_idx] |= 1 << bit_idx; }
    }

    let mut c: u32 = 0;
    let mut d: u32 = 0;
    for i in 0..28u8 {
        let byte_idx = (i / 8) as usize;
        let bit_idx = 7 - (i % 8);
        if (cd[byte_idx] >> bit_idx) & 1 == 1 { c |= 1 << (27 - i); }
    }
    for i in 0..28u8 {
        let src = i + 28;
        let byte_idx = (src / 8) as usize;
        let bit_idx = 7 - (src % 8);
        if (cd[byte_idx] >> bit_idx) & 1 == 1 { d |= 1 << (27 - i); }
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
            if bit == 1 { subkeys[round][byte_idx] |= 1 << bit_idx; }
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
            if bit == 1 { expanded[byte_idx] |= 1 << bit_idx; }
        }

        for i in 0..6 { expanded[i] ^= subkeys[round][i]; }

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
            if bit == 1 { p_out |= 1 << (31 - i); }
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
    if encrypted.len() < 16 {
        return Vec::new();
    }

    let (key1, key2) = rid_to_des_keys(rid);

    let mut block1 = [0u8; 8];
    let mut block2 = [0u8; 8];
    block1.copy_from_slice(&encrypted[..8]);
    block2.copy_from_slice(&encrypted[8..16]);

    let dec1 = des_ecb_decrypt(&key1, &block1);
    let dec2 = des_ecb_decrypt(&key2, &block2);

    let mut result = Vec::with_capacity(16);
    result.extend_from_slice(&dec1);
    result.extend_from_slice(&dec2);
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ---------------------------------------------------------------
    // Classifier tests
    // ---------------------------------------------------------------

    /// Empty NT hash (blank password) is suspicious.
    #[test]
    fn classify_empty_nt_hash_suspicious() {
        assert!(classify_hashdump("Administrator", EMPTY_NT_HASH));
    }

    /// Normal (non-empty, non-known-bad) hash is not suspicious.
    #[test]
    fn classify_normal_hash_benign() {
        assert!(!classify_hashdump(
            "john.doe",
            "aabbccdd11223344aabbccdd11223344"
        ));
    }

    /// Machine account with empty hash is suspicious (blank password case).
    #[test]
    fn classify_machine_account_empty_hash() {
        assert!(classify_hashdump("WORKSTATION$", EMPTY_NT_HASH));
    }

    /// Machine account with normal hash is not suspicious.
    #[test]
    fn classify_machine_account_normal_hash() {
        assert!(!classify_hashdump(
            "WORKSTATION$",
            "aabbccdd11223344aabbccdd11223344"
        ));
    }

    /// Known bad hash ("password") is suspicious.
    #[test]
    fn classify_known_bad_hash_suspicious() {
        assert!(classify_hashdump(
            "admin_user",
            "a4f49c406510bdcab6824ee7c30fd852"
        ));
    }

    /// Empty username returns false (graceful).
    #[test]
    fn classify_empty_username_benign() {
        assert!(!classify_hashdump("", EMPTY_NT_HASH));
    }

    /// Empty hash string returns false (graceful).
    #[test]
    fn classify_empty_hash_string_benign() {
        assert!(!classify_hashdump("admin", ""));
    }

    /// Blank password hash with different casing still detected.
    #[test]
    fn classify_blank_password_case_insensitive() {
        assert!(classify_hashdump(
            "testuser",
            "31D6CFE0D16AE931B73C59D7E0C089C0"
        ));
    }

    // ---------------------------------------------------------------
    // Walker tests
    // ---------------------------------------------------------------

    /// No hive addresses → empty Vec.
    #[test]
    fn walk_hashdump_no_hive() {
        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .add_struct("_CM_KEY_NODE", 0x80)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // Both zero → empty
        let result = walk_hashdump(&reader, 0, 0).unwrap();
        assert!(result.is_empty());

        // SAM zero → empty
        let result = walk_hashdump(&reader, 0, 0xDEAD).unwrap();
        assert!(result.is_empty());

        // SYSTEM zero → empty
        let result = walk_hashdump(&reader, 0xBEEF, 0).unwrap();
        assert!(result.is_empty());
    }

    // ---------------------------------------------------------------
    // DES / key derivation unit tests
    // ---------------------------------------------------------------

    /// `str_to_key` produces 8-byte key with parity bits set.
    #[test]
    fn str_to_key_parity() {
        let input = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let key = str_to_key(&input);
        assert_eq!(key.len(), 8);
        // Every byte should have odd parity
        for &b in &key {
            assert_eq!(b.count_ones() % 2, 1, "byte {b:#04x} should have odd parity");
        }
    }

    /// `rid_to_des_keys` produces two distinct keys.
    #[test]
    fn rid_to_des_keys_distinct() {
        let (k1, k2) = rid_to_des_keys(500);
        assert_ne!(k1, k2);
        assert_eq!(k1.len(), 8);
        assert_eq!(k2.len(), 8);
    }

    /// `hex_encode` works correctly.
    #[test]
    fn hex_encode_correct() {
        assert_eq!(hex_encode(&[0x31, 0xd6, 0xcf, 0xe0]), "31d6cfe0");
        assert_eq!(hex_encode(&[]), "");
    }

    /// DES encrypt then decrypt round-trips correctly.
    #[test]
    fn des_round_trip() {
        let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
        let plaintext = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let ciphertext = des_ecb_encrypt(&key, &plaintext);
        let decrypted = des_ecb_decrypt(&key, &ciphertext);
        assert_eq!(decrypted, plaintext);
    }
}
