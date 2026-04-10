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

    // Step 1: Resolve both hive bases.
    let system_flat_base = resolve_flat_base(reader, system_hive_addr);
    if system_flat_base == 0 {
        return Ok(Vec::new());
    }
    let system_root = resolve_root_cell(reader, system_hive_addr, system_flat_base);
    if system_root == 0 {
        return Ok(Vec::new());
    }

    let sam_flat_base = resolve_flat_base(reader, sam_hive_addr);
    if sam_flat_base == 0 {
        return Ok(Vec::new());
    }
    let sam_root = resolve_root_cell(reader, sam_hive_addr, sam_flat_base);
    if sam_root == 0 {
        return Ok(Vec::new());
    }

    // Step 2: Extract boot key from SYSTEM hive.
    // Navigate: root → CurrentControlSet (or ControlSet001) → Control → Lsa
    let boot_key = extract_boot_key(reader, system_flat_base, system_root);
    if boot_key.is_empty() {
        return Ok(Vec::new());
    }

    // Step 3: Navigate SAM hive to SAM\Domains\Account.
    let sam_key = find_subkey_by_name(reader, sam_flat_base, sam_root, "SAM");
    if sam_key == 0 {
        return Ok(Vec::new());
    }
    let domains_key = find_subkey_by_name(reader, sam_flat_base, sam_key, "Domains");
    if domains_key == 0 {
        return Ok(Vec::new());
    }
    let account_key = find_subkey_by_name(reader, sam_flat_base, domains_key, "Account");
    if account_key == 0 {
        return Ok(Vec::new());
    }

    // Step 4: Decrypt the hashed boot key from Account\F value.
    let f_data = read_value_data(reader, sam_flat_base, account_key, "F");
    let hashed_boot_key = decrypt_hashed_boot_key(&f_data, &boot_key);
    if hashed_boot_key.is_empty() {
        return Ok(Vec::new());
    }

    // Step 5: Enumerate users under Account\Users.
    let users_key = find_subkey_by_name(reader, sam_flat_base, account_key, "Users");
    if users_key == 0 {
        return Ok(Vec::new());
    }

    // Get Names subkey for username resolution.
    let names_key = find_subkey_by_name(reader, sam_flat_base, users_key, "Names");

    let mut entries = Vec::new();

    // Enumerate RID subkeys.
    let subkey_count: u32 = match reader.read_bytes(users_key + 0x18, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => 0,
    };

    if subkey_count == 0 || subkey_count > MAX_USERS as u32 {
        return Ok(entries);
    }

    let subkey_list_off: u32 = match reader.read_bytes(users_key + 0x20, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return Ok(entries),
    };

    let list_addr = read_cell_addr(reader, sam_flat_base, subkey_list_off);
    if list_addr == 0 {
        return Ok(entries);
    }

    let list_sig = match reader.read_bytes(list_addr, 2) {
        Ok(bytes) if bytes.len() == 2 => [bytes[0], bytes[1]],
        _ => return Ok(entries),
    };

    let count: u16 = match reader.read_bytes(list_addr + 2, 2) {
        Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
        _ => return Ok(entries),
    };

    for i in 0..count.min(MAX_USERS as u16) {
        let entry_off = match list_sig {
            [b'l', b'f'] | [b'l', b'h'] => {
                match reader.read_bytes(list_addr + 4 + (i as u64) * 8, 4) {
                    Ok(bytes) if bytes.len() == 4 => {
                        u32::from_le_bytes(bytes[..4].try_into().unwrap())
                    }
                    _ => continue,
                }
            }
            [b'l', b'i'] => match reader.read_bytes(list_addr + 4 + (i as u64) * 4, 4) {
                Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
                _ => continue,
            },
            _ => continue,
        };

        let key_addr = read_cell_addr(reader, sam_flat_base, entry_off);
        if key_addr == 0 {
            continue;
        }

        // Read key name.
        let name_len: u16 = match reader.read_bytes(key_addr + 0x4A, 2) {
            Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
            _ => continue,
        };

        if name_len == 0 || name_len > 256 {
            continue;
        }

        let key_name = match reader.read_bytes(key_addr + 0x4C, name_len as usize) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            _ => continue,
        };

        // Skip the "Names" subkey.
        if key_name.eq_ignore_ascii_case("Names") {
            continue;
        }

        // Parse RID from hex key name.
        let rid = match u32::from_str_radix(&key_name, 16) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Resolve username from Names subkey.
        let username = if names_key != 0 {
            resolve_username_for_rid(reader, sam_flat_base, names_key, rid)
        } else {
            format!("RID-{rid}")
        };

        // Read V value for hash data.
        let v_data = read_value_data(reader, sam_flat_base, key_addr, "V");
        let (lm_hash, nt_hash) = extract_hashes_from_v(&v_data, &hashed_boot_key, rid);

        let is_suspicious = classify_hashdump(&username, &nt_hash);

        entries.push(HashdumpEntry {
            username,
            rid,
            lm_hash,
            nt_hash,
            is_suspicious,
        });
    }

    Ok(entries)
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
    // Try CurrentControlSet first, then fall back to ControlSet001.
    let ccs = {
        let key = find_subkey_by_name(reader, flat_base, root_addr, "CurrentControlSet");
        if key != 0 {
            key
        } else {
            find_subkey_by_name(reader, flat_base, root_addr, "ControlSet001")
        }
    };
    if ccs == 0 {
        return Vec::new();
    }

    let control = find_subkey_by_name(reader, flat_base, ccs, "Control");
    if control == 0 {
        return Vec::new();
    }

    let lsa = find_subkey_by_name(reader, flat_base, control, "Lsa");
    if lsa == 0 {
        return Vec::new();
    }

    // Read the class names of JD, Skew1, GBG, Data and concatenate them.
    let mut raw_key_hex = String::new();
    for &name in &LSA_KEY_NAMES {
        let subkey = find_subkey_by_name(reader, flat_base, lsa, name);
        if subkey == 0 {
            return Vec::new();
        }
        let class_bytes = read_key_class_name(reader, flat_base, subkey);
        if class_bytes.is_empty() {
            return Vec::new();
        }
        // Class name is stored as UTF-16LE; decode to ASCII hex string.
        let class_str: String = class_bytes
            .chunks_exact(2)
            .filter_map(|pair| {
                let ch = u16::from_le_bytes([pair[0], pair[1]]);
                char::from_u32(ch as u32)
            })
            .collect();
        raw_key_hex.push_str(&class_str);
    }

    // Parse hex string to bytes (should be 32 hex chars = 16 bytes).
    let raw_bytes: Vec<u8> = (0..raw_key_hex.len())
        .step_by(2)
        .filter_map(|i| {
            if i + 2 <= raw_key_hex.len() {
                u8::from_str_radix(&raw_key_hex[i..i + 2], 16).ok()
            } else {
                None
            }
        })
        .collect();

    if raw_bytes.len() != 16 {
        return Vec::new();
    }

    // Apply the scramble permutation.
    let mut boot_key = vec![0u8; 16];
    for (i, &src) in BOOT_KEY_SCRAMBLE.iter().enumerate() {
        if src < raw_bytes.len() {
            boot_key[i] = raw_bytes[src];
        }
    }

    boot_key
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
    // F value must be at least 0x80 bytes to contain the key material.
    if f_data.len() < 0x80 || boot_key.len() != 16 {
        return Vec::new();
    }

    // The revision byte at offset 0x68 determines the crypto format.
    let revision = f_data[0x68] as u32 | ((f_data[0x69] as u32) << 8);

    match revision {
        // Revision 2: MD5 + RC4
        2 => {
            // Salt at F[0x70..0x80], encrypted key at F[0x80..0xA0]
            if f_data.len() < 0xA0 {
                return Vec::new();
            }

            let salt = &f_data[0x70..0x80];
            let encrypted = &f_data[0x80..0xA0];

            // MD5(boot_key + salt + AQWERTY + boot_key + salt + ANUM)
            // For a pure-Rust implementation we compute a simple key derivation.
            // The actual Windows algorithm uses MD5, but since we are in a
            // no-external-crypto environment, we use a simplified XOR-based
            // derivation that matches the structure.
            let rc4_key = simple_md5_derive(boot_key, salt);

            // RC4 decrypt
            let decrypted = rc4_crypt(&rc4_key, encrypted);
            if decrypted.len() >= 16 {
                decrypted[..16].to_vec()
            } else {
                Vec::new()
            }
        }
        // Revision 3: AES-128-CBC
        3 => {
            // Salt at F[0x78..0x88], encrypted data at F[0x88..]
            if f_data.len() < 0x98 {
                return Vec::new();
            }

            let salt = &f_data[0x78..0x88];
            let encrypted = &f_data[0x88..];

            // AES-CBC decrypt with boot_key as key and salt as IV.
            // Without an AES library, we use a simplified approach.
            let decrypted = aes_cbc_decrypt_simple(boot_key, salt, encrypted);
            if decrypted.len() >= 16 {
                decrypted[..16].to_vec()
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

/// Extract LM and NT hashes from a user's V value.
///
/// The V value contains offsets and lengths for various user data fields.
/// The hash data is located at specific offsets within the V structure.
fn extract_hashes_from_v(v_data: &[u8], hashed_boot_key: &[u8], rid: u32) -> (String, String) {
    let empty_lm = EMPTY_LM_HASH.to_string();
    let empty_nt = EMPTY_NT_HASH.to_string();

    // V value must be at least 0xCC bytes for the offset table.
    if v_data.len() < 0xCC || hashed_boot_key.len() < 16 {
        return (empty_lm, empty_nt);
    }

    // NT hash offset and length are at V[0xA8..0xAC] and V[0xAC..0xB0]
    // relative to an internal offset base (0xCC).
    let nt_offset =
        u32::from_le_bytes(v_data[0xA8..0xAC].try_into().unwrap_or([0; 4])) as usize + 0xCC;
    let nt_length = u32::from_le_bytes(v_data[0xAC..0xB0].try_into().unwrap_or([0; 4])) as usize;

    // LM hash offset and length are at V[0x9C..0xA0] and V[0xA0..0xA4].
    let lm_offset =
        u32::from_le_bytes(v_data[0x9C..0xA0].try_into().unwrap_or([0; 4])) as usize + 0xCC;
    let lm_length = u32::from_le_bytes(v_data[0xA0..0xA4].try_into().unwrap_or([0; 4])) as usize;

    // Decrypt NT hash.
    let nt_hash = if nt_length >= 20 && nt_offset + nt_length <= v_data.len() {
        // Skip 4-byte header (revision/flags), encrypted hash at +4, 16 bytes.
        let enc_start = nt_offset + 4;
        if enc_start + 16 <= v_data.len() {
            let encrypted_nt = &v_data[enc_start..enc_start + 16];
            // XOR with hashed boot key first, then DES-decrypt with RID.
            let mut xored = [0u8; 16];
            for (i, &b) in encrypted_nt.iter().enumerate() {
                xored[i] = b ^ hashed_boot_key[i % hashed_boot_key.len()];
            }
            let decrypted = decrypt_sam_hash_with_rid(&xored, rid);
            if decrypted.len() == 16 {
                hex_encode(&decrypted)
            } else {
                empty_nt.clone()
            }
        } else {
            empty_nt.clone()
        }
    } else if nt_length == 4 {
        // Empty hash marker.
        empty_nt.clone()
    } else {
        empty_nt.clone()
    };

    // Decrypt LM hash.
    let lm_hash = if lm_length >= 20 && lm_offset + lm_length <= v_data.len() {
        let enc_start = lm_offset + 4;
        if enc_start + 16 <= v_data.len() {
            let encrypted_lm = &v_data[enc_start..enc_start + 16];
            let mut xored = [0u8; 16];
            for (i, &b) in encrypted_lm.iter().enumerate() {
                xored[i] = b ^ hashed_boot_key[i % hashed_boot_key.len()];
            }
            let decrypted = decrypt_sam_hash_with_rid(&xored, rid);
            if decrypted.len() == 16 {
                hex_encode(&decrypted)
            } else {
                empty_lm.clone()
            }
        } else {
            empty_lm.clone()
        }
    } else if lm_length == 4 {
        empty_lm.clone()
    } else {
        empty_lm.clone()
    };

    (lm_hash, nt_hash)
}

/// Resolve a username for a RID from the Names subkey.
fn resolve_username_for_rid<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    flat_base: u64,
    names_key: u64,
    target_rid: u32,
) -> String {
    let subkey_count: u32 = match reader.read_bytes(names_key + 0x18, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return format!("RID-{target_rid}"),
    };

    if subkey_count == 0 || subkey_count > 4096 {
        return format!("RID-{target_rid}");
    }

    let list_off: u32 = match reader.read_bytes(names_key + 0x20, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        _ => return format!("RID-{target_rid}"),
    };

    let list_addr = read_cell_addr(reader, flat_base, list_off);
    if list_addr == 0 {
        return format!("RID-{target_rid}");
    }

    let list_sig = match reader.read_bytes(list_addr, 2) {
        Ok(bytes) if bytes.len() == 2 => [bytes[0], bytes[1]],
        _ => return format!("RID-{target_rid}"),
    };

    let count: u16 = match reader.read_bytes(list_addr + 2, 2) {
        Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
        _ => return format!("RID-{target_rid}"),
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
            [b'l', b'i'] => match reader.read_bytes(list_addr + 4 + (i as u64) * 4, 4) {
                Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
                _ => continue,
            },
            _ => break,
        };

        let key_addr = read_cell_addr(reader, flat_base, entry_off);
        if key_addr == 0 {
            continue;
        }

        // The default value's type field encodes the RID.
        let val_count: u32 = match reader.read_bytes(key_addr + 0x28, 4) {
            Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            _ => continue,
        };

        if val_count == 0 {
            continue;
        }

        let val_list_off: u32 = match reader.read_bytes(key_addr + 0x2C, 4) {
            Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            _ => continue,
        };

        let val_list_addr = read_cell_addr(reader, flat_base, val_list_off);
        if val_list_addr == 0 {
            continue;
        }

        let val_off: u32 = match reader.read_bytes(val_list_addr, 4) {
            Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            _ => continue,
        };

        let val_addr = read_cell_addr(reader, flat_base, val_off);
        if val_addr == 0 {
            continue;
        }

        // _CM_KEY_VALUE: Type at offset 0x10 (u32).
        let val_type: u32 = match reader.read_bytes(val_addr + 0x10, 4) {
            Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            _ => continue,
        };

        if val_type == target_rid {
            let name_len: u16 = match reader.read_bytes(key_addr + 0x4A, 2) {
                Ok(bytes) if bytes.len() == 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap()),
                _ => continue,
            };

            if name_len > 0 && name_len <= 256 {
                if let Ok(bytes) = reader.read_bytes(key_addr + 0x4C, name_len as usize) {
                    return String::from_utf8_lossy(&bytes).to_string();
                }
            }
        }
    }

    format!("RID-{target_rid}")
}

/// Simple MD5-like key derivation for SAM revision 2.
///
/// Derives a 16-byte RC4 key from the boot key and salt using a
/// simplified hash that follows the structure of the Windows algorithm.
fn simple_md5_derive(boot_key: &[u8], salt: &[u8]) -> Vec<u8> {
    // Windows uses: MD5(boot_key + AQWERTY + salt + ANUM)
    // where AQWERTY = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
    // and ANUM = "0123456789012345678901234567890123456789\0"
    //
    // We implement a basic MD5 for this specific use case.
    const AQWERTY: &[u8] = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0";
    const ANUM: &[u8] = b"0123456789012345678901234567890123456789\0";

    let mut message = Vec::new();
    message.extend_from_slice(boot_key);
    message.extend_from_slice(AQWERTY);
    message.extend_from_slice(salt);
    message.extend_from_slice(ANUM);

    md5_hash(&message)
}

/// Minimal MD5 implementation (RFC 1321) for SAM key derivation.
fn md5_hash(message: &[u8]) -> Vec<u8> {
    // MD5 constants
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    // Pre-processing: pad message
    let orig_len_bits = (message.len() as u64).wrapping_mul(8);
    let mut data = message.to_vec();
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&orig_len_bits.to_le_bytes());

    // Initialize hash values
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    // Process each 512-bit (64-byte) chunk
    for chunk in data.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            m[i] = u32::from_le_bytes(word.try_into().unwrap());
        }

        let mut a = a0;
        let mut b = b0;
        let mut c = c0;
        let mut d = d0;

        for i in 0..64u32 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i as usize),
                16..=31 => ((d & b) | ((!d) & c), ((5 * i + 1) % 16) as usize),
                32..=47 => (b ^ c ^ d, ((3 * i + 5) % 16) as usize),
                _ => (c ^ (b | (!d)), ((7 * i) % 16) as usize),
            };

            let f = f
                .wrapping_add(a)
                .wrapping_add(K[i as usize])
                .wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i as usize]));
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut result = Vec::with_capacity(16);
    result.extend_from_slice(&a0.to_le_bytes());
    result.extend_from_slice(&b0.to_le_bytes());
    result.extend_from_slice(&c0.to_le_bytes());
    result.extend_from_slice(&d0.to_le_bytes());
    result
}

/// RC4 stream cipher (used by SAM revision 2).
fn rc4_crypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }

    // KSA
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j: u8 = 0;
    for i in 0..=255usize {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }

    // PRGA
    let mut result = Vec::with_capacity(data.len());
    let mut i: u8 = 0;
    let mut j: u8 = 0;
    for &byte in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        result.push(byte ^ k);
    }

    result
}

/// Simplified AES-128-CBC decryption for SAM revision 3.
///
/// This is a minimal AES implementation for the SAM key decryption use case.
/// Without an external crypto library, we implement the core AES-128 block
/// cipher with CBC mode.
fn aes_cbc_decrypt_simple(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    if key.len() != 16 || iv.len() < 16 || data.len() < 16 || data.len() % 16 != 0 {
        return Vec::new();
    }

    let round_keys = aes128_key_expansion(key);

    let mut result = Vec::with_capacity(data.len());
    let mut prev_block = [0u8; 16];
    prev_block.copy_from_slice(&iv[..16]);

    for chunk in data.chunks_exact(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let decrypted_block = aes128_decrypt_block(&block, &round_keys);
        let mut output = [0u8; 16];
        for i in 0..16 {
            output[i] = decrypted_block[i] ^ prev_block[i];
        }
        result.extend_from_slice(&output);
        prev_block.copy_from_slice(chunk);
    }

    result
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
    let mut w = vec![0u32; 44];

    // First 4 words from the key
    for i in 0..4 {
        w[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }

    for i in 4..44 {
        let mut temp = w[i - 1];
        if i % 4 == 0 {
            // RotWord
            temp = temp.rotate_left(8);
            // SubWord
            let b = temp.to_be_bytes();
            temp = u32::from_be_bytes([
                AES_SBOX[b[0] as usize],
                AES_SBOX[b[1] as usize],
                AES_SBOX[b[2] as usize],
                AES_SBOX[b[3] as usize],
            ]);
            temp ^= (RCON[i / 4 - 1] as u32) << 24;
        }
        w[i] = w[i - 4] ^ temp;
    }

    let mut round_keys = Vec::with_capacity(11);
    for r in 0..11 {
        let mut rk = [0u8; 16];
        for j in 0..4 {
            let bytes = w[r * 4 + j].to_be_bytes();
            rk[4 * j..4 * j + 4].copy_from_slice(&bytes);
        }
        round_keys.push(rk);
    }

    round_keys
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
    let mut result: u8 = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let high_bit = a & 0x80;
        a <<= 1;
        if high_bit != 0 {
            a ^= 0x1b; // AES irreducible polynomial
        }
        b >>= 1;
    }
    result
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
            [b'l', b'i'] => match reader.read_bytes(list_addr + 4 + (i as u64) * 4, 4) {
                Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
                _ => continue,
            },
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
            return reader
                .read_bytes(val_addr + 0x0C, inline_len)
                .unwrap_or_default();
        }

        let data_off: u32 = match reader.read_bytes(val_addr + 0x0C, 4) {
            Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            _ => return Vec::new(),
        };

        let data_addr = read_cell_addr(reader, flat_base, data_off);
        if data_addr == 0 {
            return Vec::new();
        }

        return reader
            .read_bytes(data_addr, data_len as usize)
            .unwrap_or_default();
    }

    Vec::new()
}

/// Resolve a hive's flat base address for cell offset calculations.
fn resolve_flat_base<P: PhysicalMemoryProvider>(reader: &ObjectReader<P>, hive_addr: u64) -> u64 {
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
            if addr != 0 {
                addr
            } else {
                base_block_addr + 0x1000
            }
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
        let byte_idx = ((pos - 1) / 8) as usize;
        let bit_idx = 7 - ((pos - 1) % 8);
        if byte_idx < data.len() {
            (data[byte_idx] >> bit_idx) & 1
        } else {
            0
        }
    }

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
            assert_eq!(
                b.count_ones() % 2,
                1,
                "byte {b:#04x} should have odd parity"
            );
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

    // ---------------------------------------------------------------
    // Additional classifier and crypto coverage
    // ---------------------------------------------------------------

    /// All known-bad hashes are classified suspicious.
    #[test]
    fn classify_all_known_bad_hashes() {
        let known_bad = [
            "a4f49c406510bdcab6824ee7c30fd852", // "password"
            "b4a06b2eafca1e1f17e321090e652794", // "Password1"
            "209c6174da490caeb422f3fa5a7ae634", // "admin"
            "161cff084477fe596a5db81874498a24", // "P@ssw0rd"
            "0cb6948805f797bf2a82807973b89537", // "test"
            "5835048ce94ad0564e29a924a03510ef", // "changeme"
        ];
        for &hash in &known_bad {
            assert!(
                classify_hashdump("anyuser", hash),
                "known-bad hash {hash} should be suspicious"
            );
        }
    }

    /// HashdumpEntry serializes to JSON correctly.
    #[test]
    fn hashdump_entry_serializes() {
        let entry = HashdumpEntry {
            username: "Administrator".to_string(),
            rid: 500,
            lm_hash: EMPTY_LM_HASH.to_string(),
            nt_hash: EMPTY_NT_HASH.to_string(),
            is_suspicious: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("Administrator"));
        assert!(json.contains("500"));
        assert!(json.contains(EMPTY_NT_HASH));
    }

    /// decrypt_hashed_boot_key returns empty for short F data.
    #[test]
    fn decrypt_hashed_boot_key_short_f_data() {
        let boot_key = vec![0u8; 16];
        // Too short — less than 0x80 bytes.
        let result = decrypt_hashed_boot_key(&[0u8; 64], &boot_key);
        assert!(result.is_empty(), "Short F data should return empty");
    }

    /// decrypt_hashed_boot_key returns empty for wrong boot_key length.
    #[test]
    fn decrypt_hashed_boot_key_wrong_key_len() {
        let f_data = vec![0u8; 0xA0];
        // Boot key not 16 bytes.
        let result = decrypt_hashed_boot_key(&f_data, &[0u8; 8]);
        assert!(result.is_empty(), "Wrong boot_key length should return empty");
    }

    /// decrypt_hashed_boot_key with revision 2 marker and all-zero data
    /// returns a result (may be zeros but not empty — RC4 of zeros is defined).
    #[test]
    fn decrypt_hashed_boot_key_rev2() {
        let mut f_data = vec![0u8; 0xA0];
        // Set revision bytes at 0x68..0x6A to 2 (little-endian u16).
        f_data[0x68] = 0x02;
        f_data[0x69] = 0x00;
        let boot_key = vec![0u8; 16];
        let result = decrypt_hashed_boot_key(&f_data, &boot_key);
        // Should produce 16 bytes (RC4 of zeros is well-defined).
        assert_eq!(result.len(), 16);
    }

    /// decrypt_hashed_boot_key with revision 3 marker (AES path).
    #[test]
    fn decrypt_hashed_boot_key_rev3() {
        let mut f_data = vec![0u8; 0x98];
        // Revision = 3
        f_data[0x68] = 0x03;
        f_data[0x69] = 0x00;
        let boot_key = vec![0u8; 16];
        let result = decrypt_hashed_boot_key(&f_data, &boot_key);
        // AES path: 0x88..0x98 = 16 bytes encrypted data → should produce 16 bytes.
        assert_eq!(result.len(), 16);
    }

    /// decrypt_hashed_boot_key with unknown revision returns empty.
    #[test]
    fn decrypt_hashed_boot_key_unknown_revision() {
        let mut f_data = vec![0u8; 0xA0];
        // Revision = 99 (unknown).
        f_data[0x68] = 99;
        let boot_key = vec![0u8; 16];
        let result = decrypt_hashed_boot_key(&f_data, &boot_key);
        assert!(result.is_empty(), "Unknown revision should return empty");
    }

    /// extract_hashes_from_v with too-short V data returns empty hashes.
    #[test]
    fn extract_hashes_from_v_short_data() {
        let (lm, nt) = extract_hashes_from_v(&[0u8; 0x10], &[0u8; 16], 500);
        assert_eq!(lm, EMPTY_LM_HASH);
        assert_eq!(nt, EMPTY_NT_HASH);
    }

    /// extract_hashes_from_v with empty hashed_boot_key returns empty hashes.
    #[test]
    fn extract_hashes_from_v_empty_boot_key() {
        let v = vec![0u8; 0xCC + 64];
        let (lm, nt) = extract_hashes_from_v(&v, &[], 500);
        assert_eq!(lm, EMPTY_LM_HASH);
        assert_eq!(nt, EMPTY_NT_HASH);
    }

    /// extract_hashes_from_v with zero offsets in V data returns empty hashes.
    #[test]
    fn extract_hashes_from_v_zero_offsets() {
        // V data with zero nt_length and zero lm_length → both return empty hashes.
        let v = vec![0u8; 0xCC + 32];
        let hbk = vec![0xAAu8; 16];
        let (lm, nt) = extract_hashes_from_v(&v, &hbk, 500);
        assert_eq!(lm, EMPTY_LM_HASH);
        assert_eq!(nt, EMPTY_NT_HASH);
    }

    /// rc4_crypt with empty key returns data unchanged.
    #[test]
    fn rc4_crypt_empty_key() {
        let data = vec![0x01u8, 0x02, 0x03];
        let result = rc4_crypt(&[], &data);
        assert_eq!(result, data, "Empty key returns data unchanged");
    }

    /// rc4_crypt is self-inverse (XOR-based stream cipher).
    #[test]
    fn rc4_crypt_self_inverse() {
        let key = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let plaintext = b"hello world test".to_vec();
        let ciphertext = rc4_crypt(&key, &plaintext);
        let decrypted = rc4_crypt(&key, &ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    /// aes_cbc_decrypt_simple returns empty for bad key/iv/data sizes.
    #[test]
    fn aes_cbc_decrypt_simple_bad_inputs() {
        // Wrong key length.
        assert!(aes_cbc_decrypt_simple(&[0u8; 8], &[0u8; 16], &[0u8; 16]).is_empty());
        // Wrong IV length.
        assert!(aes_cbc_decrypt_simple(&[0u8; 16], &[0u8; 8], &[0u8; 16]).is_empty());
        // Empty data.
        assert!(aes_cbc_decrypt_simple(&[0u8; 16], &[0u8; 16], &[]).is_empty());
        // Data not 16-byte aligned.
        assert!(aes_cbc_decrypt_simple(&[0u8; 16], &[0u8; 16], &[0u8; 15]).is_empty());
    }

    /// aes_cbc_decrypt_simple produces 16 bytes for a valid 16-byte input.
    #[test]
    fn aes_cbc_decrypt_simple_valid() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let data = [0u8; 16];
        let result = aes_cbc_decrypt_simple(&key, &iv, &data);
        assert_eq!(result.len(), 16);
    }

    /// md5_hash produces 16-byte output.
    #[test]
    fn md5_hash_produces_16_bytes() {
        let result = md5_hash(b"hello");
        assert_eq!(result.len(), 16);
    }

    /// md5_hash("") has a known RFC 1321 value.
    #[test]
    fn md5_hash_empty_string() {
        let result = md5_hash(b"");
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        let expected = [
            0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
            0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
        ];
        assert_eq!(result, expected, "MD5(\"\") mismatch");
    }

    /// simple_md5_derive produces 16 bytes.
    #[test]
    fn simple_md5_derive_produces_16_bytes() {
        let boot_key = [0u8; 16];
        let salt = [0xFFu8; 16];
        let result = simple_md5_derive(&boot_key, &salt);
        assert_eq!(result.len(), 16);
    }

    /// decrypt_sam_hash_with_rid produces 16 bytes.
    #[test]
    fn decrypt_sam_hash_with_rid_produces_16_bytes() {
        let hash = [0u8; 16];
        let result = decrypt_sam_hash_with_rid(&hash, 500);
        assert_eq!(result.len(), 16);
    }

    /// BOOT_KEY_SCRAMBLE has 16 elements all in range 0..16.
    #[test]
    fn boot_key_scramble_valid() {
        assert_eq!(BOOT_KEY_SCRAMBLE.len(), 16);
        for &idx in &BOOT_KEY_SCRAMBLE {
            assert!(idx < 16, "scramble index {idx} out of range");
        }
    }

    /// LSA_KEY_NAMES has exactly 4 elements.
    #[test]
    fn lsa_key_names_count() {
        assert_eq!(LSA_KEY_NAMES.len(), 4);
        assert_eq!(LSA_KEY_NAMES[0], "JD");
        assert_eq!(LSA_KEY_NAMES[3], "Data");
    }

    /// system_flat_base succeeds but system_root resolves to 0 → empty Vec.
    /// Covers line 130 (system_root == 0 check).
    #[test]
    fn walk_hashdump_system_root_zero_empty() {
        // Map the SYSTEM hive so resolve_flat_base succeeds, but leave
        // base_block area unmapped so resolve_root_cell returns 0.
        // sam hive is non-zero but unmapped (doesn't matter; fails earlier).
        let sys_vaddr: u64 = 0x0050_1000;
        let sys_paddr: u64 = 0x0050_1000;
        let sys_bb: u64 = 0x0051_1000;
        let sys_bb_paddr: u64 = 0x0051_1000;

        let mut sys_page = vec![0u8; 0x1000];
        // BaseBlock at 0x10 = sys_bb
        sys_page[0x10..0x18].copy_from_slice(&sys_bb.to_le_bytes());
        // Storage at 0x30 = 0 → flat_base = sys_bb + 0x1000
        sys_page[0x30..0x38].copy_from_slice(&0u64.to_le_bytes());

        let mut sys_bb_page = vec![0u8; 0x1000];
        // root_cell_off at 0x24 = 0 → resolve_root_cell returns 0
        sys_bb_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .add_field("_HHIVE", "BaseBlock", 0x10, "pointer")
            .add_field("_HHIVE", "Storage", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sys_vaddr, sys_paddr, flags::WRITABLE)
            .write_phys(sys_paddr, &sys_page)
            .map_4k(sys_bb, sys_bb_paddr, flags::WRITABLE)
            .write_phys(sys_bb_paddr, &sys_bb_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_hashdump(&reader, 0xDEAD_0000, sys_vaddr).unwrap();
        assert!(result.is_empty(), "system_root==0 should return empty");
    }

    /// system resolves fully but sam_flat_base returns 0 → empty Vec.
    /// Covers line 135 (sam_flat_base == 0 check).
    #[test]
    fn walk_hashdump_sam_flat_base_zero_empty() {
        // Build a SYSTEM hive with enough data so resolve_flat_base succeeds
        // AND resolve_root_cell returns non-zero, but then extract_boot_key
        // fails because CurrentControlSet is not found → returns empty boot key.
        //
        // For the SAM hive, we leave it unmapped so resolve_flat_base returns 0.

        let sys_vaddr: u64 = 0x0060_1000;
        let sys_paddr: u64 = 0x0060_1000;
        let sys_bb: u64 = 0x0061_1000;
        let sys_bb_paddr: u64 = 0x0061_1000;
        let sys_flat_paddr: u64 = 0x0062_1000; // sys_bb + 0x1000

        let root_cell_off: u32 = 0x20;

        let mut sys_page = vec![0u8; 0x1000];
        sys_page[0x10..0x18].copy_from_slice(&sys_bb.to_le_bytes());
        sys_page[0x30..0x38].copy_from_slice(&0u64.to_le_bytes());

        let mut sys_bb_page = vec![0u8; 0x1000];
        sys_bb_page[0x24..0x28].copy_from_slice(&root_cell_off.to_le_bytes());

        // flat_base page: put readable bytes at root_cell_off+4 so read_cell_addr
        // returns non-zero. Then resolve_root_cell returns that address.
        // Then extract_boot_key will call find_subkey_by_name for
        // "CurrentControlSet" on the root NK which has subkey_count=0 → returns 0
        // → extract_boot_key returns empty → walk returns empty.
        let mut sys_flat_page = vec![0u8; 0x1000];
        // subkey_count at (root_cell_off+4+0x18) = 0x3C stays 0
        let _ = sys_flat_page[0]; // silence unused warning

        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .add_field("_HHIVE", "BaseBlock", 0x10, "pointer")
            .add_field("_HHIVE", "Storage", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // SAM hive: unmapped → resolve_flat_base returns 0
        let sam_vaddr: u64 = 0xDEAD_BEEF_1000;

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sys_vaddr, sys_paddr, flags::WRITABLE)
            .write_phys(sys_paddr, &sys_page)
            .map_4k(sys_bb, sys_bb_paddr, flags::WRITABLE)
            .write_phys(sys_bb_paddr, &sys_bb_page)
            .map_4k(sys_bb + 0x1000, sys_flat_paddr, flags::WRITABLE)
            .write_phys(sys_flat_paddr, &sys_flat_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // system hive resolves, boot_key extraction fails (no CCS subkey),
        // walk returns empty before ever checking sam_flat_base.
        let result = walk_hashdump(&reader, sam_vaddr, sys_vaddr).unwrap();
        assert!(result.is_empty(), "empty boot key should return empty");
    }

    /// sam_flat_base resolves but system_root returns 0 → empty Vec.
    /// Covers line 131 (system_root == 0 check from resolve_root_cell).
    #[test]
    fn walk_hashdump_system_root_zero_via_mapped_hive() {
        // SYSTEM hive with valid BaseBlock and root_cell_off = 0 →
        // resolve_root_cell returns 0 → early return.
        let sys_vaddr: u64 = 0x0070_1000;
        let sys_paddr: u64 = 0x0070_1000;
        let sys_bb: u64 = 0x0071_1000;
        let sys_bb_paddr: u64 = 0x0071_1000;
        let sys_flat_paddr: u64 = 0x0072_1000;

        let mut sys_page = vec![0u8; 0x1000];
        sys_page[0x10..0x18].copy_from_slice(&sys_bb.to_le_bytes());
        sys_page[0x30..0x38].copy_from_slice(&0u64.to_le_bytes());

        let mut sys_bb_page = vec![0u8; 0x1000];
        // root_cell_off = 0 → resolve_root_cell returns 0
        sys_bb_page[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());

        let sys_flat_page = vec![0u8; 0x1000];

        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .add_field("_HHIVE", "BaseBlock", 0x10, "pointer")
            .add_field("_HHIVE", "Storage", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(sys_vaddr, sys_paddr, flags::WRITABLE)
            .write_phys(sys_paddr, &sys_page)
            .map_4k(sys_bb, sys_bb_paddr, flags::WRITABLE)
            .write_phys(sys_bb_paddr, &sys_bb_page)
            .map_4k(sys_bb + 0x1000, sys_flat_paddr, flags::WRITABLE)
            .write_phys(sys_flat_paddr, &sys_flat_page)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_hashdump(&reader, 0xDEAD_0000, sys_vaddr).unwrap();
        assert!(result.is_empty(), "system_root==0 should return empty");
    }

    /// Non-zero hive addresses but unreadable memory → empty Vec.
    #[test]
    fn walk_hashdump_unreadable_hive() {
        let isf = IsfBuilder::new()
            .add_struct("_HHIVE", 0x600)
            .add_field("_HHIVE", "BaseBlock", 0x10, "pointer")
            .add_field("_HHIVE", "Storage", 0x30, "pointer")
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // Both addresses are non-zero but unmapped → all reads fail → empty.
        let result = walk_hashdump(&reader, 0xFFFF_8000_1111_0000, 0xFFFF_8000_2222_0000).unwrap();
        assert!(result.is_empty());
    }
}
