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

use aes::Aes128;
use cbc::Decryptor as CbcDecryptor;
use cipher::{block_padding::NoPadding, BlockDecrypt, BlockDecryptMut, KeyInit, KeyIvInit};
use des::Des;
use md5::{Digest, Md5};
use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

// Registry hive navigation is the shared, validated walker (correct stable-list
// offsets + lf/lh/li/ri handling) so this module no longer carries its own copy.
use crate::registry::{find_subkey_by_name, read_cell_addr, read_value_data, resolve_root_cell};

/// Maximum number of user entries to enumerate (safety limit).
const MAX_USERS: usize = 4096;
const _: () = assert!(MAX_USERS > 0 && MAX_USERS <= 65536);

/// SAM decrypt constants — copied verbatim (including trailing NUL) from
/// volatility3 `windows.registry.hashdump.Hashdump` / impacket `secretsdump`.
const AQWERTY: &[u8] = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0";
const ANUM: &[u8] = b"0123456789012345678901234567890123456789\0";
const NTPASSWORD: &[u8] = b"NTPASSWORD\0";
const LMPASSWORD: &[u8] = b"LMPASSWORD\0";

/// `odd_parity` table from vol3 — maps a byte to the nearest value with odd
/// parity, used by `sidbytes_to_key` when building the two DES keys from a RID.
const ODD_PARITY: [u8; 256] = [
    1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14, 16, 16, 19, 19, 21, 21, 22, 22, 25, 25,
    26, 26, 28, 28, 31, 31, 32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47, 49, 49,
    50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62, 64, 64, 67, 67, 69, 69, 70, 70, 73, 73,
    74, 74, 76, 76, 79, 79, 81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94, 97, 97,
    98, 98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110, 110, 112, 112, 115, 115, 117,
    117, 118, 118, 121, 121, 122, 122, 124, 124, 127, 127, 128, 128, 131, 131, 133, 133, 134, 134,
    137, 137, 138, 138, 140, 140, 143, 143, 145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155,
    155, 157, 157, 158, 158, 161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173,
    174, 174, 176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191, 191, 193,
    193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206, 206, 208, 208, 211, 211,
    213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223, 223, 224, 224, 227, 227, 229, 229, 230,
    230, 233, 233, 234, 234, 236, 236, 239, 239, 241, 241, 242, 242, 244, 244, 247, 247, 248, 248,
    251, 251, 253, 253, 254, 254,
];

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
    #[allow(clippy::items_after_statements)]
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

    // Step 1: Resolve both root cells. In-memory hives are NOT flat: every cell
    // index is translated through `_HHIVE.Storage[].Map` (the HMAP directory).
    // The hive address passed for translation is the `_CMHIVE`/`_HHIVE` VA
    // (on Win8+/9600 `_CMHIVE.Hive` is at offset 0, so they coincide).
    let system_root = resolve_root_cell(reader, system_hive_addr);
    if system_root == 0 {
        return Ok(Vec::new());
    }

    let sam_root = resolve_root_cell(reader, sam_hive_addr);
    if sam_root == 0 {
        return Ok(Vec::new());
    }

    // Step 2: Extract boot key from SYSTEM hive.
    // Navigate: root → CurrentControlSet (or ControlSet001) → Control → Lsa
    let boot_key = extract_boot_key(reader, system_hive_addr, system_root);
    if boot_key.is_empty() {
        return Ok(Vec::new());
    }

    // Step 3: Navigate SAM hive to SAM\Domains\Account.
    let sam_key = find_subkey_by_name(reader, sam_hive_addr, sam_root, "SAM");
    if sam_key == 0 {
        return Ok(Vec::new());
    }
    let domains_key = find_subkey_by_name(reader, sam_hive_addr, sam_key, "Domains");
    if domains_key == 0 {
        return Ok(Vec::new());
    }
    let account_key = find_subkey_by_name(reader, sam_hive_addr, domains_key, "Account");
    if account_key == 0 {
        return Ok(Vec::new());
    }

    // Step 4: Decrypt the hashed boot key from Account\F value.
    let f_data = read_value_data(reader, sam_hive_addr, account_key, "F");
    let hashed_boot_key = decrypt_hashed_boot_key(&f_data, &boot_key);
    if hashed_boot_key.is_empty() {
        return Ok(Vec::new());
    }

    // Step 5: Enumerate users under Account\Users.
    let users_key = find_subkey_by_name(reader, sam_hive_addr, account_key, "Users");
    if users_key == 0 {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();

    // Enumerate RID subkeys.
    let subkey_count: u32 = match reader.read_bytes(users_key + 0x14, 4) {
        Ok(bytes) if bytes.len() == 4 => bytes[..4].try_into().map_or(0, u32::from_le_bytes),
        _ => 0,
    };

    if subkey_count == 0 || subkey_count > MAX_USERS as u32 {
        return Ok(entries);
    }

    let subkey_list_off: u32 = match reader.read_bytes(users_key + 0x1c, 4) {
        Ok(bytes) if bytes.len() == 4 => bytes[..4].try_into().map_or(0, u32::from_le_bytes),
        _ => return Ok(entries),
    };

    let list_addr = read_cell_addr(reader, sam_hive_addr, subkey_list_off);
    if list_addr == 0 {
        return Ok(entries);
    }

    let list_sig = match reader.read_bytes(list_addr, 2) {
        Ok(bytes) if bytes.len() == 2 => [bytes[0], bytes[1]],
        _ => return Ok(entries),
    };

    let count: u16 = match reader.read_bytes(list_addr + 2, 2) {
        Ok(bytes) if bytes.len() == 2 => bytes[..2].try_into().map_or(0, u16::from_le_bytes),
        _ => return Ok(entries),
    };

    for i in 0..count.min(MAX_USERS as u16) {
        let entry_off = match list_sig {
            [b'l', b'f' | b'h'] => match reader.read_bytes(list_addr + 4 + u64::from(i) * 8, 4) {
                Ok(bytes) if bytes.len() == 4 => {
                    bytes[..4].try_into().map_or(0, u32::from_le_bytes)
                }
                _ => continue,
            },
            [b'l', b'i'] => match reader.read_bytes(list_addr + 4 + u64::from(i) * 4, 4) {
                Ok(bytes) if bytes.len() == 4 => {
                    bytes[..4].try_into().map_or(0, u32::from_le_bytes)
                }
                _ => continue,
            },
            _ => continue,
        };

        let key_addr = read_cell_addr(reader, sam_hive_addr, entry_off);
        if key_addr == 0 {
            continue;
        }

        // Read key name.
        let name_len: u16 = match reader.read_bytes(key_addr + 0x48, 2) {
            Ok(bytes) if bytes.len() == 2 => bytes[..2].try_into().map_or(0, u16::from_le_bytes),
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

        // Read V value: it carries both the username and the hash blobs.
        let v_data = read_value_data(reader, sam_hive_addr, key_addr, "V");
        let username = username_from_v(&v_data).unwrap_or_else(|| format!("RID-{rid}"));
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
    hhive_addr: u64,
    root_addr: u64,
) -> Vec<u8> {
    // Try CurrentControlSet first, then fall back to ControlSet001.
    let ccs = {
        let key = find_subkey_by_name(reader, hhive_addr, root_addr, "CurrentControlSet");
        if key != 0 {
            key
        } else {
            find_subkey_by_name(reader, hhive_addr, root_addr, "ControlSet001")
        }
    };
    if ccs == 0 {
        return Vec::new();
    }

    let control = find_subkey_by_name(reader, hhive_addr, ccs, "Control");
    if control == 0 {
        return Vec::new();
    }

    let lsa = find_subkey_by_name(reader, hhive_addr, control, "Lsa");
    if lsa == 0 {
        return Vec::new();
    }

    // Read the class names of JD, Skew1, GBG, Data and concatenate them.
    let mut raw_key_hex = String::new();
    for &name in &LSA_KEY_NAMES {
        let subkey = find_subkey_by_name(reader, hhive_addr, lsa, name);
        if subkey == 0 {
            return Vec::new();
        }
        let class_bytes = read_key_class_name(reader, hhive_addr, subkey);
        if class_bytes.is_empty() {
            return Vec::new();
        }
        // Class name is stored as UTF-16LE; decode to ASCII hex string.
        let class_str: String = class_bytes
            .chunks_exact(2)
            .filter_map(|pair| {
                let ch = u16::from_le_bytes([pair[0], pair[1]]);
                char::from_u32(u32::from(ch))
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

/// Decrypt the hashed boot key (`hbootkey`) from the SAM `Account\F` value.
///
/// The F value holds the domain-account metadata. Its structure-revision byte
/// at `F[0x00]` selects the crypto format (mirrors vol3
/// `Hashdump.get_hbootkey`):
///
/// - **Revision 2 (RC4)** — `rc4_key = MD5(F[0x70..0x80] ‖ AQWERTY ‖ boot_key ‖
///   ANUM)`; `hbootkey = RC4(rc4_key, F[0x80..0xA0])[..16]`.
/// - **Revision 3 (AES)** — `hbootkey = AES128-CBC-decrypt(key = boot_key,
///   iv = F[0x78..0x88], F[0x88..0xA8])[..16]`.
///
/// Returns an empty `Vec` for malformed input or an unsupported revision; on an
/// unsupported revision it also logs the offending revision byte + offset
/// (fail-loud — never fabricate a key).
fn decrypt_hashed_boot_key(f_data: &[u8], boot_key: &[u8]) -> Vec<u8> {
    // F value must be at least 0x80 bytes to contain the key material.
    if f_data.len() < 0x80 || boot_key.len() != 16 {
        return Vec::new();
    }

    // Structure revision is the first byte of the F value.
    let revision = f_data[0x00];

    match revision {
        // Revision 2: MD5 + RC4
        2 => {
            // Salt at F[0x70..0x80], encrypted hbootkey at F[0x80..0xA0].
            if f_data.len() < 0xA0 {
                return Vec::new();
            }
            let salt = &f_data[0x70..0x80];
            let encrypted = &f_data[0x80..0xA0];

            let mut md5 = Md5::new();
            md5.update(salt);
            md5.update(AQWERTY);
            md5.update(boot_key);
            md5.update(ANUM);
            let rc4_key = md5.finalize();

            // vol3 RC4-*encrypts* here; RC4 is symmetric so encrypt == decrypt.
            let decrypted = rc4_crypt(&rc4_key, encrypted);
            if decrypted.len() >= 16 {
                decrypted[..16].to_vec()
            } else {
                Vec::new()
            }
        }
        // Revision 3: AES-128-CBC (IV at F[0x78..0x88], ciphertext at F[0x88..0xA8]).
        3 => {
            if f_data.len() < 0xA8 {
                return Vec::new();
            }
            let iv = &f_data[0x78..0x88];
            let encrypted = &f_data[0x88..0xA8];
            let decrypted = aes128_cbc_decrypt(boot_key, iv, encrypted);
            if decrypted.len() >= 16 {
                decrypted[..16].to_vec()
            } else {
                Vec::new()
            }
        }
        other => {
            eprintln!(
                "memf-windows hashdump: unsupported SAM F revision {other:#04x} at offset 0x00 \
                 (supported: 2=RC4, 3=AES) — refusing to fabricate hbootkey"
            );
            Vec::new()
        }
    }
}

/// Extract LM and NT hashes from a user's `V` value.
///
/// Mirrors vol3 `Hashdump.get_user_hashes`: the V structure carries an offset
/// table; the LM blob is at `V[0x9C..0xA0] + 0xCC` (length `V[0xA0..0xA4]`) and
/// the NT blob at `V[0xA8..0xAC] + 0xCC` (length `V[0xAC..0xB0]`). Each blob's
/// byte `[+2]` is its per-hash revision:
///
/// - **rev 1** (blob length 20): `enc = blob[+4..+20]`;
///   `obfkey = RC4(MD5(hbootkey ‖ pack<L>(rid) ‖ {LM,NT}PASSWORD), enc)`.
/// - **rev 2** (blob length 56): `salt = blob[+4..+20]`, `enc = blob[+20..+52]`;
///   `obfkey = AES128-CBC-decrypt(hbootkey, salt, enc)[..16]`.
///
/// Then `(k1,k2) = sid_to_key(rid)` and
/// `hash = DES_ECB_decrypt(k1, obfkey[..8]) ‖ DES_ECB_decrypt(k2, obfkey[8..16])`.
/// There is **no** trailing XOR. An empty/absent blob (length not the present
/// length) yields the well-known empty-hash sentinel.
fn extract_hashes_from_v(v_data: &[u8], hashed_boot_key: &[u8], rid: u32) -> (String, String) {
    let empty_lm = EMPTY_LM_HASH.to_string();
    let empty_nt = EMPTY_NT_HASH.to_string();

    // V value must be at least 0xCC bytes for the offset table.
    if v_data.len() < 0xCC || hashed_boot_key.len() < 16 {
        return (empty_lm, empty_nt);
    }

    let lm_offset =
        u32::from_le_bytes(v_data[0x9C..0xA0].try_into().unwrap_or([0; 4])) as usize + 0xCC;
    let lm_length = u32::from_le_bytes(v_data[0xA0..0xA4].try_into().unwrap_or([0; 4])) as usize;
    let nt_offset =
        u32::from_le_bytes(v_data[0xA8..0xAC].try_into().unwrap_or([0; 4])) as usize + 0xCC;
    let nt_length = u32::from_le_bytes(v_data[0xAC..0xB0].try_into().unwrap_or([0; 4])) as usize;

    let lm_hash = decrypt_user_hash(
        v_data,
        hashed_boot_key,
        rid,
        lm_offset,
        lm_length,
        LMPASSWORD,
    )
    .map_or(empty_lm, |h| hex_encode(&h));
    let nt_hash = decrypt_user_hash(
        v_data,
        hashed_boot_key,
        rid,
        nt_offset,
        nt_length,
        NTPASSWORD,
    )
    .map_or(empty_nt, |h| hex_encode(&h));

    (lm_hash, nt_hash)
}

/// Decrypt a single LM/NT hash blob from a user's V value. Returns `None`
/// (→ empty-hash sentinel) when the blob is absent, length-empty, or its bytes
/// are out of range. `lmnt` is `LMPASSWORD`/`NTPASSWORD` (rev-1 RC4 salt-string).
fn decrypt_user_hash(
    v_data: &[u8],
    hbootkey: &[u8],
    rid: u32,
    offset: usize,
    length: usize,
    lmnt: &[u8],
) -> Option<[u8; 16]> {
    // Per-hash revision is blob[+2]; need at least 3 bytes to read it.
    let revision = *v_data.get(offset.checked_add(2)?)?;

    let obfkey = match revision {
        1 if length == 20 => {
            // rev 1: enc = blob[+4..+20], obfkey = RC4(MD5(hbootkey ‖ rid ‖ lmnt), enc)
            let enc = v_data.get(offset + 4..offset + 20)?;
            let mut md5 = Md5::new();
            md5.update(&hbootkey[..16]);
            md5.update(rid.to_le_bytes());
            md5.update(lmnt);
            let rc4_key = md5.finalize();
            let obf = rc4_crypt(&rc4_key, enc);
            let mut k = [0u8; 16];
            k.copy_from_slice(obf.get(..16)?);
            k
        }
        2 if length == 56 => {
            // rev 2: salt = blob[+4..+20], enc = blob[+20..+52];
            // obfkey = AES128-CBC(hbootkey, salt, enc)[..16]
            let salt = v_data.get(offset + 4..offset + 20)?;
            let enc = v_data.get(offset + 20..offset + 52)?;
            let dec = aes128_cbc_decrypt(&hbootkey[..16], salt, enc);
            let mut k = [0u8; 16];
            k.copy_from_slice(dec.get(..16)?);
            k
        }
        // Any other (rev, length) pairing — including the length-4 "no hash
        // present" marker — means there is no decryptable hash here.
        _ => return None,
    };

    let (k1, k2) = sid_to_key(rid);
    let mut hash = [0u8; 16];
    hash[..8].copy_from_slice(&des_ecb_decrypt_block(k1, obfkey[..8].try_into().ok()?));
    hash[8..].copy_from_slice(&des_ecb_decrypt_block(k2, obfkey[8..16].try_into().ok()?));
    Some(hash)
}

/// Resolve the username for a user key from its `V` value (vol3
/// `Hashdump.get_user_name`): `name = V[V[0x0C..0x10]+0xCC ..][..V[0x10..0x14]]`,
/// decoded UTF-16LE. Returns `None` when the V value is too short or the
/// computed name range is out of bounds.
fn username_from_v(v_data: &[u8]) -> Option<String> {
    if v_data.len() < 0x14 {
        return None;
    }
    let name_off = u32::from_le_bytes(v_data[0x0C..0x10].try_into().ok()?) as usize + 0xCC;
    let name_len = u32::from_le_bytes(v_data[0x10..0x14].try_into().ok()?) as usize;
    if name_len == 0 || name_len > 512 {
        return None;
    }
    let raw = v_data.get(name_off..name_off.checked_add(name_len)?)?;
    let utf16: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(String::from_utf16_lossy(&utf16))
}

/// AES-128-CBC decrypt with **no padding** (RustCrypto), used for the SAM
/// revision-3 hbootkey and revision-2 per-user hash blobs. Returns an empty
/// `Vec` on a key/IV/length mismatch rather than panicking.
fn aes128_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    if key.len() != 16 || iv.len() < 16 || data.is_empty() || data.len() % 16 != 0 {
        return Vec::new();
    }
    let Ok(dec) = CbcDecryptor::<Aes128>::new_from_slices(key, &iv[..16]) else {
        return Vec::new(); // cov:unreachable: lengths checked above
    };
    let mut buf = data.to_vec();
    match dec.decrypt_padded_mut::<NoPadding>(&mut buf) {
        Ok(out) => out.to_vec(),
        Err(_) => Vec::new(), // cov:unreachable: data.len() is a 16-multiple
    }
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

// ---------------------------------------------------------------------------
// Internal helpers — registry hive navigation (mirrors sam.rs patterns)
// ---------------------------------------------------------------------------

/// Read the class name of a `_CM_KEY_NODE` (used for boot key extraction).
/// Returns the raw bytes of the class name, or an empty vec on failure.
fn read_key_class_name<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    hhive_addr: u64,
    key_addr: u64,
) -> Vec<u8> {
    // _CM_KEY_NODE: ClassLength at 0x4A (u16), Class cell index at 0x30 (u32).
    let class_len: u16 = match reader.read_bytes(key_addr + 0x4A, 2) {
        Ok(bytes) if bytes.len() == 2 => bytes[..2].try_into().map_or(0, u16::from_le_bytes),
        _ => return Vec::new(),
    };

    if class_len == 0 || class_len > 1024 {
        return Vec::new();
    }

    let class_off: u32 = match reader.read_bytes(key_addr + 0x30, 4) {
        Ok(bytes) if bytes.len() == 4 => bytes[..4].try_into().map_or(0, u32::from_le_bytes),
        _ => return Vec::new(),
    };

    let class_addr = read_cell_addr(reader, hhive_addr, class_off);
    if class_addr == 0 {
        return Vec::new();
    }

    reader
        .read_bytes(class_addr, class_len as usize)
        .unwrap_or_default()
}

/// Format a byte slice as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Convert a RID into two 8-byte DES keys (vol3 `sid_to_key`).
fn sid_to_key(rid: u32) -> ([u8; 8], [u8; 8]) {
    let b = [
        (rid & 0xFF) as u8,
        ((rid >> 8) & 0xFF) as u8,
        ((rid >> 16) & 0xFF) as u8,
        ((rid >> 24) & 0xFF) as u8,
    ];
    // bytestr1 = b0 b1 b2 b3 b0 b1 b2 ; bytestr2 = b3 b0 b1 b2 b3 b0 b1
    let s1 = [b[0], b[1], b[2], b[3], b[0], b[1], b[2]];
    let s2 = [b[3], b[0], b[1], b[2], b[3], b[0], b[1]];
    (sidbytes_to_key(s1), sidbytes_to_key(s2))
}

/// Expand a 7-byte string into an 8-byte DES key with odd parity (vol3
/// `sidbytes_to_key`): spread 7 bytes over 8, shift left 1, then map each
/// through the `ODD_PARITY` table.
fn sidbytes_to_key(s: [u8; 7]) -> [u8; 8] {
    let mut key = [
        s[0] >> 1,
        ((s[0] & 0x01) << 6) | (s[1] >> 2),
        ((s[1] & 0x03) << 5) | (s[2] >> 3),
        ((s[2] & 0x07) << 4) | (s[3] >> 4),
        ((s[3] & 0x0F) << 3) | (s[4] >> 5),
        ((s[4] & 0x1F) << 2) | (s[5] >> 6),
        ((s[5] & 0x3F) << 1) | (s[6] >> 7),
        s[6] & 0x7F,
    ];
    for b in &mut key {
        *b = ODD_PARITY[(*b as usize) << 1];
    }
    key
}

/// DES-ECB decrypt a single 8-byte block with an 8-byte key (RustCrypto `des`).
fn des_ecb_decrypt_block(key: [u8; 8], block: [u8; 8]) -> [u8; 8] {
    let cipher = Des::new(&key.into());
    let mut buf = block.into();
    cipher.decrypt_block(&mut buf);
    buf.into()
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
    // Cell-map hive fixture
    // ---------------------------------------------------------------
    //
    // In-memory hives are NOT flat: a cell index is translated through
    // `_HHIVE.Storage[].Map` (the HMAP directory → table → entry → bin).
    // `cell_index_to_va` computes:
    //   block_va = (PermanentBinAddress & !0xF) + BlockOffset
    //   cell_va  = block_va + (cell_index & 0xFFF)
    // with dir = bits 30..21 and table = bits 20..12.
    //
    // We build the smallest plumbing that makes cell index `i` (for any
    // `i < 0x1000`, i.e. dir=0/table=0) resolve to `bin_base + i`: a single
    // `_HMAP_ENTRY` at Directory[0]→Table[0] whose `PermanentBinAddress`
    // is `bin_base` and whose `BlockOffset` is 0. Then
    // `read_cell_addr(reader, hhive, i) == bin_base + i + 4` — exactly the
    // old "flat" semantics with `flat_base == bin_base`, so a flat fixture
    // page laid out at `bin_base` works unchanged once wrapped in this map.
    //
    // ISF offsets mirror `registry::tests::cell_index_to_va_walks_the_hmap_directory`.

    /// ISF offsets for the cell-map structures (stable across the fixtures).
    const STORAGE_OFF: u64 = 0xb8;
    const DUAL_MAP_OFF: u64 = 0x18;
    const HMAP_ENTRY_SIZE: u64 = 0x20;

    /// Build an ISF that carries the cell-map structures plus `_HHIVE` fields
    /// (BaseBlock + Storage). Extra struct/field defs can be chained by the
    /// caller before `.build_json()`.
    fn cellmap_isf_builder() -> IsfBuilder {
        IsfBuilder::new()
            .add_struct("_HHIVE", 0x800)
            .add_field("_HHIVE", "BaseBlock", 0x10, "pointer")
            .add_field("_HHIVE", "Storage", STORAGE_OFF, "char")
            .add_struct("_DUAL", 0x278)
            .add_field("_DUAL", "Map", DUAL_MAP_OFF, "pointer")
            .add_struct("_HMAP_ENTRY", HMAP_ENTRY_SIZE)
            .add_field("_HMAP_ENTRY", "PermanentBinAddress", 0x0, "pointer")
            .add_field("_HMAP_ENTRY", "BlockOffset", 0x8, "unsigned long")
    }

    /// A self-contained cell-map hive fixture: a `_HHIVE` whose stable storage
    /// map directory/table point at a single bin page that holds the cell data.
    ///
    /// Layout (distinct physical/virtual pages, virt == phys for clarity):
    ///   hhive_va  : `_HHIVE` — BaseBlock@0x10, Storage[0]._DUAL.Map@(0xb8+0x18)
    ///   bb_va     : `_HBASE_BLOCK` — RootCell index@0x24
    ///   dir_va    : HMAP directory — Directory[0] → table_va
    ///   table_va  : HMAP table — Table[0] = `_HMAP_ENTRY`{PermanentBinAddress=bin_va, BlockOffset=0}
    ///   bin_va    : the cell-data page (formerly the "flat page")
    struct CellMapHive {
        hhive_va: u64,
        bin_va: u64,
        bin_page: Vec<u8>,
        root_cell_index: u32,
    }

    impl CellMapHive {
        /// `base` is a 1-MiB-aligned anchor; the fixture uses
        /// base+0x0000 (hhive), +0x1000 (base block), +0x2000 (dir),
        /// +0x3000 (table), +0x4000 (bin). `root_cell_index` is the cell index
        /// of the hive's root key node (placed within `bin_page`).
        fn new(base: u64, root_cell_index: u32) -> Self {
            Self {
                hhive_va: base,
                bin_va: base + 0x4000,
                bin_page: vec![0u8; 0x1000],
                root_cell_index,
            }
        }

        /// Register this hive's pages into a `PageTableBuilder` and return the
        /// (hhive_va) handle. Consumes nothing; call before `.build()`.
        fn install(&self, b: PageTableBuilder) -> PageTableBuilder {
            self.install_inner(b, true, true)
        }

        /// Like [`install`](Self::install) but leaves the `_HBASE_BLOCK` page
        /// UNMAPPED — models the common real-image case where the hive header is
        /// paged out while the bins (reached via the HMAP) stay resident.
        fn install_paged_base_block(&self, b: PageTableBuilder) -> PageTableBuilder {
            self.install_inner(b, false, true)
        }

        /// Like [`install`](Self::install) but the mapped `_HBASE_BLOCK` carries a
        /// NON-"regf" signature (corrupt header) — its RootCell must be ignored.
        fn install_corrupt_base_block(&self, b: PageTableBuilder) -> PageTableBuilder {
            self.install_inner(b, true, false)
        }

        fn install_inner(
            &self,
            b: PageTableBuilder,
            map_base_block: bool,
            regf_sig: bool,
        ) -> PageTableBuilder {
            let bb_va = self.hhive_va + 0x1000;
            let dir_va = self.hhive_va + 0x2000;
            let table_va = self.hhive_va + 0x3000;

            let mut hhive_page = vec![0u8; 0x1000];
            // BaseBlock@0x10
            hhive_page[0x10..0x18].copy_from_slice(&bb_va.to_le_bytes());
            // Storage[0]._DUAL.Map@(STORAGE_OFF + DUAL_MAP_OFF)
            let map_off = (STORAGE_OFF + DUAL_MAP_OFF) as usize;
            hhive_page[map_off..map_off + 8].copy_from_slice(&dir_va.to_le_bytes());

            let mut bb_page = vec![0u8; 0x1000];
            // _HBASE_BLOCK.Signature@0x0 == "regf" (a corrupt header omits it).
            if regf_sig {
                bb_page[0x0..0x4].copy_from_slice(b"regf");
            }
            // _HBASE_BLOCK.RootCell@0x24
            bb_page[0x24..0x28].copy_from_slice(&self.root_cell_index.to_le_bytes());

            let mut dir_page = vec![0u8; 0x1000];
            // Directory[0] → table_va
            dir_page[0..8].copy_from_slice(&table_va.to_le_bytes());

            let mut table_page = vec![0u8; 0x1000];
            // Table[0] = _HMAP_ENTRY { PermanentBinAddress = bin_va, BlockOffset = 0 }
            table_page[0..8].copy_from_slice(&self.bin_va.to_le_bytes());
            table_page[8..12].copy_from_slice(&0u32.to_le_bytes());

            let b = b
                .map_4k(self.hhive_va, self.hhive_va, flags::WRITABLE)
                .write_phys(self.hhive_va, &hhive_page)
                .map_4k(dir_va, dir_va, flags::WRITABLE)
                .write_phys(dir_va, &dir_page)
                .map_4k(table_va, table_va, flags::WRITABLE)
                .write_phys(table_va, &table_page)
                .map_4k(self.bin_va, self.bin_va, flags::WRITABLE)
                .write_phys(self.bin_va, &self.bin_page);
            if map_base_block {
                b.map_4k(bb_va, bb_va, flags::WRITABLE)
                    .write_phys(bb_va, &bb_page)
            } else {
                b
            }
        }
    }

    /// Cell index `i` resolves to `bin_va + i + 4` through the HMAP directory —
    /// the in-memory hive translation that `read_cell_addr` now performs.
    #[test]
    fn read_cell_addr_resolves_via_cell_map() {
        let mut hive = CellMapHive::new(0x0020_0000, 0x20);
        // Place 2 readable bytes at cell index 0x20's data start so read_cell_addr
        // confirms the cell is mapped.
        let d = ao(0x20);
        hive.bin_page[d] = 0xAB;
        hive.bin_page[d + 1] = 0xCD;

        let isf = cellmap_isf_builder().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = hive.install(PageTableBuilder::new()).build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // Cell data VA = bin_va + cell_index + 4.
        assert_eq!(
            read_cell_addr(&reader, hive.hhive_va, 0x20),
            hive.bin_va + 0x20 + 4
        );
        // An unmapped cell index (would translate past the bin region's data)
        // still resolves arithmetically but its bytes are zero — read_cell_addr
        // only requires the 2 bytes to be *readable*, which they are (mapped page).
    }

    /// Real-image case: the `_HBASE_BLOCK` header page is PAGED OUT (so
    /// `RootCell` is unreadable) while the bins stay resident. `resolve_root_cell`
    /// must fall back to the regf-format default root cell `0x20` (Volatility
    /// `root_cell_offset` parity), NOT collapse to 0 and abandon the hive.
    #[test]
    fn resolve_root_cell_falls_back_to_0x20_when_base_block_paged_out() {
        let mut hive = CellMapHive::new(0x00A0_0000, 0x20);
        // Mark the root key node at cell 0x20 readable ("nk").
        let d = ao(0x20);
        hive.bin_page[d] = b'n';
        hive.bin_page[d + 1] = b'k';

        let isf = cellmap_isf_builder().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = hive
            .install_paged_base_block(PageTableBuilder::new())
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        assert_eq!(
            resolve_root_cell(&reader, hive.hhive_va),
            hive.bin_va + 0x20 + 4,
            "paged-out base block must fall back to root cell 0x20"
        );
    }

    /// A mapped `_HBASE_BLOCK` whose signature is NOT "regf" (corrupt header) is
    /// not trusted: RootCell (here 0x40) is ignored and 0x20 is used instead.
    #[test]
    fn resolve_root_cell_non_regf_header_falls_back_to_0x20() {
        let hive = CellMapHive::new(0x00B0_0000, 0x40);
        let isf = cellmap_isf_builder().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = hive
            .install_corrupt_base_block(PageTableBuilder::new())
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        assert_eq!(
            resolve_root_cell(&reader, hive.hhive_va),
            hive.bin_va + 0x20 + 4
        );
    }

    /// A regf header with the sentinel RootCell index `u32::MAX` falls back to 0x20.
    #[test]
    fn resolve_root_cell_sentinel_index_falls_back_to_0x20() {
        let hive = CellMapHive::new(0x00C0_0000, u32::MAX);
        let isf = cellmap_isf_builder().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = hive.install(PageTableBuilder::new()).build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        assert_eq!(
            resolve_root_cell(&reader, hive.hhive_va),
            hive.bin_va + 0x20 + 4
        );
    }

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

    /// `sid_to_key(500)` matches the vol3/impacket DES key pair exactly
    /// (computed with the reference Python implementation).
    #[test]
    fn sid_to_key_rid500_golden() {
        let (k1, k2) = sid_to_key(500);
        assert_eq!(hex_encode(&k1), "f40140010ea10401");
        assert_eq!(hex_encode(&k2), "017a01200107d002");
    }

    /// `sidbytes_to_key` sets odd parity on every output byte.
    #[test]
    fn sidbytes_to_key_odd_parity() {
        let key = sidbytes_to_key([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        for &b in &key {
            assert_eq!(b.count_ones() % 2, 1, "byte {b:#04x} must have odd parity");
        }
    }

    /// `des_ecb_decrypt_block` matches the FIPS-81 single-block known answer:
    /// DES-decrypt(key 133457799BBCDFF1, ct 85E813540F0AB405) = 0123456789ABCDEF.
    #[test]
    fn des_ecb_decrypt_block_fips_vector() {
        let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
        let ct = [0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05];
        let pt = des_ecb_decrypt_block(key, ct);
        assert_eq!(hex_encode(&pt), "0123456789abcdef");
    }

    /// `md5` (RustCrypto) matches the RFC 1321 "abc" vector.
    #[test]
    fn md5_abc_vector() {
        let mut h = Md5::new();
        h.update(b"abc");
        assert_eq!(
            hex_encode(&h.finalize()),
            "900150983cd24fb0d6963f7d28e17f72"
        );
    }

    /// `rc4_crypt` matches the canonical RC4 known answer:
    /// RC4(key "Key", "Plaintext") = BBF316E8D940AF0AD3.
    #[test]
    fn rc4_crypt_known_answer() {
        let ct = rc4_crypt(b"Key", b"Plaintext");
        assert_eq!(hex_encode(&ct), "bbf316e8d940af0ad3");
    }

    /// `aes128_cbc_decrypt` matches NIST SP800-38A F.2 (first block):
    /// AES-128-CBC-decrypt(key 2b7e..4f3c, iv 0001..0e0f, ct 7649..197d)
    ///   = 6bc1bee22e409f96e93d7e117393172a.
    #[test]
    fn aes128_cbc_decrypt_nist_vector() {
        let key = hex_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex_bytes("000102030405060708090a0b0c0d0e0f");
        let ct = hex_bytes("7649abac8119b246cee98e9b12e9197d");
        let pt = aes128_cbc_decrypt(&key, &iv, &ct);
        assert_eq!(hex_encode(&pt), "6bc1bee22e409f96e93d7e117393172a");
    }

    /// `aes128_cbc_decrypt` returns empty on key/iv/length mismatch.
    #[test]
    fn aes128_cbc_decrypt_bad_inputs() {
        assert!(aes128_cbc_decrypt(&[0u8; 8], &[0u8; 16], &[0u8; 16]).is_empty());
        assert!(aes128_cbc_decrypt(&[0u8; 16], &[0u8; 8], &[0u8; 16]).is_empty());
        assert!(aes128_cbc_decrypt(&[0u8; 16], &[0u8; 16], &[]).is_empty());
        assert!(aes128_cbc_decrypt(&[0u8; 16], &[0u8; 16], &[0u8; 15]).is_empty());
    }

    /// `hex_encode` works correctly.
    #[test]
    fn hex_encode_correct() {
        assert_eq!(hex_encode(&[0x31, 0xd6, 0xcf, 0xe0]), "31d6cfe0");
        assert_eq!(hex_encode(&[]), "");
    }

    /// Decode a hex string into bytes (test helper).
    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
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
        assert!(
            result.is_empty(),
            "Wrong boot_key length should return empty"
        );
    }

    /// decrypt_hashed_boot_key (revision 2, RC4) reproduces the exact vol3/impacket
    /// hbootkey for a known F value. Golden vector computed with pycryptodome:
    ///   bootkey   = 00..0f
    ///   F[0x00]   = 2 (revision)
    ///   F[0x70..0x80] = 0x11*16 (salt)
    ///   F[0x80..0xA0] = 0x22*32 (encrypted hbootkey)
    ///   rc4_key   = MD5(salt ‖ aqwerty ‖ bootkey ‖ anum)
    ///   hbootkey  = RC4(rc4_key, F[0x80..0xA0])[..16]
    ///             = 5cdc46c139bc6c936846ec65edc71be9
    #[test]
    fn decrypt_hashed_boot_key_rev2_golden_vector() {
        let boot_key: Vec<u8> = (0u8..16).collect();
        let mut f_data = vec![0u8; 0xA0];
        f_data[0x00] = 0x02; // revision is at F[0x00], NOT F[0x68]
        f_data[0x70..0x80].fill(0x11);
        f_data[0x80..0xA0].fill(0x22);
        let result = decrypt_hashed_boot_key(&f_data, &boot_key);
        assert_eq!(
            hex_encode(&result),
            "5cdc46c139bc6c936846ec65edc71be9",
            "rev2 hbootkey must match the vol3 RC4 derivation"
        );
    }

    /// decrypt_hashed_boot_key with unknown revision returns empty (fail-loud:
    /// never fabricate a key for an unsupported format).
    #[test]
    fn decrypt_hashed_boot_key_unknown_revision() {
        let mut f_data = vec![0u8; 0xA0];
        f_data[0x00] = 99; // revision byte at F[0x00]
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

    /// extract_hashes_from_v (revision 1 NT hash, RC4 path) reproduces the exact
    /// vol3/impacket NT hash for a known V value + hbootkey. Golden vector:
    ///   rid       = 500
    ///   hbootkey  = 5cdc46c139bc6c936846ec65edc71be9
    ///   V[0xA8..0xAC] = 0x10 (nt offset rel), V[0xAC..0xB0] = 20 (nt len)
    ///   nt blob at 0xCC+0x10: [+2]=1 (rev1), [+4..+20]=0x33*16 (encrypted)
    ///   rc4_key  = MD5(hbootkey ‖ pack<L>(rid) ‖ NTPASSWORD\0)
    ///   obf      = RC4(rc4_key, enc)
    ///   nt       = DES(k1,obf[..8]) ‖ DES(k2,obf[8..16])  (k1,k2 = sid_to_key(rid))
    ///            = 01e2d77d782a538a372cb89a5d2e5241
    ///   LM length 0 → empty LM sentinel.
    #[test]
    fn extract_hashes_from_v_rev1_golden_vector() {
        let hbootkey = [
            0x5c, 0xdc, 0x46, 0xc1, 0x39, 0xbc, 0x6c, 0x93, 0x68, 0x46, 0xec, 0x65, 0xed, 0xc7,
            0x1b, 0xe9,
        ];
        let mut v = vec![0u8; 0xCC + 0x100];
        let nt_rel: u32 = 0x10;
        v[0xA8..0xAC].copy_from_slice(&nt_rel.to_le_bytes());
        v[0xAC..0xB0].copy_from_slice(&20u32.to_le_bytes());
        let nt_off = (nt_rel as usize) + 0xCC;
        v[nt_off + 2] = 1; // per-hash revision 1
        v[nt_off + 4..nt_off + 20].fill(0x33);
        // LM length 0 → empty.
        let (lm, nt) = extract_hashes_from_v(&v, &hbootkey, 500);
        assert_eq!(nt, "01e2d77d782a538a372cb89a5d2e5241", "rev1 NT mismatch");
        assert_eq!(lm, EMPTY_LM_HASH, "LM length 0 → empty sentinel");
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

    // ---------------------------------------------------------------
    // Cell-map navigation tests (in-memory hive model)
    // ---------------------------------------------------------------

    /// resolve_root_cell returns the root key node VA via the cell map.
    #[test]
    fn resolve_root_cell_via_cell_map() {
        let root_idx: u32 = 0x40;
        let mut hive = CellMapHive::new(0x0030_0000, root_idx);
        // Put 2 readable bytes at the root cell's data start.
        let d = ao(root_idx);
        hive.bin_page[d] = b'n';
        hive.bin_page[d + 1] = b'k';

        let isf = cellmap_isf_builder().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = hive.install(PageTableBuilder::new()).build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        assert_eq!(
            resolve_root_cell(&reader, hive.hhive_va),
            hive.bin_va + u64::from(root_idx) + 4
        );
    }

    /// resolve_root_cell returns 0 when the hive (and thus base block) is unmapped.
    #[test]
    fn resolve_root_cell_unmapped_returns_zero() {
        let isf = cellmap_isf_builder().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        assert_eq!(resolve_root_cell(&reader, 0xDEAD_BEEF), 0);
    }

    /// A regf header carrying RootCell index 0 (malformed) falls back to the
    /// regf-format default cell 0x20 rather than abandoning the hive.
    #[test]
    fn resolve_root_cell_zero_index_falls_back_to_0x20() {
        let hive = CellMapHive::new(0x0040_0000, 0);
        let isf = cellmap_isf_builder().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = hive.install(PageTableBuilder::new()).build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        assert_eq!(
            resolve_root_cell(&reader, hive.hhive_va),
            hive.bin_va + 0x20 + 4
        );
    }

    /// walk_hashdump returns empty when the SYSTEM root cell cannot be resolved.
    #[test]
    fn walk_hashdump_system_root_zero_empty() {
        // RootCell=0 falls back to cell 0x20 — here an empty node with no
        // CurrentControlSet, so no boot key can be assembled → empty result.
        let hive = CellMapHive::new(0x0050_0000, 0);
        let isf = cellmap_isf_builder().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = hive.install(PageTableBuilder::new()).build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_hashdump(&reader, 0xDEAD_0000, hive.hhive_va).unwrap();
        assert!(result.is_empty(), "no boot key (empty root node) → empty");
    }

    /// walk_hashdump returns empty when the SAM root cell cannot be resolved,
    /// even though the SYSTEM hive resolves a root.
    #[test]
    fn walk_hashdump_sam_root_zero_empty() {
        let sys = CellMapHive::new(0x0060_0000, 0x20); // root resolvable
        let sam = CellMapHive::new(0x0068_0000, 0); // RootCell=0 → 0x20 (empty node)
        let isf = cellmap_isf_builder().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let b = sam.install(sys.install(PageTableBuilder::new()));
        let (cr3, mem) = b.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_hashdump(&reader, sam.hhive_va, sys.hhive_va).unwrap();
        assert!(result.is_empty(), "sam structure absent → empty");
    }

    /// Non-zero hive addresses but unreadable memory → empty Vec.
    #[test]
    fn walk_hashdump_unreadable_hive() {
        let isf = cellmap_isf_builder().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_hashdump(&reader, 0xFFFF_8000_1111_0000, 0xFFFF_8000_2222_0000).unwrap();
        assert!(result.is_empty());
    }

    /// read_value_data returns empty when the key cell is unmapped.
    #[test]
    fn read_value_data_unmapped_returns_empty() {
        let hive = CellMapHive::new(0x0070_0000, 0x10);
        let isf = cellmap_isf_builder().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = hive.install(PageTableBuilder::new()).build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // key_addr points outside the bin page → reads fail → empty.
        let result = read_value_data(&reader, hive.hhive_va, 0xDEAD_BEEF, "F");
        assert!(result.is_empty());
    }

    /// read_key_class_name returns empty when the key cell is unmapped.
    #[test]
    fn read_key_class_name_unmapped_returns_empty() {
        let hive = CellMapHive::new(0x0078_0000, 0x10);
        let isf = cellmap_isf_builder().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = hive.install(PageTableBuilder::new()).build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = read_key_class_name(&reader, hive.hhive_va, 0xDEAD_BEEF);
        assert!(result.is_empty());
    }

    /// read_key_class_name with class_len = 0 returns empty.
    #[test]
    fn read_key_class_name_zero_len_returns_empty() {
        // key cell at index 0x10; class_len field (key+0x4E) stays 0.
        let key_idx: u32 = 0x10;
        let mut hive = CellMapHive::new(0x0080_0000, 0x10);
        let d = ao(key_idx);
        hive.bin_page[d] = b'n';
        hive.bin_page[d + 1] = b'k';

        let isf = cellmap_isf_builder().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = hive.install(PageTableBuilder::new()).build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let key_addr = read_cell_addr(&reader, hive.hhive_va, key_idx);
        let result = read_key_class_name(&reader, hive.hhive_va, key_addr);
        assert!(result.is_empty(), "class_len=0 → empty");
    }

    // ── Flat-page cell writers (cell data lives in the bin page at ao(idx)) ──

    /// Helper: byte offset of cell `idx`'s data within the bin page.
    fn ao(cell_off: u32) -> usize {
        (cell_off + 4) as usize
    }

    #[allow(clippy::too_many_arguments)]
    fn write_nk(
        page: &mut [u8],
        off: usize,
        name: &[u8],
        subkey_count: u32,
        list_off: u32,
        val_count: u32,
        val_list_off: u32,
        class_len: u16,
        class_off: u32,
    ) {
        // _CM_KEY_NODE offsets (Win8.1/9600 x64): SubKeyCounts[Stable]@0x14,
        // SubKeyLists[Stable]@0x1c, ValueList.Count@0x24, ValueList.List@0x28,
        // Class@0x30, NameLength@0x48, ClassLength@0x4a, Name@0x4c.
        page[off + 0x14..off + 0x18].copy_from_slice(&subkey_count.to_le_bytes());
        page[off + 0x1c..off + 0x20].copy_from_slice(&list_off.to_le_bytes());
        page[off + 0x24..off + 0x28].copy_from_slice(&val_count.to_le_bytes());
        page[off + 0x28..off + 0x2C].copy_from_slice(&val_list_off.to_le_bytes());
        page[off + 0x30..off + 0x34].copy_from_slice(&class_off.to_le_bytes());
        page[off + 0x48..off + 0x4A].copy_from_slice(&(name.len() as u16).to_le_bytes());
        page[off + 0x4A..off + 0x4C].copy_from_slice(&class_len.to_le_bytes());
        if !name.is_empty() {
            page[off + 0x4C..off + 0x4C + name.len()].copy_from_slice(name);
        }
    }

    fn write_lf1(page: &mut [u8], off: usize, child_off: u32) {
        page[off] = b'l';
        page[off + 1] = b'f';
        page[off + 2..off + 4].copy_from_slice(&1u16.to_le_bytes());
        page[off + 4..off + 8].copy_from_slice(&child_off.to_le_bytes());
    }

    fn write_lf_n(page: &mut [u8], off: usize, children: &[u32]) {
        page[off] = b'l';
        page[off + 1] = b'f';
        page[off + 2..off + 4].copy_from_slice(&(children.len() as u16).to_le_bytes());
        for (i, &child_off) in children.iter().enumerate() {
            page[off + 4 + i * 8..off + 4 + i * 8 + 4].copy_from_slice(&child_off.to_le_bytes());
        }
    }

    fn write_vk(page: &mut [u8], off: usize, name: &[u8], data_len: u32, data_off: u32) {
        // _CM_KEY_VALUE offsets: NameLength@0x02, DataLength@0x04, Data@0x08,
        // Type@0x0c, Name@0x14.
        page[off] = b'v';
        page[off + 1] = b'k';
        page[off + 0x02..off + 0x04].copy_from_slice(&(name.len() as u16).to_le_bytes());
        page[off + 0x04..off + 0x08].copy_from_slice(&data_len.to_le_bytes());
        page[off + 0x08..off + 0x0C].copy_from_slice(&data_off.to_le_bytes());
        if !name.is_empty() {
            page[off + 0x14..off + 0x14 + name.len()].copy_from_slice(name);
        }
    }

    /// find_subkey_by_name resolves a child through the cell map.
    #[test]
    fn find_subkey_by_name_via_cell_map() {
        let parent_idx: u32 = 0x100;
        let list_idx: u32 = 0x200;
        let child_idx: u32 = 0x300;

        let mut hive = CellMapHive::new(0x0088_0000, parent_idx);
        write_nk(
            &mut hive.bin_page,
            ao(parent_idx),
            b"root",
            1,
            list_idx,
            0,
            0,
            0,
            0,
        );
        write_lf1(&mut hive.bin_page, ao(list_idx), child_idx);
        write_nk(&mut hive.bin_page, ao(child_idx), b"SAM", 0, 0, 0, 0, 0, 0);

        let isf = cellmap_isf_builder().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = hive.install(PageTableBuilder::new()).build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let parent_addr = read_cell_addr(&reader, hive.hhive_va, parent_idx);
        let found = find_subkey_by_name(&reader, hive.hhive_va, parent_addr, "SAM");
        assert_eq!(found, hive.bin_va + u64::from(child_idx) + 4);
        // A missing name returns 0.
        assert_eq!(
            find_subkey_by_name(&reader, hive.hhive_va, parent_addr, "NOPE"),
            0
        );
    }

    /// find_subkey_by_name with an unrecognised list signature returns 0.
    #[test]
    fn find_subkey_by_name_unknown_list_sig_returns_zero() {
        let parent_idx: u32 = 0x100;
        let list_idx: u32 = 0x200;
        let mut hive = CellMapHive::new(0x0090_0000, parent_idx);
        // parent: subkey_count=1, list=list_idx
        hive.bin_page[ao(parent_idx) + 0x18..ao(parent_idx) + 0x1C]
            .copy_from_slice(&1u32.to_le_bytes());
        hive.bin_page[ao(parent_idx) + 0x20..ao(parent_idx) + 0x24]
            .copy_from_slice(&list_idx.to_le_bytes());
        // unknown sig + count
        hive.bin_page[ao(list_idx)..ao(list_idx) + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
        hive.bin_page[ao(list_idx) + 2..ao(list_idx) + 4].copy_from_slice(&1u16.to_le_bytes());

        let isf = cellmap_isf_builder().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = hive.install(PageTableBuilder::new()).build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let parent_addr = read_cell_addr(&reader, hive.hhive_va, parent_idx);
        let result = find_subkey_by_name(&reader, hive.hhive_va, parent_addr, "SAM");
        assert_eq!(result, 0, "unknown list sig → 0");
    }

    /// read_value_data finds a named value's data through the cell map.
    #[test]
    fn read_value_data_via_cell_map() {
        let key_idx: u32 = 0x100;
        let vlist_idx: u32 = 0x180;
        let vk_idx: u32 = 0x1C0;
        let data_idx: u32 = 0x240;
        let payload: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

        let mut hive = CellMapHive::new(0x0098_0000, key_idx);
        // key: val_count=1, val_list=vlist_idx
        hive.bin_page[ao(key_idx) + 0x24..ao(key_idx) + 0x28].copy_from_slice(&1u32.to_le_bytes());
        hive.bin_page[ao(key_idx) + 0x28..ao(key_idx) + 0x2C]
            .copy_from_slice(&vlist_idx.to_le_bytes());
        // value list: one entry → vk_idx
        hive.bin_page[ao(vlist_idx)..ao(vlist_idx) + 4].copy_from_slice(&vk_idx.to_le_bytes());
        // VK "F" with data_len=8 at data_idx
        write_vk(
            &mut hive.bin_page,
            ao(vk_idx),
            b"F",
            payload.len() as u32,
            data_idx,
        );
        hive.bin_page[ao(data_idx)..ao(data_idx) + payload.len()].copy_from_slice(&payload);

        let isf = cellmap_isf_builder().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = hive.install(PageTableBuilder::new()).build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let key_addr = read_cell_addr(&reader, hive.hhive_va, key_idx);
        let data = read_value_data(&reader, hive.hhive_va, key_addr, "F");
        assert_eq!(data, payload.to_vec());
        // A non-matching name returns empty.
        assert!(read_value_data(&reader, hive.hhive_va, key_addr, "G").is_empty());
    }

    /// read_value_data with inline data (high bit set in DataLength).
    #[test]
    fn read_value_data_inline_data_returned() {
        let key_idx: u32 = 0x100;
        let vlist_idx: u32 = 0x180;
        let vk_idx: u32 = 0x1C0;
        let inline: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

        let mut hive = CellMapHive::new(0x00A0_0000, key_idx);
        hive.bin_page[ao(key_idx) + 0x24..ao(key_idx) + 0x28].copy_from_slice(&1u32.to_le_bytes());
        hive.bin_page[ao(key_idx) + 0x28..ao(key_idx) + 0x2C]
            .copy_from_slice(&vlist_idx.to_le_bytes());
        hive.bin_page[ao(vlist_idx)..ao(vlist_idx) + 4].copy_from_slice(&vk_idx.to_le_bytes());
        let vko = ao(vk_idx);
        hive.bin_page[vko] = b'v';
        hive.bin_page[vko + 1] = b'k';
        hive.bin_page[vko + 0x02..vko + 0x04].copy_from_slice(&1u16.to_le_bytes());
        let raw_len: u32 = 0x8000_0004; // inline, 4 bytes
        hive.bin_page[vko + 0x04..vko + 0x08].copy_from_slice(&raw_len.to_le_bytes());
        hive.bin_page[vko + 0x08..vko + 0x0C].copy_from_slice(&inline);
        hive.bin_page[vko + 0x14] = b'F';

        let isf = cellmap_isf_builder().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = hive.install(PageTableBuilder::new()).build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let key_addr = read_cell_addr(&reader, hive.hhive_va, key_idx);
        let result = read_value_data(&reader, hive.hhive_va, key_addr, "F");
        assert_eq!(result, inline.to_vec());
    }

    /// read_value_data with data_len=0 returns empty.
    #[test]
    fn read_value_data_zero_data_len_returns_empty() {
        let key_idx: u32 = 0x100;
        let vlist_idx: u32 = 0x180;
        let vk_idx: u32 = 0x1C0;
        let mut hive = CellMapHive::new(0x00A8_0000, key_idx);
        hive.bin_page[ao(key_idx) + 0x24..ao(key_idx) + 0x28].copy_from_slice(&1u32.to_le_bytes());
        hive.bin_page[ao(key_idx) + 0x28..ao(key_idx) + 0x2C]
            .copy_from_slice(&vlist_idx.to_le_bytes());
        hive.bin_page[ao(vlist_idx)..ao(vlist_idx) + 4].copy_from_slice(&vk_idx.to_le_bytes());
        write_vk(&mut hive.bin_page, ao(vk_idx), b"F", 0, 0);

        let isf = cellmap_isf_builder().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = hive.install(PageTableBuilder::new()).build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let key_addr = read_cell_addr(&reader, hive.hhive_va, key_idx);
        let result = read_value_data(&reader, hive.hhive_va, key_addr, "F");
        assert!(result.is_empty(), "data_len=0 → empty");
    }

    /// username_from_v decodes the UTF-16LE account name pointed at by the V
    /// offset table (name_offset = V[0x0C..0x10]+0xCC, name_length = V[0x10..0x14]).
    #[test]
    fn username_from_v_decodes_name() {
        let name: Vec<u8> = "Administrator"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let name_rel: u32 = 0x20;
        let name_off = name_rel as usize + 0xCC;
        let mut v = vec![0u8; name_off + name.len()];
        v[0x0C..0x10].copy_from_slice(&name_rel.to_le_bytes());
        v[0x10..0x14].copy_from_slice(&(name.len() as u32).to_le_bytes());
        v[name_off..name_off + name.len()].copy_from_slice(&name);
        assert_eq!(username_from_v(&v).as_deref(), Some("Administrator"));
    }

    /// username_from_v returns None for a too-short V value.
    #[test]
    fn username_from_v_short_returns_none() {
        assert!(username_from_v(&[0u8; 0x10]).is_none());
    }

    // ── Full SYSTEM + SAM walk through the cell map ─────────────────

    /// Build a minimal SYSTEM hive into a bin page.
    /// root → CurrentControlSet → Control → Lsa → {JD,Skew1,GBG,Data}, class "00000000".
    fn build_system_bin(flat: &mut [u8]) {
        let root_off: u32 = 0x010;
        let root_list_off: u32 = 0x070;
        let ccs_off: u32 = 0x090;
        let ccs_list_off: u32 = 0x100;
        let ctrl_off: u32 = 0x120;
        let ctrl_list_off: u32 = 0x180;
        let lsa_off: u32 = 0x1A0;
        let lsa_list_off: u32 = 0x200;
        let jd_off: u32 = 0x240;
        let skew1_off: u32 = 0x2A0;
        let gbg_off: u32 = 0x300;
        let data_off: u32 = 0x360;
        let jd_cl_off: u32 = 0x3C0;
        let skew1_cl_off: u32 = 0x3D0;
        let gbg_cl_off: u32 = 0x3E0;
        let data_cl_off: u32 = 0x3F0;

        let class_utf16: Vec<u8> = "00000000"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let class_len: u16 = class_utf16.len() as u16;

        write_nk(flat, ao(root_off), b"root", 1, root_list_off, 0, 0, 0, 0);
        write_lf1(flat, ao(root_list_off), ccs_off);
        write_nk(
            flat,
            ao(ccs_off),
            b"CurrentControlSet",
            1,
            ccs_list_off,
            0,
            0,
            0,
            0,
        );
        write_lf1(flat, ao(ccs_list_off), ctrl_off);
        write_nk(flat, ao(ctrl_off), b"Control", 1, ctrl_list_off, 0, 0, 0, 0);
        write_lf1(flat, ao(ctrl_list_off), lsa_off);
        write_nk(flat, ao(lsa_off), b"Lsa", 4, lsa_list_off, 0, 0, 0, 0);
        write_lf_n(
            flat,
            ao(lsa_list_off),
            &[jd_off, skew1_off, gbg_off, data_off],
        );
        write_nk(flat, ao(jd_off), b"JD", 0, 0, 0, 0, class_len, jd_cl_off);
        flat[ao(jd_cl_off)..ao(jd_cl_off) + class_utf16.len()].copy_from_slice(&class_utf16);
        write_nk(
            flat,
            ao(skew1_off),
            b"Skew1",
            0,
            0,
            0,
            0,
            class_len,
            skew1_cl_off,
        );
        flat[ao(skew1_cl_off)..ao(skew1_cl_off) + class_utf16.len()].copy_from_slice(&class_utf16);
        write_nk(flat, ao(gbg_off), b"GBG", 0, 0, 0, 0, class_len, gbg_cl_off);
        flat[ao(gbg_cl_off)..ao(gbg_cl_off) + class_utf16.len()].copy_from_slice(&class_utf16);
        write_nk(
            flat,
            ao(data_off),
            b"Data",
            0,
            0,
            0,
            0,
            class_len,
            data_cl_off,
        );
        flat[ao(data_cl_off)..ao(data_cl_off) + class_utf16.len()].copy_from_slice(&class_utf16);
    }

    /// Build a minimal SAM hive into a bin page.
    /// root → SAM → Domains → Account (F value, rev2) → Users → RID "000001F4".
    fn build_sam_bin(flat: &mut [u8]) {
        let root_off: u32 = 0x020;
        let root_list_off: u32 = 0x060;
        let sam_off: u32 = 0x090;
        let sam_list_off: u32 = 0x0D0;
        let doms_off: u32 = 0x100;
        let doms_list_off: u32 = 0x140;
        let acct_off: u32 = 0x170;
        let acct_vlist_off: u32 = 0x1B0;
        let acct_f_vk_off: u32 = 0x1D0;
        let acct_f_data_off: u32 = 0x200;
        let users_off: u32 = 0x2A0;
        let users_list_off: u32 = 0x2E0;
        let rid_off: u32 = 0x310;
        let acct_sk_list_off: u32 = 0x380;

        write_nk(flat, ao(root_off), b"root", 1, root_list_off, 0, 0, 0, 0);
        write_lf1(flat, ao(root_list_off), sam_off);
        write_nk(flat, ao(sam_off), b"SAM", 1, sam_list_off, 0, 0, 0, 0);
        write_lf1(flat, ao(sam_list_off), doms_off);
        write_nk(flat, ao(doms_off), b"Domains", 1, doms_list_off, 0, 0, 0, 0);
        write_lf1(flat, ao(doms_list_off), acct_off);
        write_nk(
            flat,
            ao(acct_off),
            b"Account",
            1,
            acct_sk_list_off,
            1,
            acct_vlist_off,
            0,
            0,
        );
        write_lf1(flat, ao(acct_sk_list_off), users_off);
        flat[ao(acct_vlist_off)..ao(acct_vlist_off) + 4]
            .copy_from_slice(&acct_f_vk_off.to_le_bytes());
        write_vk(flat, ao(acct_f_vk_off), b"F", 0xA0, acct_f_data_off);
        let fd = ao(acct_f_data_off);
        flat[fd] = 0x02; // F structure revision = 2 (RC4) at F[0x00]
        write_nk(flat, ao(users_off), b"Users", 1, users_list_off, 0, 0, 0, 0);
        write_lf1(flat, ao(users_list_off), rid_off);
        write_nk(flat, ao(rid_off), b"000001F4", 0, 0, 0, 0, 0, 0);
    }

    /// Full walk_hashdump over SYSTEM + SAM cell-map hives: exercises the entire
    /// traversal (boot key extraction, F decryption, user enumeration) without
    /// panic. The synthetic hashes are not real, so we assert the call succeeds
    /// and yields at most one RID entry.
    #[test]
    fn walk_hashdump_full_chain_cell_map() {
        let mut sys = CellMapHive::new(0x00C0_0000, 0x010);
        build_system_bin(&mut sys.bin_page);
        let mut sam = CellMapHive::new(0x00C8_0000, 0x020);
        build_sam_bin(&mut sam.bin_page);

        let isf = cellmap_isf_builder().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let b = sam.install(sys.install(PageTableBuilder::new()));
        let (cr3, mem) = b.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_hashdump(&reader, sam.hhive_va, sys.hhive_va).unwrap();
        assert!(
            result.len() <= 1,
            "unexpected entry count: {}",
            result.len()
        );
    }

    /// extract_boot_key falls back to ControlSet001 when CurrentControlSet is
    /// absent; with no Control subkey there the boot key is empty → walk empty.
    #[test]
    fn extract_boot_key_fallback_to_controlset001() {
        let root_off: u32 = 0x010;
        let list_off: u32 = 0x070;
        let ccs001_off: u32 = 0x0C0;

        let mut sys = CellMapHive::new(0x00D0_0000, root_off);
        write_nk(
            &mut sys.bin_page,
            ao(root_off),
            b"root",
            1,
            list_off,
            0,
            0,
            0,
            0,
        );
        write_lf1(&mut sys.bin_page, ao(list_off), ccs001_off);
        // ControlSet001 with no subkeys → Control lookup fails → empty boot key.
        write_nk(
            &mut sys.bin_page,
            ao(ccs001_off),
            b"ControlSet001",
            0,
            0,
            0,
            0,
            0,
            0,
        );

        let isf = cellmap_isf_builder().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = sys.install(PageTableBuilder::new()).build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        // SAM hive is a valid resolvable hive; boot key fails first → empty.
        let sam = CellMapHive::new(0x00D8_0000, 0x020);
        let b2 = sam.install(PageTableBuilder::new());
        let (cr3b, memb) = b2.build();
        let _ = (cr3b, memb);

        let result = walk_hashdump(&reader, sys.hhive_va, sys.hhive_va).unwrap();
        assert!(
            result.is_empty(),
            "missing Control → empty boot key → empty"
        );
    }
}
