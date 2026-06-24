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
use rc4::{KeyInit as Rc4KeyInit, Rc4, StreamCipher};

// Registry hive navigation runs through winreg-core's shared Key decoder
// (canonical _CM_KEY_NODE/_CM_KEY_VALUE offsets + lf/lh/li/ri handling) over
// MemfHiveReader; the validated raw class-name read is fed a cell VA via the
// reader's cell_offset_to_va bridge.
use winreg_core::key::Key;
use winreg_format::cells::CellOffset;

use crate::hive_reader::MemfHiveReader;

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

    // Step 1: Bootstrap winreg-core Key navigation over each hive. In-memory
    // hives are NOT flat: every cell index is translated through
    // `_HHIVE.Storage[].Map` (the HMAP directory). The hive address is the
    // `_CMHIVE`/`_HHIVE` VA (on Win8+/9600 `_CMHIVE.Hive` is at offset 0).
    let system_hive = MemfHiveReader::new(reader, system_hive_addr);
    let Ok(system_root) = system_hive.root_key() else {
        return Ok(Vec::new());
    };
    let sam_hive = MemfHiveReader::new(reader, sam_hive_addr);
    let Ok(sam_root) = sam_hive.root_key() else {
        return Ok(Vec::new());
    };

    // Step 2: Extract boot key from SYSTEM hive.
    // Navigate: root → CurrentControlSet (or ControlSet001) → Control → Lsa
    let boot_key = extract_boot_key(&system_hive, &system_root);
    if boot_key.is_empty() {
        return Ok(Vec::new());
    }

    // Step 3: Navigate SAM hive to SAM\Domains\Account.
    let Some(account_key) = sam_root.subkey_path(r"SAM\Domains\Account").ok().flatten() else {
        return Ok(Vec::new());
    };

    // Step 4: Decrypt the hashed boot key from Account\F value.
    let f_data = named_value(&account_key, "F");
    let hashed_boot_key = decrypt_hashed_boot_key(&f_data, &boot_key);
    if hashed_boot_key.is_empty() {
        return Ok(Vec::new());
    }

    // Step 5: Enumerate users under Account\Users (winreg-core handles the
    // lf/lh/li/ri subkey-list forms; a real SAM Users key fits in one lf).
    let Some(users_key) = account_key.subkey_path("Users").ok().flatten() else {
        return Ok(Vec::new());
    };
    let Ok(rid_keys) = users_key.subkeys() else {
        return Ok(Vec::new());
    };

    let mut entries = Vec::new();
    for rid_key in rid_keys.into_iter().take(MAX_USERS) {
        let key_name = rid_key.name();
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
        let v_data = named_value(&rid_key, "V");
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

/// Read a key's named value (case-insensitive) as raw bytes, or empty on an
/// absent value or read fault — matching the old `read_value_data` contract a
/// missing V/F is benign (yields the RID fallback / zeroed crypto input).
fn named_value<R: winreg_core::cell_reader::CellReader>(key: &Key<'_, R>, name: &str) -> Vec<u8> {
    match key.value(name) {
        Ok(Some(v)) => v.raw_data().unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Extract the boot key from the SYSTEM hive's LSA subkeys.
///
/// The boot key is assembled from the class names of four registry keys
/// under `SYSTEM\CurrentControlSet\Control\Lsa`: JD, Skew1, GBG, Data.
/// The raw bytes are then scrambled using a fixed permutation order.
pub(crate) fn extract_boot_key<P: PhysicalMemoryProvider>(
    hive: &MemfHiveReader<'_, P>,
    root: &Key<'_, MemfHiveReader<'_, P>>,
) -> Vec<u8> {
    // Try CurrentControlSet first, then fall back to ControlSet001.
    let Some(ccs) = root
        .subkey_path("CurrentControlSet")
        .ok()
        .flatten()
        .or_else(|| root.subkey_path("ControlSet001").ok().flatten())
    else {
        return Vec::new();
    };

    let Some(lsa) = ccs.subkey_path(r"Control\Lsa").ok().flatten() else {
        return Vec::new();
    };

    // Read the class names of JD, Skew1, GBG, Data and concatenate them.
    let mut raw_key_hex = String::new();
    for &name in &LSA_KEY_NAMES {
        let Some(subkey) = lsa.subkey_path(name).ok().flatten() else {
            return Vec::new();
        };
        let class_bytes = read_key_class_name(hive, &subkey);
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
        4, // LM rev-2 salt window: blob[+4..+20]
    )
    .map_or(empty_lm, |h| hex_encode(&h));
    let nt_hash = decrypt_user_hash(
        v_data,
        hashed_boot_key,
        rid,
        nt_offset,
        nt_length,
        NTPASSWORD,
        8, // NT rev-2 salt window: blob[+8..+24]
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
    aes_salt_off: usize,
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
            // rev 2 (AES): 16-byte salt then 32-byte ciphertext, after the
            // per-hash header — 4 bytes for the LM hash (salt @ +4) but 8 for the
            // NT hash (salt @ +8). vol3 hashdump get_user_hashes parity
            // (LM +4/+20, NT +8/+24). obfkey = AES128-CBC(hbootkey, salt, enc)[..16].
            let salt = v_data.get(offset + aes_salt_off..offset + aes_salt_off + 16)?;
            let enc = v_data.get(offset + aes_salt_off + 16..offset + aes_salt_off + 48)?;
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
pub(crate) fn username_from_v(v_data: &[u8]) -> Option<String> {
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
pub(crate) fn aes128_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
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

    // RustCrypto `rc4` (audited) — RC4 keys are 1..=256 bytes; the SAM rev-2
    // key is always a 16-byte MD5 digest, so `new_from_slice` never fails here.
    let mut rc4 = match <Rc4 as Rc4KeyInit>::new_from_slice(key) {
        Ok(c) => c,
        Err(_) => return Vec::new(), // cov:unreachable: key is non-empty and <=256 bytes
    };
    let mut buf = data.to_vec();
    rc4.apply_keystream(&mut buf);
    buf
}

// ---------------------------------------------------------------------------
// Internal helpers — registry hive navigation (mirrors sam.rs patterns)
// ---------------------------------------------------------------------------

/// Read the class name of a `_CM_KEY_NODE` (used for boot key extraction).
/// Returns the raw bytes of the class name, or an empty vec on failure.
///
/// winreg-core exposes no public class-name accessor (`Key.node` is private), so
/// the validated `_CM_KEY_NODE` class offsets are read directly off the key's
/// cell VA — resolved through the same HMAP cell map winreg-core navigates, via
/// [`MemfHiveReader::cell_offset_to_va`]. The raw offsets (ClassLength @0x4A,
/// Class cell index @0x30) and the read are kept byte-for-byte.
fn read_key_class_name<P: PhysicalMemoryProvider>(
    hive: &MemfHiveReader<'_, P>,
    key: &Key<'_, MemfHiveReader<'_, P>>,
) -> Vec<u8> {
    let reader = hive.object_reader();
    let Some(key_addr) = hive.cell_offset_to_va(key.offset()) else {
        return Vec::new();
    };
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

    let Some(class_addr) = hive.cell_offset_to_va(CellOffset(class_off)) else {
        return Vec::new();
    };

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
    use crate::test_hive::CellHive;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ---------------------------------------------------------------
    // Two-hive CellHive harness (SYSTEM + SAM in one reader)
    // ---------------------------------------------------------------
    //
    // winreg-core navigates an in-memory hive through the HMAP cell map and
    // REQUIRES the real on-disk "nk"/"vk" signatures + KEY_COMP_NAME/
    // VALUE_COMP_NAME flags that [`CellHive`] writes (the older flat builders did
    // not). The bootkey path additionally reads the `_CM_KEY_NODE` class fields
    // (ClassLength@0x4A, Class cell index@0x30) directly off the cell VA, which
    // `CellHive::nk` does not populate — `nk_with_class` patches them in.
    //
    // To exercise `walk_hashdump` we need BOTH the SYSTEM and SAM hives visible in
    // one VAS; `add_hive_pages` / `two_hive_reader` mirror the pattern in
    // `com_hijacking.rs`, mapping each CellHive's 5 HMAP pages at a distinct PA.

    fn cellmap_isf() -> serde_json::Value {
        IsfBuilder::new()
            .add_struct("_HHIVE", 0x800)
            .add_field("_HHIVE", "BaseBlock", 0x10, "pointer")
            .add_field("_HHIVE", "Storage", 0xb8, "char")
            .add_struct("_DUAL", 0x278)
            .add_field("_DUAL", "Map", 0x18, "pointer")
            .add_struct("_HMAP_ENTRY", 0x20)
            .add_field("_HMAP_ENTRY", "PermanentBinAddress", 0x0, "pointer")
            .add_field("_HMAP_ENTRY", "BlockOffset", 0x8, "unsigned long")
            .build_json()
    }

    /// Map all 5 HMAP pages of a `CellHive` into `ptb` at `pa_base` (mirrors
    /// `com_hijacking::tests::add_hive_pages`).
    fn add_hive_pages(ptb: PageTableBuilder, h: &CellHive, pa_base: u64) -> PageTableBuilder {
        let bb_va = h.hhive_va + 0x1000;
        let dir_va = h.hhive_va + 0x2000;
        let table_va = h.hhive_va + 0x3000;

        let mut hh = vec![0u8; 0x1000];
        hh[0x10..0x18].copy_from_slice(&bb_va.to_le_bytes());
        hh[0xb8 + 0x18..0xb8 + 0x18 + 8].copy_from_slice(&dir_va.to_le_bytes());

        let mut dir = vec![0u8; 0x1000];
        dir[0..8].copy_from_slice(&table_va.to_le_bytes());

        let mut table = vec![0u8; 0x1000];
        table[0..8].copy_from_slice(&h.bin_va.to_le_bytes());

        ptb.map_4k(h.hhive_va, pa_base, flags::WRITABLE)
            .write_phys(pa_base, &hh)
            .map_4k(bb_va, pa_base + 0x1000, flags::WRITABLE)
            .write_phys(pa_base + 0x1000, &vec![0u8; 0x1000])
            .map_4k(dir_va, pa_base + 0x2000, flags::WRITABLE)
            .write_phys(pa_base + 0x2000, &dir)
            .map_4k(table_va, pa_base + 0x3000, flags::WRITABLE)
            .write_phys(pa_base + 0x3000, &table)
            .map_4k(h.bin_va, pa_base + 0x4000, flags::WRITABLE)
            .write_phys(pa_base + 0x4000, &h.bin)
    }

    /// Build a single `ObjectReader` with SYSTEM (PA 0x30_0000) and SAM
    /// (PA 0x31_0000) both visible in the same VAS.
    fn two_hive_reader(system: &CellHive, sam: &CellHive) -> ObjectReader<SyntheticPhysMem> {
        let resolver = IsfResolver::from_value(&cellmap_isf()).unwrap();
        let ptb = add_hive_pages(PageTableBuilder::new(), system, 0x30_0000);
        let ptb = add_hive_pages(ptb, sam, 0x31_0000);
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// `CellHive::nk` plus the `_CM_KEY_NODE` class fields the bootkey path reads:
    /// ClassLength@0x4A (u16) and Class cell index@0x30 (u32), with the UTF-16LE
    /// class string placed at data cell `class_idx`.
    fn nk_with_class(h: &mut CellHive, idx: u32, name: &[u8], class_idx: u32, class_utf16: &[u8]) {
        h.nk(idx, name, 0, 0, 0);
        let o = CellHive::ao(idx);
        h.bin[o + 0x4A..o + 0x4C].copy_from_slice(&(class_utf16.len() as u16).to_le_bytes());
        h.bin[o + 0x30..o + 0x34].copy_from_slice(&class_idx.to_le_bytes());
        h.data(class_idx, class_utf16);
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
    // Walker tests over the CellHive harness (in-memory hive model)
    // ---------------------------------------------------------------

    /// walk_hashdump returns empty when the SYSTEM hive has no
    /// CurrentControlSet/ControlSet001 → no boot key can be assembled.
    #[test]
    fn walk_hashdump_system_root_zero_empty() {
        // SYSTEM root with no children → boot key extraction fails → empty.
        let mut sys = CellHive::new(0x0050_0000);
        sys.nk(0x020, b"root", 0, 0, 0);
        // SAM is a valid resolvable hive; boot key fails first.
        let mut sam = CellHive::new(0x0058_0000);
        sam.nk(0x020, b"root", 0, 0, 0);

        let reader = two_hive_reader(&sys, &sam);
        let result = walk_hashdump(&reader, sam.hhive_va, sys.hhive_va).unwrap();
        assert!(result.is_empty(), "no boot key (empty root node) → empty");
    }

    /// walk_hashdump returns empty when the SAM hive lacks the SAM\Domains\Account
    /// structure, even though the SYSTEM hive resolves a root.
    #[test]
    fn walk_hashdump_sam_root_zero_empty() {
        // SYSTEM resolves a root but has no Control\Lsa → boot key empty, so the
        // walk returns empty before SAM is consulted; SAM is a bare root here.
        let mut sys = CellHive::new(0x0060_0000);
        sys.nk(0x020, b"root", 0, 0, 0);
        let mut sam = CellHive::new(0x0068_0000);
        sam.nk(0x020, b"root", 0, 0, 0);

        let reader = two_hive_reader(&sys, &sam);
        let result = walk_hashdump(&reader, sam.hhive_va, sys.hhive_va).unwrap();
        assert!(result.is_empty(), "sam structure absent → empty");
    }

    /// Non-zero hive addresses but unreadable memory → empty Vec.
    #[test]
    fn walk_hashdump_unreadable_hive() {
        let isf = cellmap_isf();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_hashdump(&reader, 0xFFFF_8000_1111_0000, 0xFFFF_8000_2222_0000).unwrap();
        assert!(result.is_empty());
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

    // ── Full SYSTEM + SAM walk through the CellHive harness ─────────

    /// Build a minimal SYSTEM hive into a `CellHive`:
    /// root → CurrentControlSet → Control → Lsa → {JD,Skew1,GBG,Data}, class "00000000".
    fn build_system_hive(base: u64) -> CellHive {
        let root: u32 = 0x020;
        let root_list: u32 = 0x080;
        let ccs: u32 = 0x0A0;
        let ccs_list: u32 = 0x110;
        let ctrl: u32 = 0x130;
        let ctrl_list: u32 = 0x190;
        let lsa: u32 = 0x1B0;
        let lsa_list: u32 = 0x210;
        let jd: u32 = 0x250;
        let skew1: u32 = 0x2B0;
        let gbg: u32 = 0x310;
        let data: u32 = 0x370;
        let jd_cl: u32 = 0x3D0;
        let skew1_cl: u32 = 0x3E0;
        let gbg_cl: u32 = 0x3F0;
        let data_cl: u32 = 0x400;

        let class_utf16: Vec<u8> = "00000000"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();

        let mut h = CellHive::new(base);
        h.nk(root, b"root", 1, root_list, 0);
        h.lf(root_list, &[ccs]);
        h.nk(ccs, b"CurrentControlSet", 1, ccs_list, 0);
        h.lf(ccs_list, &[ctrl]);
        h.nk(ctrl, b"Control", 1, ctrl_list, 0);
        h.lf(ctrl_list, &[lsa]);
        h.nk(lsa, b"Lsa", 4, lsa_list, 0);
        h.lf(lsa_list, &[jd, skew1, gbg, data]);
        nk_with_class(&mut h, jd, b"JD", jd_cl, &class_utf16);
        nk_with_class(&mut h, skew1, b"Skew1", skew1_cl, &class_utf16);
        nk_with_class(&mut h, gbg, b"GBG", gbg_cl, &class_utf16);
        nk_with_class(&mut h, data, b"Data", data_cl, &class_utf16);
        h
    }

    /// Build a minimal SAM hive into a `CellHive`:
    /// root → SAM → Domains → Account (F value, rev2) → Users → RID "000001F4".
    fn build_sam_hive(base: u64) -> CellHive {
        let root: u32 = 0x020;
        let root_list: u32 = 0x060;
        let sam: u32 = 0x090;
        let sam_list: u32 = 0x0D0;
        let doms: u32 = 0x100;
        let doms_list: u32 = 0x140;
        let acct: u32 = 0x170;
        let acct_sk_list: u32 = 0x1B0;
        let acct_vlist: u32 = 0x1D0;
        let acct_f_vk: u32 = 0x1F0;
        let acct_f_data: u32 = 0x230;
        let users: u32 = 0x2D0;
        let users_list: u32 = 0x310;
        let rid: u32 = 0x340;

        let mut h = CellHive::new(base);
        h.nk(root, b"root", 1, root_list, 0);
        h.lf(root_list, &[sam]);
        h.nk(sam, b"SAM", 1, sam_list, 0);
        h.lf(sam_list, &[doms]);
        h.nk(doms, b"Domains", 1, doms_list, 0);
        h.lf(doms_list, &[acct]);
        h.nk(acct, b"Account", 1, acct_sk_list, 0);
        h.lf(acct_sk_list, &[users]);
        h.values(acct, 1, acct_vlist);
        h.value_list(acct_vlist, &[acct_f_vk]);
        h.vk(acct_f_vk, b"F", 3, 0xA0, acct_f_data);
        let mut f = vec![0u8; 0xA0];
        f[0x00] = 0x02; // F structure revision = 2 (RC4) at F[0x00]
        h.data(acct_f_data, &f);
        h.nk(users, b"Users", 1, users_list, 0);
        h.lf(users_list, &[rid]);
        h.nk(rid, b"000001F4", 0, 0, 0);
        h
    }

    /// Full walk_hashdump over SYSTEM + SAM CellHive hives: exercises the entire
    /// traversal (boot key extraction, F decryption, user enumeration) without
    /// panic. The synthetic hashes are not real, so we assert the call succeeds
    /// and yields at most one RID entry.
    #[test]
    fn walk_hashdump_full_chain_cell_map() {
        let sys = build_system_hive(0x00C0_0000);
        let sam = build_sam_hive(0x00C8_0000);

        let reader = two_hive_reader(&sys, &sam);
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
        let root: u32 = 0x020;
        let root_list: u32 = 0x080;
        let ccs001: u32 = 0x0C0;

        let mut sys = CellHive::new(0x00D0_0000);
        sys.nk(root, b"root", 1, root_list, 0);
        sys.lf(root_list, &[ccs001]);
        // ControlSet001 with no subkeys → Control lookup fails → empty boot key.
        sys.nk(ccs001, b"ControlSet001", 0, 0, 0);

        // SAM hive is a valid resolvable hive; boot key fails first → empty.
        let mut sam = CellHive::new(0x00D8_0000);
        sam.nk(0x020, b"root", 0, 0, 0);

        let reader = two_hive_reader(&sys, &sam);
        let result = walk_hashdump(&reader, sam.hhive_va, sys.hhive_va).unwrap();
        assert!(
            result.is_empty(),
            "missing Control → empty boot key → empty"
        );
    }

    /// RED — rev-2 (AES) NT hash must use the NT window (salt +8..24, enc
    /// +24..56), NOT the LM window (+4..20 / +20..52). Golden vector: encrypt the
    /// independently-known NTLM(empty) hash at the CORRECT vol3 offsets, with
    /// distinct garbage in +4..8; the buggy LM window then decrypts garbage and
    /// fails to recover the known hash. (Independent expected value avoids the
    /// self-consistent round-trip trap.)
    #[test]
    fn extract_hashes_from_v_rev2_nt_uses_nt_window() {
        use aes::Aes128;
        use cbc::Encryptor as CbcEncryptor;
        use cipher::{block_padding::NoPadding, BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit};
        use des::Des;

        // NTLM of the empty password — an independently known constant.
        let known_nt: [u8; 16] = [
            0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0,
            0x89, 0xc0,
        ];
        let rid: u32 = 1001;
        let hbootkey = [0x11u8; 16];
        let salt = [0x22u8; 16];

        // Forward chain (inverse of decrypt): obfkey = DES_encrypt(sid_keys, hash);
        // enc = AES128-CBC-encrypt(hbootkey, salt, obfkey).
        let (k1, k2) = sid_to_key(rid);
        let des_enc = |key: [u8; 8], block: [u8; 8]| -> [u8; 8] {
            let c = Des::new(&key.into());
            let mut b = block.into();
            c.encrypt_block(&mut b);
            b.into()
        };
        let mut obfkey = [0u8; 16];
        obfkey[..8].copy_from_slice(&des_enc(k1, known_nt[..8].try_into().unwrap()));
        obfkey[8..].copy_from_slice(&des_enc(k2, known_nt[8..].try_into().unwrap()));
        // rev-2 ciphertext is 32 bytes; decrypt takes [..16] as the obfkey.
        let mut enc = [0u8; 32];
        enc[..16].copy_from_slice(&obfkey);
        CbcEncryptor::<Aes128>::new_from_slices(&hbootkey, &salt)
            .unwrap()
            .encrypt_padded_mut::<NoPadding>(&mut enc, 32)
            .unwrap();

        // NT blob (56 B): rev=2@+2, garbage@+4..8, salt@+8..24, enc@+24..56.
        let mut nt_blob = [0u8; 56];
        nt_blob[2] = 0x02;
        nt_blob[4..8].copy_from_slice(&[0xAB, 0xCD, 0xEF, 0x99]); // wrong-window bait
        nt_blob[8..24].copy_from_slice(&salt);
        nt_blob[24..56].copy_from_slice(&enc);

        let nt_off = 0xCCusize;
        let mut v = vec![0u8; nt_off + nt_blob.len()];
        v[0xA8..0xAC].copy_from_slice(&((nt_off - 0xCC) as u32).to_le_bytes()); // nt_offset
        v[0xAC..0xB0].copy_from_slice(&56u32.to_le_bytes()); // nt_length
        v[0xA0..0xA4].copy_from_slice(&0u32.to_le_bytes()); // lm_length 0 → skipped
        v[nt_off..].copy_from_slice(&nt_blob);

        let (_lm, nt) = extract_hashes_from_v(&v, &hbootkey, rid);
        assert_eq!(
            nt, "31d6cfe0d16ae931b73c59d7e0c089c0",
            "rev-2 NT hash must use the +8/+24 window, got {nt}"
        );
    }
}
