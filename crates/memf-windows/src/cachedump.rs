//! Domain Cached Credential (DCC/MSCachev2) extraction from Windows memory dumps.
//!
//! When domain users log in to a Windows machine, their credential hashes
//! are cached in `HKLM\SECURITY\Cache` as `NL$1`, `NL$2`, ... entries.
//! These Domain Cached Credentials (DCC2/MSCachev2) can be extracted for
//! offline cracking. This is the memory forensic equivalent of Volatility's
//! `cachedump` plugin.
//!
//! The SECURITY hive cache is structured as:
//! `SECURITY\Cache\NL$1` — first cached credential entry
//! `SECURITY\Cache\NL$2` — second cached credential entry
//! ...up to `NL$10` (typical maximum, configurable via CachedLogonsCount)
//!
//! Each cache entry value contains a DCC2 header (96 bytes) followed by
//! UTF-16LE encoded username and domain name strings.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use std::fmt::Write as _;

use crate::registry;

/// Maximum number of cached credential entries to enumerate (safety limit).
const MAX_CACHED_CREDS: usize = 64;
const _: () = assert!(MAX_CACHED_CREDS >= 10 && MAX_CACHED_CREDS <= 1024);

/// Information about a domain cached credential recovered from the SECURITY hive.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CachedCredentialInfo {
    /// Decrypted domain username.
    pub username: String,
    /// Decrypted logon domain (NetBIOS).
    pub domain: String,
    /// Decrypted DNS domain name (may be empty).
    pub domain_name: String,
    /// MS-Cache v2 (DCC2) hash, hex — crackable offline as
    /// `$DCC2$10240#<username>#<dcc2_hash>`.
    pub dcc2_hash: String,
    /// DCC2 PBKDF2 iteration count (fixed at 10240 by the algorithm).
    pub iteration_count: u32,
    /// Whether the credential looks suspicious (heuristic on the decrypted name).
    pub is_suspicious: bool,
}

/// Classify a cached domain credential as suspicious.
///
/// Returns `true` for credentials that match anomalous patterns:
/// - `iteration_count < 10240`: older/weaker hash (pre-Vista default was 1024)
/// - Empty domain name: indicates corrupted or tampered entry
/// - Username contains characters atypical of Active Directory usernames
///   (AD usernames are alphanumeric plus `.`, `-`, `_`)
pub fn classify_cached_credential(username: &str, domain: &str, iteration_count: u32) -> bool {
    // Older/weaker iteration count (Vista+ default is 10240)
    if iteration_count < 10240 {
        return true;
    }

    // Empty domain is anomalous — every valid cached cred has a domain
    if domain.is_empty() {
        return true;
    }

    // Check username for characters atypical of AD usernames.
    // Valid AD sAMAccountName chars: alphanumeric, '.', '-', '_'
    if !username.is_empty()
        && username
            .chars()
            .any(|c| !c.is_alphanumeric() && c != '.' && c != '-' && c != '_')
    {
        return true;
    }

    false
}

/// Extract domain cached credentials from the SECURITY registry hive in memory.
///
/// Navigates `SECURITY\Cache` in the registry hive at `security_hive_addr`,
/// reads `NL$1` through `NL$10` value entries, parses the DCC2 header to
/// extract username, domain, iteration count, and hash metadata, classifies
/// each entry, and returns the results.
///
/// Returns an empty `Vec` if the hive address is zero or navigation fails.
/// DCC2 PBKDF2 iteration count — fixed at 10240 by the MS-Cache-v2 algorithm
/// (not stored per entry).
const DCC2_ITERATIONS: u32 = 10240;

/// Walk and **decrypt** cached domain credentials from the in-memory SECURITY
/// hive (Vista+/Win8+ DCC2).
///
/// `system_hive_addr` supplies the boot key; `security_hive_addr` holds the
/// cache. Derives the LSA key + `NL$KM` (reusing the validated
/// [`crate::lsadump`] / [`crate::hashdump`] crypto), then decrypts each
/// `Cache\\NL$N` record (AES-128-CBC) into the real username, domain, and DCC2
/// hash. If the boot/LSA/NL$KM key cannot be derived, it **REFUSES** — returns
/// an empty `Vec` rather than emitting undecrypted ciphertext as credentials.
pub fn walk_cached_credentials<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    system_hive_addr: u64,
    security_hive_addr: u64,
) -> crate::Result<Vec<CachedCredentialInfo>> {
    if security_hive_addr == 0 {
        return Ok(Vec::new());
    }
    let root = registry::resolve_root_cell(reader, security_hive_addr);
    if root == 0 {
        return Ok(Vec::new());
    }
    let policy = registry::find_subkey_by_name(reader, security_hive_addr, root, "Policy");
    if policy == 0 {
        return Ok(Vec::new());
    }

    // Keys: boot key (SYSTEM) → LSA key → NL$KM. Any failure ⇒ refuse, never
    // fabricate plaintext from ciphertext.
    let lsa_key =
        crate::lsadump::derive_lsa_key(reader, system_hive_addr, security_hive_addr, policy);
    if lsa_key.is_empty() {
        return Ok(Vec::new());
    }
    let nlkm = get_nlkm(reader, security_hive_addr, policy, &lsa_key);
    if nlkm.len() < 32 {
        return Ok(Vec::new());
    }

    let cache = registry::find_subkey_by_name(reader, security_hive_addr, root, "Cache");
    if cache == 0 {
        return Ok(Vec::new());
    }

    let mut results = Vec::new();
    for value in registry::list_values(reader, security_hive_addr, cache)
        .into_iter()
        .take(MAX_CACHED_CREDS)
    {
        if value.name == "NL$Control" || !is_nl_entry(&value.name) {
            continue;
        }
        if value.data.len() < 96 {
            continue;
        }
        let (uname_len, domain_len, domain_name_len, enc_data, ch) = parse_cache_entry(&value.data);
        if uname_len == 0 || ch.len() != 16 {
            continue; // empty / unused cache slot
        }
        let dec = decrypt_dcc2(&enc_data, &nlkm, &ch);
        let (username, domain, domain_name, hash) =
            parse_decrypted_cache(&dec, uname_len, domain_len, domain_name_len);
        if username.is_empty() {
            continue;
        }
        let dcc2_hash = hash.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        let is_suspicious = classify_cached_credential(&username, &domain, DCC2_ITERATIONS);
        results.push(CachedCredentialInfo {
            username,
            domain,
            domain_name,
            dcc2_hash,
            iteration_count: DCC2_ITERATIONS,
            is_suspicious,
        });
    }
    Ok(results)
}

/// Decrypt the `NL$KM` cached-domain key material: the `NL$KM` LSA secret
/// (`Policy\\Secrets\\NL$KM\\CurrVal`), decrypted with the LSA key.
fn get_nlkm<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    security_hive_addr: u64,
    policy: u64,
    lsa_key: &[u8],
) -> Vec<u8> {
    let secrets = registry::find_subkey_by_name(reader, security_hive_addr, policy, "Secrets");
    if secrets == 0 {
        return Vec::new();
    }
    let nlkm_key = registry::find_subkey_by_name(reader, security_hive_addr, secrets, "NL$KM");
    if nlkm_key == 0 {
        return Vec::new();
    }
    let currval = registry::find_subkey_by_name(reader, security_hive_addr, nlkm_key, "CurrVal");
    if currval == 0 {
        return Vec::new();
    }
    let enc = registry::read_value_data(reader, security_hive_addr, currval, "");
    crate::lsadump::lsa_decrypt_aes(&enc, lsa_key)
}

/// Decrypt a DCC2 cache record: AES-128-CBC with key `nlkm[16:32]` and IV `ch`
/// (the record checksum). Reuses hashdump's validated `aes128_cbc_decrypt`;
/// zero-pads `enc_data` to a 16-byte multiple.
fn decrypt_dcc2(enc_data: &[u8], nlkm: &[u8], ch: &[u8]) -> Vec<u8> {
    if nlkm.len() < 32 || ch.len() < 16 {
        return Vec::new();
    }
    let mut padded = enc_data.to_vec();
    while padded.len() % 16 != 0 {
        padded.push(0);
    }
    crate::hashdump::aes128_cbc_decrypt(&nlkm[16..32], &ch[..16], &padded)
}

/// Check if a value name is a cached credential entry (`NL$1` through `NL$50`).
///
/// Windows supports up to 50 cached credentials (CachedLogonsCount registry value).
/// The hard-coded `matches!` list missed NL$11 and above; parsing the suffix as an
/// integer handles any valid count up to the 50-entry upper bound.
fn is_nl_entry(name: &str) -> bool {
    name.strip_prefix("NL$")
        .and_then(|s| s.parse::<usize>().ok())
        .is_some_and(|n| n > 0 && n <= 50)
}

/// Parse the plaintext header of an `NL$N` cache record (DCC2): returns
/// `(uname_len, domain_len, domain_name_len, enc_data, ch)`. Lengths are byte
/// counts; `ch` is the 16-byte AES IV; `enc_data` is the encrypted region.
/// Reference: Volatility3 registry/cachedump `parse_cache_entry`.
fn parse_cache_entry(data: &[u8]) -> (u16, u16, u16, Vec<u8>, Vec<u8>) {
    let rd16 = |off: usize| {
        data.get(off..off + 2)
            .and_then(|b| b.try_into().ok())
            .map_or(0, u16::from_le_bytes)
    };
    if data.len() < 96 {
        return (rd16(0), rd16(2), 0, Vec::new(), Vec::new());
    }
    (
        rd16(0),
        rd16(2),
        rd16(60),
        data[96..].to_vec(),
        data[64..80].to_vec(),
    )
}

/// Split a decrypted DCC2 cache record into `(username, domain, domain_name,
/// dcc2_hash)`. `dcc2_hash` is the 16-byte MS-Cache-v2 hash at offset 0; the
/// strings start at offset 72 with 4-byte alignment padding between them.
/// Reference: Volatility3 registry/cachedump `parse_decrypted_cache`.
fn parse_decrypted_cache(
    dec: &[u8],
    uname_len: u16,
    domain_len: u16,
    domain_name_len: u16,
) -> (String, String, String, Vec<u8>) {
    let hash = dec.get(0..16).map(<[u8]>::to_vec).unwrap_or_default();
    // 4-byte alignment padding between strings (Volatility: 2*((len/2)%2)).
    let pad = |len: u16| -> usize { 2 * usize::from((len / 2) % 2) };
    let (ul, dl, dnl) = (
        uname_len as usize,
        domain_len as usize,
        domain_name_len as usize,
    );
    let uname_off = 72usize;
    let domain_off = uname_off + ul + pad(uname_len);
    let domain_name_off = domain_off + dl + pad(domain_len);
    let field = |off: usize, len: usize| -> String {
        dec.get(off..off.saturating_add(len))
            .map_or_else(String::new, decode_utf16le)
    };
    (
        field(uname_off, ul),
        field(domain_off, dl),
        field(domain_name_off, dnl),
        hash,
    )
}

/// Decode a UTF-16LE byte slice into a String.
fn decode_utf16le(bytes: &[u8]) -> String {
    let u16_iter = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    String::from_utf16_lossy(&u16_iter.collect::<Vec<u16>>())
}

#[cfg(test)]
mod tests {
    // Test fixtures declare layout consts/helpers beside the statements that use
    // them to keep each byte-plan readable; that ordering is intentional here.
    #![allow(clippy::items_after_statements)]
    use super::*;

    // ── Classifier tests ─────────────────────────────────────────────

    /// Normal domain credential with sufficient iteration count is benign.
    #[test]
    fn classify_benign_domain_cred() {
        assert!(
            !classify_cached_credential("john.doe", "CONTOSO", 10240),
            "Normal domain cred with iteration_count=10240 should not be suspicious"
        );
    }

    /// High iteration count with standard username is benign.
    #[test]
    fn classify_benign_high_iteration() {
        assert!(
            !classify_cached_credential("admin_user", "CORP.LOCAL", 20480),
            "High iteration count domain cred should not be suspicious"
        );
    }

    /// Usernames with valid AD chars (alphanumeric, dot, dash, underscore) are benign.
    #[test]
    fn classify_benign_valid_ad_username_chars() {
        assert!(!classify_cached_credential("alice.smith", "DOMAIN", 10240));
        assert!(!classify_cached_credential("bob-jones", "DOMAIN", 10240));
        assert!(!classify_cached_credential("svc_account", "DOMAIN", 10240));
        assert!(!classify_cached_credential("User123", "DOMAIN", 10240));
    }

    /// Empty username with sufficient iteration count and non-empty domain is benign
    /// (the username chars check short-circuits for empty strings).
    #[test]
    fn classify_benign_empty_username() {
        // empty username has no invalid chars so only domain/count checked
        assert!(!classify_cached_credential("", "DOMAIN", 10240));
    }

    /// Iteration count of exactly 10240 is benign (boundary).
    #[test]
    fn classify_boundary_iteration_count() {
        assert!(!classify_cached_credential("user", "DOMAIN", 10240));
    }

    /// Iteration count of 10239 is suspicious (one below threshold).
    #[test]
    fn classify_boundary_below_threshold() {
        assert!(classify_cached_credential("user", "DOMAIN", 10239));
    }

    /// Low iteration count (pre-Vista default) is suspicious.
    #[test]
    fn classify_suspicious_low_iteration() {
        assert!(
            classify_cached_credential("user1", "DOMAIN", 1024),
            "iteration_count=1024 (below 10240) should be suspicious"
        );
    }

    /// Zero iteration count is suspicious.
    #[test]
    fn classify_suspicious_zero_iteration() {
        assert!(classify_cached_credential("user1", "DOMAIN", 0));
    }

    /// Empty domain name is suspicious (corrupted/tampered entry).
    #[test]
    fn classify_suspicious_empty_domain() {
        assert!(
            classify_cached_credential("user1", "", 10240),
            "Empty domain should be suspicious"
        );
    }

    /// Username with special characters atypical of AD is suspicious.
    #[test]
    fn classify_suspicious_special_chars() {
        assert!(
            classify_cached_credential("user@evil", "DOMAIN", 10240),
            "Username with '@' should be suspicious (not a valid AD sAMAccountName char)"
        );
    }

    /// Username with spaces is suspicious.
    #[test]
    fn classify_suspicious_space_in_username() {
        assert!(
            classify_cached_credential("user name", "DOMAIN", 10240),
            "Username with space should be suspicious"
        );
    }

    /// Username with slash is suspicious.
    #[test]
    fn classify_suspicious_slash_in_username() {
        assert!(classify_cached_credential("domain\\user", "DOMAIN", 10240));
    }

    /// Username with exclamation mark is suspicious.
    #[test]
    fn classify_suspicious_bang_in_username() {
        assert!(classify_cached_credential("user!", "DOMAIN", 10240));
    }

    // ── is_nl_entry tests ─────────────────────────────────────────────

    #[test]
    fn is_nl_entry_valid() {
        for i in 1..=10 {
            assert!(is_nl_entry(&format!("NL${i}")), "NL${i} should be valid");
        }
    }

    #[test]
    fn is_nl_entry_invalid_prefix() {
        assert!(!is_nl_entry("NL$0"));
        assert!(!is_nl_entry("NL$51")); // above 50-entry upper bound
        assert!(!is_nl_entry("NL$100")); // well above limit
        assert!(!is_nl_entry("nl$1")); // case-sensitive
        assert!(!is_nl_entry("CachedLogons"));
        assert!(!is_nl_entry(""));
        assert!(!is_nl_entry("NL$"));
    }

    #[test]
    fn is_nl_entry_boundary_values() {
        assert!(is_nl_entry("NL$1"));
        assert!(is_nl_entry("NL$10"));
        assert!(is_nl_entry("NL$11")); // was wrongly rejected before fix
        assert!(is_nl_entry("NL$50")); // upper bound
        assert!(!is_nl_entry("NL$0"));
        assert!(!is_nl_entry("NL$51")); // one above upper bound
    }

    /// NL$11, NL$25, NL$50 are all valid cached credential entries.
    #[test]
    fn is_nl_entry_above_ten_accepted() {
        assert!(is_nl_entry("NL$11"), "NL$11 should be accepted");
        assert!(is_nl_entry("NL$25"), "NL$25 should be accepted");
        assert!(is_nl_entry("NL$50"), "NL$50 should be accepted");
    }

    // ── decode_utf16le tests ──────────────────────────────────────────

    #[test]
    fn decode_utf16le_empty() {
        assert_eq!(decode_utf16le(&[]), "");
    }

    #[test]
    fn decode_utf16le_ascii() {
        // "hello" as UTF-16LE
        let bytes = b"h\0e\0l\0l\0o\0";
        assert_eq!(decode_utf16le(bytes), "hello");
    }

    #[test]
    fn decode_utf16le_unicode() {
        // U+00E9 (é) as UTF-16LE: [0xE9, 0x00]
        let bytes = &[0xE9u8, 0x00];
        let result = decode_utf16le(bytes);
        assert_eq!(result, "é");
    }

    #[test]
    fn decode_utf16le_odd_byte_count() {
        // Odd number of bytes: trailing byte is ignored by chunks_exact(2)
        let bytes = b"h\0e\0x"; // 5 bytes, last one orphaned
        let result = decode_utf16le(bytes);
        assert_eq!(result, "he"); // 'x' byte orphaned
    }

    #[test]
    fn decode_utf16le_domain_name() {
        // "CORP" as UTF-16LE
        let bytes = b"C\0O\0R\0P\0";
        assert_eq!(decode_utf16le(bytes), "CORP");
    }

    // ── MAX_CACHED_CREDS constant ─────────────────────────────────────

    // ── walk_cached_credentials body coverage ────────────────────────
    //
    // The walker reads: hive BaseBlock → root_cell_off → flat_base
    // → root_addr → Cache key → value list → NL$ entries.
    // We provide synthetic physical memory so the body is exercised
    // past the hive_addr=0 guard.

    // ── Additional coverage: classify + helpers ──────────────────────

    /// classify_cached_credential: zero iteration count with empty domain → suspicious
    /// (both conditions fire independently).
    #[test]
    fn classify_both_conditions_suspicious() {
        assert!(classify_cached_credential("user", "", 0));
    }

    /// classify_cached_credential: numeric characters in username are valid AD chars.
    #[test]
    fn classify_numeric_username_benign() {
        assert!(!classify_cached_credential("user123", "DOMAIN", 10240));
    }

    /// decode_utf16le with all-zero bytes (null terminators) → empty-ish result.
    #[test]
    fn decode_utf16le_all_zeros() {
        let bytes = [0u8; 8];
        let result = decode_utf16le(&bytes);
        // All null chars: should produce 4 null chars, but as a string.
        assert_eq!(result.len(), 4);
    }

    /// RED — DCC2 record parsers (pure, synthetically testable). Stubs return
    /// empties so these fail until implemented.
    #[test]
    fn parse_cache_entry_extracts_header() {
        let mut data = vec![0u8; 96 + 8];
        data[0..2].copy_from_slice(&10u16.to_le_bytes()); // uname_len
        data[2..4].copy_from_slice(&6u16.to_le_bytes()); // domain_len
        data[60..62].copy_from_slice(&14u16.to_le_bytes()); // domain_name_len
        data[64..80].copy_from_slice(&[0xCCu8; 16]); // ch (IV)
        data[96..104].copy_from_slice(&[0xEE; 8]); // enc_data
        let (ul, dl, dnl, enc, ch) = parse_cache_entry(&data);
        assert_eq!(ul, 10);
        assert_eq!(dl, 6);
        assert_eq!(dnl, 14);
        assert_eq!(ch, vec![0xCCu8; 16]);
        assert_eq!(enc, vec![0xEEu8; 8]);
    }

    #[test]
    fn parse_decrypted_cache_splits_fields() {
        // hash @0 (16), username @72, then domain, then domain_name (4-byte pads).
        let user = "rick"; // 4 chars → 8 bytes (even → no pad)
        let dom = "CORP"; // 4 chars → 8 bytes
        let dnsdom = "corp.local"; // 10 chars → 20 bytes
        let u16b = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        let (ub, db, nb) = (u16b(user), u16b(dom), u16b(dnsdom));
        let mut dec = vec![0u8; 72 + ub.len() + db.len() + nb.len()];
        dec[0..16].copy_from_slice(&[0x11u8; 16]); // dcc2 hash
        let mut off = 72;
        dec[off..off + ub.len()].copy_from_slice(&ub);
        off += ub.len(); // 8, even → pad 0
        dec[off..off + db.len()].copy_from_slice(&db);
        off += db.len(); // even → pad 0
        dec[off..off + nb.len()].copy_from_slice(&nb);
        let (username, domain, domain_name, hash) =
            parse_decrypted_cache(&dec, ub.len() as u16, db.len() as u16, nb.len() as u16);
        assert_eq!(username, "rick");
        assert_eq!(domain, "CORP");
        assert_eq!(domain_name, "corp.local");
        assert_eq!(hash, vec![0x11u8; 16]);
    }
}
