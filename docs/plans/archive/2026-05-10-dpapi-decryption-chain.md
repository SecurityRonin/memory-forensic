# DPAPI Decryption Chain Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend the Windows memory forensics pipeline with end-to-end DPAPI decryption — extract live decrypted master keys from LSASS's `g_MasterKeyCache`, parse DPAPI blob structures, decrypt blobs with AES-256-CBC or 3DES-CBC + HMAC-SHA1 verification, and wire Chrome cookie v10 (AES-256-GCM) decryption into the existing `browser_cookies.rs` walker.

**Architecture:** Five sequential tasks. Task 1 adds RustCrypto workspace deps. Task 2 extends `LsaSecretInfo` to capture raw `DPAPI_SYSTEM` bytes. Task 3 creates a new `memf-dpapi` library crate with blob parser + decryption logic, fully unit-testable with no memory reader dependency. Task 4 implements the `g_MasterKeyCache` linked-list walk. Task 5 integrates Tasks 3+4 into `browser_cookies.rs` for Chrome v10 cookie decryption. Each task has a RED→GREEN commit pair.

**Tech Stack:** Rust 2021, RustCrypto family (`aes`, `cbc`, `aes-gcm`, `sha1`, `sha2`, `hmac`, `pbkdf2`, `des`, `digest`, `block-padding`), `thiserror`.

**Commit convention:** `--no-gpg-sign`. RED commit (failing tests) then GREEN commit (passing implementation). `GITSIGN_CREDENTIAL_CACHE=/Users/4n6h4x0r/Library/Caches/sigstore/gitsign/cache.sock`.

---

## Background

### What exists

- `crates/memf-windows/src/dpapi_keys.rs` — stub returning `Ok(Vec::new())`; `DpapiMasterKeyInfo { guid, version, flags, description, master_key: Vec<u8>, is_suspicious }`
- `crates/memf-windows/src/lsadump.rs` — `walk_lsa_secrets` classifies `DPAPI_SYSTEM` but reads only `length: u32`, not data bytes; `LsaSecretInfo { name, secret_type, length, is_suspicious }`
- No crypto crates in workspace

### Key forensic insight

In a live memory dump, LSASS holds **already-decrypted** master key material in `lsasrv!g_MasterKeyCache` as a doubly-linked list. Walking this gives `{GUID → decrypted_master_key}` pairs **without needing user passwords or PBKDF2**. This is the Mimikatz approach. The hard crypto (PBKDF2 + 3DES/AES for offline decryption from disk master key files) is only needed for offline scenarios — out of scope for this memory-dump-focused tool.

### Windows DPAPI blob wire format

```
[4]  version
[16] provider GUID (ignored)
[16] master key GUID  ← links to the master key needed for decryption
[4]  flags
[4]  description length
[N]  description (UTF-16LE)
[4]  algIdEncrypt (0x6610 = AES-256-CBC, 0x6603 = 3DES-CBC)
[4]  algIdHash    (0x8004 = SHA-1, 0x800C = SHA-512)
[4]  dataLen
[4]  HMACLen
[4]  algIdHash (repeated)
[M]  HMAC key
[K]  ciphertext
[H]  HMAC digest
```

### Chrome cookie v10 format (AES-256-GCM)

Blob in Cookies SQLite `encrypted_value` column:
- `v10` (3 bytes) + 12-byte GCM nonce + ciphertext + 16-byte tag
- App key = AES-256 key stored in `Local State` JSON as base64 of `DPAPI_blob`
- In heap: the `Local State` key appears decrypted in the browser process heap during runtime

---

## Task 1: Add RustCrypto workspace deps

**Files:**
- Modify: `Cargo.toml` (workspace root)

### Step 1: Add to `[workspace.dependencies]`

```toml
aes            = "0.8"
cbc            = { version = "0.1", features = ["alloc"] }
aes-gcm        = "0.10"
sha1           = { version = "0.10", features = ["oid"] }
sha2           = "0.10"
hmac           = "0.12"
pbkdf2         = "0.12"
des            = "0.8"
digest         = "0.10"
block-padding  = "0.3"
```

### Step 2: Verify workspace compiles

```bash
cargo check --workspace 2>&1 | grep "^error" | head -5
```

Expected: no errors (nothing uses these deps yet).

### Step 3: Commit

```bash
git add Cargo.toml Cargo.lock
git commit --no-gpg-sign -m "chore(dpapi): add RustCrypto workspace deps for DPAPI decryption chain"
```

---

## Task 2: Extend `LsaSecretInfo` to carry data bytes (TDD)

**Files:**
- Modify: `crates/memf-windows/src/types.rs` (add `data` field)
- Modify: `crates/memf-windows/src/lsadump.rs` (read data bytes from CurrVal)

### Step 1: Write RED tests

In `lsadump.rs` test module, add:

```rust
#[test]
fn lsa_secret_dpapi_system_carries_40_byte_data() {
    // Build a synthetic SECURITY hive with DPAPI_SYSTEM secret whose CurrVal
    // contains exactly 40 bytes. Assert result[0].data == Some(40-byte vec).
    // ... (use existing hive builder infrastructure from other lsadump tests)
    let result = walk_lsa_secrets(&reader, security_hive_addr)
        .expect("walk should succeed");
    let dpapi = result.iter().find(|s| s.name == "DPAPI_SYSTEM")
        .expect("DPAPI_SYSTEM must be found");
    assert!(dpapi.data.is_some());
    assert_eq!(dpapi.data.as_ref().unwrap().len(), 40);
}

#[test]
fn lsa_secret_data_field_exists_on_struct() {
    // Compile-time: LsaSecretInfo must have a `data` field.
    let info = LsaSecretInfo {
        name: "test".into(),
        secret_type: "generic".into(),
        length: 0,
        is_suspicious: false,
        data: None,  // must compile
    };
    assert!(info.data.is_none());
}
```

Run: `cargo test -p memf-windows lsa` — expect compile error (no `data` field yet). RED commit:

```bash
git commit --no-gpg-sign -m "test(dpapi): RED — LsaSecretInfo data field tests"
```

### Step 2: Add `data` field to `LsaSecretInfo`

In `types.rs`, add after `is_suspicious`:
```rust
/// Raw bytes of the secret value; `None` if unavailable or exceeds 1 KiB.
pub data: Option<Vec<u8>>,
```

### Step 3: Extend `lsadump.rs` to read CurrVal data

Find the code that reads `CurrVal` length. After reading `length`, add:

```rust
let data = if length > 0 && length <= 1024 {
    let mut buf = vec![0u8; length as usize];
    reader.read_bytes(data_ptr_va, length as usize)
        .ok()
        .filter(|b| b.len() == length as usize)
} else {
    None
};
```

Update all `LsaSecretInfo { ... }` struct literals to include `data`.

### Step 4: Run tests, GREEN commit

```bash
cargo test -p memf-windows lsa 2>&1 | tail -10
git add crates/memf-windows/src/types.rs crates/memf-windows/src/lsadump.rs
git commit --no-gpg-sign -m "feat(dpapi): GREEN — LsaSecretInfo carries raw data bytes (max 1 KiB)"
```

---

## Task 3: New `memf-dpapi` crate — blob parser + decryptor (TDD)

**Files:**
- Create: `crates/memf-dpapi/Cargo.toml`
- Create: `crates/memf-dpapi/src/lib.rs`
- Create: `crates/memf-dpapi/src/dpapi_blob.rs`
- Create: `crates/memf-dpapi/src/master_key_blob.rs`
- Create: `crates/memf-dpapi/src/decrypt.rs`
- Create: `crates/memf-dpapi/src/chrome.rs`
- Modify: `Cargo.toml` (add `memf-dpapi` to `[workspace.members]`)

### Step 1: Create `crates/memf-dpapi/Cargo.toml`

```toml
[package]
name = "memf-dpapi"
version = "0.1.0"
edition = "2021"

[dependencies]
thiserror.workspace = true
aes.workspace = true
cbc.workspace = true
aes-gcm.workspace = true
sha1.workspace = true
sha2.workspace = true
hmac.workspace = true
des.workspace = true
digest.workspace = true
block-padding.workspace = true
```

### Step 2: Write RED tests in each submodule

**`dpapi_blob.rs` RED tests:**

```rust
#[test]
fn parse_dpapi_blob_rejects_too_short() {
    assert!(parse_dpapi_blob(&[0u8; 10]).is_err());
}

#[test]
fn parse_dpapi_blob_extracts_master_key_guid() {
    // Hand-crafted minimal blob: version(4) + provider_guid(16) + master_key_guid(16) + ...
    let mut blob = vec![0u8; 100];
    blob[0..4].copy_from_slice(&2u32.to_le_bytes()); // version = 2
    // master key GUID at byte 20
    blob[20] = 0xAA; blob[21] = 0xBB;
    let result = parse_dpapi_blob(&blob); // will fail (not implemented yet)
    // When implemented: assert result.master_key_guid[0] == 0xAA
}
```

**`decrypt.rs` RED tests:**

```rust
#[test]
fn decrypt_aes256_cbc_known_vector() {
    // NIST AES-256-CBC test vector
    let key = [0u8; 32];
    let iv = [0u8; 16];
    let plaintext = b"0000000000000000"; // 16 bytes
    let ciphertext = encrypt_then_decrypt(key, iv, plaintext); // stub
    assert_eq!(ciphertext, plaintext); // will fail (not implemented)
}

#[test]
fn verify_hmac_sha1_correct_key_passes() {
    // will fail (not implemented)
}
```

**`chrome.rs` RED tests:**

```rust
#[test]
fn detect_v10_prefix_recognises_v10() {
    let data = b"v10\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b"; // 3 + 12 bytes nonce
    assert!(matches!(detect_chrome_cookie_encoding(data), ChromeCookieEncoding::V10 { .. }));
}

#[test]
fn detect_dpapi_prefix_recognises_dpapi() {
    let data = b"DPAPI\x00\x01\x02"; // DPAPI prefix
    assert!(matches!(detect_chrome_cookie_encoding(data), ChromeCookieEncoding::DpapiBlob(_)));
}

#[test]
fn detect_unknown_returns_raw() {
    let data = b"hello world plaintext cookie value";
    assert!(matches!(detect_chrome_cookie_encoding(data), ChromeCookieEncoding::Raw));
}
```

RED commit:
```bash
git commit --no-gpg-sign -m "test(dpapi): RED — memf-dpapi crate skeleton with failing blob/decrypt/chrome tests"
```

### Step 3: Implement `dpapi_blob.rs`

```rust
#[derive(Debug, Clone)]
pub struct DpapiBlob {
    pub provider_guid: [u8; 16],
    pub master_key_guid: [u8; 16],
    pub description: String,
    pub alg_id_encrypt: u32,
    pub alg_id_hash: u32,
    pub hmac_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub hmac: Vec<u8>,
}

pub fn parse_dpapi_blob(data: &[u8]) -> Result<DpapiBlob, DpapiError> {
    if data.len() < 60 { return Err(DpapiError::TooShort); }
    let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if version != 1 && version != 2 { return Err(DpapiError::UnsupportedVersion(version)); }
    // ... parse all fields with cursor
}
```

### Step 4: Implement `decrypt.rs`

```rust
use aes::Aes256;
use cbc::Decryptor;
use cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use sha1::Sha1;

pub fn decrypt_aes256_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DpapiError> {
    let decryptor = Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| DpapiError::InvalidKeyLength)?;
    let mut buf = ciphertext.to_vec();
    decryptor.decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map(|pt| pt.to_vec())
        .map_err(|_| DpapiError::DecryptionFailed)
}

pub fn verify_hmac_sha1(key: &[u8], data: &[u8], expected: &[u8]) -> Result<(), DpapiError> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key)
        .map_err(|_| DpapiError::InvalidKeyLength)?;
    mac.update(data);
    mac.verify_slice(expected).map_err(|_| DpapiError::HmacMismatch)
}

pub fn decrypt_dpapi_blob(blob: &DpapiBlob, master_key: &[u8]) -> Result<Vec<u8>, DpapiError> {
    // 1. Derive session key from master_key using HMAC-SHA1
    // 2. Verify HMAC over ciphertext
    // 3. Decrypt ciphertext with AES-256-CBC or 3DES-CBC
}
```

### Step 5: Implement `chrome.rs`

```rust
pub enum ChromeCookieEncoding {
    Raw,
    DpapiBlob(Vec<u8>),
    V10 { nonce: [u8; 12], ciphertext: Vec<u8> },
    V20 { nonce: [u8; 12], ciphertext: Vec<u8> },
}

pub fn detect_chrome_cookie_encoding(data: &[u8]) -> ChromeCookieEncoding {
    if data.starts_with(b"v20") && data.len() > 15 { ... }
    else if data.starts_with(b"v10") && data.len() > 15 { ... }
    else if data.starts_with(b"DPAPI") { ... }
    else { ChromeCookieEncoding::Raw }
}

pub fn decrypt_v10_cookie(
    nonce: &[u8; 12],
    ciphertext: &[u8],
    key: &[u8; 32],
) -> Result<Vec<u8>, DpapiError> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead, Nonce};
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| DpapiError::InvalidKeyLength)?;
    let nonce = Nonce::from_slice(nonce);
    cipher.decrypt(nonce, ciphertext).map_err(|_| DpapiError::DecryptionFailed)
}
```

### Step 6: Run tests, GREEN commit

```bash
cargo test -p memf-dpapi 2>&1 | tail -10
git add crates/memf-dpapi/
git commit --no-gpg-sign -m "feat(dpapi): GREEN — memf-dpapi blob parser, AES/3DES decryptor, Chrome v10 detector"
```

---

## Task 4: Walk `g_MasterKeyCache` in `dpapi_keys.rs` (TDD)

**Files:**
- Modify: `crates/memf-windows/src/dpapi_keys.rs`
- Modify: `crates/memf-windows/Cargo.toml` (add `memf-dpapi` dep)

### Step 1: Write RED test

```rust
#[test]
fn walk_master_key_cache_with_synthetic_entry() {
    // Build a synthetic memory with:
    // - g_MasterKeyCache symbol pointing to a list head at 0x1000
    // - One LIST_ENTRY at 0x1000: Flink=0x2000, Blink=0x1000
    // - Cache entry at 0x2000:
    //   [0x00] Flink = 0x1000 (back to head)
    //   [0x08] Blink = 0x1000
    //   [0x18] GUID bytes (16 bytes)
    //   [0x28] key blob pointer → 0x3000
    //   [0x30] key blob length = 64
    // - 64 bytes of "master key" at 0x3000
    let result = walk_dpapi_master_keys(&reader, ps_head_vaddr)
        .expect("should succeed");
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].master_key.len(), 64);
}
```

RED commit: `git commit --no-gpg-sign -m "test(dpapi): RED — g_MasterKeyCache walk with synthetic cache entry"`

### Step 2: Implement the walk

```rust
pub fn walk_dpapi_master_keys<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
    _ps_head_vaddr: u64,
) -> Result<Vec<DpapiMasterKeyInfo>> {
    // Win10 x64 hardcoded offsets from Mimikatz kuhl_m_sekurlsa_dpapi.c:
    const ENTRY_GUID_OFFSET: u64 = 0x18;
    const ENTRY_BLOB_PTR_OFFSET: u64 = 0x28;
    const ENTRY_BLOB_LEN_OFFSET: u64 = 0x30;

    let list_head_va = reader.required_symbol("g_MasterKeyCache")?;
    let max_entries = 1000usize;
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let mut flink_buf = [0u8; 8];
    reader.read_virt(list_head_va, &mut flink_buf)?;
    let mut current = u64::from_le_bytes(flink_buf);

    for _ in 0..max_entries {
        if current == list_head_va || current == 0 { break; }
        if !seen.insert(current) { break; } // cycle

        let mut guid_buf = [0u8; 16];
        if reader.read_virt(current + ENTRY_GUID_OFFSET, &mut guid_buf).is_err() {
            break;
        }

        let mut ptr_buf = [0u8; 8];
        let mut len_buf = [0u8; 4];
        let blob = if reader.read_virt(current + ENTRY_BLOB_PTR_OFFSET, &mut ptr_buf).is_ok()
            && reader.read_virt(current + ENTRY_BLOB_LEN_OFFSET, &mut len_buf).is_ok()
        {
            let blob_ptr = u64::from_le_bytes(ptr_buf);
            let blob_len = u32::from_le_bytes(len_buf) as usize;
            if blob_len > 0 && blob_len <= 512 {
                reader.read_bytes(blob_ptr, blob_len).unwrap_or_default()
            } else { Vec::new() }
        } else { Vec::new() };

        let guid = format_guid(&guid_buf);
        results.push(DpapiMasterKeyInfo {
            guid,
            version: 1,
            flags: 0,
            description: String::new(),
            master_key: blob,
            is_suspicious: false,
        });

        // Advance Flink
        if reader.read_virt(current, &mut flink_buf).is_err() { break; }
        current = u64::from_le_bytes(flink_buf);
    }

    Ok(results)
}
```

### Step 3: GREEN commit

```bash
cargo test -p memf-windows dpapi 2>&1 | tail -10
git add crates/memf-windows/src/dpapi_keys.rs crates/memf-windows/Cargo.toml
git commit --no-gpg-sign -m "feat(dpapi): GREEN — walk g_MasterKeyCache to extract live LSASS master keys"
```

---

## Task 5: Chrome v10 cookie decryption in `browser_cookies.rs` (TDD)

**Files:**
- Modify: `crates/memf-windows/src/types.rs` (add `encrypted: bool` to `BrowserCookieInfo`)
- Modify: `crates/memf-windows/src/browser_cookies.rs`
- Modify: `crates/memf-windows/Cargo.toml` (add `memf-dpapi` dep)

### Step 1: Write RED tests

```rust
#[test]
fn scan_cookie_region_detects_v10_prefix() {
    // 3-byte "v10" prefix + 12-byte nonce + some ciphertext
    let mut data = vec![0u8; 100];
    data[0..3].copy_from_slice(b"v10");
    let results = scan_cookie_region(&data);
    // When implemented: assert results contains an entry with encrypted=true
    // For now: currently returns nothing (no v10 handling) → RED
    assert!(!results.is_empty(), "v10 cookie should be detected");
}
```

RED commit: `git commit --no-gpg-sign -m "test(dpapi): RED — scan_cookie_region v10 detection test"`

### Step 2: Extend `scan_cookie_region` to detect encrypted cookies

Alongside the existing `Set-Cookie` and Netscape patterns, add a pass that looks for `v10` or `v20` prefixes in raw heap bytes. When found, emit a `BrowserCookieInfo` with:
- `name = "(encrypted)"`, `value = "(v10-encrypted)"`, `domain = ""` (unknown until decrypted)
- `encrypted = true`

This surfaces encrypted cookies in the output even before decryption. A separate `decrypt_browser_cookies(cookies, master_keys)` function (in `memf-dpapi`) can enrich them post-walk.

### Step 3: Add `encrypted` field to `BrowserCookieInfo`

In `types.rs`:
```rust
/// `true` if the cookie value is encrypted (e.g. Chrome v10 AES-GCM) and was
/// not decrypted due to missing key material.
#[serde(default)]
pub encrypted: bool,
```

### Step 4: GREEN commit

```bash
cargo test -p memf-windows browser_cookies 2>&1 | tail -10
cargo test --workspace 2>&1 | tail -5
git add crates/memf-windows/src/browser_cookies.rs \
        crates/memf-windows/src/types.rs \
        crates/memf-windows/Cargo.toml
git commit --no-gpg-sign -m "feat(dpapi): GREEN — detect Chrome v10 encrypted cookies in heap scanner"
```

---

## Expected outcomes

| Capability | Before | After |
|---|---|---|
| `DPAPI_SYSTEM` data extraction | classified only | raw bytes in `LsaSecretInfo.data` |
| DPAPI master key extraction from LSASS | stub → empty | real keys from `g_MasterKeyCache` |
| DPAPI blob parsing | none | `parse_dpapi_blob` in `memf-dpapi` |
| DPAPI blob decryption | none | AES-256-CBC + 3DES + HMAC verify |
| Chrome v10 cookie detection | invisible | surfaced as `encrypted=true` entries |
| Chrome v10 cookie decryption | none | AES-256-GCM with app key |
