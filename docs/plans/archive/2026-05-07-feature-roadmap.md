# memory-forensic Feature Roadmap & Research Report

**Date:** 2026-05-07
**Scope:** DPAPI decryption chain, framebuffer extraction, comprehensive feature gap analysis

---

## 1. DPAPI Decryption Chain — Full Technical Spec

### 1.1 How Windows DPAPI Works Internally

The Data Protection API (DPAPI) is a symmetric encryption system built into Windows.
The chain from `CryptProtectData()` to ciphertext works as follows:

1. **User password** → PBKDF2(SHA1 or SHA256, password UTF-16LE, SID-derived salt, 4000+ iterations) → **prekey**
2. **Prekey** + master key file on disk (`%APPDATA%\Microsoft\Protect\<SID>\<GUID>`) → decrypt the **master key** (64 bytes)
3. **Master key** + DPAPI blob salt → HMAC-SHA1 (old) or HMAC-SHA512 (new) → derive **session key**
4. **Session key** → 3DES-CBC (old, algId 0x6603) or AES-256-CBC (new, algId 0x6610) → decrypt the **DPAPI blob** plaintext

When LSASS is running, the decrypted master keys are cached in
`lsasrv!g_MasterKeyCache` → linked list of `LSAP_DPAPI_MASTERKEY_CACHE_ENTRY`.
Each entry contains:
- Master key GUID (matches the filename under `%APPDATA%\Microsoft\Protect\<SID>\`)
- Decrypted master key bytes (64 bytes SHA1 hash of the actual master key material)
- Flags and timestamps

**In a memory dump, the master key bytes are already decrypted** — no need to
derive from password. This is what `dpapi_keys.rs` extracts (currently stubbed).

### 1.2 DPAPI Blob Structure (`DPAPI_BLOB`)

```
Offset  Size   Field
0x00    4      dwVersion (1)
0x04    16     guidProvider (df9d8cd0-1501-11d1-8c7a-00c04fc297eb = user, typically)
0x14    4      dwMasterKeyVersion
0x18    16     guidMasterKey — links blob to master key GUID
0x28    4      dwFlags
0x2C    4      dwDescriptionLen
0x30    var    szDescription (UTF-16LE)
...     4      algCrypt (0x6603=3DES, 0x6610=AES-256, 0x6611=AES-128)
...     4      dwAlgCryptLen (key length in bits)
...     4      dwSaltLen
...     var    pbSalt
...     4      dwStrongKeyLen (usually 0)
...     4      algHash (0x8004=SHA1, 0x800E=SHA512)
...     4      dwAlgHashLen
...     4      dwHmac2KeyLen
...     var    pbHmak2Key
...     4      dwDataLen
...     var    pbData (encrypted payload)
...     4      dwSignLen
...     var    pbSign (HMAC signature)
```

### 1.3 Mimikatz vs pypykatz Approach

**Mimikatz `dpapi::masterkey`**: Decrypts the on-disk master key file using
password/domain backup key/SYSTEM key. Produces the 64-byte SHA1 master key.

**Mimikatz `dpapi::blob`**: Takes a decrypted master key + raw DPAPI blob,
derives the session key via HMAC, decrypts ciphertext via 3DES/AES.

**pypykatz `dpapi_system`** (in `pypykatz/lsa/packages/dpapi/dpapi.py`):
Extracts the DPAPI_SYSTEM LSA secret from registry (SECURITY hive), which
contains the machine master key and user master key used for SYSTEM-context
DPAPI operations. This is different from per-user master keys.

**pypykatz blob decryption** (in `pypykatz/dpapi/dpapi.py`):
```python
def decrypt_blob(master_key_bytes, dpapi_blob_bytes):
    blob = DPAPIBlob.from_bytes(dpapi_blob_bytes)
    # Derive session key
    hmac_key = hmac_algo(master_key_bytes, blob.hmac2_key)
    session_key = hmac_algo(hmac_key, blob.salt)
    # Decrypt
    if blob.algCrypt == 0x6603:  # 3DES
        plaintext = des3_cbc_decrypt(session_key[:24], blob.salt[:8], blob.data)
    elif blob.algCrypt == 0x6610:  # AES-256
        plaintext = aes_cbc_decrypt(session_key[:32], blob.salt[:16], blob.data)
    return plaintext
```

### 1.4 Implementation Plan: `dpapi_decrypt.rs`

**New module:** `crates/memf-windows/src/dpapi_decrypt.rs`

**Rust crates needed** (all from RustCrypto, pure Rust, no OpenSSL):
- `hmac = "0.12"` — HMAC computation
- `sha1 = "0.10"` — SHA1 for old DPAPI blobs
- `sha2 = "0.10"` — SHA512 for new DPAPI blobs
- `aes = "0.8"` — AES-256 block cipher
- `cbc = "0.1"` — CBC mode wrapper
- `des = "0.8"` — 3DES (Triple DES) block cipher

**Structs:**

```rust
/// Parsed DPAPI blob header.
#[derive(Debug, Clone)]
pub struct DpapiBlob {
    pub version: u32,
    pub provider_guid: [u8; 16],
    pub master_key_guid: String,  // formatted GUID
    pub flags: u32,
    pub description: String,
    pub crypt_alg: u32,          // 0x6603=3DES, 0x6610=AES-256
    pub crypt_key_len: u32,
    pub salt: Vec<u8>,
    pub hash_alg: u32,           // 0x8004=SHA1, 0x800E=SHA512
    pub hmac2_key: Vec<u8>,
    pub encrypted_data: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Result of DPAPI blob decryption.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DpapiDecryptedBlob {
    pub master_key_guid: String,
    pub description: String,
    pub algorithm: String,
    pub plaintext: Vec<u8>,
}
```

**Algorithm:**

```rust
pub fn decrypt_dpapi_blob(
    master_key: &[u8],  // 64-byte SHA1 master key from dpapi_keys.rs
    blob: &DpapiBlob,
) -> Result<Vec<u8>> {
    // 1. Derive HMAC key
    let hmac_calc_key = match blob.hash_alg {
        0x8004 => hmac_sha1(master_key, &blob.hmac2_key),
        0x800E => hmac_sha512(master_key, &blob.hmac2_key),
        _ => return Err(DpapiError::UnsupportedHashAlg(blob.hash_alg)),
    };

    // 2. Derive session key from HMAC key + salt
    let session_key = match blob.hash_alg {
        0x8004 => hmac_sha1(&hmac_calc_key, &blob.salt),
        0x800E => hmac_sha512(&hmac_calc_key, &blob.salt),
        _ => unreachable!(),
    };

    // 3. Decrypt ciphertext
    match blob.crypt_alg {
        0x6603 => {
            // 3DES-CBC: key = first 24 bytes of session_key, IV = first 8 bytes of salt
            let key = &session_key[..24];
            let iv = &blob.salt[..8];
            des3_cbc_decrypt(key, iv, &blob.encrypted_data)
        }
        0x6610 => {
            // AES-256-CBC: key = first 32 bytes of session_key, IV = first 16 bytes of salt
            let key = &session_key[..32];
            let iv = &blob.salt[..16];
            aes256_cbc_decrypt(key, iv, &blob.encrypted_data)
        }
        _ => Err(DpapiError::UnsupportedCryptAlg(blob.crypt_alg)),
    }
}
```

**Test vectors:** Use the well-known test vectors from Benjamin Delpy's
Mimikatz test suite and the DPAPI test blobs published in the impacket
test suite (`impacket/tests/dpapi_test.py`). Specific test approach:
- Hardcode a known master key (64 bytes) and a known DPAPI blob (hex)
- Verify decryption produces the expected plaintext
- Test both 3DES/SHA1 (Windows 7) and AES-256/SHA512 (Windows 10+) paths
- Test HMAC signature verification (reject tampered blobs)

### 1.5 DPAPI Blob Sources for Auto-Decryption

| Artifact | Location | Master Key Source | Notes |
|----------|----------|-------------------|-------|
| Chrome/Edge passwords | `Login Data` SQLite `password_value` column | User DPAPI master key via `guidMasterKey` | Blob is standard DPAPI; on Chrome 80+ there's an additional AES-GCM layer with `Local State` encrypted key |
| Chrome/Edge cookies | `Cookies` SQLite `encrypted_value` | Same | `v10`/`v20` prefix = AES-GCM with DPAPI-protected key from `Local State`; older = raw DPAPI blob |
| Credential Manager | `%LOCALAPPDATA%\Microsoft\Credentials\*` | User DPAPI | Already extracted as blobs in `credman.rs` — need decryption |
| RDP saved passwords | `HKCU\Software\Microsoft\Terminal Server Client\Servers\<host>\UsernameHint` + credential blob | User DPAPI | Stored via CredManager |
| WiFi PSKs | `HKLM\SOFTWARE\Microsoft\Wlansvc\Profiles\Interfaces\<GUID>\<profile>` → `keyMaterial` | SYSTEM DPAPI (machine key) | `dpapi_system` LSA secret needed |
| Outlook/Teams | Credential Manager entries or Office-specific cache | User DPAPI | Standard DPAPI blobs |
| Windows Vault | `%LOCALAPPDATA%\Microsoft\Vault\*` | User DPAPI | `.vcrd` files with DPAPI blobs |

**Implementation priority:** CredManager decryption first (blobs already extracted),
then Chrome/Edge passwords (highest forensic value), then WiFi PSKs (requires
SYSTEM DPAPI key from `lsadump.rs`).

---

## 2. Framebuffer / Screenshot Extraction — Technical Spec

### 2.1 Framebuffer in Physical Memory

**Legacy VGA/VESA:**
- VGA text mode: physical 0xB8000 (80x25 chars)
- VGA graphics: physical 0xA0000 (64KB window)
- VESA/VBE linear framebuffer: physical address from VBE mode info block
  (typically 0xE0000000 or similar PCI BAR address)

**UEFI GOP (modern systems):**
- `EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE` structure contains:
  - `FrameBufferBase` — physical address of the linear framebuffer
  - `FrameBufferSize` — total size in bytes
  - `Info->HorizontalResolution`, `Info->VerticalResolution`
  - `Info->PixelFormat` (0=RGBX, 1=BGRX, 2=bitmask, 3=BltOnly)
  - `Info->PixelsPerScanLine` (may differ from HorizontalResolution due to padding)

**Finding the framebuffer in a Windows dump:**

1. **EFI runtime services table** → `EFI_BOOT_SERVICES` → locate GOP protocol
   via `EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID` = `{9042A9DE-23DC-4A38-96FB-7ADED080516A}`
2. **Scan `_PHYSICAL_MEMORY_DESCRIPTOR`** (from `MmPhysicalMemoryBlock` symbol)
   for memory ranges marked as device memory / MMIO
3. **Heuristic scan:** Look for large contiguous regions (>= 1920*1080*4 = ~8MB)
   at physical addresses above 0xC0000000 that contain non-zero pixel data
   with reasonable entropy (not random, not all-zero, not repeating)

**Finding the framebuffer in a Linux dump:**

1. Parse `/proc/iomem` equivalent from kernel memory: `iomem_resource` linked list
   → look for entries named `Video RAM area`, `efifb`, `vesafb`, `simplefb`
2. Read `struct screen_info` (from kernel's `boot_params.screen_info`) which
   contains `lfb_base`, `lfb_size`, `lfb_width`, `lfb_height`, `lfb_depth`,
   `lfb_linelength`

### 2.2 Pixel Format Detection

Common formats (all little-endian in memory):
- **XRGB8888** (32bpp): `[B, G, R, X]` per pixel — most common on modern systems
- **XBGR8888** (32bpp): `[R, G, B, X]` per pixel
- **RGB888** (24bpp): `[B, G, R]` per pixel (rare in framebuffers, common in BMP)
- **RGB565** (16bpp): `[GGGBBBBB, RRRRRGGG]` — mobile/embedded

**Width/height detection heuristics (when metadata unavailable):**

1. Detect scanline length by autocorrelation: for a candidate width W, check
   if `pixel[x, y] ≈ pixel[x, y+1]` more than random (adjacent scanlines
   in a real image are correlated)
2. Try common resolutions: 1920x1080, 2560x1440, 3840x2160, 1366x768,
   1280x1024, 1024x768
3. For each candidate: compute total size = W * H * bpp, compare against
   framebuffer region size

### 2.3 Implementation Plan

**New module:** `crates/memf-windows/src/framebuffer.rs` (and `crates/memf-linux/src/framebuffer.rs`)

**Rust crates:**
- `png = "0.17"` — pure Rust PNG encoder (no native deps)

**Structs:**

```rust
#[derive(Debug, Clone, serde::Serialize)]
pub struct FramebufferInfo {
    pub physical_address: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,          // bytes per scanline
    pub pixel_format: String, // "XRGB8888", "XBGR8888", etc.
    pub total_size: u64,
    pub source: String,       // "EFI_GOP", "screen_info", "heuristic"
}

pub struct FramebufferScreenshot {
    pub info: FramebufferInfo,
    pub png_data: Vec<u8>,    // PNG-encoded screenshot
}
```

**Algorithm:**
1. Locate framebuffer metadata (GOP struct, screen_info, or heuristic)
2. Read raw pixel data from physical memory at the framebuffer address
3. Convert pixel format to RGB888 for PNG encoding
4. Encode as PNG using the `png` crate
5. Return `FramebufferScreenshot` with metadata + PNG bytes

**Test approach:**
- Construct synthetic framebuffer data (e.g., 64x64 gradient pattern) in
  `SyntheticPhysMem` at a known physical address
- Write a fake `screen_info` struct pointing to it
- Verify the walker extracts correct dimensions and pixel data
- Verify PNG output is valid (parse it back with `png` crate)

---

## 3. Prioritised Feature Roadmap — Top 20

### Rank 1: DPAPI Blob Decryption Engine
- **Description:** Given extracted master keys from `dpapi_keys.rs`, decrypt DPAPI blobs (3DES/AES-256) to recover plaintext credentials
- **Difficulty:** Medium
- **Differentiation:** No memory forensics tool does this in a single pass — Volatility requires external tools (Mimikatz/pypykatz) for decryption. This would be the first tool to extract + decrypt DPAPI blobs end-to-end from a memory image alone
- **Implementation:** `dpapi_decrypt.rs` with RustCrypto crates (`hmac`, `sha1`, `sha2`, `aes`, `cbc`, `des`). Parse `DPAPI_BLOB` header, derive session key, decrypt. See Section 1 above
- **TDD:** Straightforward — hardcoded test vectors from impacket/Mimikatz test suites

### Rank 2: Chrome/Edge Password Decryption (DPAPI + AES-GCM)
- **Description:** Decrypt Chromium `Login Data` password blobs using extracted DPAPI master keys, handling both legacy DPAPI and v80+ AES-GCM-with-DPAPI-key format
- **Difficulty:** Medium
- **Differentiation:** Currently `browser_credentials.rs` extracts plaintext creds from heap. This adds SQLite-blob-level decryption for encrypted passwords. No other memory forensics tool does this automatically
- **Implementation:** Parse `Login Data` `password_value` column format. For `v10`/`v20` prefix: DPAPI-decrypt the key from `Local State`, then AES-256-GCM decrypt the password. Crate: `aes-gcm = "0.10"`
- **TDD:** Straightforward with synthetic blobs

### Rank 3: TLS Session Key Extraction
- **Description:** Extract TLS pre-master secrets and session keys from SChannel (Windows) and OpenSSL (Linux) heap memory, enabling Wireshark-compatible `SSLKEYLOGFILE` output
- **Difficulty:** Hard
- **Differentiation:** No existing memory forensics tool produces `SSLKEYLOGFILE` from a dump. MemProcFS extracts some TLS structures but not session keys. This enables full traffic decryption when combined with a PCAP
- **Implementation:** Scan LSASS/schannel.dll VADs for `NCRYPT_SSL_KEY` structures (Windows). Scan OpenSSL `SSL_SESSION` structs in process heaps (Linux). Key fields: `master_key[48]`, `client_random[32]`. Output NSS key log format: `CLIENT_RANDOM <hex> <hex>`
- **TDD:** Hard — requires real dump fixtures or carefully crafted synthetic SSL_SESSION structs

### Rank 4: Framebuffer Screenshot Extraction
- **Description:** Extract the visible screen contents from physical memory by locating the linear framebuffer (UEFI GOP or VBE) and encoding as PNG
- **Difficulty:** Hard
- **Differentiation:** Unique capability — no memory forensics tool does this. Potentially game-changing for incident response (see attacker's screen at time of acquisition)
- **Implementation:** See Section 2 above. `png` crate for output. GOP struct scanning + heuristic fallback
- **TDD:** Straightforward with synthetic framebuffer in SyntheticPhysMem

### Rank 5: STIX 2.1 / MITRE ATT&CK Output
- **Description:** Auto-generate STIX 2.1 bundles from ForensicEvents with proper ATT&CK technique references, observable types, and relationship objects
- **Difficulty:** Easy-Medium
- **Differentiation:** Volatility/Rekall produce CSV/JSON. No tool produces threat-intel-ready STIX bundles. Enables direct import into MISP, OpenCTI, TheHive
- **Implementation:** New `crates/memf-correlate/src/stix.rs`. Map `ForensicEvent` → STIX `observed-data`, `indicator`, `attack-pattern`. Use `serde_json` for output (STIX is JSON). Map `MitreAttackId` → STIX `attack-pattern` with proper STIX IDs
- **TDD:** Straightforward — validate JSON schema compliance

### Rank 6: Azure AD PRT (Primary Refresh Token) Extraction
- **Description:** Extract Azure AD Primary Refresh Tokens from `lsass.exe` / `AADPlugin.dll` / `BrowserCore.exe` memory, enabling cloud identity theft detection
- **Difficulty:** Hard
- **Differentiation:** Only Mimikatz and ROADtools do PRT extraction, neither from memory dumps. This detects PRT theft (MITRE T1528) in post-mortem analysis. Critical for hybrid AD environments
- **Implementation:** Scan AAD-related processes for PRT structures. PRT is a JWT-like token with `x-ms-cc` claim. Look for `{"token_type":"Bearer","scope":"openid"` pattern in VAD regions. Also check `CloudAP` SSP in LSASS
- **TDD:** Hard — requires real dump fixtures

### Rank 7: Memory Compression (MemCompression) Page Recovery
- **Description:** Decompress pages stored in the Windows 10+ `MemCompression` process (store manager) to recover data from compressed memory regions
- **Difficulty:** Very Hard
- **Differentiation:** No tool does this. Windows 10+ compresses inactive pages into the MemCompression process instead of writing to pagefile. Without decompression, significant portions of memory are invisible to forensic tools. This is the single biggest blind spot in modern Windows memory forensics
- **Implementation:** Parse `SMKM_STORE` structures in MemCompression process memory. Each store contains `ST_DATA_MGR` → pages compressed with XPRESS (Huffman variant) or LZ77. Use `rust-lzxpress` (already in workspace deps) for XPRESS decompression. Map compressed page keys back to virtual addresses via `SmGlobals` → `SmStoreManager`
- **TDD:** Very Hard — need real compressed pages. Can unit-test XPRESS decompression with known test vectors

### Rank 8: Parallel Walker Execution (rayon)
- **Description:** Execute independent walkers concurrently using rayon thread pool for 4-8x speedup on large dumps
- **Difficulty:** Medium
- **Differentiation:** Volatility 3 is single-threaded. MemProcFS has some parallelism but at the I/O layer. This would make memory-forensic the fastest tool for full triage
- **Implementation:** Walkers that only read (no shared mutable state) are safe to parallelize: process list, network, handles, VADs, registry, credentials, etc. `ObjectReader` needs `Send + Sync` (currently is, since `PhysicalMemoryProvider` uses `memmap2` which is `Send + Sync`). Use `rayon::scope` to fan out independent walkers. Merge results after all complete
- **TDD:** Straightforward — run same walkers serial vs parallel, compare results

### Rank 9: BitLocker FVEK Pool Scan (complete implementation)
- **Description:** Complete the stubbed `bitlocker_keys.rs` to actually scan non-paged pool for `FVE2`-tagged allocations containing FVEK/VMK key material
- **Difficulty:** Medium
- **Differentiation:** Only Passware and Elcomsoft do this, both proprietary. Open-source BitLocker key recovery from memory is a major differentiator
- **Implementation:** Scan pool pages for `FVE2` tag (4 bytes). Parse `FVE_BLOCK_DEVICE_CONTEXT` → `FVE_KEYS` → extract 16/32-byte FVEK and tweak key. Algorithm detection from `FVE_ENCRYPTION_ALGORITHM` field. Already have `classify_bitlocker_key()` validator
- **TDD:** Medium — can construct synthetic pool allocation with FVE2 tag

### Rank 10: VeraCrypt/TrueCrypt Key Schedule Detection
- **Description:** Detect AES/Twofish/Serpent key schedules in memory to recover full-disk-encryption master keys from VeraCrypt/TrueCrypt volumes
- **Difficulty:** Hard
- **Differentiation:** AES key schedule detection (finding round keys in memory) is implemented in Elcomsoft Forensic Disk Decryptor but no open-source tool. Detecting expanded AES key schedules is well-documented (Halderman et al., "Lest We Remember: Cold Boot Attacks on Encryption Keys", USENIX Security 2008)
- **Implementation:** Scan physical memory for AES-256 key schedule pattern: 15 consecutive 16-byte round keys where each is derived from the previous via the AES key schedule algorithm. Verify candidate by checking the mathematical relationship between round keys. Crate: `aes` for key schedule verification
- **TDD:** Straightforward — generate a known AES key schedule, embed in synthetic memory

### Rank 11: Sigma Rule Matching
- **Description:** Apply Sigma detection rules against extracted forensic events (process creation, network connections, registry, etc.)
- **Difficulty:** Medium
- **Differentiation:** No memory forensics tool applies Sigma rules. This bridges memory forensics and SIEM detection, enabling analysts to use their existing Sigma ruleset against memory images
- **Implementation:** New `crates/memf-correlate/src/sigma.rs`. Parse Sigma YAML rules (field conditions, logic). Match against `ForensicEvent` fields. Use `serde_yaml` for parsing. Focus on `process_creation`, `network_connection`, `registry_event` categories
- **TDD:** Straightforward — write Sigma rules, generate matching events, verify detection

### Rank 12: LUKS/dm-crypt Key Extraction (Linux)
- **Description:** Extract dm-crypt master keys from kernel memory (`crypt_config` → `key` field) for LUKS-encrypted volumes
- **Difficulty:** Medium
- **Differentiation:** Only Passware does this (proprietary). No open-source Linux memory forensics tool extracts dm-crypt keys
- **Implementation:** Walk `dm_table` → `dm_target` (type "crypt") → `crypt_config.key`. The key is stored in plaintext in kernel memory when the volume is unlocked. Key length from `crypt_config.key_size`. Algorithm from `crypt_config.cipher_string`
- **TDD:** Medium — need kernel struct offsets from BTF/DWARF

### Rank 13: Hypervisor Detection (VT-x VMCS Structures)
- **Description:** Detect active hypervisors by scanning for Intel VT-x VMCS (Virtual Machine Control Structure) regions in physical memory
- **Difficulty:** Very Hard
- **Differentiation:** No memory forensics tool detects hypervisor presence from memory alone. Critical for detecting hypervisor-based rootkits (Blue Pill, SubVirt) and confirming VM-aware analysis
- **Implementation:** VMCS regions are 4KB-aligned and start with a VMCS revision identifier (first 4 bytes match IA32_VMX_BASIC MSR bits 0-30). Scan physical memory for 4KB-aligned pages where first 4 bytes match known CPU revision IDs. Parse VMCS fields (guest CR3, guest RIP, VM-exit reason) to characterize the hypervisor
- **TDD:** Straightforward — embed synthetic VMCS page in SyntheticPhysMem

### Rank 14: WFP Callout / MiniFilter Hook Detection
- **Description:** Enumerate Windows Filtering Platform callout registrations and filesystem MiniFilter callbacks to detect network/filesystem hooking by rootkits
- **Difficulty:** Hard
- **Differentiation:** Volatility has no WFP or MiniFilter plugins. MemProcFS has basic minifilter support. Full WFP callout enumeration is novel
- **Implementation:** WFP: walk `netio.sys!gWfpGlobal` → callout table → `FWPS_CALLOUT` entries. MiniFilter: walk `FltGlobals` → `FrameList` → `Filter` → `Operations` → callback addresses. Resolve each callback to a module. Flag callbacks outside known security products
- **TDD:** Medium — need realistic kernel structure layouts

### Rank 15: Elastic Common Schema (ECS) Output
- **Description:** Output forensic findings in Elastic Common Schema format for direct ingestion into Elasticsearch/Kibana
- **Difficulty:** Easy
- **Differentiation:** Immediate integration with the most popular SIEM stack. No memory forensics tool produces ECS-formatted output
- **Implementation:** Map `ForensicEvent` fields to ECS field names: `event.category`, `event.kind`, `process.pid`, `process.name`, `source.ip`, `destination.ip`, `threat.technique.id`, etc. Output as NDJSON (one ECS event per line). Already have NDJSON support in the output pipeline
- **TDD:** Straightforward — validate field names against ECS schema

### Rank 16: MFT Record Recovery from Memory
- **Description:** Extract resident NTFS $MFT records from Windows kernel memory (cached by NTFS.sys) to reconstruct file metadata including timestamps, file sizes, and $DATA for small files
- **Difficulty:** Hard
- **Differentiation:** Volatility's `mftparser` works on disk images. Extracting MFT records from memory reveals files that may have been deleted from disk but remain cached in kernel memory. Unique forensic value for anti-forensics detection
- **Implementation:** Scan NTFS.sys pool allocations for MFT record signatures (`FILE0` magic at offset 0). Parse `FILE_RECORD_HEADER` → attribute list → `$STANDARD_INFORMATION` (timestamps), `$FILE_NAME`, `$DATA` (if resident). Pool tag: `NtfF` or `NtfM`
- **TDD:** Straightforward — embed synthetic MFT record with FILE0 magic in pool

### Rank 17: Container Escape Indicators (Linux)
- **Description:** Detect container escape conditions: namespace mismatches, capabilities outside expected namespaces, mount namespace breakouts, privileged container indicators
- **Difficulty:** Medium
- **Differentiation:** Existing `container_escape.rs` likely covers basics. Extend with: cgroup namespace cross-references, detecting `CAP_SYS_ADMIN` in non-init namespaces, `nsenter`-style PID namespace transitions, `/proc/1/root` breakout indicators
- **Implementation:** Cross-reference `task_struct.nsproxy` across processes. Flag processes with `CAP_SYS_ADMIN` or `CAP_SYS_PTRACE` outside the init PID namespace. Detect mount namespace transitions (MNT_NS != parent MNT_NS with sensitive mounts)
- **TDD:** Medium — need realistic namespace/cgroup structures

### Rank 18: HTTP/SMB Reconstruction from Socket Buffers
- **Description:** Extract HTTP request/response headers and SMB session data from kernel socket buffer (sk_buff) chains in both Windows and Linux
- **Difficulty:** Very Hard
- **Differentiation:** No memory forensics tool reconstructs application-layer protocols from socket buffers. Provides network context without requiring a PCAP
- **Implementation:** Windows: walk `_TCP_ENDPOINT` → pending IRP buffers → `AFD_BUFFER` chains. Linux: walk `struct sock` → `sk_receive_queue`/`sk_write_queue` → `sk_buff` → data. Parse HTTP headers (`HTTP/1.1`, `GET`, `POST`). Parse SMB headers (0xFF534D42 for SMBv1, 0xFE534D42 for SMBv2)
- **TDD:** Very Hard — requires realistic socket buffer chains

### Rank 19: PGP/GPG Private Key Detection
- **Description:** Scan process memory for OpenPGP secret key packets (tag 5) and GPG agent cached passphrases
- **Difficulty:** Medium
- **Differentiation:** No memory forensics tool extracts PGP keys. Significant for investigations involving encrypted communications
- **Implementation:** Scan for OpenPGP packet tag 5 (Secret-Key Packet) header: old format `0x95`/`0x97` or new format `0xC5`. Parse key algorithm (RSA=1, DSA=17, ECDSA=19, EdDSA=22). For gpg-agent: scan for `S2K` (String-to-Key) specifier followed by key material. Crate: raw byte scanning, no PGP crate needed for detection
- **TDD:** Straightforward — embed known PGP secret key packet bytes

### Rank 20: Timesketch-Compatible JSONL Timeline
- **Description:** Output a unified timeline in Timesketch JSONL format combining all temporal artifacts (process creation/exit, network connections, file access, registry changes, logon sessions)
- **Difficulty:** Easy-Medium
- **Differentiation:** Timesketch integration enables visual timeline analysis of memory forensics data alongside disk/log artifacts. No memory forensics tool produces Timesketch-native output
- **Implementation:** New `crates/memf-correlate/src/timesketch.rs`. Each `ForensicEvent` with a timestamp → Timesketch JSONL record: `{"message": "...", "datetime": "2024-...", "timestamp_desc": "...", "data_type": "memory:..."}`. Collect all timestamped events, sort, output
- **TDD:** Straightforward — generate events with timestamps, validate JSONL format

---

## Appendix A: Current Codebase Gap Summary

### What's Already Implemented (97 Windows walkers, 78 Linux walkers)

**Windows (complete or with classifiers):**
processes, threads, DLLs, VADs, malfind, IAT hooks, handles, registry, services,
network (TCP), DNS cache, prefetch, shellbags, scheduled tasks, mutants, pipes,
desktops, clipboard, EVTX chunks, pool tags/scan, MBR scan, PE version info,
RDP sessions, SSDT hooks, driver IRPs, callbacks, ETW/ETW patches, AMSI bypass,
process hollowing, DKOM detection, direct syscalls, APC injection, fiber/FLS,
TLS callbacks, CLR assemblies, WoW64/Heaven's Gate, section objects, heap spray,
token/privileges, SID enumeration, PEB masquerade, suspicious threads, debug
registers, COM hijacking, WMI persistence, skeleton key, shimcache, amcache,
userassist, typed URLs, run keys, atom table, device tree, big pools, message hooks,
symlinks, consoles, sysinfo, timers, DSE bypass, psxview (CID), sam/hashdump/lsadump,
cachedump, WDigest, CredMan, browser credentials, Firefox credentials, cloud credentials,
session tokens, SSH agent keys, browser cookies, DPAPI keys (stub), BitLocker keys (stub),
Kerberos tickets (stub), NTLM SSP, token impersonation, svc_diff, crashinfo,
object directory, file scan, registry keys

**Linux (complete or with classifiers):**
processes, threads, maps, ELF info, network (TCP4/6, ARP, raw sockets, unix sockets),
modules, eBPF programs, eBPF maps, capabilities, seccomp, dentry cache,
tmpfs recovery, bash history, SSH keys, crontab, systemd units, kernel timers,
IPC, kthread, deleted executables, LD_PRELOAD, container escape, io_uring,
netfilter, netlink audit, capabilities, cgroups, namespaces, psxview/psaux,
process hidden detection, modxview, ptrace, signal handlers, fuse abuse,
futex forensics, vdso tamper, timerfd/signalfd, tty check, zombie/orphan,
user namespace escalation, shared memory anomaly, dmesg/kmsg, boot time,
iomem, mountinfo, library list, magic GID, memfd_create, CPU pinning,
OOM events, PAM hooks, perf event, ftrace, keyboard notifiers, check_afinfo,
check_creds, check_fops, check_hooks, check_idt, check_modules, malfind,
proc cmdline, env vars, files, fs, KASLR, syscalls, heuristics

### What's Stubbed (walker function exists but returns empty)
- `dpapi_keys.rs` — DPAPI master key extraction (needs `g_MasterKeyCache` parsing)
- `bitlocker_keys.rs` — BitLocker FVEK pool scan (needs `FVE2` tag scanning)
- `kerberos_tickets.rs` — Kerberos ticket extraction (needs `KerbLogonSessionTable` walking)

### What's Missing Entirely
- DPAPI blob decryption (master key → plaintext)
- Chrome/Edge encrypted password/cookie decryption
- TLS session key extraction
- Framebuffer/screenshot recovery
- STIX/Sigma/ECS output formats
- Azure AD PRT extraction
- MemCompression page decompression
- Parallel walker execution
- Full disk encryption key detection (VeraCrypt, LUKS)
- Hypervisor/VMCS detection
- WFP/MiniFilter hook enumeration
- MFT record recovery from memory
- HTTP/SMB socket buffer reconstruction
- PGP key detection
- Timesketch timeline output
- macOS/XNU support
- VMware .vmss/.vmem format (beyond current format crates)

### Architecture Strengths to Leverage
- `ForensicEvent` + `IntoForensicEvents` trait enables automatic correlation
- `MitreAttackId` validation enables STIX/ATT&CK output
- `ObjectReader<P>` abstraction makes all walkers format-agnostic
- `SyntheticPhysMem` + `PageTableBuilder` enable comprehensive unit testing
- `IsfBuilder` enables symbol table mocking for walker tests
- RustCrypto ecosystem provides all needed crypto primitives without native deps
- Workspace already uses `serde`/`serde_json` throughout — ECS/STIX/Timesketch
  output is straightforward serialization

---

## Appendix B: References

- Delpy, B. "Mimikatz" — `modules/dpapi/kuhl_m_dpapi.c` (CC BY 4.0)
- SkelSec. "pypykatz" — `pypykatz/dpapi/dpapi.py`, `pypykatz/lsa/packages/dpapi/` (MIT)
- Halderman, J.A. et al. "Lest We Remember: Cold Boot Attacks on Encryption Keys" USENIX Security 2008
- Microsoft. "Data Protection API" — MSDN documentation
- Microsoft. "UEFI Graphics Output Protocol" — UEFI Specification 2.10, Section 12.9
- STIX 2.1 Specification — OASIS Open, https://docs.oasis-open.org/cti/stix/v2.1/
- Elastic Common Schema — https://www.elastic.co/guide/en/ecs/current/
- Sigma Rule Specification — https://sigmahq.io/docs/
- Timesketch JSONL format — https://timesketch.org/guides/user/import-from-json-csv/
- "curing" io_uring rootkit (2025) — https://www.crowdstrike.com/blog/curing-ebpf-io-uring-rootkit/
- Windows Internals 7th Edition — Russinovich, Solomon, Ionescu (pool tags, DPAPI internals)
