# Memory Forensics: File Reconstruction, Registry, Credentials, BitLocker & Symbols

> Research compiled 2026-03-31 for memory-forensic Rust implementation

---

## 1. File Reconstruction from Memory

### 1.1 MemProcFS Methods

MemProcFS uses three primary methods for file recovery:

1. **Kernel Pool File Objects** — Scans kernel pool for `_FILE_OBJECT` structures and follows process handles. Pool tag scanning locates objects in non-paged pool.
2. **VAD Tree Mapping** — Walks each process's `_EPROCESS.VadRoot` AVL tree to find memory-mapped files. Cross-references `_SUBSECTION -> _CONTROL_AREA -> _FILE_OBJECT` chain.
3. **NTFS MFT Recovery** — Recovers small files with `$DATA` resident in MFT records extracted from memory.

Filesystem paths: `forensic/files/` (reconstructed filesystem), NTFS module for small resident files. Plugin source: `modules/m_fc_file.c`.

### 1.2 Windows File Caching Architecture

- Cache Manager maps file portions in **256-KB views** using section objects
- Files described by **Shared Cache Map** (FileSize, ValidDataLength) and **Private Cache Map**
- Section Objects created by `CreateFileMapping()` link to **Control Area** (non-paged pool) -> **Segment** -> **Subsections**
- **Prototype PTEs (PPTEs)** are software PTEs used by VMM as intermediate translation for shared memory-mapped pages
- System cache pages are always sharable; trimmed pages have invalid PTEs

### 1.3 VAD-Based File Extraction

Walk `_EPROCESS.VadRoot` -> for each Mapped/Image VAD -> follow `_SUBSECTION -> _CONTROL_AREA -> _FILE_OBJECT` -> walk PPTE array -> resolve to physical pages -> read and concatenate.

Key structures: `_MMVAD`, `_CONTROL_AREA`, `_SUBSECTION`, `_MMPTE`, `_FILE_OBJECT` (all from PDB symbols).

### 1.4 PE Module Reconstruction

Memory layout differs from disk: sections page-aligned, IAT resolved, headers possibly erased.

Reconstruction: dump from VA space, fix headers (alignment, sizes), reconstruct IAT. Tools like PE-sieve offer 6 reconstruction modes. Volatility's `impscan` builds import tables for analysis.

### 1.5 Linux Page Cache Recovery

Volatility's `linux.pagecache` plugin: walks `page_tree` (radix tree) of each file's `address_space`, indexes `struct page` into `mem_map` array, shifts PFN by `PAGE_SHIFT` (12) to get physical offset, reads and concatenates pages.

Critical for tmpfs recovery (`/dev/shm`) — exists only in memory.

### 1.6 Recovery Rates

No fixed percentage. R.B. van Baar (2008) found ~25% of memory dump data was memory-mapped files. Completeness depends on system activity, memory pressure, recency of file access, and total RAM.

### References

- [MemProcFS Forensic Files Wiki](https://github.com/ufrisk/MemProcFS/wiki/FS_Forensic_Files)
- [Black Hat 2011 — Physical Memory Forensics for Files and Cache](https://media.blackhat.com/bh-us-11/Butler/BH_US_11_ButlerMurdock_Physical_Memory_Forensics-WP.pdf)
- [CodeMachine — Prototype PTEs](https://codemachine.com/articles/prototype_ptes.html)
- [Volatility Labs — Cache Rules Everything Around Me(mory)](https://volatility-labs.blogspot.com/2012/10/movp-44-cache-rules-everything-around.html)
- [Volatility 3 linux.pagecache docs](https://volatility3.readthedocs.io/en/latest/volatility3.plugins.linux.pagecache.html)
- [ResearchGate — The VAD Tree: A Process-Eye View of Physical Memory](https://www.researchgate.net/publication/228977811_The_VAD_tree_A_process-eye_view_of_physical_memory)

---

## 2. Registry Hive Reconstruction

### 2.1 CMHIVE and HHIVE Structures

- **`_CMHIVE`**: ~0x12F8 bytes, paged pool, pool tag `"CM10"`. Contains `_HHIVE` at offset 0, hive path, handle count, `HiveList` linked list entry.
- **`_HHIVE`**: 0x600 bytes, 49 members. Signature `0xBEE0BEE0`. Manages cell allocation, dirty tracking, cell map for index translation.

### 2.2 Finding Hives

1. **Signature scan**: Search for `0xBEE0BEE0` in physical memory
2. **Pool tag scan**: Search for `"CM10"` pool allocations
3. **Linked list traversal**: Find one hive, follow `HiveList.Flink` to enumerate all

### 2.3 Cell Index Translation

Cell index = 1-bit storage selector + 10-bit table directory index + 9-bit table entry + 12-bit page offset. No bounds checking in `HvpGetCellPaged`.

### 2.4 Bins and Cells

- Bins: 0x1000 bytes (4KB). Cells: variable-length, 4-byte signed size (negative = allocated).
- Cell types: nk (key node), lf/lh/ri/li (subkey lists), vk (value), sk (security)
- Volatile cells exist only in memory — forensically unique data

### 2.5 Dirty Pages and Transaction Logs

- In-memory state may differ from disk — detects rootkit tampering
- Win8.1+ transaction logs use ring-buffer format
- Memory vs disk comparison reveals uncommitted changes

### 2.6 Reusing winreg-forensic

**winreg-format** (pure BinRead structs) is directly reusable. **winreg-core** parser can consume bytes reconstructed from memory via cell map traversal. Gap: need memory-specific code for `_CMHIVE`/`_HHIVE` location, cell map translation, and volatile storage handling.

### References

- [Dolan-Gavitt 2008 — Forensic Analysis of the Windows Registry in Memory](https://www.sciencedirect.com/science/article/pii/S1742287608000297)
- [Moyix Blog — Enumerating Registry Hives](https://moyix.blogspot.com/2008/02/enumerating-registry-hives.html)
- [Google Project Zero — The Windows Registry Adventure #6](https://projectzero.google/2025/04/the-windows-registry-adventure-6-kernel.html)
- [Mandiant — Digging Up the Past: Windows Registry Forensics Revisited](https://cloud.google.com/blog/topics/threat-intelligence/digging-up-the-past-windows-registry-forensics-revisited/)

---

## 3. Credential Extraction

### 3.1 NTLM Hash Extraction (SAM Hive)

**Encryption chain**: Boot Key (SYSTEM hive, 4 registry key Class attributes) -> descramble with permutation table -> derive SAM key -> decrypt hashes.

- **Revision 1** (pre-Win10 1607): RC4 + DES double-block with RID-derived keys
- **Revision 2** (Win10 1607+): AES-128-CBC + DES double-block with RID-derived keys
- Boot key from: `SYSTEM\CurrentControlSet\Control\Lsa\{JD,Skew1,GBG,Data}` Class attributes
- Permutation: `[0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7]`

### 3.2 LSA Secrets

- LSA key derived from boot key via `SECURITY\Policy\PolEKList` (Win2008+) or `PolSecretEncryptionKey` (older)
- Secrets at `SECURITY\Policy\Secrets\{name}\CurrVal`
- Key secrets: `$MACHINE.ACC`, `DPAPI_SYSTEM`, `NL$KM`, `DefaultPassword`, `_SC_{service}`

### 3.3 Cached Domain Credentials (MSCash2)

- Stored at `HKLM\Security\Cache` -> `NL$1..NL$N`
- Format: `[64B metadata][16B challenge][16B T][encrypted_data]`
- Decrypt: `HMAC-MD5(NL$KM, challenge)` -> RC4 key -> decrypt data
- First 16 bytes = MSCash2 hash (`PBKDF2(HMAC-SHA1, MD4(password)+lowercase(username), 10240 iterations)`)

### 3.4 LSASS Process (Mimikatz/Pypykatz)

LSASS caches: NT hashes, Kerberos tickets (TGT/TGS), cleartext passwords (if WDigest enabled), DPAPI master keys, SmartCard PINs.

Key DLLs: `msv1_0.dll` (NT hashes), `kerberos.dll` (tickets), `wdigest.dll` (cleartext), `tspkg.dll` (TS creds), `dpapi.dll` (master keys).

pypykatz: Pure Python mimikatz. Reader abstraction separates parsing from data source. Uses DLL timestamps for version-specific struct selection. Handles 32/64-bit alignment.

### 3.5 Kerberos Ticket Extraction

- `sekurlsa::tickets /export` -> `.kirbi` files (ASN.1 DER encoded)
- Groups: 0=TGS, 1=client, 2=TGT
- Convertible to `.ccache` (Unix) via Impacket's `ticketConverter.py`

### 3.6 DPAPI Master Keys

- Cached decrypted in LSASS, encrypted with AES-256-CFB (IV + key in `lsasrv.dll` memory)
- `sekurlsa::dpapi` extracts from minidump
- Domain backup key (from DC LSASS) compromises all users' DPAPI — never changes

### 3.7 SSH Keys (Linux)

- Pre-2019: plaintext in ssh-agent memory (sshkey-grab, ssh-keyfinder)
- Post-2019: shielded with symmetric key from 16KB `pre_key`. Need both `shielded_private` + `shield_prekey`, then call `sshkey_unshield_private()`
- Generic: 7-byte ASN.1 signature for RSA PKCS#8 key scanning

### 3.8 Browser Credentials

- **Chrome**: SQLite `Login Data` encrypted with DPAPI. Chrome 127+: additional App-Bound Encryption layer
- **Firefox**: NSS library (AES-256-CBC/3DES-CBC), `key4.db` + `logins.json`
- Memory forensics: extract DPAPI master keys from LSASS -> decrypt Chrome passwords

### References

- [Moyix Blog — SysKey and the SAM](https://moyix.blogspot.com/2008/02/syskey-and-sam.html)
- [Moyix Blog — Decrypting LSA Secrets](https://moyix.blogspot.com/2008/02/decrypting-lsa-secrets.html)
- [Moyix Blog — Cached Domain Credentials](https://moyix.blogspot.com/2008/02/cached-domain-credentials.html)
- [Synacktiv — Windows Secrets Extraction Summary](https://www.synacktiv.com/en/publications/windows-secrets-extraction-a-summary)
- [pypykatz GitHub](https://github.com/skelsec/pypykatz)
- [Mimikatz Kerberos Wiki](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos)
- [HN Security — OpenSSH Shielded Private Key Extraction](https://security.humanativaspa.it/openssh-ssh-agent-shielded-private-key-extraction-x86_64-linux/)
- [Reverse Engineering LSASS for DPAPI Keys](https://medium.com/@redfanatic7/reverse-engineering-lsass-to-decrypt-dpapi-keys-012e02e26751)

---

## 4. BitLocker FVEK Extraction

### 4.1 Key Architecture

FVEK (encrypts disk) -> encrypted by VMK -> VMK encrypted by protectors (TPM, recovery key, password). FVE metadata: signature `-FVE-FS-`, three redundant copies on volume.

### 4.2 Pool Tags by Windows Version

| Version | Pool Tag | Driver | Notes |
|---------|----------|--------|-------|
| Win 7 | `FVEc` | `fvevol.sys` | Direct extraction, AES-128 + Elephant Diffuser |
| Win 8/8.1/10 | `Cngb` | `ksecdd.sys` | Pool size 672, key length at offset 0x68 |
| Win 11 | `dFVE` | `dumpfve.sys` | Prefaced by `0x0480`, most consistent |

### 4.3 Validation

AES key schedule validation: 176 bytes for AES-128, 240 bytes for AES-256. Expand candidate key and verify round keys.

### 4.4 Decryption

Use extracted FVEK with Dislocker or bdemount (libyal) to mount encrypted volumes on Linux.

### References

- [MemProcFS BitLocker Wiki](https://github.com/ufrisk/MemProcFS/wiki/FS_BitLocker)
- [Volatility 3 BitLocker Plugin](https://github.com/lorelyai/volatility3-bitlocker)
- [elceef/bitlocker Volatility Plugin](https://github.com/elceef/bitlocker)
- [Memory-Dump-UEFI (Win11 bypass)](https://noinitrd.github.io/Memory-Dump-UEFI/)

---

## 5. Windows PDB Symbol Resolution

### 5.1 Symbol Server Protocol

URL: `https://msdl.microsoft.com/download/symbols/{pdb_name}/{GUID}{Age}/{pdb_name}`

Auto-detection: scan memory for RSDS signatures (`"RSDS"` magic) in PE debug directories -> extract GUID + Age -> download matching PDB.

### 5.2 Rust PDB Crates

| Crate | Maintainer | Read | Write | Best For |
|-------|-----------|------|-------|----------|
| `pdb` | Community | Yes | No | Cross-platform parsing, mature |
| `ms-pdb` | Microsoft | Yes | Yes | Full R/W, newer |
| `pdb-addr2line` | Community | Yes | No | Address symbolication |

### 5.3 Volatility 3 ISF Approach

ISF = JSON-based symbol tables. `pdbconv.py` converts PDB -> ISF. `PdbReader` parses TPI (type stream 2) + symbols stream. Auto-detection via `pdbname_scan` finds RSDS headers, matches cached ISF by GUID/Age, downloads + converts if needed.

### 5.4 Recommended Implementation

Extend existing `memf-symbols` crate: add PDB backend using `pdb` crate, add Symbol Server downloader, convert PDB type info to existing `StructInfo`/`FieldInfo` format, cache as ISF JSON.

Critical structs: `_EPROCESS`, `_CMHIVE`, `_HHIVE`, `_FILE_OBJECT`, `_MMVAD`, `_CONTROL_AREA`, `_SUBSECTION`, `_POOL_HEADER`, `_PEB`, `_LDR_DATA_TABLE_ENTRY`.

### References

- [pdb crate docs](https://docs.rs/pdb/latest/pdb/)
- [ms-pdb GitHub (Microsoft)](https://github.com/microsoft/pdb-rs)
- [Volatility 3 pdbconv docs](https://volatility3.readthedocs.io/en/latest/volatility3.framework.symbols.windows.pdbconv.html)
- [Volatility 3 Symbol Tables docs](https://volatility3.readthedocs.io/en/latest/symbol-tables.html)
- [Volatility 3 ISF unification PR #630](https://github.com/volatilityfoundation/volatility3/pull/630)
