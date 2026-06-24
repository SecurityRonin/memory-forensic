# Fleet DRY audit — memory-forensic parsers vs disk-based fleet crates

Audit of every memory-forensic parser/walker against the fleet's disk crates, to
find shared-vs-duplicated logic. Method: four parallel read-only agents, each
reading **both** sides. Confidence is tiered per finding (confirmed = both
implementations read; inferred = derived from structure).

## Executive summary

memf is a **good fleet citizen** on most layers — it reuses `shellitem`, `goblin`,
`forensicnomicon`, the fleet `lzo` crate, `winevt-core` constants, and RustCrypto.
The audit found **one bug, one large duplication, and a handful of clean
delegations**; it also confirmed several apparent duplications are *legitimately
separate* (memory-VA reads vs flat-file reads; live-kernel-struct walks with no
disk analog).

Ranked by value:

1. **[BUG, fix now] Hand-rolled RC4 in `hashdump.rs`** — replace with the `rc4` crate.
2. **[large] Registry cell-parser duplication** — memf reimplements ~2,400 LoC of
   nk/vk/lf/lh/ri parsing + value decode that `winreg-core`/`winreg-format` own.
   Unify behind a `CellReader` backend trait; memf supplies the HMAP impl.
3. **[clean] `prefetch.rs` → `prefetch-core`** — delegate SCCA parsing (fleet crate
   also does v31 + MAM decompression memf lacks).
4. **[low-risk] PE header offset decoders** duplicated 3× in memf (`pe.rs`,
   `iat_hooks.rs`, `hollowing.rs`) — lift the pure offset math into `forensicnomicon`.
5. **[quick] Pure registry helpers** (rot13, value decoders, the userassist 72-byte
   / amcache classify) — share immediately, no trait refactor; de-risks #2.
6. **[small] `evtx.rs`** — already shares `winevt-core` constants; finish by calling
   its `EvtxChunkHeader::parse`/`EvtxRecordHeader::parse` instead of hand reads.
7. **[deferred] Adopt the fleet `xpress-huffman` crate** when memf reads Win10+
   Huffman-compressed hiberfil/hive streams (not needed today).

## Finding 1 — [BUG] hand-rolled RC4 (Tier-1 crypto-rule violation)

`memf-windows/src/hashdump.rs::rc4_crypt` (KSA+PRGA, ~lines 609-635) hand-rolls RC4
for the SAM rev-2 hbootkey path; no `rc4` crate is in the workspace. The
crypto-inversion rule lists `rc4` among the RustCrypto crates that MUST be used
instead of hand-rolling. Severity is moderate (decode-only, reading evidence, not
protecting a secret — the side-channel argument is weak), but it's a rule
violation and a 1-function swap. **Fix:** `rc4.workspace = true` + replace
`rc4_crypt` with `rc4::Rc4`. Strict TDD; the existing hashdump golden vectors guard
it. *(Confidence: confirmed — read the fn body; `grep rc4` in workspace Cargo.toml
returns nothing.)* Everything else (AES/DES/MD5/SHA1/SHA2/HMAC/PBKDF2) correctly
uses RustCrypto.

## Finding 2 — [LARGE] registry cell-parser unification (the big one)

memf reimplements the **entire** Windows registry parser — `registry.rs`
(`find_subkey_by_name`/`list_subkeys`/`list_values`/`read_value_data`/
`resolve_root_cell`/`root_cell_index`, lf/lh/li/**ri** recursion, stable-vs-volatile
lists) and `registry_keys.rs` (REG_SZ/DWORD/QWORD/BINARY/MULTI_SZ decode + type
names) — that already exists, tested and panic-hardened, in `winreg-format`
(`cells.rs`: `RawKeyNode`/`RawKeyValue`/`SubkeyIndex`) + `winreg-core`
(`key.rs`/`value.rs`/`cell_reader.rs`). Every memf registry-artifact walker
(`shellbags`, `amcache`, `userassist`, `typed_urls`, `hashdump`, `lsadump`,
`cachedump`) navigates via memf's private functions. *(Confidence: confirmed —
both sides read.)*

**The only legitimate difference is cell *resolution*:** winreg-core resolves a
cell as a flat file offset (`4096 + cell_offset` into a `Vec<u8>`); memf resolves a
cell index through the in-memory `_HHIVE.Storage[].Map` HMAP directory
(`cell_index_to_va`). Everything above that is identical.

**The seam:** `winreg-core` already declares `Hive<R: ReadSeek>` (generic, "to
support mmap, in-memory buffers, and overlays") but its actual cell reads
(`cell_reader.rs::read_cell*`, `Key`/`Value` in `key.rs`/`value.rs`) are hard-bound
to `Hive<Cursor<Vec<u8>>>`. Introduce a one-method **`CellReader` trait**
("give me the bytes of the cell at this index/offset"), make `read_cell` + `Key` +
`Value` + `collect_subkey_offsets` generic over it. winreg-core ships the flat-file
impl; **memf adds an HMAP impl** wrapping `ObjectReader<P>` + `cell_index_to_va`.
memf then deletes its cell-structure parsing (~2,400 LoC; keeps only `walk_hive_list`
+ `cell_index_to_va`, ~400 LoC) and its artifact walkers navigate via winreg-core.

**Stays memf-only:** the live `_CMHIVE` `walk_hive_list`, `cell_index_to_va`, and the
SAM/LSA/DCC2 **decryption** pipelines (no disk analog).

**Sequence (TDD, each RED/GREEN):** (1) add the trait + flat-file impl in winreg-core,
keep concrete methods as thin wrappers (no behaviour change); (2) make `Key`/`Value`
generic; (3) add memf's HMAP impl; (4) migrate memf artifact walkers one at a time,
deleting each private duplicate as it lands. **Risk: moderate** — touches winreg-core
signatures + winreg-artifacts call sites, but `winreg-format/cells.rs` is unchanged
and both sides have dense test suites (memf's `CellHive` builder; winreg-core's
`hive_builder`). **Caveat to validate, not assume:** winreg-core's `read_cell_raw`
rejects unallocated cells and validates the base-block checksum on open — the HMAP
backend must NOT inherit those on-disk-file assumptions (live kernel hives differ);
verify against citadeldc01.mem during step 3.

**Lower-effort partial win available now (no trait):** the pure functions are already
shareable — `rot13_decode` (userassist), winreg-core's public `decode_utf16le`/
`decode_multi_sz`/REG-type decoders, and the userassist 72-byte / amcache `classify_*`
decoders. Lift into a shared no-I/O crate (or reuse winreg-core's public decoders)
to kill verbatim duplication and de-risk step 4.

## Finding 3 — [CLEAN] prefetch.rs → prefetch-core

`prefetch.rs` re-declares the SCCA v30 layout as private consts
(`PREFETCH_MAGIC`, `EXE_NAME_OFFSET=0x10`, `HASH_OFFSET=0x4C`, `RUN_COUNT_OFFSET=0xD0`)
and parses the header by hand. `prefetch-core` exposes
`parse_decompressed(&[u8]) -> PrefetchInfo` + `SCCA_SIGNATURE`/`SCCA_SIGNATURE_OFFSET`
and additionally handles v31 (Win11) + MAM/Xpress-Huffman decompression memf lacks.
**Delegate:** keep memf's heap-scan for the SCCA magic on page boundaries
(memory-specific), then `prefetch_core::parse_decompressed(&bytes)`. One workspace
dep. *(Confidence: high.)*

## Finding 3b — [CLEAN, audit correction] extract DPAPI blob/decrypt to `dpapi-core`

**Correction to the first-pass audit, which wrongly called DPAPI "memory-only / not a
standalone disk artifact."** DPAPI is one of the *largest* Windows **disk** artifact
classes — Chrome/Edge saved passwords (`Login Data`) and the cookie key in
`Local State`, Credential Manager (`%APPDATA%\Microsoft\Credentials\`), Vault, Wi-Fi
keys, scheduled-task/RDP creds, and the master-key files themselves
(`%APPDATA%\Microsoft\Protect\<SID>\<GUID>`). The `DPAPI_BLOB` wire format and the
decrypt-given-key crypto are identical on disk and in memory.

memf's `dpapi/` module is already cleanly split, and 3 of its 4 pieces are
**byte-oriented** (no I/O, no VA reads) — so this is a *move*, not a refactor:
- `dpapi/dpapi_blob.rs` `parse_dpapi_blob(&[u8])`, `dpapi/decrypt.rs` (decrypt given a
  key), `dpapi/chrome.rs` (`detect_chrome_cookie_encoding(&[u8])`,
  `decrypt_v10_cookie(key, ciphertext)`) → extract verbatim into a shared no-I/O
  `dpapi-core`, consumed by memf **and** future disk tools (Chrome/Edge, Credential
  Manager, master-key files).
- `dpapi_keys.rs` (master-key extraction from LSASS `g_MasterKeyCache`) stays
  memory-specific — it's the *source* of keys. A disk tool supplies keys differently
  (parse master-key files + derive from the user password SHA1→PBKDF2, or the domain
  backup key) — code memf doesn't have and shouldn't grow.

So memf is the **donor** (its blob/decrypt/chrome code seeds `dpapi-core`); only the
key *source* differs by medium. *(Confidence: confirmed — `parse_dpapi_blob(data: &[u8])`,
`decrypt_v10_cookie(key, ciphertext)`, and the LSASS-only `dpapi_keys.rs` all read.)*

### Split into `~/src/dpapi-forensic` (template: `ntfs-forensic`)

New two-crate workspace at `~/src/dpapi-forensic` (SecurityRonin/dpapi-forensic),
mirroring `ntfs-forensic`: `members = ["core", "forensic"]` (dirs at the repo root),
`[workspace.lints.rust] unsafe_code = "forbid"` + the fleet clippy set
(pedantic/correctness/suspicious/unwrap_used/expect_used …), edition 2021, Apache-2.0,
SecurityRonin README/LICENSE/CHANGELOG/SECURITY/CONTRIBUTING + `.github` CI & tag-driven
release. Structure knowledge (DPAPI provider GUIDs, alg-ids) → **`forensicnomicon`**;
crypto → audited RustCrypto crates; never hand-rolled (cf. the RC4 finding).

**`core/` → `dpapi-core`** — pure-Rust, byte-oriented (`&[u8]`-in), `no_std`-friendly
DPAPI library (the role `ntfs-core` plays: "parse the structure over any source"):
- `blob.rs` — `parse_dpapi_blob(&[u8])` (seed verbatim from memf `dpapi/dpapi_blob.rs`).
- `decrypt.rs` — decrypt a blob **given the master key** (seed from memf `dpapi/decrypt.rs`);
  RustCrypto `aes`/`cbc`/`des`/`hmac`/`sha1`/`sha2`.
- `chrome.rs` — Chrome/Edge cookie `v10`/`v20` AES-GCM unwrap (seed from memf `dpapi/chrome.rs`).
- `masterkey.rs` — **NEW (disk side, not in memf)**: parse master-key files
  (`%APPDATA%\Microsoft\Protect\<SID>\<GUID>`), derive the key-protection key from the
  user password (SHA1 → PBKDF2-HMAC) or the domain backup key (`pbkdf2` crate). This is
  the disk counterpart of memf's LSASS `dpapi_keys.rs` — same *consumer* (dpapi-core
  decrypt), different *source* of keys.
- `error.rs` (the existing `DpapiError`).

**`forensic/` → `dpapi-forensic`** — higher-level auditor built on dpapi-core (the role
`ntfs-forensic` plays: "graded `report::Finding`s"): given an acquired filesystem (or
extracted artifacts), enumerate + decrypt DPAPI-protected stores — Chrome/Edge
`Login Data` passwords + the `Local State` cookie key, Credential Manager
(`…\Credentials\`), Vault, Wi-Fi (`Wlansvc`) — and emit graded findings (recovered
credentials/domains) using the `forensicnomicon` report model. Ship a `dpapi4n6` CLI
per the fleet `*4n6` pattern.

**memf-windows migration (the dedup):** add `dpapi-core = { workspace=true }`; delete the
local `dpapi/{dpapi_blob,decrypt,chrome}.rs` (their unit tests move to dpapi-core); keep
`dpapi_keys.rs` (LSASS `g_MasterKeyCache` extraction — memory-specific) but have it call
`dpapi_core::{parse_dpapi_blob, decrypt, detect_chrome_cookie_encoding, …}`. Net: memf
keeps the memory-specific key *source*, the shared blob/decrypt/chrome live once in
`dpapi-core`, and the new `dpapi-forensic` gives the fleet on-disk DPAPI for the first
time.

## Finding 4 — [LOW-RISK] PE header offset decoders → forensicnomicon

memf hand-rolls the DOS→COFF→optional-header→section/data-directory offset math
**3×** (`pe.rs::module_section_range`, `iat_hooks.rs` import parse, `hollowing.rs`
DOS/sig prologue), reading from a **live VA via `ObjectReader::read_bytes`**. This
duplication is **largely justified**: goblin (used by `issen-parser-pe` and memf's
own `pe_debug::extract_pdb_id`) assumes a **flat file** (`PointerToRawData`), which is
invalid for a memory-mapped image (sections sit at RVAs) — the codebase has *two*
PDB-ID extractors for exactly this reason (`extract_pdb_id` flat/goblin vs
`extract_pdb_id_tolerant` VA-scan). **Do NOT** push memf onto goblin for live walkers
(reintroduces the file-offset bug). **Do** consolidate the repeated *pure* offset math
(0x3C/+6/+0x14/+0x18, the 40-byte section entry, PE32-vs-PE32+ data-directory offset)
into pure decoders that take caller-fetched bytes — natural home is `forensicnomicon`
(already hosts PE constants `MZ_MAGIC`/`PE_SIGNATURE`, already a shared dep of both
memf and issen). A heavier `PeReader<R: ReadAt>` backend-trait crate is **YAGNI**
(only memf needs the VA backend). No EAT/export parsing exists in memf; `pe_version_info`
is a stub. *(Confidence: confirmed for the duplication; forensicnomicon-as-home is
inferred.)*

## Finding 5/6 — small shares
- **evtx.rs**: already imports `ELFCHNK_MAGIC`/`RECORD_MAGIC`/`CHUNK_SIZE` from
  `winevt-core`; finish by calling its `EvtxChunkHeader::parse`/`EvtxRecordHeader::parse`
  on carved bytes so the field offsets live in one place. Low effort.
- **xpress-huffman** (deferred): memf uses 3rd-party `rust-lzxpress` for plain
  LZXPRESS + LZNT1 (a real gap — the fleet has no published plain-LZXPRESS/LZNT1
  crate, so this is fine). The fleet's own `xpress-huffman` crate is **unused** —
  adopt it when memf decodes Win10+ Huffman streams (no `MAM`/Huffman refs today).

## Correctly NOT shared (don't force it)
- **Live-kernel-struct walkers** — `network` (`_TCP_ENDPOINT`/pool scan), `dns_cache`
  (`DNS_HASHTABLE`), `atom_table`, `consoles`, `etw` (`_WMI_LOGGER_CONTEXT`),
  `crashinfo`, `clr_heap`, `dll` (`_PEB_LDR_DATA`), `getsids` (`_TOKEN`/`_SID`): no
  on-disk file format → no fleet counterpart. Comparing them to disk crates is a
  category error.
- **Container provider trait** — memf-format's `PhysicalMemoryProvider::read_phys`
  (address-addressed, sparse, `&self`/Sync) vs the disk containers' cursor-based
  `std::io::Read+Seek` (`EwfReader`/`VmdkReader`/`Qcow2Reader`/`VhdxReader`). Their
  common ground is already `std::io`; a shared "byte provider" trait would be a
  forced abstraction. Leave separate.
- **browser_cookies/sessions** — heap string/regex carving, not format parsing; no
  disk-SQLite dup (a lateral dup with `browser-forensic-memory`'s URL scanner exists,
  low priority).

## Follow-up (unverified)
- `forensic-hashdb` vulnerable-driver/known-good lists vs `forensicnomicon`'s catalog
  — possible content overlap; compare before assuming redundancy.

## Suggested order
RC4 fix (now, it's a bug) → PE-offset decoders + pure registry helpers (low-risk,
de-risk the big one) → prefetch delegation → the winreg-core `CellReader` unification
(its own multi-step effort) → evtx tightening. Each is independently shippable.
