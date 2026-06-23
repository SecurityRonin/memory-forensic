# LSA secret + DCC2 cached-credential decryption

> **For Claude:** strict TDD; NEVER hand-roll crypto — use RustCrypto crates
> (already in the tree). Validate byte-for-byte vs Volatility on a real dump
> (Doer-Checker). REFUSE (fail-loud), never fabricate, on unsupported
> revisions / missing keys.

**Goal:** real decryption for `lsadump` (LSA secrets) and `cachedump` (DCC2
cached domain creds), replacing the deferral. Reuses the validated `hashdump.rs`
boot-key + AES/RC4 machinery. **Scope:** Vista+/Win8+/Win10 x64 (the corpus);
fail-loud `NotImplemented` for pre-Vista (the RC4/DES legacy path) rather than a
wrong/garbage result.

**Reference (authoritative):** Volatility3
`framework/plugins/windows/registry/{lsadump,cachedump}.py`.

**Golden oracle (tier-1, byte-for-byte):** `vol.py … lsadump` on
`citadeldc01.mem` decrypts 5 secrets — `DefaultPassword` → UTF-16LE "ROOT#123",
plus `NL$KM`/`DPAPI_SYSTEM`/`$MACHINE.ACC`/… (captured in `/tmp/cred_oracle.txt`).
`cachedump` is empty there (a DC doesn't cache) — validate DCC2 on a workstation
dump (DESKTOP-SDN1RPT.mem, check for `Cache\NL$N`).

## Algorithm (Vista+ x64)

**Boot key** — reuse `hashdump::extract_boot_key(syshive)` (SYSTEM hive: Lsa
JD/Skew1/GBG/Data class names, descrambled). Both walkers must therefore take
**SYSTEM + SECURITY** hive VAs (like hashdump).

**`decrypt_aes(secret, key)`** (the LSA Vista+ scheme):
- `aeskey = SHA256(key ‖ secret[28:60] repeated 1000×)` (32-byte AES-256 key).
- output = for each 16-byte block of `secret[60:]`: `AES256-ECB-decrypt(aeskey)`
  (Volatility uses CBC with a zero IV reset per block ⇒ ECB; zero-pad the tail).
- NEW. Needs **`sha2`** crate (add to workspace + memf-windows; only `sha1` is
  currently declared). AES-256 single-block via the `aes` crate's `Aes256`.

**`get_lsa_key(sechive, bootkey)`** = `decrypt_aes(PolEKList_CurrVal, bootkey)[68:100]`
where `PolEKList_CurrVal` = `Policy\PolEKList` default value data (32-byte LSA key).

**LSA secret** (lsadump): for each `Policy\Secrets\<name>`, `enc = <name>\CurrVal`
default value; `secret = decrypt_aes(enc, lsakey)`. The decrypted blob's first
16 bytes are a length header (`len@0`, then 16-byte aligned value); Volatility
renders the whole blob hex — match that for `data`.

**NL$KM** (cachedump) = the `NL$KM` LSA secret, decrypted as above.

**DCC2 record** (cachedump): for each `Cache\NL$N` value (skip `NL$Control`):
- `parse_cache_entry(data)`: `uname_len@0` (u16), `domain_len@2`, `domain_name_len@60`,
  `ch = data[64:80]` (16-byte IV), `enc_data = data[96:]`. Skip if `uname_len==0`.
- `dec = decrypt_hash(enc_data, nlkm, ch)` = **AES-128-CBC**(key=`nlkm[16:32]`,
  IV=`ch`) over `enc_data` (proper CBC, zero-pad tail) — reuse hashdump's
  `aes128_cbc_decrypt`-style path (cbc::Decryptor<Aes128>).
- `parse_decrypted_cache`: `hash = dec[:0x10]` (MS-Cache-v2 / DCC2 hash);
  `uname_offset=72`; `username = dec[72:72+uname_len]` UTF-16LE; `domain` after
  2-byte-aligned padding; `domain_name` after that. Output `$DCC2$10240#user#hex(hash)`.

## TDD increments

1. **sha2 dep + `decrypt_aes` + `get_lsa_key`** (memf-windows). No pure golden
   vector available (Volatility prints no intermediate key) → validated
   end-to-end in step 2.
2. **`lsadump` decryption** — `walk_lsa_secrets(reader, system_hive, security_hive)`;
   reuse `extract_boot_key` (make pub(crate)); set `data = decrypted secret`.
   Refuse (no decryption, empty data + a flag) on pre-Vista / missing keys.
   **Validate vs the citadeldc01 golden** (issen, under the local patch): the 5
   secrets' hex must match `/tmp/cred_oracle.txt` exactly (incl. "ROOT#123").
3. **`cachedump` DCC2** — `walk_cached_credentials(reader, system_hive, security_hive)`;
   `get_nlkm` + `decrypt_hash` + parse; emit `{username, domain, dcc2_hash}`.
   Replace the fabricated struct fields with the real decrypted values.
   **Validate vs Volatility cachedump on a workstation dump** with cached creds.
4. Update issen dispatch callers (both now need SYSTEM+SECURITY).

## Disciplines (binding)

- RustCrypto only (`aes`, `cbc`, `sha2`, `hmac`, `md-5`, `des` for legacy) — no
  hand-rolled rounds. hashdump already sets the precedent + the refuse pattern.
- Validate against Volatility on the real dump, not synthetic round-trips.
- Pre-Vista path: refuse loudly (named error / empty + flag), never fabricate.
