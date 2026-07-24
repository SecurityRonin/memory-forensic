# 9. Pure-Rust, license-clean decoders and audited RustCrypto — batteries included

Date: 2026-07-24
Status: Accepted

## Context

Dump formats and in-memory artifacts carry compressed pages (LZO, Xpress, zstd,
deflate, snappy, LZMA, bzip2) and, on Windows, encrypted secrets (SAM/LSA/cached
credentials use DES, RC4, AES, HMAC, PBKDF2, MD5, SHA). Two fleet rules bind here:
never hand-roll crypto — reach for audited RustCrypto crates
(`~/src/ronin-issen/CLAUDE.md`, the crypto exception to "prefer our own"); and keep
the license/`unsafe` posture clean, since the workspace denies `unsafe` (ADR 0003)
and `deny.toml` allowlists only permissive licenses. LZO has a licensing fork: the
canonical `lzo1x` crate is GPL-2.0, incompatible with the Apache-2.0 repo license.

## Decision

Use pure-Rust, license-clean decoders and audited crypto crates, and compile them
all in (fleet Batteries-Included default — no capability feature-gating):

- Decompression: `lzo` (our own decode-only, Apache-2.0) on the production path
  (`crates/memf-core/src/lzo.rs`); `rust-lzxpress`, `ruzstd`, `snap`,
  `flate2`(miniz_oxide, no C), `lzma-rs`, `bzip2`. The GPL `lzo1x` crate is kept
  **only** as a `memf-core` dev-dependency — a round-trip oracle for the Apache
  decoder — never linked into a shipped artifact (`Cargo.toml` comments).
- ZIP reads via pure-Rust `zip-forensic-core`; the C-FFI `zip` writer is slimmed to
  deflate-only for test fixtures (drops bzip2-sys/zstd-sys/lzma-sys), per ADR 0008.
- Crypto: the RustCrypto stack (`aes`, `aes-gcm`, `cbc`, `des`, `rc4`, `md-5`,
  `sha1`, `sha2`, `hmac`, `pbkdf2`, `cipher`, `digest`) in `memf-windows` for
  hashdump/lsadump/cachedump — no hand-rolled S-boxes or key schedules.

## Consequences

Every `mem4n6` build decodes every supported compression and decrypts every
supported secret with no `--features` incantation, so an examiner never ships a
binary that silently reads less than the evidence contains. The graph stays
Apache-compatible and C-FFI-minimal, keeping `cargo deny` green and the `unsafe`
audit surface at the two mmap sites. Keeping GPL `lzo1x` as a dev-only oracle gives
the Doer-Checker cross-check (Apache decoder validated against an independent
implementation) without contaminating the license of what ships.
