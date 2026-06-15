# memory-forensic

**Walk any memory dump — processes, modules, hooks, and injected memory — in Rust. No Python required.**

`memory-forensic` is an open-source Rust library and CLI toolkit for digital forensics and incident response (DFIR) practitioners. It reads LiME, AVML, Windows crash dumps, hiberfil.sys, VMware snapshots, and raw images — then walks Linux and Windows kernel data structures to enumerate processes, network connections, loaded modules, and injected code regions.

```bash
cargo install memory-forensic
memf ps memdump.lime --symbols linux.json --tree
memf framebuf memdump.lime --symbols linux.json --png screen.png
memf check memdump.dmp --symbols ntkrnlmp.json --dpapi-keys --browser-cookies
```

Highlights: ELF dynamic symbol analysis for LD_PRELOAD rootkit behavioral fingerprinting, DPAPI master key extraction from LSASS `g_MasterKeyCache`, Chrome v10/v20 AES-GCM cookie detection, framebuffer screenshot extraction, and injection-proof output — RFC 4180 CSV with formula-injection guard, bidi/control-character stripping on all table and terminal output.

See the [Validation](validation.md) report for cross-checks against Volatility 3 on genuine memory images.

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · [GitHub](https://github.com/SecurityRonin/memory-forensic) · © 2026 Security Ronin Ltd.
