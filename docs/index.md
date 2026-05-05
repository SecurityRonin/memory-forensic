# memory-forensic

**Walk any memory dump — processes, modules, hooks, and injected memory — in Rust. No Python required.**

`memory-forensic` is an open-source Rust library and CLI toolkit for digital forensics and incident response (DFIR) practitioners. It reads LiME, AVML, Windows crash dumps, hiberfil.sys, VMware snapshots, and raw images — then walks Linux and Windows kernel data structures to enumerate processes, network connections, loaded modules, and injected code regions.

```bash
cargo install memory-forensic
memf ps memdump.lime --symbols linux.json --tree
```

**[GitHub Repository →](https://github.com/SecurityRonin/memory-forensic)** · **[API Docs →](memf_core/index.html)**

---

[Privacy Policy](privacy/) · [Terms of Service](terms/) · [GitHub](https://github.com/SecurityRonin/memory-forensic) · © 2026 Security Ronin Ltd.
