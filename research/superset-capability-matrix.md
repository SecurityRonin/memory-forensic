# memf Superset Capability Matrix

> **Goal**: Catalog every capability from every memory forensics tool. Build memf into the comprehensive superset.
>
> **Date**: 2026-04-01
> **Sources**: Volatility 2/3, MemProcFS, Rekall, DAMM, Orochi, mquire, academic papers (2024-2026), existing memf research corpus

---

## Legend

| Symbol | Meaning |
|--------|---------|
| **Y** | Fully implemented |
| **P** | Partial implementation |
| **N** | Not implemented |
| **--** | Not applicable to this tool |
| **R** | Research prototype only |

**Priority**: P0 = critical differentiator, P1 = must-have parity, P2 = valuable addition, P3 = nice-to-have, P4 = future/research

---

## 1. Dump Format Support

| Format | Volatility 3 | MemProcFS | Rekall | memf Today | Priority | Phase |
|--------|-------------|-----------|--------|------------|----------|-------|
| Raw/dd flat image | Y | Y | Y | **Y** | -- | Done |
| LiME v1 (.lime) | Y | Y | Y | **Y** | -- | Done |
| AVML v2 (Snappy compressed) | Y | Y | N | **Y** | -- | Done |
| ELF core dump (QEMU, libvirt) | Y | Y | Y | **Y** | -- | Done |
| Windows Full Crash Dump (.dmp) | Y | Y | Y | N | P1 | 3 |
| Windows Kernel Crash Dump | Y | Y | Y | N | P1 | 3 |
| Windows Minidump | Y | Y | N | N | P2 | 4 |
| Hiberfil.sys (Win10+) | Y | Y | N | N | P1 | 3 |
| VMware .vmem + .vmss/.vmsn | Y | Y | Y | N | P1 | 3 |
| VirtualBox .elf/.sav | Y | Y | Y | N | P2 | 4 |
| Hyper-V .bin + .vsv | Y | Y | N | N | P2 | 4 |
| QEMU .qcow2 (memory snapshot) | P | Y | N | N | P2 | 4 |
| Proxmox dump | N | Y | N | N | P3 | 5 |
| XEN core dump | Y | N | N | N | P3 | 5 |
| macOS Mach-O core | Y | N | Y | N | P3 | 5 |
| kdump (Linux makedumpfile) | Y | N | N | N | P1 | 3 |
| AVML v1 (uncompressed LiME) | Y | Y | N | **Y** | -- | Done |
| FireEye/Mandiant AFF4 | P | N | Y | N | P3 | 5 |
| LiME padded mode | Y | Y | N | N | P2 | 4 |
| Pagefile.sys integration | N | Y | N | N | P1 | 4 |
| Swapfile.sys integration | N | Y | N | N | P2 | 4 |

**Superset target**: 20+ formats. memf today: 4. Gap: 16 formats.

**Differentiator**: No single tool supports all formats. Volatility supports the most via its layer system, MemProcFS handles the most practical ones. We aim to support everything both handle plus formats neither does (AFF4, XEN).

---

## 2. Architecture / Page Table Support

| Capability | Volatility 3 | MemProcFS | Rekall | memf Today | Priority | Phase |
|-----------|-------------|-----------|--------|------------|----------|-------|
| x86_64 4-level (4KB pages) | Y | Y | Y | **Y** | -- | Done |
| x86_64 4-level (2MB large) | Y | Y | Y | **Y** | -- | Done |
| x86_64 4-level (1GB huge) | Y | Y | N | **Y** | -- | Done |
| x86_64 5-level (LA57) | Y | Y | N | N | P2 | 4 |
| x86 PAE (3-level) | Y | Y | Y | N | P2 | 4 |
| x86 non-PAE (2-level) | Y | Y | Y | N | P3 | 5 |
| AArch64 (4-level, 4KB) | Y | Y | N | N | P1 | 4 |
| AArch64 (4-level, 64KB) | P | Y | N | N | P2 | 5 |
| AArch64 (3-level) | P | Y | N | N | P3 | 5 |
| ARM32 (short descriptor) | P | N | N | N | P3 | 5 |
| RISC-V Sv39/Sv48 | N | N | N | N | P4 | 6 |
| Windows memory compression | N (Mandiant fork) | **Y** | N | N | **P0** | 3 |
| Transition PTE resolution | P | Y | N | N | P1 | 3 |
| Prototype PTE resolution | N | Y | N | N | P1 | 4 |
| PFN database walking | P | Y | N | N | P1 | 4 |

**Differentiator**: Windows memory compression is the single biggest gap in the ecosystem. Volatility cannot read compressed pages (stock). MemProcFS is the only tool that handles this. Building this in Rust with safe code would be a first.

---

## 3. OS Kernel Support

| OS Target | Volatility 3 | MemProcFS | Rekall | memf Today | Priority | Phase |
|-----------|-------------|-----------|--------|------------|----------|-------|
| Linux (process list walk) | Y | N | Y | **Y** | -- | Done |
| Linux (kernel modules) | Y | N | Y | **Y** | -- | Done |
| Linux (network connections) | Y | N | Y | **Y** | -- | Done |
| Linux (KASLR detection) | Y | N | Y | **Y** | -- | Done |
| Windows (EPROCESS walk) | Y | Y | Y | N | P1 | 3 |
| Windows (pool scanning) | Y | Y | Y | N | P1 | 3 |
| Windows (PDB symbols) | Y | Y | Y | N | P1 | 3 |
| Windows (registry hives) | Y | Y | Y | N | P1 | 4 |
| Windows (network/netscan) | Y | Y | Y | N | P1 | 3 |
| Windows (services) | Y | Y | N | N | P2 | 4 |
| Windows (scheduled tasks) | Y | Y | N | N | P2 | 4 |
| macOS (process walking) | Y | N | Y | N | P3 | 5 |
| macOS (network) | Y | N | Y | N | P3 | 5 |
| macOS (kernel modules) | Y | N | Y | N | P3 | 5 |

---

## 4. Process Analysis

| Capability | Volatility 3 | MemProcFS | memf Today | Priority | Phase |
|-----------|-------------|-----------|------------|----------|-------|
| **Linux** | | | | | |
| Process list (task_struct walk) | Y | N | **Y** | -- | Done |
| Process tree (parent-child) | Y | N | **Y** | -- | Done |
| Process command line | Y | N | N | P1 | 3 |
| Process environment vars | Y | N | N | P2 | 4 |
| Process memory maps (proc_maps) | Y | N | N | P2 | 4 |
| Process ELF binary extraction | Y | N | N | P2 | 4 |
| Shared library enumeration | Y | N | N | P2 | 4 |
| Bash history recovery | Y | N | N | P2 | 4 |
| /proc/pid/fd (open files) | Y | N | N | P1 | 3 |
| Kernel threads (kthreads) | Y | N | N | P2 | 4 |
| PID hash table walk | Y | N | N | P2 | 4 |
| Ptrace detection | Y | N | N | P2 | 4 |
| **Windows** | | | | | |
| EPROCESS linked list walk | Y | Y | N | P1 | 3 |
| EPROCESS pool scanning (psscan) | Y | Y | N | P1 | 3 |
| Cross-view detection (psxview) | Y (4 methods) | Y (2 methods) | N | **P0** | 3 |
| Process tree with timestamps | Y | Y | N | P1 | 3 |
| Command line (cmdline) | Y | Y | N | P1 | 3 |
| Environment variables | Y | Y | N | P2 | 4 |
| DLL list (from PEB Ldr) | Y | Y | N | P1 | 3 |
| Handle enumeration | Y | Y | N | P1 | 4 |
| VAD tree walking | Y | Y | N | P1 | 3 |
| Process dump to disk | Y | Y | N | P2 | 4 |
| Thread enumeration | Y | Y | N | P1 | 4 |
| Token/privilege analysis | Y | Y | N | P2 | 4 |
| Session enumeration | Y | Y | N | P2 | 4 |
| Process hollowing detection | Y (malfind) | Y (PROC_BASEADDR) | N | **P0** | 3 |
| PEB masquerading detection | N | Y (PEB_MASQ) | N | **P0** | 3 |
| Process parent validation | N | Y (PROC_PARENT) | N | **P0** | 3 |

---

## 5. Kernel / Driver Analysis

| Capability | Volatility 3 | MemProcFS | memf Today | Priority | Phase |
|-----------|-------------|-----------|------------|----------|-------|
| **Linux** | | | | | |
| Module list (lsmod) | Y | N | **Y** | -- | Done |
| Hidden module detection (5-view) | Y | N | N | **P0** | 3 |
| Syscall table hook detection | Y | N | N | **P0** | 3 |
| IDT hook detection | Y | N | N | P1 | 4 |
| Network operation hooks (afinfo) | Y | N | N | P1 | 4 |
| TTY hook detection | Y | N | N | P2 | 4 |
| Keyboard notifier hooks | Y | N | N | P2 | 4 |
| Ftrace hook detection | Y | N | N | P1 | 4 |
| eBPF program enumeration | Y (community) | N | N | **P0** | 4 |
| eBPF rootkit scoring | N | N | N | **P0** | 4 |
| Kernel log buffer (kmsg) | Y | N | N | P2 | 4 |
| Iomem mapping | Y | N | N | P2 | 4 |
| Credentials check (check_creds) | Y | N | N | P1 | 4 |
| Process capabilities | Y | N | N | P2 | 4 |
| **Windows** | | | | | |
| Driver list (modules/modscan) | Y | Y | N | P1 | 3 |
| SSDT validation | Y | Y | N | P1 | 4 |
| IRP hook detection (driverirp) | Y | Y | N | P1 | 4 |
| Driver path validation | N | Y (DRIVER_PATH) | N | P1 | 4 |
| Device tree enumeration | Y | Y | N | P2 | 4 |
| Callback enumeration | Y | Y | N | P1 | 4 |
| Timer/DPC enumeration | Y | N | N | P2 | 5 |
| Big pool scanning | Y | Y | N | P2 | 4 |
| Object manager enumeration | Y | Y | N | P2 | 4 |

---

## 6. Network Analysis

| Capability | Volatility 3 | MemProcFS | memf Today | Priority | Phase |
|-----------|-------------|-----------|------------|----------|-------|
| **Linux** | | | | | |
| TCP/UDP socket enumeration | Y | N | **Y** | -- | Done |
| Socket scan (sockscan) | Y | N | N | P2 | 4 |
| Netfilter rules | Y | N | N | P2 | 4 |
| IP interface config | Y | N | N | P2 | 4 |
| IP link info | Y | N | N | P2 | 4 |
| **Windows** | | | | | |
| Netscan (pool tag scanning) | Y | Y | N | P1 | 3 |
| Active TCP connections | Y | Y | N | P1 | 3 |
| Active UDP listeners | Y | Y | N | P1 | 3 |
| Connection to process mapping | Y | Y | N | P1 | 3 |
| TIME_WAIT/closed connections | P | Y | N | P1 | 4 |

---

## 7. File System from Memory

| Capability | Volatility 3 | MemProcFS | memf Today | Priority | Phase |
|-----------|-------------|-----------|------------|----------|-------|
| File object scanning (filescan) | Y | Y | N | P1 | 4 |
| File dump from VAD | Y | Y | N | P1 | 4 |
| PE module reconstruction | Y | Y | N | P2 | 4 |
| NTFS MFT recovery | N | Y | N | P2 | 4 |
| Linux page cache recovery | Y | N | N | P2 | 4 |
| Kernel pool file object scan | Y | Y | N | P1 | 4 |
| Handle-based file recovery | Y | Y | N | P2 | 4 |
| Reconstructed filesystem view | N | Y (forensic/files) | N | P2 | 5 |
| Prefetch file extraction | N | Y | N | P2 | 5 |
| Event log (.evtx) extraction | N | Y | N | P2 | 5 |

---

## 8. Registry from Memory

| Capability | Volatility 3 | MemProcFS | memf Today | Priority | Phase |
|-----------|-------------|-----------|------------|----------|-------|
| Hive enumeration (hivelist) | Y | Y | N | P1 | 4 |
| CMHIVE signature scanning | Y | Y | N | P1 | 4 |
| Registry key browsing | Y | Y | N | P1 | 4 |
| Volatile keys (memory-only) | Y | Y | N | P1 | 4 |
| Dirty page detection | P | Y | N | P2 | 5 |
| UserAssist decoding | Y | Y | N | P2 | 5 |
| ShimCache extraction | Y | Y | N | P2 | 5 |
| Amcache extraction | Y | Y | N | P2 | 5 |
| Shellbags extraction | Y | N | N | P2 | 5 |
| Reuse winreg-forensic parsers | -- | -- | N | P1 | 4 |

**Differentiator**: memf can reuse the existing `winreg-format` and `winreg-core` crates from the sibling winreg-forensic project for bin-level parsing. Only the memory-specific CMHIVE/HHIVE location and cell map translation needs new code.

---

## 9. Credential Extraction

| Capability | Volatility 3 | MemProcFS | pypykatz | memf Today | Priority | Phase |
|-----------|-------------|-----------|----------|------------|----------|-------|
| SAM NTLM hash extraction | Y (hashdump) | N | Y | N | P1 | 4 |
| LSA secrets decryption | Y (lsadump) | N | Y | N | P1 | 4 |
| Cached domain creds (MSCash2) | Y (cachedump) | N | Y | N | P1 | 4 |
| LSASS heap parsing | N | N | Y | N | P2 | 5 |
| Kerberos ticket extraction | N | N | Y | N | P2 | 5 |
| DPAPI master key recovery | N | N | Y | N | P2 | 5 |
| WDigest cleartext passwords | N | N | Y | N | P2 | 5 |
| SSH private keys (Linux) | N | N | N | N | P2 | 5 |
| SSH agent shielded keys | N | N | N | N | P3 | 6 |
| Browser cred decryption | N | N | P | N | P3 | 6 |

**Differentiator**: No single open-source tool provides complete credential extraction from memory dumps. pypykatz handles LSASS but requires separate invocation. An integrated credential pipeline would be unique.

---

## 10. Encryption Key Recovery

| Capability | Volatility 3 | MemProcFS | Dedicated Tools | memf Today | Priority | Phase |
|-----------|-------------|-----------|-----------------|------------|----------|-------|
| BitLocker FVEK (Win7, FVEc) | Y (community) | Y | Passware, Elcomsoft | N | P1 | 4 |
| BitLocker FVEK (Win10, Cngb) | P (community) | Y | Passware, Elcomsoft | N | P1 | 4 |
| BitLocker FVEK (Win11, dFVE) | N | Y | Passware | N | P1 | 4 |
| AES key schedule validation | N | Y | N | N | P1 | 4 |
| FileVault 2 (macOS) | N | N | Passware | N | P3 | 6 |
| LUKS master key (Linux) | N | N | R | N | P2 | 5 |
| VeraCrypt/TrueCrypt key | N | N | Passware, Elcomsoft | N | P3 | 6 |
| TLS session key extraction | N | N | R | N | P2 | 5 |

---

## 11. Malware/Rootkit Detection

| Detection | Volatility 3 | MemProcFS FindEvil | memf Today | Priority | Phase |
|-----------|-------------|-------------------|------------|----------|-------|
| **Injection Detection** | | | | | |
| VAD-based code injection (malfind) | Y | Y (PRIVATE_RWX) | N | **P0** | 3 |
| RWX private memory (PTE-level) | N | Y (actual PTE flags) | N | **P0** | 3 |
| Unlinked PE modules (PE_NOLINK) | N | Y | N | **P0** | 3 |
| Injected PE in private memory | P (malfind) | Y (PE_INJECT) | N | P1 | 3 |
| PE patched via prototype PTE | N | Y (PE_PATCHED) | N | **P0** | 4 |
| **Process Anomalies** | | | | | |
| Hidden process (DKOM) | Y (psxview) | Y (PROC_NOLINK) | N | **P0** | 3 |
| Process hollowing | Y (malfind) | Y (PROC_BASEADDR) | N | **P0** | 3 |
| PEB masquerading | N | Y (PEB_MASQ) | N | **P0** | 3 |
| Parent process validation | N | Y (PROC_PARENT) | N | **P0** | 3 |
| User context validation | N | Y (PROC_USER) | N | P1 | 4 |
| SeDebugPrivilege detection | N | Y (PROC_DEBUG) | N | P1 | 4 |
| Bad DTB detection | N | Y (PROC_BAD_DTB) | N | P1 | 4 |
| **Thread Anomalies** | | | | | |
| Thread start in private mem | N | Y (THREAD) | N | P1 | 4 |
| LoadLibrary injection | N | Y (THREAD) | N | P1 | 4 |
| APC injection (UM_APC) | N | Y | N | P1 | 4 |
| Start addr not RtlUserThread | N | Y | N | P2 | 4 |
| SYSTEM impersonation | N | Y | N | P2 | 4 |
| **Kernel Integrity** | | | | | |
| Syscall table validation (Linux) | Y | N | N | **P0** | 3 |
| Hidden modules (Linux, 5-view) | Y | N | N | **P0** | 3 |
| IDT validation (Linux) | Y | N | N | P1 | 4 |
| SSDT validation (Windows) | Y | Y | N | P1 | 4 |
| Inline hook detection | Y | Y | N | P1 | 4 |
| Driver IRP hooks | Y | Y | N | P2 | 4 |
| **Entropy/Payload Detection** | | | | | |
| High entropy regions | N | Y (HIGH_ENTROPY) | N | P1 | 4 |
| Entropy profiling per region | N | P | N | **P0** | 4 |
| **YARA Integration** | | | | | |
| YARA scanning (process memory) | Y | Y | N | P1 | 4 |
| YARA scanning (kernel memory) | Y | Y | N | P2 | 4 |
| Elastic FindEvil YARA rules | N | Y (built-in) | N | P1 | 4 |
| YARA-X from raw strings | -- | -- | **Y** | -- | Done |
| Windows Defender log parsing | N | Y (AV_*) | N | P3 | 5 |

---

## 12. String / IoC Analysis

| Capability | Volatility 3 | MemProcFS | memf Today | Priority | Phase |
|-----------|-------------|-----------|------------|----------|-------|
| ASCII string extraction | Y | N | **Y** | -- | Done |
| UTF-16LE string extraction | Y | N | **Y** | -- | Done |
| Regex-based classification | N | N | **Y** (12 categories) | -- | Done |
| YARA-X rule matching | Y (yarascan) | Y | **Y** | -- | Done |
| From-file string parsing | N | N | **Y** | -- | Done |
| Process-attributed strings | Y | Y | N | P1 | 4 |
| PFN-based process attribution | N | N | N | **P0** | 4 |
| Cryptocurrency address detection | N | N | **Y** | -- | Done |
| PEM key detection | N | N | **Y** | -- | Done |
| Base64 blob detection | N | N | **Y** | -- | Done |
| Shell command detection | N | N | **Y** | -- | Done |
| URL/IP/email classification | N | N | **Y** | -- | Done |

**Differentiator**: memf already leads in string classification with 12 regex categories. Adding process attribution via PFN database would make this unique across all tools.

---

## 13. Symbol Resolution

| Capability | Volatility 3 | MemProcFS | memf Today | Priority | Phase |
|-----------|-------------|-----------|------------|----------|-------|
| ISF JSON (Volatility format) | Y | N | **Y** | -- | Done |
| BTF (Linux kernel built-in) | N | N | **Y** | -- | Done |
| Windows PDB download | Y | Y | N | P1 | 3 |
| PDB parsing (type info) | Y | Y | N | P1 | 3 |
| RSDS auto-detection in memory | Y | Y | N | P1 | 3 |
| ISF auto-generation from PDB | Y | N | N | P2 | 4 |
| Symbol caching | Y | Y | N | P1 | 3 |
| Profile-free analysis | N | Y | N | P2 | 5 |
| Linux kallsyms parsing | Y | N | N | P2 | 4 |

---

## 14. Output / Interface

| Capability | Volatility 3 | MemProcFS | memf Today | Priority | Phase |
|-----------|-------------|-----------|------------|----------|-------|
| Table output | Y | Y | **Y** | -- | Done |
| JSON (NDJSON) output | Y | Y | **Y** | -- | Done |
| CSV output | Y | N | **Y** | -- | Done |
| SQLite database output | N | Y | N | P2 | 5 |
| FUSE virtual filesystem | N | Y | N | P2 | 5 |
| Timeline generation | N | Y | N | P1 | 4 |
| Python API/bindings | Y (native) | Y | N | P3 | 6 |
| Rust API (library crate) | N | Y (memprocfs crate) | **Y** | -- | Done |
| VolShell (interactive) | Y | N | N | P3 | 6 |
| Web UI (Orochi-like) | N (Orochi) | N (Analyzer) | N | P3 | 6 |

---

## 15. Novel / Differentiating Capabilities

These capabilities are not fully implemented in any existing tool. Building them would establish memf as the leader.

| Capability | Nearest Existing | Current State | Priority | Phase |
|-----------|-----------------|---------------|----------|-------|
| **Dump quality scoring** | None | Research only (DFRWS 2025) | **P0** | 3 |
| **Streaming analysis engine** | MemCatcher (research) | Research only | **P0** | 5 |
| **Temporal/differential analysis** | DAMM (V2 only), FIMAR (hypervisor) | Research only | P1 | 5 |
| **UEFI Runtime Services validation** | UefiMemDump (Ben Gurion) | Research only | P1 | 5 |
| **eBPF rootkit detection + scoring** | BPFVol3 (V3 plugin) | Community plugin | **P0** | 4 |
| **Process masquerading scoring** | Elastic rules (external) | Rule-based only | P1 | 4 |
| **Memory permission anomaly scoring** | MemProcFS (partial) | Heuristic only | P1 | 4 |
| **Call stack analysis (EDR bypass)** | Academic (2024) | Research only | P2 | 5 |
| **Encrypted memory metadata analysis** | None | Research only | P3 | 6 |
| **Per-page confidence scoring** | None | Research only | **P0** | 3 |
| **Context-aware YARA (PFN attribution)** | Cohen 2017 paper | Research only | P1 | 4 |
| **Smear-aware page table reconstruction** | SAM (research) | Academic only | P2 | 5 |
| **Container forensics (Docker/K8s)** | V3 community plugin | Community plugin | P2 | 5 |
| **LLM-augmented triage** | Academic (2025) | Research only | P4 | 6 |

---

## 16. Live / Remote Analysis

| Capability | Volatility 3 | MemProcFS | memf Today | Priority | Phase |
|-----------|-------------|-----------|------------|----------|-------|
| PCIe DMA (FPGA) acquisition | N | Y (LeechCore) | N | P3 | 6 |
| Remote IR agent | N | Y (LeechAgent) | N | P3 | 6 |
| VMware live memory | N | Y | N | P3 | 6 |
| Hypervisor-based acquisition | N | P (LeechCore) | N | P4 | 6 |
| /dev/crash reading | N | N (AVML does) | N | P3 | 6 |
| /proc/kcore reading | N | N (AVML does) | N | P3 | 6 |
| Virtual machine introspection | N | Y (VM mount) | N | P3 | 6 |

---

## Phase Roadmap

### Phase 3: Windows Foundation + Detection Core (next)

**Goal**: Windows memory analysis parity with the basics. Detection engine foundation.

| # | Capability | Why |
|---|-----------|-----|
| 1 | Windows crash dump format (.dmp) | Unlock Windows analysis |
| 2 | PDB symbol resolution (download + parse) | Required for all Windows plugins |
| 3 | RSDS auto-detection in dump | Auto-find correct PDB |
| 4 | EPROCESS linked list walk | Windows process enumeration |
| 5 | EPROCESS pool scanning (psscan) | Find hidden processes |
| 6 | Cross-view process detection (7-method psxview) | **P0 differentiator** |
| 7 | DLL list from PEB Ldr | Module enumeration |
| 8 | VAD tree walking | Memory region analysis |
| 9 | malfind equivalent (VAD + RWX + MZ) | Injection detection |
| 10 | PRIVATE_RWX (PTE-level, MemProcFS approach) | **P0 differentiator** |
| 11 | PROC_NOLINK (hidden process) | DKOM rootkit detection |
| 12 | PROC_BASEADDR (process hollowing) | Hollowing detection |
| 13 | PEB_MASQ (PEB masquerading) | Masquerading detection |
| 14 | PROC_PARENT validation | Parent spoofing detection |
| 15 | Windows netscan (pool tag scanning) | Network forensics |
| 16 | Dump quality scoring | **P0 novel differentiator** |
| 17 | Per-page confidence scoring | **P0 novel differentiator** |
| 18 | Windows memory compression (Xpress/LZ4) | **P0 critical gap filler** |
| 19 | Linux syscall table hook detection | Linux rootkit detection |
| 20 | Linux hidden module detection (5-view) | Linux rootkit detection |
| 21 | Hiberfil.sys format | Common acquisition source |
| 22 | VMware .vmem format | Common VM source |
| 23 | kdump format | Linux makedumpfile |

### Phase 4: Deep Analysis + Credential Extraction

**Goal**: Feature parity with Volatility 3 and MemProcFS on major capabilities. Unique credential pipeline.

| # | Capability |
|---|-----------|
| 1 | PE_NOLINK (unlinked module detection) |
| 2 | PE_PATCHED (prototype PTE comparison) |
| 3 | PE_INJECT (PE in private memory) |
| 4 | Thread anomaly detection (THREAD) |
| 5 | APC injection detection (UM_APC) |
| 6 | Shannon entropy profiling per region |
| 7 | SSDT validation |
| 8 | Driver IRP hook detection |
| 9 | Callback enumeration |
| 10 | Handle enumeration |
| 11 | File object scanning + dump |
| 12 | Registry hive reconstruction (reuse winreg-format/winreg-core) |
| 13 | SAM NTLM hash extraction |
| 14 | LSA secrets decryption |
| 15 | Cached domain creds (MSCash2) |
| 16 | BitLocker FVEK extraction (all Windows versions) |
| 17 | Process-attributed YARA scanning |
| 18 | PFN-based string attribution |
| 19 | eBPF rootkit enumeration + scoring |
| 20 | Linux IDT hook detection |
| 21 | Linux network operation hooks |
| 22 | Timeline generation |
| 23 | AArch64 page table support |
| 24 | Process command line + environment |
| 25 | Linux open files (lsof) |

### Phase 5: Advanced + Novel

**Goal**: Surpass all existing tools with capabilities no one else offers.

| # | Capability |
|---|-----------|
| 1 | Streaming analysis engine (pages as events) |
| 2 | Temporal/differential analysis (DAMM-like) |
| 3 | UEFI Runtime Services hook detection |
| 4 | Smear-aware page table reconstruction |
| 5 | Call stack analysis (EDR bypass detection) |
| 6 | LSASS heap parsing (pypykatz equivalent) |
| 7 | Kerberos ticket extraction |
| 8 | DPAPI master key recovery |
| 9 | LUKS master key recovery (Linux) |
| 10 | TLS session key extraction |
| 11 | Container/namespace forensics |
| 12 | FUSE virtual filesystem |
| 13 | SQLite output |
| 14 | Pagefile.sys + Swapfile.sys integration |
| 15 | VirtualBox/Hyper-V formats |
| 16 | NTFS MFT from memory |
| 17 | File reconstruction from VAD + page cache |
| 18 | Event log extraction from memory |
| 19 | Prefetch extraction |
| 20 | SSH private key extraction (Linux) |

### Phase 6: Research Frontier

| # | Capability |
|---|-----------|
| 1 | Encrypted memory metadata analysis (SEV/TDX/CCA) |
| 2 | RISC-V page table support |
| 3 | LLM-augmented triage pipeline |
| 4 | FPGA/PCIe DMA acquisition |
| 5 | Remote agent (LeechAgent equivalent) |
| 6 | VMI (Virtual Machine Introspection) |
| 7 | Python bindings |
| 8 | Web UI |
| 9 | macOS full support |
| 10 | FileVault 2 / VeraCrypt key recovery |

---

## Competitive Summary

### What memf has today (Phase 1-2 complete)

- 4 dump formats (LiME, AVML, ELF core, Raw)
- x86_64 page table walking (4KB/2MB/1GB)
- Linux process/module/network walking + KASLR detection
- ISF JSON + BTF symbol resolution
- String extraction (ASCII + UTF-16LE) with 12-category regex classification
- YARA-X integration
- CLI with table/JSON/CSV output
- 237 tests, zero unsafe code, Apache-2.0

### What makes memf unique already

1. **Pure Rust, zero unsafe** -- no other framework achieves this
2. **12-category string classification** -- regex + YARA pipeline no one else has
3. **Dual symbol backends** (ISF + BTF) -- only tool with native BTF support
4. **Apache-2.0 license** -- Volatility has restrictive VSL, MemProcFS is AGPL

### What will make memf the superset

1. **Windows memory compression in safe Rust** -- MemProcFS only tool that does this, and it's C
2. **7-method cross-view process detection** -- surpasses both Volatility (4) and MemProcFS (2)
3. **Integrated FindEvil-class detection** -- MemProcFS has it in C, Volatility doesn't
4. **Dump quality scoring with per-page confidence** -- no tool has this
5. **eBPF rootkit scoring** -- only community plugins exist, no integrated tool
6. **Integrated credential pipeline** -- combines hashdump + lsadump + FVEK in one tool
7. **Streaming analysis** -- O(n) single-pass analysis as pages arrive
8. **20+ dump format support** -- more than any single tool

### Key crate dependencies to add

| Crate | Purpose | Phase |
|-------|---------|-------|
| `pdb` | Windows PDB parsing | 3 |
| `rust-lzxpress` | Xpress LZ77 decompression (Win memory compression) | 3 |
| `lz4_flex` | LZ4 decompression (Win11 24H2+) | 3 |
| `goblin` | PE/ELF/Mach-O parsing (already used) | -- |
| `yara-x` | YARA scanning (already used) | -- |
| winreg-format | Registry hive parsing (sibling crate) | 4 |
| winreg-core | Registry key navigation (sibling crate) | 4 |

---

## References

- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
- [MemProcFS GitHub + Wiki](https://github.com/ufrisk/MemProcFS/wiki)
- [MemProcFS FindEvil](https://github.com/ufrisk/MemProcFS/wiki/FS_FindEvil)
- [DFRWS 2025 - Memory Acquisition Quality](https://dfrws.org/presentation/a-scenario-based-quality-assessment-of-memory-acquisition-tools-and-its-investigative-implications/)
- [DFRWS 2025 - Hidden Kernel Modules](https://dfrws.org/wp-content/uploads/2025/05/Detecting-hidden-kernel-modules-in-memory-snapshots.pdf)
- [FIMAR Paper](https://www.sciencedirect.com/science/article/pii/S2666281723001154)
- [UefiMemDump](https://arxiv.org/html/2501.16962v1)
- [BPFVol3](https://github.com/vobst/BPFVol3)
- [pypykatz](https://github.com/skelsec/pypykatz)
- [DAMM](https://github.com/504ensicsLabs/DAMM)
- [Elastic FindEvil Research](https://www.elastic.co/security-labs/get-injectedthreadex-detection-thread-creation-trampolines)
- [MemProcFS Source (mm_win.c)](https://github.com/ufrisk/MemProcFS/blob/master/vmm/mm/mm_win.c)
- [Mandiant - Finding Evil in Windows 10 Compressed Memory](https://cloud.google.com/blog/topics/threat-intelligence/finding-evil-in-windows-ten-compressed-memory-part-one)
- [rust-lzxpress](https://github.com/MagnetForensics/rust-lzxpress)
- [pdb crate](https://docs.rs/pdb/latest/pdb/)
