# Advanced Memory Forensics Capabilities Research

> Research compiled April 2026. Detailed technical findings indexed in context-mode
> knowledge base under sources prefixed with `memf-research-*`.

## 1. Windows Memory Compression (Win10/11)

### Architecture
The Store Manager kernel component manages compression stores via `SMKM_STORE` structures.
Pages are compressed using **Xpress (LZ77)** at ~320MB/s compression, ~440MB/s decompression,
achieving 30-50% of original size. The MemCompression process (child of System) owns all
compressed memory.

### B+Tree Traversal for Compressed Page Recovery
1. Derive `SM_PAGE_KEY` from PTE
2. Traverse `SMKM_STORE_MGR.sGlobalTree` (global B+tree) to find store index
3. Index into 32x32 array of `SMKM_STORE_METADATA` elements via `nt!SmGlobals`
4. Navigate `SMKM_STORE` -> `ST_STORE` -> `ST_DATA_MGR`
5. Traverse `ST_DATA_MGR.sLocalTree` (local B+tree) to get chunk key
6. Decode chunk key into `SMHP_CHUNK_METADATA.aChunkPointer` 2D array
7. Read `ST_PAGE_RECORD` and decompress with `RtlDecompressBufferEx`

### Compression Algorithms
| Algorithm | Use Case | Speed |
|-----------|----------|-------|
| Xpress (LZ77) | Primary memory page compression | 320/440 MB/s |
| XpressHuff (LZ77+Huffman) | WIM, SuperFetch, bootmgr | Higher ratio, slower |
| LZNT1 | Legacy, simpler variant | Moderate |
| LZ4 | Win11 24H2 / Server 2025 (SMB) | >500 MB/s / multi-GB/s |

### Key Rust Libraries
- [MagnetForensics/rust-lzxpress](https://github.com/MagnetForensics/rust-lzxpress) -- Xpress in Rust
- [coderforlife/ms-compress](https://github.com/coderforlife/ms-compress) -- All MS algorithms
- [MemProcFS Rust crate](https://crates.io/crates/memprocfs) v5.17.0 -- Full memory analysis API

### References
- [BlackHat USA 2019 whitepaper](https://i.blackhat.com/USA-19/Thursday/us-19-Sardar-Paging-All-Windows-Geeks-Finding-Evil-In-Windows-10-Compressed-Memory-wp.pdf)
- [Mandiant blog: Finding Evil in Win10 Compressed Memory](https://cloud.google.com/blog/topics/threat-intelligence/finding-evil-in-windows-ten-compressed-memory-part-one)
- [mandiant/win10_volatility](https://github.com/mandiant/win10_volatility/blob/win10_compressed_memory/volatility/plugins/addrspaces/win10_memcompression.py)
- [MS-XCA Specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/a8b7cb0a-92a6-4187-a23b-5e14273b96f8)

---

## 2. Credential Extraction

### LSASS Memory Layout
| Authentication Package | Data Available | Structure |
|----------------------|----------------|-----------|
| MSV1_0 | NTLM hashes (NtOwfPassword, LmOwfPassword) | LogonSessionList |
| Kerberos | TGTs, service tickets, session keys | Kerberos ticket cache |
| WDigest | Plaintext passwords (if enabled) | WDigest credential array |
| TSPKG | Terminal Services credentials | TsPkg credential store |
| CloudAP | Azure AD PRT + session key | CloudAP plugin cache |
| DPAPI | Cached master keys | DPAPI cache in LSASS |

### Azure AD PRT Attack Chain
1. Extract PRT from LSASS CloudAP cache (admin required)
2. Extract session key (TPM-protected, but extractable with admin)
3. Create SSO cookies for Azure/M365 access
4. Credential Guard protects on-prem but NOT CloudAP credentials

### Browser Credentials
- **Chrome**: SQLite `Login Data` + AES-GCM key in `Local State` (DPAPI-encrypted)
- **Chrome 127+**: App-Bound Encryption requires live session triage
- **Firefox**: NSS-based, `key4.db` + `logins.json`, optional master password

### References
- [MITRE T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [Synacktiv: Windows Secrets Extraction Summary](https://www.synacktiv.com/en/publications/windows-secrets-extraction-a-summary)
- [Mimikatz Comprehensive Guide](https://hadess.io/mimikatz-comprehensive-guide/)
- [AADInternals: Pass-the-PRT](https://aadinternals.com/post/prt/)
- [Browser Forensics 2026](https://blog.elcomsoft.com/2026/01/browser-forensics-in-2026-app-bound-encryption-and-live-triage/)

---

## 3. Rootkit/Malware Detection Algorithms

### Cross-View Hidden Process Detection
Compare process lists from 7+ independent sources to detect DKOM:

| Source | Structure | Resilience |
|--------|-----------|------------|
| PsActiveProcessHead | EPROCESS linked list | Easily DKOM'd |
| Pool tag scanning | 'Proc' pool tags | Very resilient |
| ETHREAD scanning | Thread -> owner process | Resilient (must also hide threads) |
| PspCidTable | Kernel PID/TID handle table | Moderate (FUTo can manipulate) |
| CSRSS handle table | All created process handles | Resilient |
| Session process links | Per-session EPROCESS list | Moderate |
| Desktop threads | Window station thread list | Resilient |

### SSDT/IDT Hook Detection
- Read each SSDT entry, verify pointer falls within ntoskrnl.exe
- Read IDT entries (256), verify handlers point to expected modules
- Legitimate hooks possible (AV/firewall) -- cross-reference with known drivers

### Inline Hook Detection
- Disassemble function prologues (first 16 bytes)
- Detect JMP/CALL instructions targeting addresses outside the owning module
- Compare in-memory code with on-disk module (integrity checking)

### Callback Enumeration
Key arrays to scan:
- `PspCreateProcessNotifyRoutine` (up to 64 entries)
- `PspCreateThreadNotifyRoutine`
- `PspLoadImageNotifyRoutine`
- `CmCallbackListHead` (registry callbacks, linked list)
- `ObCallbackList` (per OBJECT_TYPE, linked list of CALLBACK_ENTRY_ITEM)

### Timer DPC Analysis
- Scan for KTIMER objects, extract KDPC.DeferredRoutine pointers
- Resolve to containing module; flag routines in unknown/unloaded modules

### References
- [Volatility psxview source](https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/malware/psxview.py)
- [DKOM Wikipedia](https://en.wikipedia.org/wiki/Direct_kernel_object_manipulation)
- [BlackHat: DKOM by Jamie Butler](https://blackhat.com/presentations/win-usa-04/bh-win-04-butler.pdf)
- [CodeMachine: Kernel Callbacks](https://codemachine.com/articles/kernel_callback_functions.html)
- [Kernel rootkit detection survey (arXiv)](https://arxiv.org/pdf/2304.00473)

---

## 4. File Reconstruction from Memory

### PE Extraction from VADs
- Walk VAD tree to find mapped files (ControlArea -> FileObject)
- `malfind`: detects injected code (RWX non-file-backed regions with MZ headers)
- Compare PEB InLoadOrderModuleList with VAD tree to find hidden DLLs
- Reloc tool: 200K+ PE relocation fragments for exact hash-verified recovery

### Registry Hive Extraction
- Scan for `regf` signature (0x72656766) to find HBASE_BLOCK
- Walk CMHIVE list for all loaded hives
- Average recovery: 631 volatile keys + 1,231 volatile values per image
- Detect in-memory-only registry modifications (invisible to disk analysis)

### Other Recoverable Artifacts
- Office documents: scan for PK (ZIP/OOXML) or D0CF11E0 (OLE2) headers
- PDF: scan for `%PDF-1.` magic bytes
- SQLite databases: `SQLite format 3\000` header
- Certificates: ASN.1 DER structures, CNG key blobs

### References
- [HADESS: Memory Forensic Guide](https://hadess.io/memory-forensic-a-comprehensive-technical-guide/)
- [Registry in Memory (ScienceDirect)](https://www.sciencedirect.com/science/article/pii/S1742287608000297)

---

## 5. Network Forensics from Memory

### Connection Recovery (Vista+)
Pool tag scanning for `_TCP_ENDPOINT`, `_TCP_LISTENER`, `_UDP_ENDPOINT`:
- Tags: TcpL, TcpE, UdpA, RawE
- Finds terminated/closed connections still in pool memory
- `netstat` plugin uses partition table walking in tcpip.sys

### DNS Cache
- `dnsrslvr.dll` in svchost.exe contains `g_HashTable` hash table
- Volatility `dnscache` plugin (mnemonic-no) walks hash table via PDB symbols
- Reveals recently resolved domains, C2 indicators, DNS tunneling

### TLS Session Key Extraction
| Method | Tool | Requirements |
|--------|------|-------------|
| SSLKEYLOGFILE | Env var (Chrome/Firefox) | Pre-configured |
| LSASS memory | Volatility plugin | Memory dump of lsass.exe |
| Function hooking | FriTap | Runtime access |
| VM introspection | TLSkex | Hypervisor access |
| Process memory scan | Custom | Known structure layouts |

### References
- [Volatility netscan docs](https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.netscan.html)
- [Volatility Labs: Raw Sockets](https://volatility-labs.blogspot.com/2023/08/memory-forensics-r-d-illustrated-recovering-raw-sockets0-on-windows-10.html)
- [mnemonic-no/dnscache](https://github.com/mnemonic-no/dnscache)
- [TLS Key Material Identification (ScienceDirect 2024)](https://www.sciencedirect.com/science/article/pii/S2666281724000854)

---

## 6. Container/VM Forensics

### Docker Container Detection
- Container processes visible as standard EPROCESS structures in host memory
- Identify via: containerd-shim parent, cgroup paths, namespace IDs
- CRIU for checkpoint/restore memory snapshots
- Kubernetes: forensic container checkpointing (alpha feature)

### Nested VM Detection
- Scan for VMCS structures, extract EPTP (EPT Pointer)
- Walk EPT page tables: PML4 -> PDPT -> PD -> PT
- Reconstruct guest physical address space
- Apply forensic analysis to reconstructed guest image

### Hyper-V
- LiveCloudKd: direct VM memory access via hvlib.dll/hvmm.sys
- EXDi integration for WinDBG kernel debugging
- Raw/crash dump generation for offline analysis

### References
- [Kubernetes forensic checkpointing](https://kubernetes.io/blog/2023/03/10/forensic-container-analysis/)
- [Hypervisor Memory Forensics (Springer)](https://link.springer.com/chapter/10.1007/978-3-642-41284-4_2)
- [Docker Forensics (Red Hat)](https://www.redhat.com/en/blog/docker-forensics-for-containers-how-to-conduct-investigations)

---

## 7. Temporal Analysis

### Timeline Sources in Memory
- Process creation/exit times (EPROCESS)
- Thread creation times (ETHREAD)
- Network connection timestamps
- Registry key last-write times
- DLL load timestamps
- Boot time from KUSER_SHARED_DATA.BootTime

### Temporal Consistency
- Memory acquisition is not atomic -- pages captured at different wall-clock times
- Research (Pagani et al., ACM TOPS 2019): locality-based acquisition minimizes inconsistency
- Multiple consecutive dumps enable static/dynamic page classification

### References
- [Temporal Dimension in Memory Forensics (ACM TOPS)](https://dl.acm.org/doi/10.1145/3310355)
- [TBDCyber: Timeline Analysis](https://www.tbdcyber.com/post/timeline-analysis-overview-and-its-use-in-memory-forensics)

---

## 8. ARM64 Support

### Key Differences
- 4-level page tables with 4KB pages (48-bit VA), 2-level with 64KB
- TCR_EL1 controls radix tree shape (critical for forensic page table walking)
- Pointer Authentication Codes (PAC): must strip before dereferencing
- Memory Tagging Extension (MTE): mask tag bits for address resolution

### Tool Support
- MemProcFS: ARM64 Windows support (recent)
- Volatility: limited ARM64 support
- Fossil, Katana, MMUShell: OS-agnostic alternatives

### References
- [AArch64 Memory Layout (kernel.org)](https://docs.kernel.org/arch/arm64/memory.html)
- [Multi-arch Memory Forensics (EURECOM)](https://www.s3.eurecom.fr/docs/tops22_oliveri.pdf)
- [Katana binary-only forensics](https://www.cs.cit.tum.de/fileadmin/w00cfj/ct/papers/2022-RAID-Franzen.pdf)

---

## 9. UEFI/Firmware Forensics

### UEFI Memory Forensics Framework (Ben Gurion, Jan 2025)
- **UefiMemDump**: Pre-OS memory acquisition
- **UEFIDumpAnalysis**: Modules for function pointer hooking, inline hooking, image carving
- Detects: Glupteba, CosmicStrand, MoonBounce, ThunderStrike bootkits

### UEberForensIcs (DFRWS EU 2021)
- Firmware-resident acquisition tool
- Cold boot-like capture before OS loads

### References
- [UEFI Memory Forensics (arXiv)](https://arxiv.org/html/2501.16962v1)
- [UEberForensIcs (DFRWS)](https://dfrws.org/wp-content/uploads/2021/03/Bringing-Forensic-Readiness-to-Modern-Computer-Firmware.pdf)
- [CHIPSEC](https://ringzer0.training/system-firmware-attack-and-defense-for-the-enterprise/)

---

## 10. Streaming/Incremental Analysis

### Approaches
- MemProcFS virtual file system: lazy page loading, on-demand access
- LeechCore abstraction: unified interface for dump files, live memory, DMA, remote
- SPECTRE: modular pipeline with queue-based processing
- Key: never load full dump; use LRU page cache + prefetch

---

## 11. Differential Analysis

### DAMM (504ENSICS Labs)
- Compare objects across multiple memory samples via SQLite persistence
- Unique keys: PID+PPID+name+start_time (same boot) or name+path+cmdline (cross-boot)
- Detects: new/terminated processes, modified attributes, hidden processes

### References
- [DAMM (GitHub)](https://github.com/504ensicsLabs/DAMM)
- [Multiple dump analysis (Springer)](https://link.springer.com/chapter/10.1007/978-3-642-15506-2_13)

---

## 12. Machine Learning Approaches

### State of the Art (2025)
| Approach | Accuracy | Key Innovation |
|----------|----------|----------------|
| 1D-CNN on raw byte sequences | 98.28% | End-to-end, no manual features |
| 2D-CNN on memory visualizations | 97.8% | Image classification of memory regions |
| RNN on temporal features | ~96% | Sequential pattern detection |
| LLM integration | Emerging | GPT-4o, Gemini, Grok for forensic analysis |

### Comprehensive Survey (ACM Computing Surveys)
- 30% surge in cyberattacks in 2024 driving memory forensics research
- Strong upward publication trend since 2020
- Focus: fileless malware detection, family classification

### References
- [Deep Learning + Memory Forensics (MDPI)](https://www.mdpi.com/2073-8994/15/3/758)
- [Advanced Memory Forensics with DL (Springer 2025)](https://link.springer.com/article/10.1007/s10586-025-05104-7)
- [LLMs for Memory Forensics (ACM)](https://dl.acm.org/doi/full/10.1145/3748263)
- [Memory Analysis Survey (ACM Computing Surveys)](https://dl.acm.org/doi/10.1145/3764580)
- [SPECTRE system (Springer 2026)](https://link.springer.com/article/10.1007/s10207-026-01212-6)
