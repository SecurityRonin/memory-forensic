# Novel Memory Forensics Capabilities Research

> Research compiled 2026-03-31. All claims backed by referenced academic papers and industry publications.

## Table of Contents

1. [Temporal/Differential Memory Analysis](#1-temporaldifferential-memory-analysis)
2. [Dump Quality Assessment](#2-dump-quality-assessment)
3. [UEFI/Firmware Memory Analysis](#3-uefifirmware-memory-analysis)
4. [Streaming/Real-Time Analysis Architecture](#4-streamingreal-time-analysis-architecture)
5. [Statistical Anomaly Detection](#5-statistical-anomaly-detection)
6. [Encrypted Memory Forensics](#6-encrypted-memory-forensics)
7. [eBPF Rootkit Detection](#7-ebpf-rootkit-detection)
8. [Differentiation Opportunities](#8-differentiation-opportunities)

---

## 1. Temporal/Differential Memory Analysis

### 1.1 FIMAR Approach: Incremental Memory Acquisition

FIMAR (Fast Incremental Memory Acquisition and Restoration) uses BitVisor, a thin hypervisor, with Second Level Address Translation (SLAT/EPT) to track page-level changes between sequential memory snapshots.

**Core algorithm:**

1. **EPT-Based Dirty Page Tracking**: Clear write permissions on all Extended Page Table entries. When the guest writes to a page, an EPT violation fires; the hypervisor records the page address + timestamp, restores write permission, and increments a modification counter.
2. **Hash-Based Deduplication**: Each 4 KiB page is hashed (SHA-256). Only pages whose hash differs from the previous snapshot are stored. Memory overhead: 32 bytes per 4 KiB page = 0.78%.
3. **TLB Shootdown for Atomicity**: Inter-processor interrupts flush the TLB on all cores simultaneously, ensuring a consistent EPT state view across all cores. This was the key improvement over prior hypervisor-based acquisition.
4. **Per-Core EPT Manipulation**: FIMAR accounts for the fact that each core has its own EPT pointer cached in the TLB, and synchronizes them before snapshot.

**Metadata tracked per page:**
- Last modification timestamp (TSC value)
- SHA-256 hash of page content at last snapshot
- Access flags (R/W/X) since last snapshot
- Core ID of last accessor
- Modification count since baseline
- Page state (active/transition/paged-out)
- Owner process (via PFN database or page table walk)

**Evaluation**: Tested against BlueSky ransomware with anti-forensic logic. Demonstrated complete timeline reconstruction of ransomware activity across multiple incremental snapshots.

**Reference**: [FIMAR Paper (Hirano et al., 2023)](https://www.sciencedirect.com/science/article/pii/S2666281723001154)

### 1.2 Timestamp Estimation for Individual Pages

- **TSC (Time Stamp Counter)**: Per-core monotonic counter; can approximate when a page was last written via EPT violation handler timestamping.
- **NMI Watchdog**: Periodic non-maskable interrupts can sample page state, providing temporal granularity independent of EPT violations.
- **EPT violation timestamps**: Each page access generates a timestamped event in the hypervisor log.

### 1.3 Consistency/Atomicity Scoring

A memory dump is **time-consistent** if there exists a hypothetical atomic acquisition that could have returned the same result. **Causal atomicity** (Vomel & Freiling) is more permissive: pages collected at different times are acceptable if causal relationships between memory operations and inter-process synchronization are satisfied.

**Empirical findings** (360 Linux dumps):
- ~1/3 had empty process list (obviously incomplete)
- ~50% of analyzable dumps showed some form of inconsistency
- ~20% of all images showed page table inconsistencies
- ~1 in 5 acquisitions produced a corrupted image

**References**:
- [Temporal Dimension in Memory Forensics (Pagani et al., 2019)](https://dl.acm.org/doi/10.1145/3310355)
- [Comprehensive Quantification of Inconsistencies (2025)](https://arxiv.org/pdf/2503.15065)
- [Evaluating Atomicity & Integrity (Gruhn & Freiling, 2016)](https://www.sciencedirect.com/science/article/pii/S1742287616000049)

---

## 2. Dump Quality Assessment

### 2.1 DFRWS 2025 Key Findings

Rzepka et al. evaluated memory acquisition tool quality across four investigative scenarios using 400 dumps from QEMU VM with Windows 10 22H2:

- **VAD analysis failed in 70/400 dumps** across all tools
- Only **1 dump** contained zero VAD inconsistencies
- Tool 3: all 72 analyzable dumps had 137,000+ total inconsistencies (mean 2x higher than next tool)
- **Unstructured analysis methods** (string search, YARA) more robust against low-quality dumps than structured methods (process tree walking, VAD analysis)

**Reference**: [DFRWS 2025 Quality Assessment (Rzepka et al.)](https://dfrws.org/presentation/a-scenario-based-quality-assessment-of-memory-acquisition-tools-and-its-investigative-implications/)

### 2.2 Specific Consistency Checks

#### VAD Tree Validation
- Walk the VAD tree (balanced binary tree of Virtual Address Descriptors)
- Verify nodes point to valid memory ranges with non-overlapping addresses
- Check VAD flags match expected page protections
- Cross-reference VAD entries with PTE entries

#### EPROCESS Cross-Reference Validation
- `EPROCESS.ActiveProcessLinks` must form valid circular doubly-linked list
- `EPROCESS.UniqueProcessId` must be unique and positive
- `EPROCESS.Peb` must point to valid PEB in user space
- `EPROCESS.ObjectTable` must point to valid `HANDLE_TABLE`
- `EPROCESS.Token` must point to valid `TOKEN` structure
- `EPROCESS.CreateTime` must be within reasonable range
- `EPROCESS.ImageFileName` must match `PEB->ProcessParameters->ImagePathName`

#### Page Table Consistency
- Walk 4-level page tables (PML4 -> PDPT -> PD -> PT)
- Verify `PTE.PFN` references a physical page within the dump's address range
- Cross-reference with PFN database: `PFN_DB[pfn].u4.PrototypePte` must match PTE type
- Validate transition PTEs: PFN should reference standby/modified page in PFN DB
- Detect page table smearing: parent PTE references child table modified during acquisition

#### PFN Database Validation
- Verify PFN entries reference valid page tables
- Check `PFN.ReferenceCount > 0` for active pages
- Validate `PFN.ShareCount <= PFN.ReferenceCount`
- Cross-reference `PFN.PteAddress` with actual PTE location

#### Acquisition Impact Estimation
- Pages written by the acquisition tool identified via known patterns of driver code
- Pages allocated after acquisition start time
- Memory regions used by acquisition tool's process
- Impact score: percentage of pages likely modified during acquisition

**References**:
- [PTE Analysis (Block & Dewald, DFRWS 2019)](https://dfrws.org/wp-content/uploads/2019/06/2019_USA_paper-windows_memory_forensics_detecting_unintentionally_hidden_injected_code_by_examining_page_table_entries.pdf)
- [SAM: Smear-Aware Forensic Analysis](https://www.tandfonline.com/doi/abs/10.1080/19361610.2022.2161972)

---

## 3. UEFI/Firmware Memory Analysis

### 3.1 Ben Gurion's UefiMemDump Framework (Jan 2025)

First framework specifically addressing volatile UEFI runtime memory analysis.

**UefiMemDump (Acquisition)**:
- Available as DXE driver or UEFI shell application
- Uses `GetMemoryMap()` to create detailed memory layout
- Identifies volatile/persistent regions, copies bit-for-bit to raw binary

**UEFIDumpAnalysis (Detection Modules)**:

| Module | Technique | Detects |
|---|---|---|
| Function Pointer Hooking | Verify each Boot/Runtime Services table pointer targets legitimate driver memory | CosmicStrand, EfiGuard |
| Inline Hooking | Disassemble function prologues for injected JMP/CALL | MoonBounce, BlackLotus |
| UEFI Image Carving | Extract PE files from memory, compare against known firmware | Unauthorized DXE drivers |

### 3.2 EFI System Table

The root data structure in UEFI. Contains pointers to Boot Services Table, Runtime Services Table, and Configuration Table. In DXE phase, passed as parameter to every DXE driver entry point. After `ExitBootServices()`, only Runtime Services and Configuration Table remain accessible.

### 3.3 Bootkit Signatures

| Bootkit | Technique | Signature |
|---|---|---|
| MoonBounce | Inline hooks AllocatePool, CreateEventEx, ExitBootServices | JMP in function prologue |
| CosmicStrand | Modifies CSMCORE DXE driver; alters Boot+Runtime service pointers | Function pointer outside driver range |
| ThunderStrike | Replaces Apple EFI RSA key via Thunderbolt Option ROM | RSA key mismatch |
| BlackLotus | Patches OslArchTransferToKernel; bypasses Secure Boot | CVE-2022-21894 exploit pattern |
| ESPecter | Clears CR0 WP bit; patches boot manager | CR0 WP bit clearing pattern |

**Common YARA signatures**: CR0 WP bit clearing (detected in MoonBounce, CosmicStrand, ESPecter). Binarly's YARA rule caught Bootlicker variants with very low VirusTotal detection.

### 3.4 UEFI Structures in Regular OS-Level Dumps

**Partially available**:
- Runtime Services table and code (EfiRuntimeServicesCode/Data regions)
- EFI System Table pointer (Windows: stored in HAL data area)
- ACPI tables (RSDP, RSDT/XSDT)

**Not available**:
- Boot Services (freed after ExitBootServices())
- Non-runtime DXE driver code (reclaimed by OS)
- Full UEFI memory map

**Reference**: [UefiMemDump Framework (arXiv:2501.16962)](https://arxiv.org/html/2501.16962v1)

---

## 4. Streaming/Real-Time Analysis Architecture

### 4.1 Core Design: Pages as Events

Treat each acquired 4 KiB page as an event in a stream. Build forensic artifacts incrementally as pages arrive.

**Processing pipeline:**
1. **Ingestion**: Receive raw pages, index by physical address
2. **Classification**: Identify page type (kernel code, user data, page table, pool, etc.)
3. **Structure Detection**: Scan for pool tags (`Proc`, `Thre`, `File`), PE headers, etc.
4. **Assembly**: Build higher-level structures from page-level primitives
5. **Analysis**: Run modules (process tree, YARA, entropy)
6. **Reporting**: Emit findings as discovered

### 4.2 Incremental Process List Building

1. As pages arrive, check for EPROCESS pool tag in pool header
2. Parse available EPROCESS fields from that page
3. Add partial process entry with "completeness score"
4. Maintain "wanted pages" set for unresolved forward references (PEB, VAD root, thread list)
5. When wanted page arrives, trigger resolution callbacks
6. Publish process entry when minimum viable fields resolved (PID, PPID, name, create time)

### 4.3 Streaming YARA Scanning

YARA's C API supports streaming via `YR_SCANNER` with `YR_MEMORY_BLOCK_ITERATOR`:
- Return `ERROR_BLOCK_NOT_READY` to buffer blocks
- Return `ERROR_SUCCESS` to trigger scan across buffered blocks
- **Cross-block matching works**: rules spanning two blocks can match

**Context-aware scanning** (Cohen 2017): Use PFN database to identify process owner of each physical page. Single pass over physical image scans all processes simultaneously.

### 4.4 Out-of-Order Page Handling

- Maintain sparse page map: `HashMap<PhysicalAddress, PageData>`
- Structure walkers check page availability before following pointers
- Re-trigger analysis when previously missing pages arrive
- Every result includes confidence score based on data completeness

### 4.5 Prior Art

- **MemCatcher**: Linear-time O(n) detection pipeline, single pass, constant working set, single executable
- **FPGA Acceleration**: PCIe DMA acquisition + on-the-fly pool tag scanning, no target software required
- **RX-INT**: Kernel-level real-time engine with user-mode client + kernel-mode driver

**References**:
- [MemCatcher](https://www.mdpi.com/2076-3417/15/21/11800)
- [FPGA Acceleration](https://www.sciencedirect.com/science/article/pii/S2214212626000232)
- [YARA Streaming API Discussion](https://github.com/VirusTotal/yara/issues/1994)

---

## 5. Statistical Anomaly Detection

### 5.1 Entropy Profiling

**Shannon entropy thresholds for memory regions:**

| Range | Interpretation |
|---|---|
| H < 1.0 | Zero-filled, guard pages, unmapped |
| 1.0-4.0 | Structured data (code, data structures, strings) |
| 4.0-6.0 | Compressed or mixed content |
| 6.0-7.0 | Packed/obfuscated code (suspicious) |
| 7.0-7.9 | Likely encrypted or compressed |
| H >= 7.9 | Near-maximum, strong encryption indicator |

**Algorithm**: For each memory region, compute Shannon entropy, 256-byte sliding window sub-profiles, Renyi entropy (alpha=2,4,6), and entropy gradient. Compare against baseline for region type (.text ~5.5-6.5, .data ~3.0-5.0, stack ~2.0-4.0).

**Evasion awareness**: Ransomware can use "entropy sharing" to distribute high-entropy data. Counter with multi-granularity analysis and Renyi entropy.

### 5.2 Process Masquerading Detection (ML-Free)

**Feature vector per process:**
1. Damerau-Levenshtein distance to known system process names
2. Expected vs. actual file path
3. Expected parent PID relationship
4. Singleton enforcement (lsass.exe, services.exe should have exactly 1 instance)
5. PE header features (image base, subsystem, characteristics)
6. Memory layout (entropy profile, RWX region count, heap size)

**Clustering**: Use Mahalanobis distance from expected baseline per process type. No training data needed--baselines are hardcoded from Windows internals documentation.

### 5.3 Memory Permission Anomaly Scoring

```
score = w_rwx * count_rwx_regions
      + w_exec_heap * has_executable_heap
      + w_exec_stack * has_executable_stack
      + w_unbacked * count_unbacked_executable
      + w_modified_code * count_modified_code_sections
      + w_hidden * count_hidden_regions
      + w_entropy * entropy_deviation_score
      + w_parent * parent_anomaly_score
      + w_name * name_similarity_score
```

### 5.4 Advantages of ML-Free Approaches
- No training data required
- No model drift
- Fully explainable (each anomaly has concrete reason)
- Deterministic (same dump = same results)
- Works on first encounter
- Based on kernel structure invariants

**References**:
- [Entropy Analysis for Malware (Lyda & Hamrock)](https://www.researchgate.net/publication/3437909_Using_Entropy_Analysis_to_Find_Encrypted_and_Packed_Malware)
- [Process Masquerading (Red Canary)](https://redcanary.com/blog/process-masquerading/)
- [Elastic Detection Rules](https://github.com/elastic/detection-rules/blob/main/rules/windows/privilege_escalation_unusual_parentchild_relationship.toml)

---

## 6. Encrypted Memory Forensics

### 6.1 AMD SEV-SNP

- Per-VM AES-256 encryption with XEX mode (address-based tweak)
- **What leaks**: Memory access patterns, page table structure, RMP table (page ownership), ciphertext patterns (deterministic encryption), VMSA register page
- **Known attacks**: Cipherleaks (register dictionary), Heracles (chosen plaintext oracle, 1-16 bytes/query), BadRam (memory aliasing), TEE.Fail (DDR5 bus interposition, <$1000)

### 6.2 Intel TDX

- AES-XTS-128 encryption, 28-bit MAC per cache line (SHA-3-256)
- **What leaks**: TD ownership tags (1-bit/cache line), page table walks, SEPT structure, GPA-to-HPA mappings, memory allocation patterns
- **Known attacks**: TEE.Fail (nonce recovery -> private key reconstruction), Heracles (theoretical with DRAM snooping)

### 6.3 ARM CCA

- Realm Management Extension (RME): four-world model (Normal, Secure, Root, Realm)
- Granule Protection Table (GPT) enforces per-page world assignment
- **What leaks**: GPT structure (which pages belong to which world), RMM communication (SMC calls), page allocation/timing patterns
- **Hardware blocks**: Normal world CANNOT read Realm memory (faulting exception)
- First confidential computing architecture with formal security verification

### 6.4 Analysis Without Decryption

Even without keys:
- **Ciphertext change detection**: Track which pages changed between snapshots
- **Access pattern analysis**: Reconstruct behavior from memory access patterns
- **Structure inference**: Page table layout reveals virtual address space
- **Known plaintext matching**: Compare ciphertext at addresses where plaintext is known

### 6.5 Cross-Platform Comparison

| Feature | AMD SEV-SNP | Intel TDX | ARM CCA |
|---|---|---|---|
| Ciphertext visible to host | Yes | Limited | No (faulting) |
| Page table metadata leaked | Extensive | Moderate | Minimal (GPT only) |
| Known attacks | Cipherleaks, Heracles, BadRam | TEE.Fail | None published |
| Formal verification | No | No | Yes |

**References**:
- [Confidential VMs Explained](https://dl.acm.org/doi/10.1145/3700418)
- [Heracles Attack (CCS 2025)](https://heracles-attack.github.io/Heracles-CCS2025.pdf)
- [TEE.Fail](https://www.bleepingcomputer.com/news/security/teefail-attack-breaks-confidential-computing-on-intel-amd-nvidia-cpus/)
- [ARM CCA](https://www.arm.com/architecture/security-features/arm-confidential-compute-architecture)
- [Intel TDX Demystified](https://arxiv.org/pdf/2303.15540)

---

## 7. eBPF Rootkit Detection

### 7.1 How eBPF Rootkits Work

eBPF programs run in the kernel without kernel modules. Rootkits abuse this by:
1. Loading malicious programs via `bpf()` syscall
2. Attaching to kprobes, tracepoints, LSM hooks, XDP, TC
3. Using `bpf_probe_write_user` to modify user-space data
4. Hooking `sys_bpf` itself to hide from `bpftool`

**Real-world example -- LinkPro (Oct 2025)**: Targeted AWS K8s clusters. Hooks getdents64 to hide files, hooks sys_bpf to hide its own programs. "Magic TCP SYN" trigger (window size 54321) activates reverse shell.

### 7.2 Key Memory Structures

**`bpf_prog` structure** contains: program type, instruction count, JIT status, tag, auxiliary data (name, helpers, used maps), and the bytecode itself.

**Suspicious helper functions:**

| Helper | Risk Level | Reason |
|---|---|---|
| `bpf_probe_write_user` | CRITICAL | Modifies user-space memory |
| `bpf_override_return` | HIGH | Changes syscall return values |
| `bpf_send_signal` | HIGH | Can kill processes |
| `bpf_skb_store_bytes` | MEDIUM | Modifies network packets |

### 7.3 Volatility 3 Plugins

- **BPFVol3** (vobst): `bpf_graph` (visualize subsystem), `bpf_listprogs`, `bpf_listmaps`, `bpf_lsm` (LSM hook analysis), `bpf_netdev` (TC program detection)
- **AsafEitani plugin**: Rootkit suspicion scoring, JIT code dumping, automated static analysis of flagged programs

### 7.4 Detection Framework

1. **Acquire**: Hypervisor-based or hardware-based (rootkit hooks sys_bpf, hiding from userspace tools)
2. **Extract**: Locate `bpf_prog_idr` radix tree, walk to find all `bpf_prog` structures
3. **Classify**: Check type, helpers, attachment points against heuristics
4. **Analyze**: Decompile bytecode in Ghidra (BPF architecture support available)

**References**:
- [Detecting eBPF Rootkits (ICISSP 2024)](https://www.scitepress.org/Papers/2024/124708/124708.pdf)
- [BPFVol3](https://github.com/vobst/BPFVol3)
- [BPF Rootkit Workshop (DFRWS EU 2023)](https://github.com/fkie-cad/bpf-rootkit-workshop)
- [LinkPro Analysis (Synacktiv)](https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis)
- [eBPF Backdoor Detection Framework](https://windshock.github.io/en/post/2025-04-29-ebpf-backdoor-detection-framework/)

---

## 8. Differentiation Opportunities

Based on this research, the following capabilities would differentiate our tool beyond anything currently available:

### Tier 1: No existing tool offers this
1. **Integrated dump quality scoring** with per-page confidence and cross-reference validation matrix
2. **Streaming analysis engine** that builds process lists and runs YARA as pages arrive
3. **Unified UEFI + OS-level analysis** detecting Runtime Services hooks from regular dumps
4. **eBPF rootkit detection** with helper function risk scoring (currently only Volatility plugins, no integrated tool)

### Tier 2: Exists in research, not in any product
5. **Temporal/differential analysis** with per-page timestamps and incremental snapshots (FIMAR is research prototype only)
6. **Statistical anomaly detection suite** with entropy profiling, process masquerading scoring, and permission anomaly detection in a single integrated pipeline
7. **Encrypted memory analysis** extracting metadata and structure even from SEV/TDX/CCA-encrypted dumps

### Tier 3: Enhancement of existing capabilities
8. **Context-aware streaming YARA** with PFN-based process attribution (single-pass scanning)
9. **Smear-aware analysis** with SAM-style timeline-based page table reconstruction
10. **Cross-platform consistency validation** with EPROCESS/PEB/VAD/PTE/PFN cross-reference checks
