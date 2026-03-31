# Memory Forensics Detection Algorithms: MemProcFS FindEvil & Volatility

## Research Reference for Rust Implementation

**Date:** 2026-03-31
**Sources:** MemProcFS source code (vmm/modules/m_evil_*.c), Volatility 2/3 plugin source, academic papers (2024-2025)

---

## 1. MemProcFS FindEvil Detection Algorithms

All FindEvil detections are implemented in `vmm/modules/m_evil_*.c` files within the
[ufrisk/MemProcFS](https://github.com/ufrisk/MemProcFS) repository. The aggregation
plugin is `m_fc_findevil.c`. FindEvil targets **user-mode malware only** on **64-bit
Windows 10/11**.

### 1.1 PROC_NOLINK — Hidden Process (DKOM) Detection

**Source:** `m_evil_proc1.c` (MEvilProc1_Modules function)

**Algorithm:**
1. MemProcFS maintains two independent process enumerations:
   - **List walk:** Traverse the `EPROCESS.ActiveProcessLinks` doubly-linked list
     starting from `PsActiveProcessHead` (obtained via KDBG or PDB symbols).
   - **Pool scan:** Scan physical memory for `_EPROCESS` pool tag signatures
     (`Proc` tag in pool headers) using heuristic validation.
2. A process found via pool scanning but absent from the `ActiveProcessLinks`
   list walk is flagged as `PROC_NOLINK`.
3. Validation checks: the process must have a valid DTB, non-zero PID, and
   reasonable creation timestamps to filter out terminated/corrupt entries.

**Cross-view technique:**
- MemProcFS uses its internal process table (populated from both list walk and
  scan) and marks processes that failed the linked-list verification.
- The `fNoLink` flag in the VMM process structure tracks this.

**Kernel structures needed:**
```
_EPROCESS.ActiveProcessLinks    // FLINK/BLINK doubly-linked list
_EPROCESS.UniqueProcessId       // PID
_EPROCESS.ImageFileName         // 15-byte process name
_EPROCESS.CreateTime / ExitTime
_EPROCESS.DirectoryTableBase    // CR3 / page table base
Pool header: Tag = "Proc" (0xe36f7250)
```

**Offsets (version-dependent, resolved via PDB):**
- Windows 10 22H2: `ActiveProcessLinks` at +0x448, `UniqueProcessId` at +0x440
- Windows 11 23H2: `ActiveProcessLinks` at +0x448, `UniqueProcessId` at +0x440

---

### 1.2 PROC_BASEADDR — Process Hollowing Detection

**Source:** `m_evil_proc2.c` or process initialization code

**Algorithm:**
1. Read `EPROCESS.SectionBaseAddress` — the kernel's record of where the process
   image section was originally mapped.
2. Read `PEB.ImageBaseAddress` — the user-mode record of the image base.
3. If `PEB.ImageBaseAddress != EPROCESS.SectionBaseAddress`, flag as `PROC_BASEADDR`.

**Why this works:**
- In process hollowing, the attacker unmaps the original image (via
  `NtUnmapViewOfSection`) and maps a new PE at a potentially different base.
- If the attacker updates `PEB.ImageBaseAddress` (required for the hollowed PE to
  work properly), it will differ from the kernel's `SectionBaseAddress`.
- Some sophisticated hollowers reset `PEB.ImageBaseAddress` to match, which evades
  this check. Combined with VAD analysis (checking MEM_PRIVATE vs MEM_IMAGE at the
  image base), this evasion can be countered.

**Kernel structures:**
```
_EPROCESS.SectionBaseAddress    // Kernel-side image base
_EPROCESS.Peb                  // Pointer to PEB (user space)
_PEB.ImageBaseAddress           // Offset +0x10 (64-bit)
```

---

### 1.3 PEB_MASQ — PEB Masquerading Detection

**Source:** `m_evil_proc2.c` → `MEvilProc2_PebMasquerade()`

**Algorithm (from source code):**
```c
VOID MEvilProc2_PebMasquerade(VMM_HANDLE H, PVMM_PROCESS pProcess)
{
    // 1. Get user-mode process parameters from PEB
    PVMMWIN_USER_PROCESS_PARAMETERS pu = VmmWin_UserProcessParameters_Get(H, pProcess);

    // 2. Bail if no user process params or image path too short
    if(!pu || (pu->cbuImagePathName < MIN_LENGTH)) { return; }

    // 3. Get kernel-side path (from EPROCESS/FILE_OBJECT)
    // pProcess->pObPersistent->uszPathKernel

    // 4. Compare: kernel path must end-with the PEB image path (minus drive prefix)
    //    Check if kernel path ends with PEB path (skipping "\\Device\\HarddiskVolume" prefix)
    if(CharUtil_StrEndsWith(kernelPath, pebImagePath + 12, TRUE)) { return; }  // OK

    // 5. Also check file extension match to filter Windows Store apps
    if(CharUtil_StrEndsWith(kernelPath, fileExtension, TRUE)) { return; }      // OK

    // 6. If neither match → PEB masquerading detected
    FcEvilAdd(H, EVIL_PEB_MASQ, pProcess, 0, "");
}
```

**What it compares:**
- **Kernel path:** Derived from `EPROCESS.ImageFilePointer` → `_FILE_OBJECT.FileName`
  or from the VAD tree's file mapping for the process image.
- **PEB path:** `PEB.ProcessParameters.ImagePathName` (user-writable structure).
- If an attacker modifies the PEB path to impersonate another process (e.g., changing
  "malware.exe" to "svchost.exe"), the kernel path won't match.

**Side effect:** When PEB_MASQ is detected, PE_NOLINK findings are suppressed for
that process (since the PEB is already known to be tampered with).

---

### 1.4 PE_NOLINK — Unlinked Module Detection

**Source:** `m_evil_proc1.c` → `MEvilProc1_Modules()`

**Algorithm (from source code):**
```c
VOID MEvilProc1_Modules(VMM_HANDLE H, PVMM_PROCESS pProcess)
{
    // 1. Get module map (combines PEB Ldr lists + VAD-based modules)
    VmmMap_GetModule(H, pProcess, 0, &pObModuleMap);

    // 2. Check if PEB Ldr is valid (at least one NORMAL type module)
    for(i = 0; i < pObModuleMap->cMap; i++) {
        if(pObModuleMap->pMap[i].tp == VMM_MODULE_TP_NORMAL) {
            fBadLdr = FALSE;  // PEB Ldr is working
            break;
        }
    }

    // 3. If no normal modules found → PEB_BAD_LDR (entire PEB may be corrupt)
    if(fBadLdr) { FcEvilAdd(EVIL_PEB_BAD_LDR, ...); return; }

    // 4. For each module in the map:
    for(i = 0; i < pObModuleMap->cMap; i++) {
        peModule = &pObModuleMap->pMap[i];

        // Skip normal (linked) modules
        if(peModule->tp == VMM_MODULE_TP_NORMAL) continue;

        // VMM_MODULE_TP_NOTLINKED = in VAD but not in PEB Ldr lists
        if(peModule->tp == VMM_MODULE_TP_NOTLINKED) {
            // → PE_NOLINK detection
            // Get the VAD entry for this module
            // Report: module name, base address, VAD info
        }

        // VMM_MODULE_TP_INJECTED = PE header found in non-image VAD
        if(peModule->tp == VMM_MODULE_TP_INJECTED) {
            // → PE_INJECT detection
        }
    }
}
```

**How MemProcFS builds the module map internally:**
1. Walk `PEB.Ldr.InLoadOrderModuleList` → get all "normal" modules
2. Walk `PEB.Ldr.InMemoryOrderModuleList` → additional modules
3. Walk `PEB.Ldr.InInitializationOrderModuleList` → additional modules
4. Walk the VAD tree → find all image-type VADs with PE headers
5. Cross-reference: VAD modules not in any PEB Ldr list → `NOTLINKED`
6. PE headers found in private/non-image VADs → `INJECTED`

This is equivalent to Volatility's `ldrmodules` plugin but integrated into
the module enumeration pipeline.

---

### 1.5 PE_PATCHED — Modified Executable Page Detection

**Source:** `m_evil_proc1.c` → `MEvilProc1_VadScan()` (the VAD page walk)

**Algorithm:**
1. For each process, enumerate all VADs of type **Image** (mapped PE files).
2. For each image VAD, walk the **extended VAD pages** (`VadEx` entries).
3. For each page in an image VAD:
   - Read the **process page table entry (PTE)** — this points to the physical page
     the process actually uses.
   - Read the **prototype PTE** — this points to the original, shared copy of the
     page as loaded from the file on disk.
   - Compare: if the PTE's physical address differs from the prototype PTE's physical
     address, AND the page has execute permission, the page has been patched in memory.
4. Flag as `PE_PATCHED` with details about PTE flags, VAD protection, and addresses.

**Key data from source:**
```c
#define EVIL_MAXCOUNT_VAD_PATCHED_PE  4  // max patched pages reported per VAD

// For each page in an image VAD:
pex = pObVadEx->pMap;  // VadEx entry with PTE + prototype PTE info

// Report format includes:
// - pex->pa          (physical address from process PTE)
// - pex->pte         (PTE value)
// - pex->proto.pa    (physical address from prototype PTE)
// - pex->proto.pte   (prototype PTE value)
// - PTE type (Hardware/Transition/etc.)
// - Page permissions (rwx flags from PTE)
```

**Why prototype PTEs matter:**
- When Windows loads a DLL, pages are initially **shared** via prototype PTEs
  (copy-on-write). The prototype PTE points to the original file-backed page.
- If malware patches a code page (e.g., inline hook in ntdll.dll), Windows
  creates a private copy (copy-on-write triggers), and the process PTE now
  points to a different physical page than the prototype PTE.
- By comparing `PTE.PhysicalAddress != PrototypePTE.PhysicalAddress` for
  executable pages, we detect modifications.

**False positives:** Relocations in 32-bit processes cause legitimate PTE divergence.
.NET JIT and SysWOW64 thunking also trigger false positives.

---

### 1.6 PRIVATE_RWX — RWX Private Memory Detection

**Source:** `m_evil_proc1.c` → `MEvilProc1_VadScan()`

**Algorithm:**
1. For each process, get the full VAD map.
2. For each VAD entry of type **Private** (not image-backed):
   - Walk the extended VAD pages (VadEx).
   - For each page, check the **actual PTE flags** (not just VAD protection):
     - `VADEXENTRY_FLAG_HARDWARE` = page is present
     - `VADEXENTRY_FLAG_W` = page is writable
     - `!(VADEXENTRY_FLAG_NX)` = page is executable (NX bit NOT set)
   - If a page is present + writable + executable → RWX detected.
3. Report up to `EVIL_MAXCOUNT_VAD_EXECUTE` (4) pages per VAD.
4. **Allowlist:** Some processes are excluded (JIT engines like browsers, .NET).

**Key distinction from Volatility's malfind:**
- Volatility checks **VAD protection flags** (PAGE_EXECUTE_READWRITE).
- MemProcFS checks **actual PTE flags** in the hardware page table, which is
  more accurate because VAD protection represents the *maximum* allowed
  protection, while PTE flags show the *current* protection.

**Additional detection types using the same scan:**
- `NOIMAGE_RWX`: RWX pages in non-image VADs (broader than private)
- `PRIVATE_RX`: Read+Execute only in private memory (no write — may indicate
  shellcode that used VirtualProtect to remove write after injection)
- `NOIMAGE_RX`: Read+Execute in non-image VADs

---

### 1.7 UM_APC — User-Mode APC Injection Detection

**Source:** Likely in `m_evil_thread1.c` or a dedicated APC scanner

**Algorithm:**
1. For each thread (`ETHREAD`), examine the **APC queue**:
   - `KTHREAD.ApcState.ApcListHead[UserMode]` — the user-mode APC queue
2. For each queued user-mode APC (`KAPC` structure):
   - Read `KAPC.NormalRoutine` — the function to execute in user mode
   - Read `KAPC.NormalContext` — parameter passed to the routine
   - Read `KAPC.SystemArgument1` and `KAPC.SystemArgument2`
3. Resolve each address to a module/symbol.
4. If `NormalRoutine` points to suspicious memory (private, RWX, or unknown
   module), flag as `UM_APC`.

**Output fields:**
- ApcNormalRoutine address
- ApcNormalContext address and description
- ApcSystemArgument1 address and description
- ApcSystemArgument2 address and description
- Thread ID (TID)

**Kernel structures:**
```
_KTHREAD.ApcState.ApcListHead[0]     // KernelMode APC list
_KTHREAD.ApcState.ApcListHead[1]     // UserMode APC list
_KAPC.NormalRoutine                   // User-mode callback
_KAPC.NormalContext                   // Callback parameter
_KAPC.SystemArgument1/2              // Additional arguments
_KAPC.ApcListEntry                   // LIST_ENTRY for linked list
```

---

### 1.8 HIGH_ENTROPY — Encrypted/Packed Payload Detection

**Source:** Dedicated m_evil module (likely m_evil_proc3.c or similar)

**Algorithm:**
1. For each process, scan private memory VADs.
2. For regions of sufficient size, calculate **Shannon entropy** per region:
   ```
   H = -Σ p(x) * log2(p(x))  for each byte value x ∈ [0, 255]
   ```
   where `p(x)` = frequency of byte value `x` / total bytes.
3. Maximum Shannon entropy for byte data = 8.0 bits.
4. Threshold: Regions with entropy > ~7.0-7.2 bits are flagged (exact threshold
   is in the source code; typical encrypted/compressed data has entropy > 7.0).
5. Applies to private memory regions — not image-backed memory.

**False positives:** Legitimately encrypted data (DRM, compressed resources),
obfuscated binaries, and crypto libraries will trigger this detection.

---

### 1.9 THREAD — Thread-Based Anomaly Detection

**Source:** `m_evil_thread1.c` (MEvilThread1 functions)

**Algorithm (from source code):**

Based on Elastic Security Labs research on
[GetInjectedThreadEx detection](https://www.elastic.co/security-labs/get-injectedthreadex-detection-thread-creation-trampolines).

```c
typedef struct tdMEVIL_THREAD1_ENTRY {
    QWORD vaETHREAD;
    QWORD vaWin32StartAddress;
    DWORD dwPID;
    DWORD dwTID;
    // detections:
    BOOL fNoImage;               // Thread start not in image memory
    BOOL fPrivate;               // Thread start in private memory
    BOOL fBadModule;             // Thread in module without legit entry point
    BOOL fLoadLibrary;           // Start address = kernel32!LoadLibrary
    BOOL fSystemImpersonation;   // Thread impersonating SYSTEM
    BOOL fNoRtlUserThreadStart;  // Startup not via RtlUserThreadStart
} MEVIL_THREAD1_ENTRY;
```

**Initialization phase:**
1. Find `smss.exe` process (first non-terminated instance).
2. Resolve key addresses from PDB symbols:
   - `kernel32.dll!LoadLibrary`
   - `ntdll.dll!RtlUserThreadStart`
   - `ntdll.dll!TppWorkerThread` (thread pool)
   - `ntdll.dll!EtwpLogger` (ETW logger thread)
   - `ntdll.dll!DbgUiRemoteBreakin` (debugger attach)
   - `ntdll.dll!RtlpQueryProcessDebugInformationRemote`

**Per-thread analysis:**
1. Read `ETHREAD.Win32StartAddress` — the effective start address.
2. Look up the VAD containing the start address:
   - If in **private memory** → `fPrivate = TRUE` (shellcode indicator)
   - If **not in any image VAD** → `fNoImage = TRUE`
3. Check if start address matches `LoadLibrary` → `fLoadLibrary = TRUE`
   (classic `CreateRemoteThread` + `LoadLibrary` injection pattern)
4. Check if the thread's initial call comes through `RtlUserThreadStart`
   (all legitimate user threads should) → `fNoRtlUserThreadStart` if not.
5. Check token impersonation level for SYSTEM → `fSystemImpersonation`
6. Allow-list known legitimate thread entry points (TppWorkerThread,
   EtwpLogger, DbgUiRemoteBreakin, etc.).

---

### 1.10 Additional FindEvil Detections

| Detection | Algorithm |
|-----------|-----------|
| `PROC_PARENT` | Check well-known processes (smss, csrss, services, svchost, etc.) against expected parent using ROT13 hash of process names. Validate creation time ordering. |
| `PROC_USER` | Flag well-known system processes (cmd, powershell) running as unexpected users. Uses token SID comparison. |
| `PROC_BAD_DTB` | Flag active processes where `EPROCESS.DirectoryTableBase` resolves to 0 in MemProcFS (invalid page tables). |
| `PROC_DEBUG` | Flag non-SYSTEM processes with `SeDebugPrivilege` enabled. |
| `DRIVER_PATH` | Compare kernel driver paths against allowlist (`\SystemRoot\system32\DRIVERS\`, etc.). Flag drivers from non-standard paths. |
| `PE_INJECT` | PE header found in non-image (private) VAD memory → reflective DLL injection. |
| `YR_*` | YARA rules (Elastic Security) applied to process memory and file objects. |
| `AV_*` | Parse Windows Defender MPLog files from the analyzed system for detection events. |

---

## 2. Volatility Detection Plugin Algorithms

### 2.1 malfind — Injected Code Detection

**Source:** `volatility/plugins/malware/malfind.py` (Volatility 2),
`volatility3/framework/plugins/windows/malfind.py` (Volatility 3)

**Algorithm (from source code):**
```python
class Malfind(vadinfo.VADDump):
    # Core detection: uses task._injection_filter()
    # which checks each VAD for injection characteristics

    def _is_vad_empty(self, vad, address_space):
        """Filter out false positives where VAD region is all zeros or paged out"""
        PAGE_SIZE = 0x1000
        all_zero = True
        offset = vad.Start
        while offset < vad.Start + vad.Length:
            data = address_space.zread(offset, PAGE_SIZE)
            if data != "\x00" * PAGE_SIZE:
                all_zero = False
                break
            offset += PAGE_SIZE
        return all_zero  # True = empty, skip this VAD
```

**Detection criteria (task._injection_filter):**
1. VAD must have **execute** permission: `PAGE_EXECUTE_READWRITE`,
   `PAGE_EXECUTE_WRITECOPY`, or `PAGE_EXECUTE_READ`
2. VAD tag must be `VadS` (short VAD — no file mapping) or `VadF` with
   no associated file object
3. If `VadS` + executable → suspicious (no file already occupying the space)
4. If region contains PE header (MZ magic `0x5A4D`) → very suspicious
5. Optional refined mode (`-W`): Skip regions not starting with known
   opcode patterns (e.g., PUSH EBP) — reduces noise but may miss NOP sleds

**Output per detection:**
- Process name, PID
- VAD start address, tag, protection
- First 64 bytes of memory (hex + disassembly)
- Option to dump entire region to disk

---

### 2.2 psxview — Cross-View Hidden Process Detection

**Source:** `volatility/plugins/malware/psxview.py` (Volatility 2)

**Algorithm — 7 enumeration methods cross-referenced:**

```python
class PsXview:
    def check_pslist(self, all_tasks):
        """Method 1: PsActiveProcessHead linked list walk"""
        return dict((offset, process) for process in all_tasks)

    def check_psscan(self):
        """Method 2: Pool tag scanning for EPROCESS objects"""
        return dict((offset, process)
                    for process in PSScan(self._config).calculate())

    def check_thrdproc(self, addr_space):
        """Method 3: ETHREAD scanning → bounce to owning EPROCESS"""
        for ethread in ThrdScan(self._config).calculate():
            process = ethread.ThreadsProcess.dereference()
            if process and process.ExitTime == 0 and process.UniqueProcessId > 0:
                ret[offset] = process

    def check_pspcid(self, addr_space):
        """Method 4: PspCidTable handle table enumeration"""
        # Walk the PspCidTable (kernel handle table for PIDs/TIDs)
        # Each valid entry with type _EPROCESS is a running process

    def check_csrss_handles(self, all_tasks):
        """Method 5: CSRSS.exe open handles to process objects"""
        # Find csrss.exe, enumerate its handle table
        # Each handle to a process object = known process

    def check_session_processes(self, addr_space):
        """Method 6: Session process list (Mm session space)"""
        # Walk MmSessionSpace.ProcessList for each session

    def check_desktop_threads(self, addr_space):
        """Method 7: Desktop thread scanning"""
        # Enumerate window station → desktop → thread list
        # Bounce from thread to owning process
```

**Cross-reference logic:**
- Run all 7 methods, collect process sets.
- Display matrix: for each process, show True/False for each method.
- A process showing `False` in `pslist` but `True` in `psscan` = **hidden
  from EPROCESS list** (DKOM attack).
- A process showing `False` in `psscan` but `True` elsewhere = **pool
  header corruption** or memory paging.

**Volatility 3 version** (`windows.psxview`): Uses 4 of these methods as
documented in "The Art of Memory Forensics."

---

### 2.3 check_syscall — Linux Syscall Table Hook Detection

**Source:** `volatility/plugins/linux/check_syscall.py`

**Algorithm:**
```python
class linux_check_syscall:
    def calculate(self):
        # 1. Locate sys_call_table symbol address
        table_addr = self.addr_space.profile.get_symbol("sys_call_table")

        # 2. Determine table size (3 methods, take minimum):
        #    a) Disassemble syscall entry (system_call_fastpath or sysenter_do_call)
        #       to find: "cmp reg, NR_syscalls" instruction
        #    b) Count __syscall_meta__* symbols
        #    c) Find next symbol after sys_call_table, compute size

        # 3. For each entry in sys_call_table[0..table_size]:
        for i in range(table_size):
            # Read function pointer
            func_addr = obj.Object("address", table_addr + (i * ptr_size), vm)

            # 4. Resolve to symbol name
            sym_name = self.profile.get_symbol_by_address("kernel", func_addr)

            # 5. Check if address is within known kernel/module text
            module = self._is_known_address(func_addr)

            # 6. Also check for INLINE HOOKS at the handler address:
            if has_distorm3:
                # Disassemble first bytes of handler
                # Look for JMP/CALL to addresses outside kernel text
                # This catches ftrace-style hooks

        # 7. Also scan: IA32 syscall table (32-bit compat on 64-bit)
        #    table_addr_ia32 = profile.get_symbol("ia32_sys_call_table")
```

**What constitutes a "hooked" entry:**
- Function pointer outside kernel text section boundaries
- Function pointer inside a kernel module (may be legitimate or rootkit)
- Inline JMP/CALL at the handler's entry point redirecting elsewhere

---

### 2.4 check_idt — Interrupt Descriptor Table Check

**Source:** `volatility/plugins/linux/check_idt.py`

**Algorithm:**
```python
class linux_check_idt:
    def calculate(self):
        # IDT structure (64-bit):
        # struct idt_desc {
        #     u16 offset_low;     // bits 0-15 of handler address
        #     u16 segment;        // code segment selector
        #     u16 ist;            // interrupt stack table
        #     u16 offset_middle;  // bits 16-31
        #     u32 offset_high;    // bits 32-63
        #     u32 unused;
        # };

        # 1. Get idt_table symbol address
        table_addr = profile.get_symbol("idt_table")

        # 2. Determine gate structure type (arch-dependent):
        #    gate_struct64 / gate_struct / idt_desc

        # 3. Check vectors: 0-19 (hardware exceptions) + 128 (syscall)
        check_idxs = list(range(0, 20)) + [128]

        # 4. For each IDT entry:
        for i in range(256):
            gate = Object(idt_type, table_addr + i * entry_size, vm)

            # 5. Reconstruct full handler address:
            handler_addr = (gate.offset_high << 32) |
                          (gate.offset_middle << 16) |
                          gate.offset_low

            # 6. Check if handler_addr is in kernel symbol table
            if handler_addr not in sym_addrs:
                # Potential hook!
                yield (i, handler_addr, "HOOKED")
```

---

### 2.5 ssdt — System Service Descriptor Table Validation

**Source:** `volatility/plugins/ssdt.py`

**Algorithm (unique approach — NOT via exported symbol):**
```python
def find_tables(nt_base, start_addr, vm):
    """Find SSDT by disassembling KeAddSystemServiceTable.

    Looking for instructions like:
    cmp qword ptr [r10+r11+RVA_SSDT], 0
    cmp qword ptr [r10+r11+RVA_SSDT_SHADOW], 0

    The RVAs extracted give us KeServiceDescriptorTable
    and KeServiceDescriptorTableShadow locations.
    """

class SSDT(common.AbstractWindowsCommand):
    def calculate(self):
        # 1. Find all unique SSDT pointers via ETHREAD scanning
        #    (NOT via KeServiceDescriptorTable export — more robust)
        for ethread in ThrdScan:
            service_table = ethread.Tcb.ServiceTable
            tables.add(service_table)

        # 2. For each unique service table found:
        for table_addr in tables:
            # 3. Read ServiceDescriptor array (up to 4 tables)
            #    KeServiceDescriptorTable contains:
            #    - Base: pointer to system call function array
            #    - Count: pointer to call count array
            #    - Limit: number of entries
            #    - Number: pointer to argument table

            # 4. For each entry in the function array:
            for i in range(table.Limit):
                # On x64: entries are relative offsets, not absolute addresses
                # func_addr = base + (entry >> 4)
                func_addr = resolve_entry(base, i)

                # 5. Find containing module
                module = find_module(func_addr, module_list)

                # 6. If module not found → "UNKNOWN" (potential hook)
                if not module:
                    yield (i, func_addr, "UNKNOWN")
                else:
                    yield (i, func_addr, module.BaseDllName)
```

**Why ETHREAD-based discovery is superior:**
- Rootkits can create copies of the SSDT and assign them to specific threads
  via `ETHREAD.Tcb.ServiceTable`.
- Scanning all threads discovers these shadow/modified SSDTs that a simple
  symbol lookup would miss.

---

### 2.6 driverirp — Driver IRP Hook Detection

**Source:** `volatility/plugins/malware/malfind.py` (DriverIrp class in the same file)

**Algorithm:**
```python
class DriverIrp:
    def calculate(self):
        # 1. Scan for DRIVER_OBJECT structures in pool memory
        for driver in DriverScan(self._config).calculate():

            # 2. Read the MajorFunction table (28 entries)
            # IRP_MJ_CREATE, IRP_MJ_READ, IRP_MJ_WRITE, IRP_MJ_DEVICE_CONTROL...
            for i, func_addr in enumerate(driver.MajorFunction):

                # 3. Resolve containing module
                module = find_module(func_addr, module_list)

                # 4. Check for inline hooks at the IRP handler address:
                #    Read first N bytes, disassemble
                #    Look for JMP/CALL redirections
                data = read_memory(func_addr, 24)
                for instruction in disassemble(data):
                    if is_hook_instruction(instruction):
                        # Report inline hook
                        yield HookInfo(driver, i, func_addr, instruction)
```

**28 IRP Major Functions checked:**
`IRP_MJ_CREATE`, `IRP_MJ_CREATE_NAMED_PIPE`, `IRP_MJ_CLOSE`, `IRP_MJ_READ`,
`IRP_MJ_WRITE`, `IRP_MJ_QUERY_INFORMATION`, `IRP_MJ_SET_INFORMATION`,
`IRP_MJ_QUERY_EA`, `IRP_MJ_SET_EA`, `IRP_MJ_FLUSH_BUFFERS`, etc.

---

### 2.7 check_modules — Linux Hidden Module Detection

**Source:** `volatility/plugins/linux/check_modules.py` and
`volatility3/framework/plugins/linux/check_modules.py`

**Algorithm:**
```
Cross-view comparison of 5 independent kernel data sources:

Source 1: modules linked list (struct module.list → list_head)
  - Standard lsmod enumeration
  - Walk: modules symbol → first module → list.next → ...

Source 2: module_kset / sysfs kobject chain
  - Walk: module_kset.list → kobject entries → parent module
  - Represents /sys/module/ entries

Source 3: Module memory tree (kernel 4.2+)
  - Red-black tree of module_layout / module_memory structures
  - Tracks kernel memory allocated for module text/data

Source 4: kallsyms symbol table
  - Symbols tagged with owning module name
  - Enumerate all symbols with non-empty module field

Source 5: Physical memory scanning
  - Scan for struct module signatures in kernel memory

Detection: Module in Source 2-5 but NOT in Source 1 = hidden module
(rootkit removed itself from the standard list but forgot other views)
```

**DFRWS 2025 research** by Roland Nagy et al. extended this to all 5 sources
and validated against 55 rootkit-infected memory dumps across 27 kernel versions.

---

## 3. Windows Kernel Structures Required for Implementation

### 3.1 EPROCESS (Critical Fields)

```
Offset  Field                        Purpose
------  -----                        -------
+0x000  Pcb (KPROCESS)               Contains DirectoryTableBase (DTB/CR3)
+0x028  DirectoryTableBase           Page table base physical address
+0x440  UniqueProcessId              Process ID
+0x448  ActiveProcessLinks           LIST_ENTRY — doubly linked list
+0x450  RundownProtect               Process rundown protection
+0x5A0  ImageFileName                15-byte ASCII process name
+0x5A8  PriorityClass                Priority
+0x550  Peb                          Pointer to PEB (user space VA)
+0x558  InheritedFromUniqueProcessId Parent PID
+0x570  Token                        EX_FAST_REF to _TOKEN
+0x7D8  VadRoot                      Root of VAD balanced tree
+0x7E8  VadHint                      Last VAD accessed (cache)
+0x520  SectionBaseAddress           Original image mapping address
+0x538  ImageFilePointer             _FILE_OBJECT for the executable
```
*Note: Offsets are for Windows 10 22H2 x64. MUST be resolved via PDB symbols.*

### 3.2 PEB (Process Environment Block)

```
Offset  Field                        Purpose
------  -----                        -------
+0x010  ImageBaseAddress             Base address of process image
+0x018  Ldr                          Pointer to _PEB_LDR_DATA
+0x020  ProcessParameters            Pointer to RTL_USER_PROCESS_PARAMETERS
+0x0BC  NumberOfProcessors           (useful validation field)
+0x100  pImageHeaderHash             (PE header hash)
```

### 3.3 PEB_LDR_DATA (Module Lists)

```
Offset  Field                           Purpose
------  -----                           -------
+0x010  InLoadOrderModuleList           LIST_ENTRY head
+0x020  InMemoryOrderModuleList         LIST_ENTRY head
+0x030  InInitializationOrderModuleList LIST_ENTRY head
```

Each list links `_LDR_DATA_TABLE_ENTRY` structures:
```
+0x000  InLoadOrderLinks
+0x010  InMemoryOrderLinks
+0x020  InInitializationOrderLinks
+0x030  DllBase                 Module base address
+0x038  EntryPoint              Module entry point
+0x040  SizeOfImage             Module size
+0x048  FullDllName             UNICODE_STRING
+0x058  BaseDllName             UNICODE_STRING
```

### 3.4 VAD (Virtual Address Descriptor)

```
_MMVAD_SHORT:
+0x000  VadNode                 _RTL_BALANCED_NODE (left, right, parent)
+0x018  StartingVpn             Start virtual page number
+0x01C  EndingVpn               End virtual page number
+0x020  StartingVpnHigh         High bits (for large VA)
+0x021  EndingVpnHigh           High bits
+0x024  CommitChargeAndFlags    Commit charge + flags
+0x028  Flags                   _MMVAD_FLAGS (Protection, VadType, etc.)

_MMVAD (long — has file mapping info):
+0x000  Core                    _MMVAD_SHORT
+0x040  Subsection              Pointer to _SUBSECTION (file mapping)

Key VAD Flags:
- Protection: 3 bits encoding PAGE_* constants
- VadType: VadNone, VadDevicePhysicalMemory, VadImageMap, VadAwe, VadWriteWatch, VadLargePages, VadRotatePhysical, VadLargePageSection
- PrivateMemory: 1 = private (not shared/mapped)

Protection encoding (3-bit field):
0 = PAGE_NOACCESS
1 = PAGE_READONLY
2 = PAGE_EXECUTE
3 = PAGE_EXECUTE_READ
4 = PAGE_READWRITE
5 = PAGE_WRITECOPY
6 = PAGE_EXECUTE_READWRITE
7 = PAGE_EXECUTE_WRITECOPY
```

### 3.5 PTE (Page Table Entry — x86-64)

```
Bit(s)  Field                Purpose
------  -----                -------
0       Present (P)          Page is in physical memory
1       Read/Write (R/W)     0=read-only, 1=read-write
2       User/Supervisor      0=kernel, 1=user
3       PWT                  Page write-through
4       PCD                  Page cache disabled
5       Accessed (A)         Page has been read
6       Dirty (D)            Page has been written
7       PAT/PS               Page size (4KB vs 2MB)
11:8    Available            OS-defined flags
12:M    PFN                  Physical frame number (bits 12-M)
62      Available            OS-defined
63      NX (XD)              No-execute bit (1 = not executable)

Prototype PTE (software PTE — not hardware):
- Located in the SUBSECTION/CONTROL_AREA structures
- Points to the original file-backed page
- Used by MemProcFS for PE_PATCHED comparison
```

### 3.6 KAPC (Kernel APC)

```
Offset  Field                Purpose
------  -----                -------
+0x000  Type                 APC type
+0x001  SpareByte0
+0x002  Size
+0x003  SpareByte1
+0x004  SpareLong0
+0x008  Thread               Pointer to KTHREAD
+0x010  ApcListEntry         LIST_ENTRY in APC queue
+0x020  KernelRoutine        Kernel-mode APC routine
+0x028  RundownRoutine       Cleanup routine
+0x030  NormalRoutine        User-mode APC routine (for UM APCs)
+0x038  NormalContext         Parameter for NormalRoutine
+0x040  SystemArgument1      Additional parameter
+0x048  SystemArgument2      Additional parameter
+0x050  ApcStateIndex
+0x051  ApcMode              KernelMode(0) or UserMode(1)
+0x052  Inserted             Whether APC is in queue
```

### 3.7 KTHREAD / ETHREAD (Thread Analysis)

```
_KTHREAD:
+0x000  Header               DISPATCHER_HEADER
+0x098  ApcState             KAPC_STATE (contains ApcListHead[2])
+0x1C0  Teb                  Pointer to TEB (user space)
+0x1D8  Win32Thread          Win32 thread info pointer
+0x220  Process              Back-pointer to KPROCESS/EPROCESS
+0x280  ServiceTable         Pointer to SSDT used by this thread

_ETHREAD:
+0x000  Tcb                  Embedded KTHREAD
+0x640  Cid                  CLIENT_ID (ProcessId + ThreadId)
+0x680  Win32StartAddress    Thread's start function address
+0x6A8  ThreadListEntry      LIST_ENTRY in process thread list
```

---

## 4. Linux Kernel Structures for Rootkit Detection

### 4.1 Syscall Table Hook Detection

```c
// sys_call_table: array of function pointers
// Located via: kallsyms_lookup_name("sys_call_table") or symbol file
extern void *sys_call_table[];

// Detection algorithm:
for (int i = 0; i < NR_syscalls; i++) {
    void *handler = sys_call_table[i];

    // Check 1: Is handler within kernel text section?
    if (handler < _stext || handler > _etext) {
        // If in a module range → identify module
        // If in unknown memory → HOOKED
    }

    // Check 2: Inline hook at handler entry
    uint8_t *code = (uint8_t *)handler;
    if (code[0] == 0xE9) {  // JMP rel32
        // Extract target, check if in kernel text
    }
    if (code[0] == 0x48 && code[1] == 0xB8) {  // MOV RAX, imm64 (+ JMP RAX)
        // Extract target
    }
}

// Also check: ia32_sys_call_table (32-bit compat syscalls on x64)
```

### 4.2 Kernel Module Hiding Detection

```c
// Source 1: Standard module list
struct module *mod;
list_for_each_entry(mod, &modules, list) {
    known_modules.insert(mod->name);
}

// Source 2: module_kset (sysfs)
struct kset *kset = module_kset;  // symbol
struct kobject *kobj;
list_for_each_entry(kobj, &kset->list, entry) {
    struct module_kobject *mk = container_of(kobj, struct module_kobject, kobj);
    sysfs_modules.insert(mk->mod->name);
}

// Source 3: Module memory tree (kernel 6.4+)
// mod_tree / module_memory red-black tree
// Walk rb_first/rb_next, each node → struct module

// Source 4: kallsyms
// Enumerate all symbols, collect unique module names

// Cross-view: module in Sources 2-4 but NOT Source 1 → HIDDEN
```

### 4.3 eBPF Rootkit Detection (2024-2025)

**New attack vectors:**
- **eBPF syscall hooking:** Attach BPF programs to tracepoints/kprobes for
  `sys_enter_*` / `sys_exit_*` to intercept and modify syscall behavior.
- **io_uring evasion:** Use `io_uring_enter` to batch file/network/process
  operations that bypass syscall-based monitoring entirely.

**Detection approach:**
```c
// 1. Enumerate loaded BPF programs
//    Read /proc/*/fdinfo/* for BPF map/prog references
//    Or walk kernel bpf_prog_array structures

// 2. Check BPF program attachment points
//    Tracepoints: /sys/kernel/debug/tracing/events/syscalls/
//    Kprobes: registered kprobes list
//    XDP/TC: network hooks

// 3. Validate BPF helper functions used
//    bpf_probe_write_user — can modify user memory (dangerous)
//    bpf_override_return — can change syscall return values

// 4. Cross-reference with known BPF programs (e.g., from security tools)
```

### 4.4 Inline Function Hook Detection

```c
// For each critical kernel function:
// 1. Read first N bytes from memory
// 2. Compare against known-good bytes from vmlinux/System.map

// Common hook patterns (x86-64):
// JMP rel32:         E9 xx xx xx xx
// MOV RAX + JMP RAX: 48 B8 xx xx xx xx xx xx xx xx FF E0
// INT3 + ftrace:     CC (replaced by ftrace framework)

// ftrace-based hooks are legitimate but can be abused by rootkits:
// Check ftrace_ops list for unexpected callbacks
struct ftrace_ops *ops;
// Walk ftrace_ops_list and verify each callback address
```

---

## 5. Novel Detection Techniques (2024-2025 Academic Research)

### 5.1 Call Stack Analysis for EDR Bypass Detection

**Research:** Volatility 3 plugins for detecting direct/indirect syscalls and
module overwriting (2024-2025 papers).

**Algorithm:**
1. For each thread, walk the user-mode call stack using frame pointers or
   RBP chain (or stack unwinding via `.pdata` / `.xdata` on x64).
2. Extract return addresses from the stack.
3. Validate each return address:
   - Must be within a known module (from VAD map)
   - Must follow a CALL instruction (check preceding bytes)
   - Return address sequence must form a plausible call chain
4. **Direct syscall detection:** If a `SYSCALL` instruction is found outside
   `ntdll.dll`, the thread is using direct syscalls (EDR bypass technique).
5. **Indirect syscall detection:** If the call chain shows execution bouncing
   through `ntdll.dll` syscall stubs via computed jumps (not normal CALLs),
   this indicates indirect syscall usage.
6. **Module overwriting:** If a return address points into a module whose
   text section has been modified (compare against on-disk PE), the module
   may have been stomped for code execution.

### 5.2 Memory Segment Entropy Profiling

**Research:** "Intelligent malware detection method based on memory segments"
(Springer Cybersecurity, 2025)

**Algorithm:**
- Input: Raw memory byte sequences from process memory dumps
- 1D CNN applied to memory segments (page-level or region-level)
- Features automatically learned (no manual feature engineering)
- Achieves 98.28% accuracy on malware detection
- Key insight: malware memory segments have distinctive byte-level patterns
  detectable by convolutional filters

### 5.3 Thread Anomaly Detection with VMI

**Research:** "Utilizing Virtual Machine Introspection and Memory Forensics" (2025)

**Compared tools:**
- Hollowfind, Malfind, Threadmap, Malofind, ProcInjectionsFind
- Evaluated on Precision, Recall, FPR across Windows environments
- Thread-based analysis (Threadmap) showed strong detection for:
  - Thread creation trampolines
  - Start address spoofing
  - APC-based injection
  - Thread context hijacking

### 5.4 LLM-Augmented Memory Forensics

**Research:** ACM Digital Threats (2025)

**Approach:**
- Memory dumps processed by Volatility to extract structured features
- LLMs (GPT-4o, Gemini, Grok) used for automated triage
- Rule-based explainable layer recommended before LLM inference
- Challenge: LLM hallucinations on forensic evidence
- Best accuracy: GPT-4o with rule-based pre-filtering

### 5.5 Kernel Data Type Evolution Impact

**Research:** "Evolution of kernel data types" (ScienceDirect, 2025)

**Key finding:** Analysis of 2,298 Volatility 3 profiles (Linux/macOS/Windows,
2007-2024) shows that forensically-relevant kernel structures change frequently.
Recommendation: Move toward hybrid approaches combining automated structure
inference, version-aware parsing, and redundant analysis strategies.

---

## 6. Implementation Priority for Rust Tool

### Tier 1 — High Value, Well-Defined Algorithms
1. **PROC_NOLINK** (cross-view process detection via list walk vs pool scan)
2. **PRIVATE_RWX** (VAD walk + PTE flag checking for RWX private pages)
3. **PE_NOLINK** (cross-reference PEB Ldr lists vs VAD image entries)
4. **malfind equivalent** (VAD tag + protection + MZ header scan)
5. **Linux check_syscall** (syscall table integrity check)
6. **Linux check_modules** (cross-view module detection)

### Tier 2 — Moderate Complexity
7. **PE_PATCHED** (prototype PTE comparison — requires PTE walking infrastructure)
8. **PEB_MASQ** (kernel vs user-land path comparison)
9. **PROC_BASEADDR** (PEB.ImageBaseAddress vs EPROCESS.SectionBaseAddress)
10. **SSDT validation** (ETHREAD ServiceTable scanning + module resolution)
11. **THREAD anomalies** (Win32StartAddress validation, LoadLibrary detection)

### Tier 3 — Advanced / Research-Level
12. **HIGH_ENTROPY** (Shannon entropy per memory region)
13. **UM_APC** (APC queue inspection)
14. **IDT/check_idt** (interrupt handler validation)
15. **driverirp** (IRP hook detection with inline hook analysis)
16. **Call stack analysis** (direct/indirect syscall detection)
17. **eBPF rootkit detection** (BPF program enumeration)

---

## References

- [MemProcFS FindEvil Wiki](https://github.com/ufrisk/MemProcFS/wiki/FS_FindEvil)
- [MemProcFS Source Code](https://github.com/ufrisk/MemProcFS) — vmm/modules/m_evil_*.c
- [Volatility 2 Malware Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference-Mal)
- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
- [Elastic Security Labs: Get-InjectedThreadEx](https://www.elastic.co/security-labs/get-injectedthreadex-detection-thread-creation-trampolines)
- [Elastic Security Labs: Hooked on Linux](https://www.elastic.co/security-labs/linux-rootkits-1-hooked-on-linux)
- [HollowFind Volatility Plugin](https://cysinfo.com/detecting-deceptive-hollowing-techniques/)
- [Detecting Hidden Kernel Modules in Memory Snapshots, DFRWS 2025](https://dfrws.org/wp-content/uploads/2025/05/Detecting-hidden-kernel-modules-in-memory-snapshots.pdf)
- [HKRD: Hidden Kernel-level Rootkit Detector](https://www.sciencedirect.com/science/article/abs/pii/S0167404825002718)
- [Memory Analysis for Malware Detection: OSCAR Survey, ACM Computing Surveys 2025](https://dl.acm.org/doi/10.1145/3764580)
- [VoidLink Rootkit Analysis, Elastic Security Labs](https://www.elastic.co/security-labs/illuminating-voidlink)
- [Process Hollowing Detection via PEB vs VAD](https://cysinfo.com/detecting-deceptive-hollowing-techniques/)
- [ired.team: Process Hollowing and PE Relocations](https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations)
- [ired.team: PEB Masquerading](https://www.ired.team/offensive-security/defense-evasion/masquerading-processes-in-userland-through-_peb)
- [Aquasec: Hunting Rootkits with eBPF](https://www.aquasec.com/blog/linux-syscall-hooking-using-tracee/)
