# Test Data — memory-forensic

All corpora here are **memory forensics** challenges or samples (Windows/Linux memory dumps,
crash dumps, or hibernation files). Artefacts with no memory component (pure disk images,
memory-less UAC collections, iOS images) live in `~/src/issen/tests/data/` and are not
mirrored here.

Three memory-bearing corpora (`cyberspace-ctf-2024`, `dfirmadness-szechuan-sauce`,
`hal-linux-dfir-challenge`) are **owned by issen** and live in `~/src/issen/tests/data/`.
They are **symlinked** into this directory for local convenience. The symlinks are
**gitignored** (`tests/data/*` is excluded from git except this README), so git never tracks
or materializes them — the Windows CI runner sees only tracked files and is unaffected. (The
fleet caution against symlinked fixtures applies to *committed* symlinks, which git would
materialize as a plain text file on Windows; gitignored ones never reach CI.) Tests resolve
this data via its `tests/data/…` path or the `MEMF_TEST_DATA` env var.

Files are large and **not tracked in git** — download them manually per the instructions below.
For the fleet-wide corpus inventory see [`docs/corpus-catalog.md`](../../docs/corpus-catalog.md).

---

## Corpora

### cyberspace-ctf-2024 *(owned by issen)*

| Field | Value |
|---|---|
| **Source** | CyberSpace CTF 2024 — memory forensics challenge |
| **Type** | Windows memory forensics |
| **Windows build** | Unknown — no writeup available; run `imageinfo` on extracted image |
| **Location** | `~/src/issen/tests/data/cyberspace-ctf-2024/` (symlinked into `tests/data/`) |
| **MD5** | `c4821afa54754127a3a2161bafccea90` (703 MB) |
| **Redistribution** | Public CTF artifact |

Files:

| File | Notes |
|---|---|
| `csctf-2024_forensics_memory.zip` | Windows memory image (703 MB) |

---

### dfirmadness-szechuan-sauce *(owned by issen)*

| Field | Value |
|---|---|
| **Author** | DFIR Madness — "Stolen Szechuan Sauce" Case 001 |
| **Type** | Mixed: Windows memory dumps + disk images + PCAP |
| **Windows build** | Windows Server 2019 (DC01, build 17763) / Windows 10 x64 (DESKTOP-SDN1RPT, build 17763) |
| **Source** | <https://dfirmadness.com/the-stolen-szechuan-sauce/> |
| **Location** | `~/src/issen/tests/data/dfirmadness-szechuan-sauce/` (symlinked into `tests/data/`) |
| **Redistribution** | Public DFIR challenge |

Memory-relevant files:

| File | MD5 | Notes |
|---|---|---|
| `DC01-memory.zip` | `64a4e2cb47138084a5c2878066b2d7b1` | Windows Server 2019 DC01 memory dump (561 MB) |
| `DESKTOP-SDN1RPT-memory.zip` | `cf31e2635c77811aaa1bb04a92a721e2` | Windows 10 x64 desktop memory dump (803 MB) |
| `DC01-pagefile.zip` | `964eeaf0009d08cc101de4a83a4e5d23` | DC01 pagefile (14 MB) |
| `Desktop-SDN1RPT-pagefile.zip` | `45c096f2688a0b5de0346fb72391b245` | Desktop pagefile (222 MB) |

Non-memory files (disk images, PCAP, autoruns) also present — use issen directly for those.

---

### hal-linux-dfir-challenge *(owned by issen)*

| Field | Value |
|---|---|
| **Source** | Self-collected — Linux VirtualBox VM triaged with UAC + AVML, March 24, 2026 |
| **Type** | Linux memory forensics (AVML `.lime` format) |
| **Kernel** | VirtualBox Linux guest — derive the exact banner/version from the dump (no published writeup) |
| **Location** | `~/src/issen/tests/data/hal-linux-dfir-challenge/` (symlinked into `tests/data/`) |
| **Redistribution** | Self-collected — internal use |

Memory-relevant files:

| File | Notes |
|---|---|
| `uac-vbox-linux-20260324234043.tar.gz` | UAC collection including `memory_dump/avml.lime` (~5.5 GB AVML-format memory dump); 5.9 GB archive — the Linux RAM oracle for `memf-linux` walkers |

The smaller `uac-vbox-linux-20260324193807.tar.gz` (143 MB) is filesystem artifacts only — **no
memory dump** (present in the dir, not a memory image).

---

### 13cubed-mini-memory-ctf

| Field | Value |
|---|---|
| **Author** | Richard Davis — 13Cubed |
| **Type** | Windows 7 SP1 x86 memory CTF |
| **Windows build** | Windows 7 SP1 x86 (build 7601) — documented in official solutions guide; Volatility profile `Win7SP1x86` |
| **Download** | <https://cdn.13cubed.com/downloads/mini_memory_ctf.zip> |
| **Solution PDF** | <https://cdn.13cubed.com/downloads/mini_memory_ctf_solutions_guide.pdf> |
| **Redistribution** | Public CTF artifact — free to redistribute for educational use |

Files:

| File | Notes |
|---|---|
| `mini_memory_ctf.zip` | Windows 7 SP1 x86 (32-bit) memory image (1.3 GB) |
| `mini_memory_ctf_solutions_guide.pdf` | Official solution guide |
| `writeup-13cubed-mini-brootware.html` | Brootware writeup (saved offline) |

---

### 13cubed-windows-memory-forensics-challenge

| Field | Value |
|---|---|
| **Author** | Richard Davis — 13Cubed |
| **Type** | Windows 10 x64 memory CTF |
| **Windows build** | Windows 10 x64 (exact build TBD — run `imageinfo` on extracted image; no build number in saved writeup) |
| **Info** | <https://www.13cubed.com/> (YouTube walkthrough — no direct download page) |
| **Redistribution** | Public CTF artifact — free to redistribute for educational use |

Files:

| File | Notes |
|---|---|
| `windows_challenge.zip` | Windows 10 x64 memory image (1.4 GB) |
| `writeup-13cubed-windows-iblue.html` | iBlue Team writeup (saved offline) |

---

### CyberDefenders/78-DeepDive.zip

| Field | Value |
|---|---|
| **Author** | CyberDefenders.org — Challenge #78 "DeepDive" |
| **Type** | Windows memory forensics (Volatility-based) |
| **Windows build** | Unknown — no writeup HTML saved; run `imageinfo` on extracted image |
| **Download** | <https://cyberdefenders.org/blueteam-ctf-challenges/deepdive/> (account required) |
| **MD5** | `2c6d06eef52cae743e16633fe4ee1734` (536.7 MB) |
| **Redistribution** | CyberDefenders challenge — do not redistribute publicly |

---

### houseplant-ctf-2020-imagery

| Field | Value |
|---|---|
| **Source** | Houseplant CTF 2020 — "Imagery" forensics challenge |
| **Type** | Windows 10 memory forensics |
| **Windows build** | Windows 10 (exact build TBD — writeup uses `win10_volatility` profile; run `imageinfo` for precise build) |
| **Info** | <https://ctftime.org/event/1041> |
| **Redistribution** | Public CTF artifact |

Files:

| File | Notes |
|---|---|
| `imagery.7z` | Windows 10 memory image (584 MB) |
| `writeup-houseplant-imagery-ctftime.html` | CTFtime writeup #20330 (saved offline) |

---

### inctf-2019-notchitup

| Field | Value |
|---|---|
| **Author** | bi0s team — InCTF International 2019 |
| **Type** | Windows 7 SP1 x64 memory forensics (Volatility) |
| **Windows build** | Windows 7 SP1 x64 (build 7601) — Volatility profile `Win7SP1x64` used throughout writeup |
| **Info** | <https://blog.bi0s.in/2019/09/24/Forensics/InCTFi19-NotchItUp/> |
| **Redistribution** | Public CTF artifact |

Files:

| File | Notes |
|---|---|
| `Challenge_NotchItUp.7z` | Windows memory dump (342 MB) |
| `writeup-inctf-notchitup-bi0s.html` | Official bi0s writeup (saved offline) |

---

### memlabs-lab1-beginners-luck

| Field | Value |
|---|---|
| **Author** | stuxnet0 — MemLabs |
| **Type** | Windows 7 SP1 x64 memory forensics (Volatility) |
| **Windows build** | Windows 7 SP1 x64 (build 7601) — Volatility profile `Win7SP1x64` confirmed in writeup |
| **Source** | <https://github.com/stuxnet0/MemLabs> |
| **Redistribution** | MIT / free educational use |

Files:

| File | Notes |
|---|---|
| `MemLabs-Lab1.7z` | Windows 7 SP1 x64 memory dump (151 MB) |
| `writeup-memlabs-lab1-forensic8or.html` | forensic8or writeup (saved offline) |
| `writeup-memlabs-lab1-n1ght-w0lf.html` | n1ght-w0lf writeup (saved offline) |

---

### memlabs-lab3-the-evils-den

| Field | Value |
|---|---|
| **Author** | stuxnet0 — MemLabs |
| **Type** | Windows 7 SP1 x86 memory forensics (Volatility) |
| **Windows build** | Windows 7 SP1 x86 (build 7601) — writeup uses profile `Win7SP1x86_23418`; 32-bit image per MemLabs repo |
| **Source** | <https://github.com/stuxnet0/MemLabs> |
| **Redistribution** | MIT / free educational use |

Files:

| File | Notes |
|---|---|
| `MemLabs-Lab3.7z` | Windows 7 SP1 x86 (32-bit) memory dump (242 MB) |
| `writeup-memlabs-lab3-n1ght-w0lf.html` | n1ght-w0lf writeup (saved offline) |

---

### otterctf-2018

| Field | Value |
|---|---|
| **Source** | OtterCTF 2018 by ReallyFast |
| **Type** | Windows 7 SP1 x64 memory forensics |
| **Windows build** | Windows 7 SP1 x64 (build 7601) — Volatility profile `Win7SP1x64` confirmed in TCERT writeup |
| **Info** | <https://tcert.net/otterctf-2018-memory-forensic-walkthrough/> |
| **Redistribution** | Public CTF artifact |

Files:

| File | Notes |
|---|---|
| `OtterCTF.7z` | Windows 7 SP1 x64 memory image (484 MB) |
| `writeup-otterctf-tcert.html` | TCERT full walkthrough, all 12 flags (saved offline) |

---

### samsclass-volatility-project

| Field | Value |
|---|---|
| **Author** | Sam Bowne — CNIT 121, Project P5 |
| **Type** | Windows XP SP2 x86 memory forensics (Volatility teaching exercise) |
| **Windows build** | Windows XP SP2 x86 (build 2600) — Volatility profile `WinXPSP2x86` confirmed in writeup |
| **Source** | <https://samsclass.info/121/proj/p5-Vol.htm> |
| **Redistribution** | Free educational use |

Files:

| File | Notes |
|---|---|
| `memdump.7z` | Windows memory dump (124 MB) |
| `writeup-samsclass-p5-volatility.html` | Sam Bowne project instructions + answers (saved offline) |

---

### SecurityNik/TOTAL_RECALL_memory_forensics_CHALLENGE.zip

| Field | Value |
|---|---|
| **Author** | Nik Alleyne — SecurityNik, TOTAL RECALL 2024 |
| **Type** | Windows 11 22H2 x64 crash dump, acquired with DumpIt 3.0 |
| **Windows build** | Windows 11 22H2 x64 (build 22621) — confirmed in `.md5sums.log` metadata |
| **Source** | <https://www.securitynik.com/2024/03/total-recall-2024-memory-forensics-self.html> |
| **Files** | <https://github.com/SecurityNik/CTF> |
| **MD5** | `7dceb1fcae2ed8beacc8f81f85bf935c` (1.2 GB) |
| **SHA256** | `cabe2fd543eac1cd2eab9ccd0a840d83481a3f00e16015287323b2cb44fe0686` |
| **Host** | `SECURITYNIK-WIN` / user `securitynik` |
| **Redistribution** | Attribution — SecurityNik public challenge |

---

### Volatility/cridex_memdump.zip

| Field | Value |
|---|---|
| **Author** | Volatility Foundation — public malware sample |
| **Type** | Windows XP SP2 x86 memory image with Cridex banking trojan |
| **Windows build** | Windows XP SP2 x86 (build 2600) — documented on Volatility Foundation wiki |
| **Source** | <https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples> |
| **MD5** | `ebcbb798f7fa5df87375dbc4ee329209` (38.5 MB) |
| **Redistribution** | Public educational sample |

---

### wannacry-memory-analysis

| Field | Value |
|---|---|
| **Source** | null0x4d5a — WannaCry memory analysis blog post, May 2017 |
| **Type** | Windows 7 x86 memory dump with WannaCry ransomware |
| **Windows build** | Windows 7 x86 (build 7601, likely SP1) — `i386` architecture confirmed in writeup; WannaCry's primary target platform |
| **Info** | <https://www.null0x4d5a.com/2017/05/memory-analsyis-of-wannacry-ransomware.html> |
| **Redistribution** | Free educational use |

Files:

| File | Notes |
|---|---|
| `wannacry.7z` | Windows 7 x86 memory dump with active WannaCry infection (42 MB) |
| `writeup-wannacry-null0x4d5a.html` | null0x4d5a analysis post (saved offline) |

---

## Integration test references

Tests reference corpora via the `MEMF_TEST_DATA` env var (absolute path to this directory),
or relative to the workspace root (`tests/data/…`). Tests skip cleanly when files are absent.

| Test | Corpus |
|---|---|
| *(none wired yet — corpora used for manual validation)* | |

When you wire an integration test to a corpus, add a row here and in the test file's doc comment.

---

## Checksums not yet recorded

The following corpora lack checksums in the fleet's `.md5sums.log` (they were downloaded directly
into this repo, not through issen's pipeline). Run `md5 <file>` and add the result to
`~/src/issen/tests/data/.md5sums.log` under the appropriate label when time permits:

- `13cubed-mini-memory-ctf/mini_memory_ctf.zip`
- `13cubed-windows-memory-forensics-challenge/windows_challenge.zip`
- `houseplant-ctf-2020-imagery/imagery.7z`
- `inctf-2019-notchitup/Challenge_NotchItUp.7z`
- `memlabs-lab1-beginners-luck/MemLabs-Lab1.7z`
- `memlabs-lab3-the-evils-den/MemLabs-Lab3.7z`
- `otterctf-2018/OtterCTF.7z`
- `samsclass-volatility-project/memdump.7z`
- `wannacry-memory-analysis/wannacry.7z`
