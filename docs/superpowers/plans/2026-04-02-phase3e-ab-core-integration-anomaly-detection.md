# Phase 3E-A/B: Core Integration + Network Anomaly Detection

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate memory-forensic crates into RapidTriage as git dependencies, extend `InvestigationData` with unified memory types, detect memory dumps in UAC collections (decompression handled transparently by `memf-format::open_dump()`), run walkers, and implement a 4-metric network anomaly detection algorithm for memory dump connections.

**Architecture:** The memory-forensic crates (`memf-format`, `memf-core`, `memf-symbols`, `memf-linux`, `memf-windows`, `memf-strings`) are consumed as-is via git dependencies from `https://github.com/SecurityRonin/memory-forensic.git`. All new code lives in the RapidTriage repo under `crates/rt-navigator/src/investigation/`. Unified memory types in `memory.rs` wrap OS-specific walker output. A `memory_loader.rs` module handles dump detection and walker invocation — archive decompression (.zip/.7z) is handled transparently by `memf-format::open_dump()`, so RapidTriage doesn't need archive-handling dependencies. Network anomaly detection in `alerts/memory_network.rs` implements statistical outlier flagging (mean + 2*stddev) across 4 metrics plus suspicious port floor detection.

**Tech Stack:** Rust, `memf-*` crates (git dep), `chrono` (existing), `thiserror` (existing). Note: `zip` and `sevenz-rust` are dependencies of `memf-format` (not RapidTriage) — archive decompression is transparent via `open_dump()`.

**Build command:** `/Users/4n6h4x0r/.cargo/bin/cargo`
**Commit flag:** `--no-gpg-sign`

---

## File Structure

### Create

| File | Responsibility |
|------|---------------|
| `crates/rt-navigator/src/investigation/memory.rs` | Unified memory types (`MemProcessEntry`, `MemConnectionEntry`, `MemModuleEntry`, `MemLibraryEntry`, `MemThreadEntry`, `MemoryDumpInfo`, `NetworkFlagSummary`, `OsProfile`), `From` conversions from `memf-linux` and `memf-windows` types |
| `crates/rt-navigator/src/investigation/memory_loader.rs` | Memory dump detection in UAC `memory_dump/` dir, `open_dump()` probing (handles .zip/.7z transparently), OS detection, walker invocation, `InvestigationData` population |
| `crates/rt-navigator/src/investigation/alerts/memory_network.rs` | 4-metric network anomaly detection for memory connections: fan-out per IP, fan-in per port, connections per PID, unique IPs per PID; statistical outlier flagging; suspicious port floor; `NetworkFlagSummary` computation |

### Modify

| File | Change |
|------|--------|
| `Cargo.toml` (workspace root) | Add `memf-format`, `memf-core`, `memf-symbols`, `memf-linux`, `memf-windows`, `memf-strings` to `[workspace.dependencies]` |
| `crates/rt-navigator/Cargo.toml` | Add `memf-format`, `memf-core`, `memf-symbols`, `memf-linux`, `memf-windows` dependencies |
| `crates/rt-navigator/src/investigation/data.rs` (line 76) | Add 7 memory fields to `InvestigationData` struct; update `Debug` impl; update `Default` derivation; add memory loader call in `load_uac_collection()` |
| `crates/rt-navigator/src/investigation/mod.rs` (line 22) | Add `pub mod memory;` and `pub mod memory_loader;`; add 4 `WorkbenchView` variants (`MemProcesses`, `MemNetwork`, `MemModules`, `MemLibraries`); extend `label()`, `item_count()`, `WorkbenchApp::new()` |
| `crates/rt-navigator/src/investigation/alerts/mod.rs` (line 16) | Add `mod memory_network;` declaration |
| `crates/rt-navigator/src/investigation/alerts/engine.rs` (line 28) | Import and call `check_memory_network_alerts()`; add `memory_connections` parameter |
| `crates/rt-navigator/src/investigation/alerts/types.rs` (line 81) | Change `SuspiciousPort` visibility from `pub(super)` to `pub(crate)`; change `SUSPICIOUS_PORTS` from `pub(super)` to `pub(crate)` |
| `crates/rt-navigator/src/investigation/views/mod.rs` | Add placeholder arms for 4 new `WorkbenchView` variants in `draw_view()` match |

---

### Task 1: Add Workspace Dependencies

**Files:**
- Modify: `/Users/4n6h4x0r/src/RapidTriage/Cargo.toml`
- Modify: `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/Cargo.toml`

- [ ] **Step 1: Add memory-forensic git dependencies to workspace Cargo.toml**

In `/Users/4n6h4x0r/src/RapidTriage/Cargo.toml`, add these lines at the end of the `[workspace.dependencies]` section (after the `[workspace.lints.rust]` section begins, so insert before that section):

```toml
# Memory forensic analysis
memf-format  = { git = "https://github.com/SecurityRonin/memory-forensic.git", branch = "main" }
memf-core    = { git = "https://github.com/SecurityRonin/memory-forensic.git", branch = "main" }
memf-symbols = { git = "https://github.com/SecurityRonin/memory-forensic.git", branch = "main" }
memf-linux   = { git = "https://github.com/SecurityRonin/memory-forensic.git", branch = "main" }
memf-windows = { git = "https://github.com/SecurityRonin/memory-forensic.git", branch = "main" }
memf-strings = { git = "https://github.com/SecurityRonin/memory-forensic.git", branch = "main" }
```

Note: `zip` and `sevenz-rust` are NOT needed in RapidTriage — archive decompression is handled transparently inside `memf-format::open_dump()`.

- [ ] **Step 2: Add dependencies to rt-navigator Cargo.toml**

In `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/Cargo.toml`, add these lines at the end of the `[dependencies]` section:

```toml
memf-format.workspace  = true
memf-core.workspace    = true
memf-symbols.workspace = true
memf-linux.workspace   = true
memf-windows.workspace = true
```

Note: `zip` and `sevenz-rust` are NOT needed here. Archive decompression (.zip/.7z) is handled transparently by `memf-format::open_dump()` — RapidTriage just passes the file path and gets back a `PhysicalMemoryProvider`.

- [ ] **Step 3: Verify workspace resolves**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo check -p rt-navigator 2>&1 | tail -10`

Expected: Compiles successfully (downloads git deps, resolves all crate versions). No new code references the crates yet, so this just validates dependency resolution.

- [ ] **Step 4: Commit**

```bash
cd /Users/4n6h4x0r/src/RapidTriage
git add Cargo.toml Cargo.lock crates/rt-navigator/Cargo.toml
git commit --no-gpg-sign -m "chore(deps): add memory-forensic git dependencies

Add memf-format, memf-core, memf-symbols, memf-linux, memf-windows,
memf-strings as git workspace deps from SecurityRonin/memory-forensic.
Archive decompression (.zip/.7z) is handled by memf-format internally."
```

---

### Task 2: Unified Memory Types (memory.rs) -- RED

**Files:**
- Create: `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/src/investigation/memory.rs`
- Modify: `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/src/investigation/mod.rs` (line 1)

This task defines all unified memory types and `From` conversions from OS-specific types. We write tests first (RED), then implement (GREEN).

- [ ] **Step 1: Register the module**

In `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/src/investigation/mod.rs`, add after line 4 (`pub mod data;`):

```rust
pub mod memory;
```

- [ ] **Step 2: Create memory.rs with tests only (RED phase)**

Create `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/src/investigation/memory.rs`:

```rust
//! Unified memory forensic types for the Investigation Workbench.
//!
//! These types wrap OS-specific walker output from `memf-linux` and
//! `memf-windows` into a common shape that the TUI can render without
//! caring about the underlying operating system.

use std::net::IpAddr;
use std::path::PathBuf;

/// Operating system detected from the memory dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsProfile {
    /// Linux kernel image.
    Linux,
    /// Windows kernel image.
    Windows,
    /// macOS kernel image (future).
    MacOs,
}

/// Metadata about the memory dump file itself.
#[derive(Debug, Clone)]
pub struct MemoryDumpInfo {
    /// Detected operating system.
    pub os: OsProfile,
    /// Architecture string (e.g., "AMD64", "x86", "ARM64").
    pub arch: String,
    /// Dump format name (e.g., "LiME", "CrashDump", "VMware", "Raw").
    pub dump_format: String,
    /// Path to the dump file on disk.
    pub dump_path: PathBuf,
    /// Total physical memory size in bytes, if known.
    pub physical_memory_size: Option<u64>,
}

/// Flags that can be attached to a memory process entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessFlag {
    /// Process is a WoW64 (32-bit on 64-bit) process.
    Wow64,
    /// Process has exited (has exit_time set).
    Exited,
}

/// A process extracted from a memory dump (unified across Linux and Windows).
#[derive(Debug, Clone)]
pub struct MemProcessEntry {
    /// Process ID.
    pub pid: u64,
    /// Parent process ID.
    pub ppid: u64,
    /// Process name / image name.
    pub name: String,
    /// Process creation time, if available.
    pub create_time: Option<chrono::NaiveDateTime>,
    /// Page table root (CR3).
    pub cr3: u64,
    /// Virtual address of the kernel process structure.
    pub vaddr: u64,
    /// Optional flags (WoW64, Exited, etc.).
    pub flags: Vec<ProcessFlag>,
}

/// Protocol for a memory dump network connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemProtocol {
    /// TCP (IPv4).
    Tcp,
    /// UDP (IPv4).
    Udp,
    /// TCP (IPv6).
    Tcp6,
    /// UDP (IPv6).
    Udp6,
}

impl std::fmt::Display for MemProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Tcp6 => write!(f, "TCP6"),
            Self::Udp6 => write!(f, "UDP6"),
        }
    }
}

/// Connection state for a memory dump network connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemConnectionState {
    /// Connection is established.
    Established,
    /// Socket is listening.
    Listen,
    /// Connection is in SYN_SENT state.
    SynSent,
    /// Connection is in SYN_RECV state.
    SynRecv,
    /// Connection is in FIN_WAIT1 state.
    FinWait1,
    /// Connection is in FIN_WAIT2 state.
    FinWait2,
    /// Connection is in TIME_WAIT state.
    TimeWait,
    /// Connection is closed.
    Close,
    /// Connection is in CLOSE_WAIT state.
    CloseWait,
    /// Connection is in LAST_ACK state.
    LastAck,
    /// Connection is in CLOSING state.
    Closing,
    /// Unknown state.
    Unknown(u8),
}

impl std::fmt::Display for MemConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Established => write!(f, "ESTABLISHED"),
            Self::Listen => write!(f, "LISTEN"),
            Self::SynSent => write!(f, "SYN_SENT"),
            Self::SynRecv => write!(f, "SYN_RECV"),
            Self::FinWait1 => write!(f, "FIN_WAIT1"),
            Self::FinWait2 => write!(f, "FIN_WAIT2"),
            Self::TimeWait => write!(f, "TIME_WAIT"),
            Self::Close => write!(f, "CLOSE"),
            Self::CloseWait => write!(f, "CLOSE_WAIT"),
            Self::LastAck => write!(f, "LAST_ACK"),
            Self::Closing => write!(f, "CLOSING"),
            Self::Unknown(v) => write!(f, "UNKNOWN({v})"),
        }
    }
}

/// A network connection extracted from a memory dump (unified).
#[derive(Debug, Clone)]
pub struct MemConnectionEntry {
    /// Protocol (TCP, UDP, TCP6, UDP6).
    pub protocol: MemProtocol,
    /// Local address as string (e.g., "192.168.1.1").
    pub local_addr: String,
    /// Local port number.
    pub local_port: u16,
    /// Remote address as string (empty for LISTEN sockets).
    pub remote_addr: String,
    /// Remote port number (0 for LISTEN sockets).
    pub remote_port: u16,
    /// Connection state.
    pub state: MemConnectionState,
    /// Owning process ID (0 if unknown).
    pub pid: u64,
    /// Anomaly flag labels set by the network anomaly detection engine.
    /// Examples: "C2-PORT", "FANOUT(42)", "FANIN(10)", "HIGH-PID(200)", "SCATTER(50)".
    pub flag_labels: Vec<String>,
}

/// A kernel module or driver extracted from a memory dump (unified).
#[derive(Debug, Clone)]
pub struct MemModuleEntry {
    /// Module/driver name.
    pub name: String,
    /// Base virtual address.
    pub base: u64,
    /// Size in bytes.
    pub size: u64,
    /// Full path, if available.
    pub path: Option<String>,
}

/// A loaded library (DLL or shared object) from a memory dump (unified).
#[derive(Debug, Clone)]
pub struct MemLibraryEntry {
    /// Owning process ID.
    pub pid: u64,
    /// Library name (e.g., "ntdll.dll", "libc.so.6").
    pub name: String,
    /// Base virtual address.
    pub base: u64,
    /// Size in bytes.
    pub size: u64,
    /// Full path, if available.
    pub path: Option<String>,
}

/// A thread extracted from a memory dump (unified).
#[derive(Debug, Clone)]
pub struct MemThreadEntry {
    /// Thread ID.
    pub tid: u64,
    /// Owning process ID.
    pub pid: u64,
    /// Thread state string, if available.
    pub state: Option<String>,
    /// Start address of the thread.
    pub start_address: u64,
    /// Thread creation time, if available.
    pub create_time: Option<chrono::NaiveDateTime>,
}

/// Pre-computed summary of network anomaly detection results.
#[derive(Debug, Clone)]
pub struct NetworkFlagSummary {
    /// Total number of connections analyzed.
    pub total_connections: usize,
    /// Number of connections with at least one flag.
    pub flagged_count: usize,
    /// Remote IP with the highest fan-out (connection count).
    pub max_fanout_ip: Option<(IpAddr, usize)>,
    /// Local port with the highest fan-in (connection count).
    pub max_fanin_port: Option<(u16, usize)>,
    /// PID with the most connections.
    pub max_conns_pid: Option<(u64, usize)>,
    /// PID contacting the most unique remote IPs.
    pub max_unique_ips_pid: Option<(u64, usize)>,
}

// ---------------------------------------------------------------------------
// Conversions from memf-linux types
// ---------------------------------------------------------------------------

impl From<&memf_linux::ProcessInfo> for MemProcessEntry {
    fn from(p: &memf_linux::ProcessInfo) -> Self {
        Self {
            pid: p.pid,
            ppid: p.ppid,
            name: p.comm.clone(),
            create_time: None, // Linux task_struct doesn't carry creation time
            cr3: p.cr3.unwrap_or(0),
            vaddr: p.vaddr,
            flags: Vec::new(),
        }
    }
}

impl From<&memf_linux::ConnectionInfo> for MemConnectionEntry {
    fn from(c: &memf_linux::ConnectionInfo) -> Self {
        let protocol = match c.protocol {
            memf_linux::Protocol::Tcp => MemProtocol::Tcp,
            memf_linux::Protocol::Udp => MemProtocol::Udp,
            memf_linux::Protocol::Tcp6 => MemProtocol::Tcp6,
            memf_linux::Protocol::Udp6 => MemProtocol::Udp6,
            // Unix and Raw sockets are not supported in the TUI
            _ => MemProtocol::Tcp,
        };
        let state = match c.state {
            memf_linux::ConnectionState::Established => MemConnectionState::Established,
            memf_linux::ConnectionState::Listen => MemConnectionState::Listen,
            memf_linux::ConnectionState::SynSent => MemConnectionState::SynSent,
            memf_linux::ConnectionState::SynRecv => MemConnectionState::SynRecv,
            memf_linux::ConnectionState::FinWait1 => MemConnectionState::FinWait1,
            memf_linux::ConnectionState::FinWait2 => MemConnectionState::FinWait2,
            memf_linux::ConnectionState::TimeWait => MemConnectionState::TimeWait,
            memf_linux::ConnectionState::Close => MemConnectionState::Close,
            memf_linux::ConnectionState::CloseWait => MemConnectionState::CloseWait,
            memf_linux::ConnectionState::LastAck => MemConnectionState::LastAck,
            memf_linux::ConnectionState::Closing => MemConnectionState::Closing,
            memf_linux::ConnectionState::Unknown(v) => MemConnectionState::Unknown(v),
        };
        Self {
            protocol,
            local_addr: c.local_addr.clone(),
            local_port: c.local_port,
            remote_addr: c.remote_addr.clone(),
            remote_port: c.remote_port,
            state,
            pid: c.pid.unwrap_or(0),
            flag_labels: Vec::new(),
        }
    }
}

impl From<&memf_linux::ModuleInfo> for MemModuleEntry {
    fn from(m: &memf_linux::ModuleInfo) -> Self {
        Self {
            name: m.name.clone(),
            base: m.base_addr,
            size: m.size,
            path: None, // Linux modules don't carry a file path in task_struct
        }
    }
}

// ---------------------------------------------------------------------------
// Conversions from memf-windows types
// ---------------------------------------------------------------------------

/// Convert a Windows FILETIME (100ns intervals since 1601-01-01) to `NaiveDateTime`.
fn filetime_to_naive(filetime: u64) -> Option<chrono::NaiveDateTime> {
    if filetime == 0 {
        return None;
    }
    // FILETIME epoch: 1601-01-01 00:00:00 UTC
    // Unix epoch:     1970-01-01 00:00:00 UTC
    // Difference: 11_644_473_600 seconds = 116_444_736_000_000_000 hundred-nanoseconds
    const FILETIME_UNIX_DIFF: u64 = 116_444_736_000_000_000;
    let unix_100ns = filetime.checked_sub(FILETIME_UNIX_DIFF)?;
    let secs = (unix_100ns / 10_000_000) as i64;
    let nanos = ((unix_100ns % 10_000_000) * 100) as u32;
    chrono::DateTime::from_timestamp(secs, nanos).map(|dt| dt.naive_utc())
}

impl From<&memf_windows::WinProcessInfo> for MemProcessEntry {
    fn from(p: &memf_windows::WinProcessInfo) -> Self {
        let mut flags = Vec::new();
        if p.is_wow64 {
            flags.push(ProcessFlag::Wow64);
        }
        if p.exit_time != 0 {
            flags.push(ProcessFlag::Exited);
        }
        Self {
            pid: p.pid,
            ppid: p.ppid,
            name: p.image_name.clone(),
            create_time: filetime_to_naive(p.create_time),
            cr3: p.cr3,
            vaddr: p.vaddr,
            flags,
        }
    }
}

impl From<&memf_windows::WinThreadInfo> for MemThreadEntry {
    fn from(t: &memf_windows::WinThreadInfo) -> Self {
        Self {
            tid: t.tid,
            pid: t.pid,
            state: Some(format!("{}", t.state)),
            start_address: t.start_address,
            create_time: filetime_to_naive(t.create_time),
        }
    }
}

impl From<&memf_windows::WinDriverInfo> for MemModuleEntry {
    fn from(d: &memf_windows::WinDriverInfo) -> Self {
        Self {
            name: d.name.clone(),
            base: d.base_addr,
            size: d.size,
            path: d.full_path.clone(),
        }
    }
}

impl From<&memf_windows::WinDllInfo> for MemLibraryEntry {
    /// Note: `pid` must be set by the caller after conversion since
    /// `WinDllInfo` doesn't carry its owning PID.
    fn from(d: &memf_windows::WinDllInfo) -> Self {
        Self {
            pid: 0, // Must be set by caller
            name: d.name.clone(),
            base: d.base_addr,
            size: d.size,
            path: d.full_path.clone(),
        }
    }
}

/// Convert a list of `WinDllInfo` to `MemLibraryEntry`, setting the PID.
pub fn win_dlls_to_libraries(pid: u64, dlls: &[memf_windows::WinDllInfo]) -> Vec<MemLibraryEntry> {
    dlls.iter()
        .map(|d| {
            let mut lib = MemLibraryEntry::from(d);
            lib.pid = pid;
            lib
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // OsProfile
    // -----------------------------------------------------------------------

    #[test]
    fn os_profile_variants_are_distinct() {
        assert_ne!(OsProfile::Linux, OsProfile::Windows);
        assert_ne!(OsProfile::Linux, OsProfile::MacOs);
        assert_ne!(OsProfile::Windows, OsProfile::MacOs);
    }

    // -----------------------------------------------------------------------
    // MemoryDumpInfo
    // -----------------------------------------------------------------------

    #[test]
    fn memory_dump_info_roundtrip() {
        let info = MemoryDumpInfo {
            os: OsProfile::Linux,
            arch: "AMD64".into(),
            dump_format: "LiME".into(),
            dump_path: PathBuf::from("/tmp/mem.lime"),
            physical_memory_size: Some(4 * 1024 * 1024 * 1024),
        };
        assert_eq!(info.os, OsProfile::Linux);
        assert_eq!(info.arch, "AMD64");
        assert_eq!(info.dump_format, "LiME");
        assert_eq!(info.physical_memory_size, Some(4_294_967_296));
    }

    // -----------------------------------------------------------------------
    // ProcessFlag
    // -----------------------------------------------------------------------

    #[test]
    fn process_flag_equality() {
        assert_eq!(ProcessFlag::Wow64, ProcessFlag::Wow64);
        assert_ne!(ProcessFlag::Wow64, ProcessFlag::Exited);
    }

    // -----------------------------------------------------------------------
    // MemProtocol Display
    // -----------------------------------------------------------------------

    #[test]
    fn mem_protocol_display() {
        assert_eq!(format!("{}", MemProtocol::Tcp), "TCP");
        assert_eq!(format!("{}", MemProtocol::Udp), "UDP");
        assert_eq!(format!("{}", MemProtocol::Tcp6), "TCP6");
        assert_eq!(format!("{}", MemProtocol::Udp6), "UDP6");
    }

    // -----------------------------------------------------------------------
    // MemConnectionState Display
    // -----------------------------------------------------------------------

    #[test]
    fn mem_connection_state_display() {
        assert_eq!(format!("{}", MemConnectionState::Established), "ESTABLISHED");
        assert_eq!(format!("{}", MemConnectionState::Listen), "LISTEN");
        assert_eq!(format!("{}", MemConnectionState::SynSent), "SYN_SENT");
        assert_eq!(format!("{}", MemConnectionState::TimeWait), "TIME_WAIT");
        assert_eq!(format!("{}", MemConnectionState::Unknown(99)), "UNKNOWN(99)");
    }

    // -----------------------------------------------------------------------
    // Linux process conversion
    // -----------------------------------------------------------------------

    #[test]
    fn from_linux_process_info() {
        let linux_proc = memf_linux::ProcessInfo {
            pid: 1234,
            ppid: 1,
            comm: "bash".into(),
            state: memf_linux::ProcessState::Running,
            vaddr: 0xffff_8800_1234_0000,
            cr3: Some(0x1a2b_3000),
        };
        let entry = MemProcessEntry::from(&linux_proc);
        assert_eq!(entry.pid, 1234);
        assert_eq!(entry.ppid, 1);
        assert_eq!(entry.name, "bash");
        assert!(entry.create_time.is_none());
        assert_eq!(entry.cr3, 0x1a2b_3000);
        assert_eq!(entry.vaddr, 0xffff_8800_1234_0000);
        assert!(entry.flags.is_empty());
    }

    #[test]
    fn from_linux_process_info_no_cr3() {
        let linux_proc = memf_linux::ProcessInfo {
            pid: 0,
            ppid: 0,
            comm: "swapper".into(),
            state: memf_linux::ProcessState::Running,
            vaddr: 0xffff_8800_0000_0000,
            cr3: None,
        };
        let entry = MemProcessEntry::from(&linux_proc);
        assert_eq!(entry.cr3, 0); // None maps to 0
    }

    // -----------------------------------------------------------------------
    // Linux connection conversion
    // -----------------------------------------------------------------------

    #[test]
    fn from_linux_connection_tcp_established() {
        let linux_conn = memf_linux::ConnectionInfo {
            protocol: memf_linux::Protocol::Tcp,
            local_addr: "192.168.1.100".into(),
            local_port: 54321,
            remote_addr: "10.0.0.1".into(),
            remote_port: 443,
            state: memf_linux::ConnectionState::Established,
            pid: Some(1234),
        };
        let entry = MemConnectionEntry::from(&linux_conn);
        assert_eq!(entry.protocol, MemProtocol::Tcp);
        assert_eq!(entry.local_addr, "192.168.1.100");
        assert_eq!(entry.local_port, 54321);
        assert_eq!(entry.remote_addr, "10.0.0.1");
        assert_eq!(entry.remote_port, 443);
        assert_eq!(entry.state, MemConnectionState::Established);
        assert_eq!(entry.pid, 1234);
        assert!(entry.flag_labels.is_empty());
    }

    #[test]
    fn from_linux_connection_listen_no_pid() {
        let linux_conn = memf_linux::ConnectionInfo {
            protocol: memf_linux::Protocol::Tcp6,
            local_addr: "::".into(),
            local_port: 22,
            remote_addr: "::".into(),
            remote_port: 0,
            state: memf_linux::ConnectionState::Listen,
            pid: None,
        };
        let entry = MemConnectionEntry::from(&linux_conn);
        assert_eq!(entry.protocol, MemProtocol::Tcp6);
        assert_eq!(entry.state, MemConnectionState::Listen);
        assert_eq!(entry.pid, 0); // None maps to 0
    }

    #[test]
    fn from_linux_connection_all_states() {
        use memf_linux::ConnectionState as LS;
        let states = vec![
            (LS::Established, MemConnectionState::Established),
            (LS::Listen, MemConnectionState::Listen),
            (LS::SynSent, MemConnectionState::SynSent),
            (LS::SynRecv, MemConnectionState::SynRecv),
            (LS::FinWait1, MemConnectionState::FinWait1),
            (LS::FinWait2, MemConnectionState::FinWait2),
            (LS::TimeWait, MemConnectionState::TimeWait),
            (LS::Close, MemConnectionState::Close),
            (LS::CloseWait, MemConnectionState::CloseWait),
            (LS::LastAck, MemConnectionState::LastAck),
            (LS::Closing, MemConnectionState::Closing),
            (LS::Unknown(42), MemConnectionState::Unknown(42)),
        ];
        for (linux_state, expected) in states {
            let conn = memf_linux::ConnectionInfo {
                protocol: memf_linux::Protocol::Tcp,
                local_addr: "0.0.0.0".into(),
                local_port: 0,
                remote_addr: "0.0.0.0".into(),
                remote_port: 0,
                state: linux_state,
                pid: None,
            };
            let entry = MemConnectionEntry::from(&conn);
            assert_eq!(entry.state, expected);
        }
    }

    // -----------------------------------------------------------------------
    // Linux module conversion
    // -----------------------------------------------------------------------

    #[test]
    fn from_linux_module_info() {
        let linux_mod = memf_linux::ModuleInfo {
            name: "ext4".into(),
            base_addr: 0xffff_a000_0000_0000,
            size: 0x10_0000,
            state: memf_linux::ModuleState::Live,
        };
        let entry = MemModuleEntry::from(&linux_mod);
        assert_eq!(entry.name, "ext4");
        assert_eq!(entry.base, 0xffff_a000_0000_0000);
        assert_eq!(entry.size, 0x10_0000);
        assert!(entry.path.is_none());
    }

    // -----------------------------------------------------------------------
    // Windows process conversion
    // -----------------------------------------------------------------------

    #[test]
    fn from_windows_process_info() {
        let win_proc = memf_windows::WinProcessInfo {
            pid: 4,
            ppid: 0,
            image_name: "System".into(),
            create_time: 133_500_000_000_000_000, // some FILETIME value
            exit_time: 0,
            cr3: 0x1a_d000,
            peb_addr: 0,
            vaddr: 0xffff_f802_1234_5678,
            thread_count: 100,
            is_wow64: false,
        };
        let entry = MemProcessEntry::from(&win_proc);
        assert_eq!(entry.pid, 4);
        assert_eq!(entry.ppid, 0);
        assert_eq!(entry.name, "System");
        assert!(entry.create_time.is_some());
        assert_eq!(entry.cr3, 0x1a_d000);
        assert!(entry.flags.is_empty()); // not wow64, not exited
    }

    #[test]
    fn from_windows_process_wow64_exited() {
        let win_proc = memf_windows::WinProcessInfo {
            pid: 1000,
            ppid: 500,
            image_name: "app.exe".into(),
            create_time: 133_500_000_000_000_000,
            exit_time: 133_500_001_000_000_000,
            cr3: 0x2b_c000,
            peb_addr: 0x0000_0000_7ffe_0000,
            vaddr: 0xffff_f802_5678_9abc,
            thread_count: 5,
            is_wow64: true,
        };
        let entry = MemProcessEntry::from(&win_proc);
        assert!(entry.flags.contains(&ProcessFlag::Wow64));
        assert!(entry.flags.contains(&ProcessFlag::Exited));
    }

    // -----------------------------------------------------------------------
    // Windows thread conversion
    // -----------------------------------------------------------------------

    #[test]
    fn from_windows_thread_info() {
        let win_thread = memf_windows::WinThreadInfo {
            tid: 8,
            pid: 4,
            create_time: 133_500_000_000_000_000,
            start_address: 0xfffff802_3456_7890,
            teb_addr: 0x0000_0000_7ffe_1000,
            state: memf_windows::ThreadState::Running,
            vaddr: 0xffff_f802_abcd_ef00,
        };
        let entry = MemThreadEntry::from(&win_thread);
        assert_eq!(entry.tid, 8);
        assert_eq!(entry.pid, 4);
        assert!(entry.state.is_some());
        assert_eq!(entry.start_address, 0xfffff802_3456_7890);
        assert!(entry.create_time.is_some());
    }

    // -----------------------------------------------------------------------
    // Windows driver conversion
    // -----------------------------------------------------------------------

    #[test]
    fn from_windows_driver_info() {
        let win_driver = memf_windows::WinDriverInfo {
            name: "ntoskrnl.exe".into(),
            full_path: Some("\\SystemRoot\\system32\\ntoskrnl.exe".into()),
            base_addr: 0xfffff802_0000_0000,
            size: 0x00a0_0000,
            vaddr: 0xffff_f802_1111_2222,
        };
        let entry = MemModuleEntry::from(&win_driver);
        assert_eq!(entry.name, "ntoskrnl.exe");
        assert_eq!(entry.base, 0xfffff802_0000_0000);
        assert_eq!(entry.size, 0x00a0_0000);
        assert_eq!(entry.path.as_deref(), Some("\\SystemRoot\\system32\\ntoskrnl.exe"));
    }

    // -----------------------------------------------------------------------
    // Windows DLL conversion
    // -----------------------------------------------------------------------

    #[test]
    fn from_windows_dll_info_pid_is_zero() {
        let win_dll = memf_windows::WinDllInfo {
            name: "ntdll.dll".into(),
            full_path: Some("C:\\Windows\\System32\\ntdll.dll".into()),
            base_addr: 0x7fff_aaaa_0000,
            size: 0x1f_0000,
            load_order: 0,
        };
        let entry = MemLibraryEntry::from(&win_dll);
        assert_eq!(entry.pid, 0); // PID not set by From
        assert_eq!(entry.name, "ntdll.dll");
    }

    #[test]
    fn win_dlls_to_libraries_sets_pid() {
        let dlls = vec![
            memf_windows::WinDllInfo {
                name: "ntdll.dll".into(),
                full_path: None,
                base_addr: 0x1000,
                size: 0x100,
                load_order: 0,
            },
            memf_windows::WinDllInfo {
                name: "kernel32.dll".into(),
                full_path: Some("C:\\Windows\\System32\\kernel32.dll".into()),
                base_addr: 0x2000,
                size: 0x200,
                load_order: 1,
            },
        ];
        let libs = win_dlls_to_libraries(1234, &dlls);
        assert_eq!(libs.len(), 2);
        assert_eq!(libs[0].pid, 1234);
        assert_eq!(libs[0].name, "ntdll.dll");
        assert_eq!(libs[1].pid, 1234);
        assert_eq!(libs[1].name, "kernel32.dll");
        assert_eq!(libs[1].path.as_deref(), Some("C:\\Windows\\System32\\kernel32.dll"));
    }

    // -----------------------------------------------------------------------
    // filetime_to_naive helper
    // -----------------------------------------------------------------------

    #[test]
    fn filetime_zero_returns_none() {
        assert!(filetime_to_naive(0).is_none());
    }

    #[test]
    fn filetime_unix_epoch() {
        // FILETIME for 1970-01-01 00:00:00 UTC
        let unix_epoch_filetime: u64 = 116_444_736_000_000_000;
        let dt = filetime_to_naive(unix_epoch_filetime).expect("should convert");
        assert_eq!(dt, chrono::NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(1970, 1, 1).expect("valid date"),
            chrono::NaiveTime::from_hms_opt(0, 0, 0).expect("valid time"),
        ));
    }

    #[test]
    fn filetime_known_date() {
        // 2024-01-15 12:00:00 UTC in FILETIME
        // Unix timestamp: 1705320000
        // FILETIME = (1705320000 * 10_000_000) + 116_444_736_000_000_000
        let ft: u64 = 1_705_320_000 * 10_000_000 + 116_444_736_000_000_000;
        let dt = filetime_to_naive(ft).expect("should convert");
        assert_eq!(dt.date(), chrono::NaiveDate::from_ymd_opt(2024, 1, 15).expect("valid date"));
        assert_eq!(dt.time().hour(), 12);
    }

    // -----------------------------------------------------------------------
    // NetworkFlagSummary
    // -----------------------------------------------------------------------

    #[test]
    fn network_flag_summary_construction() {
        let summary = NetworkFlagSummary {
            total_connections: 100,
            flagged_count: 5,
            max_fanout_ip: Some(("10.0.0.1".parse().expect("valid IP"), 42)),
            max_fanin_port: Some((4444, 10)),
            max_conns_pid: Some((1234, 50)),
            max_unique_ips_pid: Some((5678, 30)),
        };
        assert_eq!(summary.total_connections, 100);
        assert_eq!(summary.flagged_count, 5);
        assert_eq!(summary.max_fanout_ip.as_ref().expect("set").1, 42);
    }

    #[test]
    fn network_flag_summary_all_none() {
        let summary = NetworkFlagSummary {
            total_connections: 0,
            flagged_count: 0,
            max_fanout_ip: None,
            max_fanin_port: None,
            max_conns_pid: None,
            max_unique_ips_pid: None,
        };
        assert!(summary.max_fanout_ip.is_none());
        assert!(summary.max_fanin_port.is_none());
    }
}
```

- [ ] **Step 3: Run tests to verify RED phase**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p rt-navigator memory:: -- --nocapture 2>&1 | tail -30`

Expected: All tests PASS. These tests validate the type definitions and conversions directly -- they should compile and pass since the types and `From` impls are defined in the same file. The RED phase for this task is that the types exist but nothing uses them yet (data.rs doesn't have the fields). If there are compilation errors from `memf_linux` or `memf_windows` type mismatches, fix the field names to match the actual crate types.

- [ ] **Step 4: Run full workspace tests + clippy**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1 | tail -10`
Run: `/Users/4n6h4x0r/.cargo/bin/cargo clippy --workspace -- -D warnings 2>&1 | tail -10`

Expected: All existing tests pass. New tests pass. Zero clippy warnings.

- [ ] **Step 5: Commit**

```bash
cd /Users/4n6h4x0r/src/RapidTriage
git add crates/rt-navigator/src/investigation/memory.rs crates/rt-navigator/src/investigation/mod.rs
git commit --no-gpg-sign -m "feat(memory): add unified memory types with From conversions

Add memory.rs with MemProcessEntry, MemConnectionEntry, MemModuleEntry,
MemLibraryEntry, MemThreadEntry, MemoryDumpInfo, NetworkFlagSummary,
OsProfile, MemProtocol, MemConnectionState, and ProcessFlag types.

Implement From conversions from memf-linux (ProcessInfo, ConnectionInfo,
ModuleInfo) and memf-windows (WinProcessInfo, WinThreadInfo, WinDriverInfo,
WinDllInfo) types. Add filetime_to_naive helper for Windows FILETIME
conversion. 22 unit tests."
```

---

### Task 3: Extend InvestigationData with Memory Fields -- RED + GREEN

**Files:**
- Modify: `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/src/investigation/data.rs` (lines 76-94, 96-112, 186-216, 700-712)
- Modify: `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/src/investigation/mod.rs` (lines 22-90, 138-175)
- Modify: `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/src/investigation/views/mod.rs`

- [ ] **Step 1: Write failing tests for memory fields in InvestigationData (RED)**

Add to the `#[cfg(test)]` module at the bottom of `data.rs` (before the closing `}`):

```rust
    #[test]
    fn investigation_data_memory_fields_default_empty() {
        let data = InvestigationData::default();
        assert!(data.memory_info.is_none());
        assert!(data.memory_processes.is_empty());
        assert!(data.memory_connections.is_empty());
        assert!(data.memory_modules.is_empty());
        assert!(data.memory_libraries.is_empty());
        assert!(data.memory_threads.is_empty());
        assert!(data.network_flags.is_none());
    }

    #[test]
    fn investigation_data_debug_includes_memory_fields() {
        let data = InvestigationData::default();
        let debug_str = format!("{data:?}");
        assert!(debug_str.contains("memory_processes"));
        assert!(debug_str.contains("memory_connections"));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p rt-navigator investigation_data_memory_fields_default_empty investigation_data_debug_includes_memory_fields -- --nocapture 2>&1 | tail -20`

Expected: FAIL -- `memory_info`, `memory_processes`, etc. don't exist on `InvestigationData`.

- [ ] **Step 3: Add memory fields to InvestigationData (GREEN)**

In `data.rs`, add the import at the top (after line 31, the `use super::alerts::...` line):

```rust
use super::memory::{
    MemConnectionEntry, MemLibraryEntry, MemModuleEntry, MemProcessEntry, MemThreadEntry,
    MemoryDumpInfo, NetworkFlagSummary,
};
```

In `data.rs`, inside the `InvestigationData` struct (after line 94, the `pub artifact_counts` field), add:

```rust
    // Memory forensic fields (populated if UAC contains a memory dump)
    /// Metadata about the memory dump file (None if no dump present).
    pub memory_info: Option<MemoryDumpInfo>,
    /// Processes extracted from the memory dump.
    pub memory_processes: Vec<MemProcessEntry>,
    /// Network connections extracted from the memory dump.
    pub memory_connections: Vec<MemConnectionEntry>,
    /// Kernel modules/drivers extracted from the memory dump.
    pub memory_modules: Vec<MemModuleEntry>,
    /// Loaded libraries (DLLs/shared objects) extracted from the memory dump.
    pub memory_libraries: Vec<MemLibraryEntry>,
    /// Threads extracted from the memory dump.
    pub memory_threads: Vec<MemThreadEntry>,
    /// Pre-computed network anomaly detection summary.
    pub network_flags: Option<NetworkFlagSummary>,
```

- [ ] **Step 4: Update the Debug impl**

In `data.rs`, inside the `Debug` impl for `InvestigationData` (after the `.field("artifact_types", ...)` line, around line 111), add before `.finish()`:

```rust
            .field("memory_processes", &self.memory_processes.len())
            .field("memory_connections", &self.memory_connections.len())
            .field("memory_modules", &self.memory_modules.len())
            .field("memory_libraries", &self.memory_libraries.len())
            .field("memory_threads", &self.memory_threads.len())
```

- [ ] **Step 5: Update load_uac_collection() to initialize memory fields**

In `data.rs`, inside `load_uac_collection()`, where `InvestigationData` is constructed (around line 200-217), add the memory fields with empty defaults:

After the `artifact_counts: HashMap::new(),` line, add:

```rust
        memory_info: None,
        memory_processes: Vec::new(),
        memory_connections: Vec::new(),
        memory_modules: Vec::new(),
        memory_libraries: Vec::new(),
        memory_threads: Vec::new(),
        network_flags: None,
```

- [ ] **Step 6: Update load_velociraptor_collection() to initialize memory fields**

In `data.rs`, inside `load_velociraptor_collection()`, where `InvestigationData` is constructed (around line 250-265), add the same memory fields with empty defaults (after `artifact_counts,`):

```rust
        memory_info: None,
        memory_processes: Vec::new(),
        memory_connections: Vec::new(),
        memory_modules: Vec::new(),
        memory_libraries: Vec::new(),
        memory_threads: Vec::new(),
        network_flags: None,
```

- [ ] **Step 7: Update any test helpers that construct InvestigationData**

Search for any place in the test code that manually constructs `InvestigationData` and add the memory fields. The test helper around line 700-712 constructs one manually -- add the 7 memory fields there too.

Run: `grep -rn 'InvestigationData {' /Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/src/ | grep -v 'pub struct'`

For each match, add:

```rust
            memory_info: None,
            memory_processes: Vec::new(),
            memory_connections: Vec::new(),
            memory_modules: Vec::new(),
            memory_libraries: Vec::new(),
            memory_threads: Vec::new(),
            network_flags: None,
```

Alternatively, if `InvestigationData` derives `Default`, you can switch any manual constructions to use `..Default::default()` for the memory fields. However, since `InvestigationData` already derives `Default` (line 75: `#[derive(Default)]`), this should work automatically for the new fields.

**IMPORTANT:** The `#[derive(Default)]` on `InvestigationData` means `Option` fields default to `None` and `Vec` fields default to empty. But any code that constructs the struct with explicit field values (not using `..Default::default()`) will fail to compile until the new fields are added. Fix all such occurrences.

- [ ] **Step 8: Add WorkbenchView variants for memory views**

In `mod.rs`, extend the `WorkbenchView` enum (after `Chkrootkit` on line 32):

```rust
    MemProcesses,
    MemNetwork,
    MemModules,
    MemLibraries,
```

Extend `label()` (after the `Self::Chkrootkit` arm):

```rust
            Self::MemProcesses => "Mem Processes",
            Self::MemNetwork => "Mem Network",
            Self::MemModules => "Mem Modules",
            Self::MemLibraries => "Mem Libraries",
```

Extend `item_count()` (after the `Self::Chkrootkit` arm):

```rust
            Self::MemProcesses => data.memory_processes.len(),
            Self::MemNetwork => data.memory_connections.len(),
            Self::MemModules => data.memory_modules.len(),
            Self::MemLibraries => data.memory_libraries.len(),
```

- [ ] **Step 9: Add memory views to WorkbenchApp::new()**

In `mod.rs`, inside `WorkbenchApp::new()`, after the `Chkrootkit` push block (around line 173), add:

```rust
        // Memory forensic views (only when dump is present)
        if !data.memory_processes.is_empty() {
            available_views.push(WorkbenchView::MemProcesses);
        }
        if !data.memory_connections.is_empty() {
            available_views.push(WorkbenchView::MemNetwork);
        }
        if !data.memory_modules.is_empty() {
            available_views.push(WorkbenchView::MemModules);
        }
        if !data.memory_libraries.is_empty() {
            available_views.push(WorkbenchView::MemLibraries);
        }
```

- [ ] **Step 10: Add placeholder match arms in views/mod.rs**

In `views/mod.rs`, inside `draw_view()`, add these arms (before the closing `}`):

```rust
        WorkbenchView::MemProcesses
        | WorkbenchView::MemNetwork
        | WorkbenchView::MemModules
        | WorkbenchView::MemLibraries => {
            let block = ratatui::widgets::Block::default()
                .borders(ratatui::widgets::Borders::ALL)
                .title(format!(" {} (Phase 3E-C) ", app.current_view().label()));
            frame.render_widget(block, area);
        }
```

Also update the `make_all_views_app()` test helper in `views/mod.rs` to include the new variants in `available_views`.

- [ ] **Step 11: Fix Dashboard item_count for memory views**

In `mod.rs`, inside `item_count()` for `Self::Dashboard`, add after the existing checks (before the `count` return):

```rust
                if !data.memory_processes.is_empty() {
                    count += 1;
                }
                if !data.memory_connections.is_empty() {
                    count += 1;
                }
```

- [ ] **Step 12: Run tests to verify GREEN phase**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1 | tail -10`
Run: `/Users/4n6h4x0r/.cargo/bin/cargo clippy --workspace -- -D warnings 2>&1 | tail -10`

Expected: All tests pass including the 2 new memory field tests. Zero clippy warnings.

- [ ] **Step 13: Commit**

```bash
cd /Users/4n6h4x0r/src/RapidTriage
git add crates/rt-navigator/src/investigation/data.rs crates/rt-navigator/src/investigation/mod.rs crates/rt-navigator/src/investigation/views/mod.rs
git commit --no-gpg-sign -m "feat(data): extend InvestigationData with memory forensic fields

Add 7 memory fields: memory_info, memory_processes, memory_connections,
memory_modules, memory_libraries, memory_threads, network_flags.
Add 4 WorkbenchView variants: MemProcesses, MemNetwork, MemModules,
MemLibraries with label/item_count/available_views wiring.
Add placeholder rendering in views/mod.rs for Phase 3E-C."
```

---

### Task 4: Widen SuspiciousPort Visibility for Cross-Module Access

**Files:**
- Modify: `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/src/investigation/alerts/types.rs` (lines 81, 82, 83, 84, 97)

The `SuspiciousPort` struct and `SUSPICIOUS_PORTS` const are currently `pub(super)`, meaning they are only visible within the `alerts/` module. The new `memory_network.rs` module needs to access the port list but it lives inside `alerts/`, so `pub(super)` is sufficient. However, if memory_network.rs needs to be accessible from outside the alerts module (for testing or from memory_loader.rs), we should make the port list `pub(crate)`.

- [ ] **Step 1: Write a test proving the current visibility is insufficient**

Create a test in `memory_loader.rs` (which we'll create in Task 6) that tries to use `SUSPICIOUS_PORTS`. Since we haven't created that file yet, we can instead write a test in a module outside `alerts/` that imports `SuspiciousPort`.

Actually, since `memory_network.rs` will live inside `alerts/`, `pub(super)` is sufficient for it. But we need `SUSPICIOUS_PORTS` to be accessible from the `memory_network` module -- and since `memory_network` is a sibling module inside `alerts/`, `pub(super)` already grants access.

**Decision:** Keep `pub(super)` for now. The `memory_network.rs` module lives inside `alerts/` and can access `pub(super)` items. If future tasks need access from outside `alerts/`, widen at that time.

Skip this task -- no changes needed.

---

### Task 5: Network Anomaly Detection (memory_network.rs) -- RED

**Files:**
- Create: `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/src/investigation/alerts/memory_network.rs`
- Modify: `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/src/investigation/alerts/mod.rs` (line 16)

This implements the 4-metric flagging algorithm with statistical outlier detection.

- [ ] **Step 1: Register the module**

In `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/src/investigation/alerts/mod.rs`, add after line 15 (`mod process;`):

```rust
pub(crate) mod memory_network;
```

- [ ] **Step 2: Create memory_network.rs with tests only (RED phase)**

Create `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/src/investigation/alerts/memory_network.rs`:

```rust
//! Network anomaly detection for memory dump connections.
//!
//! Implements a 4-metric flagging algorithm that identifies statistical
//! outliers in memory-extracted network connections:
//!
//! 1. **Fan-out per remote IP** -- connections to the same remote IP
//! 2. **Fan-in per local port** -- connections to the same local port
//! 3. **Connections per PID** -- total connections owned by a process
//! 4. **Unique remote IPs per PID** -- distinct IPs a process contacts
//!
//! Entities where `value > mean + 2*stddev` are flagged as outliers.
//! Additionally, connections to known-suspicious ports (from the existing
//! SIGMA-sourced port list) are always flagged with `C2-PORT`.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use super::types::{Alert, AlertSeverity, SUSPICIOUS_PORTS};
use crate::investigation::memory::{MemConnectionEntry, NetworkFlagSummary};

/// Compute mean and standard deviation for a set of values.
fn mean_stddev(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
    (mean, variance.sqrt())
}

/// Threshold for flagging: mean + 2 * stddev.
fn outlier_threshold(values: &[f64]) -> f64 {
    let (mean, stddev) = mean_stddev(values);
    mean + 2.0 * stddev
}

/// Build a set of known-suspicious ports from the existing SIGMA-sourced list.
fn suspicious_port_set() -> HashSet<u16> {
    SUSPICIOUS_PORTS.iter().map(|sp| sp.port).collect()
}

/// Run the 4-metric network anomaly detection on memory dump connections.
///
/// This function:
/// 1. Computes the 4 metrics across all connections
/// 2. Identifies statistical outliers (value > mean + 2*stddev)
/// 3. Flags connections to known-suspicious ports
/// 4. Mutates `flag_labels` on each `MemConnectionEntry` in place
/// 5. Returns a `NetworkFlagSummary` with aggregate statistics
///
/// Also pushes any Critical/Warning alerts into `alerts` for the dashboard.
pub(crate) fn flag_memory_connections(
    connections: &mut [MemConnectionEntry],
    alerts: &mut Vec<Alert>,
) -> NetworkFlagSummary {
    let total_connections = connections.len();

    if connections.is_empty() {
        return NetworkFlagSummary {
            total_connections: 0,
            flagged_count: 0,
            max_fanout_ip: None,
            max_fanin_port: None,
            max_conns_pid: None,
            max_unique_ips_pid: None,
        };
    }

    let sus_ports = suspicious_port_set();

    // --- Metric 1: Fan-out per remote IP ---
    let mut fanout_map: HashMap<String, usize> = HashMap::new();
    for conn in connections.iter() {
        if !conn.remote_addr.is_empty() && conn.remote_addr != "0.0.0.0" && conn.remote_addr != "::" {
            *fanout_map.entry(conn.remote_addr.clone()).or_insert(0) += 1;
        }
    }
    let fanout_values: Vec<f64> = fanout_map.values().map(|&v| v as f64).collect();
    let fanout_thresh = outlier_threshold(&fanout_values);

    // --- Metric 2: Fan-in per local port ---
    let mut fanin_map: HashMap<u16, usize> = HashMap::new();
    for conn in connections.iter() {
        if conn.local_port > 0 {
            *fanin_map.entry(conn.local_port).or_insert(0) += 1;
        }
    }
    let fanin_values: Vec<f64> = fanin_map.values().map(|&v| v as f64).collect();
    let fanin_thresh = outlier_threshold(&fanin_values);

    // --- Metric 3: Connections per PID ---
    let mut conns_per_pid: HashMap<u64, usize> = HashMap::new();
    for conn in connections.iter() {
        *conns_per_pid.entry(conn.pid).or_insert(0) += 1;
    }
    let conns_pid_values: Vec<f64> = conns_per_pid.values().map(|&v| v as f64).collect();
    let conns_pid_thresh = outlier_threshold(&conns_pid_values);

    // --- Metric 4: Unique remote IPs per PID ---
    let mut unique_ips_per_pid: HashMap<u64, HashSet<String>> = HashMap::new();
    for conn in connections.iter() {
        if !conn.remote_addr.is_empty() && conn.remote_addr != "0.0.0.0" && conn.remote_addr != "::" {
            unique_ips_per_pid
                .entry(conn.pid)
                .or_default()
                .insert(conn.remote_addr.clone());
        }
    }
    let scatter_map: HashMap<u64, usize> = unique_ips_per_pid
        .iter()
        .map(|(&pid, ips)| (pid, ips.len()))
        .collect();
    let scatter_values: Vec<f64> = scatter_map.values().map(|&v| v as f64).collect();
    let scatter_thresh = outlier_threshold(&scatter_values);

    // --- Apply flags to each connection ---
    for conn in connections.iter_mut() {
        // Suspicious port check
        if sus_ports.contains(&conn.remote_port) {
            conn.flag_labels.push("C2-PORT".into());
        }

        // Fan-out check
        if let Some(&count) = fanout_map.get(&conn.remote_addr) {
            if fanout_values.len() > 1 && (count as f64) > fanout_thresh {
                conn.flag_labels.push(format!("FANOUT({count})"));
            }
        }

        // Fan-in check
        if let Some(&count) = fanin_map.get(&conn.local_port) {
            if fanin_values.len() > 1 && (count as f64) > fanin_thresh {
                conn.flag_labels.push(format!("FANIN({count})"));
            }
        }

        // Connections-per-PID check
        if let Some(&count) = conns_per_pid.get(&conn.pid) {
            if conns_pid_values.len() > 1 && (count as f64) > conns_pid_thresh {
                conn.flag_labels.push(format!("HIGH-PID({count})"));
            }
        }

        // Scatter check (unique IPs per PID)
        if let Some(&count) = scatter_map.get(&conn.pid) {
            if scatter_values.len() > 1 && (count as f64) > scatter_thresh {
                conn.flag_labels.push(format!("SCATTER({count})"));
            }
        }
    }

    // --- Compute summary ---
    let flagged_count = connections.iter().filter(|c| !c.flag_labels.is_empty()).count();

    let max_fanout_ip = fanout_map
        .iter()
        .max_by_key(|(_, &count)| count)
        .and_then(|(ip, &count)| ip.parse::<IpAddr>().ok().map(|addr| (addr, count)));

    let max_fanin_port = fanin_map
        .iter()
        .max_by_key(|(_, &count)| count)
        .map(|(&port, &count)| (port, count));

    let max_conns_pid = conns_per_pid
        .iter()
        .max_by_key(|(_, &count)| count)
        .map(|(&pid, &count)| (pid, count));

    let max_unique_ips_pid = scatter_map
        .iter()
        .max_by_key(|(_, &count)| count)
        .map(|(&pid, &count)| (pid, count));

    // --- Generate alerts for flagged connections ---
    if flagged_count > 0 {
        // Summary alert
        alerts.push(Alert {
            severity: AlertSeverity::Warning,
            category: "memory-network".into(),
            message: format!(
                "Memory dump: {flagged_count}/{total_connections} connections flagged as anomalous"
            ),
            detail: String::new(),
        });

        // Individual C2-PORT alerts (Critical)
        for conn in connections.iter() {
            if conn.flag_labels.iter().any(|l| l == "C2-PORT") {
                alerts.push(Alert {
                    severity: AlertSeverity::Critical,
                    category: "memory-network".into(),
                    message: format!(
                        "Memory dump: connection to suspicious port {}:{}",
                        conn.remote_addr, conn.remote_port
                    ),
                    detail: format!(
                        "proto={} local={}:{} pid={} flags=[{}]",
                        conn.protocol,
                        conn.local_addr,
                        conn.local_port,
                        conn.pid,
                        conn.flag_labels.join(", ")
                    ),
                });
            }
        }
    }

    NetworkFlagSummary {
        total_connections,
        flagged_count,
        max_fanout_ip,
        max_fanin_port,
        max_conns_pid,
        max_unique_ips_pid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::investigation::memory::{MemConnectionState, MemProtocol};

    /// Helper: build a TCP connection with the given parameters.
    fn make_conn(
        remote_addr: &str,
        remote_port: u16,
        local_port: u16,
        pid: u64,
    ) -> MemConnectionEntry {
        MemConnectionEntry {
            protocol: MemProtocol::Tcp,
            local_addr: "192.168.1.100".into(),
            local_port,
            remote_addr: remote_addr.into(),
            remote_port,
            state: MemConnectionState::Established,
            pid,
            flag_labels: Vec::new(),
        }
    }

    // -----------------------------------------------------------------------
    // mean_stddev
    // -----------------------------------------------------------------------

    #[test]
    fn mean_stddev_empty() {
        let (m, s) = mean_stddev(&[]);
        assert_eq!(m, 0.0);
        assert_eq!(s, 0.0);
    }

    #[test]
    fn mean_stddev_single_value() {
        let (m, s) = mean_stddev(&[5.0]);
        assert!((m - 5.0).abs() < f64::EPSILON);
        assert!((s - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn mean_stddev_uniform() {
        // All same value -> stddev = 0
        let (m, s) = mean_stddev(&[3.0, 3.0, 3.0, 3.0]);
        assert!((m - 3.0).abs() < f64::EPSILON);
        assert!((s - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn mean_stddev_known_values() {
        // Values: 2, 4, 4, 4, 5, 5, 7, 9
        // Mean = 5.0, Variance = 4.0, StdDev = 2.0
        let (m, s) = mean_stddev(&[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]);
        assert!((m - 5.0).abs() < 0.001);
        assert!((s - 2.0).abs() < 0.001);
    }

    // -----------------------------------------------------------------------
    // outlier_threshold
    // -----------------------------------------------------------------------

    #[test]
    fn outlier_threshold_known() {
        // mean=5, stddev=2, threshold = 5 + 2*2 = 9
        let t = outlier_threshold(&[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]);
        assert!((t - 9.0).abs() < 0.001);
    }

    // -----------------------------------------------------------------------
    // Empty connections
    // -----------------------------------------------------------------------

    #[test]
    fn flag_empty_connections() {
        let mut conns: Vec<MemConnectionEntry> = Vec::new();
        let mut alerts = Vec::new();
        let summary = flag_memory_connections(&mut conns, &mut alerts);
        assert_eq!(summary.total_connections, 0);
        assert_eq!(summary.flagged_count, 0);
        assert!(summary.max_fanout_ip.is_none());
        assert!(alerts.is_empty());
    }

    // -----------------------------------------------------------------------
    // Suspicious port detection (C2-PORT)
    // -----------------------------------------------------------------------

    #[test]
    fn flag_c2_port() {
        // Port 4444 is in the SUSPICIOUS_PORTS list (Metasploit default)
        let mut conns = vec![
            make_conn("10.0.0.1", 4444, 54321, 1234),
            make_conn("10.0.0.2", 443, 54322, 1235),
        ];
        let mut alerts = Vec::new();
        let summary = flag_memory_connections(&mut conns, &mut alerts);

        // First connection should have C2-PORT flag
        assert!(conns[0].flag_labels.contains(&"C2-PORT".to_string()));
        // Second connection should NOT have C2-PORT flag (443 is not suspicious)
        assert!(!conns[1].flag_labels.contains(&"C2-PORT".to_string()));

        assert!(summary.flagged_count >= 1);
        // Should have at least one Critical alert
        assert!(alerts.iter().any(|a| a.severity == AlertSeverity::Critical));
    }

    // -----------------------------------------------------------------------
    // Fan-out detection (FANOUT)
    // -----------------------------------------------------------------------

    #[test]
    fn flag_fanout_outlier() {
        // Create a scenario: most IPs have 1-2 connections, one IP has 20
        let mut conns = Vec::new();
        // 10 different IPs with 1 connection each
        for i in 0..10 {
            conns.push(make_conn(&format!("10.0.0.{i}"), 80, 50000 + i, 100));
        }
        // One IP with 20 connections (outlier)
        for _ in 0..20 {
            conns.push(make_conn("10.0.0.99", 80, 60000, 200));
        }

        let mut alerts = Vec::new();
        let summary = flag_memory_connections(&mut conns, &mut alerts);

        // The connections to 10.0.0.99 should be flagged with FANOUT
        let flagged_99: Vec<_> = conns
            .iter()
            .filter(|c| c.remote_addr == "10.0.0.99")
            .collect();
        assert!(flagged_99.iter().any(|c| c.flag_labels.iter().any(|l| l.starts_with("FANOUT"))));

        // Summary should track the max fan-out IP
        assert!(summary.max_fanout_ip.is_some());
        let (ip, count) = summary.max_fanout_ip.as_ref().expect("should be set");
        assert_eq!(ip.to_string(), "10.0.0.99");
        assert_eq!(*count, 20);
    }

    // -----------------------------------------------------------------------
    // Fan-in detection (FANIN)
    // -----------------------------------------------------------------------

    #[test]
    fn flag_fanin_outlier() {
        let mut conns = Vec::new();
        // 10 different local ports with 1 connection each
        for i in 0..10 {
            conns.push(make_conn("10.0.0.1", 80, 50000 + i, 100));
        }
        // One local port with 20 connections (outlier)
        for i in 0..20 {
            conns.push(make_conn(&format!("10.0.1.{i}"), 80, 8080, 200));
        }

        let mut alerts = Vec::new();
        let summary = flag_memory_connections(&mut conns, &mut alerts);

        // Connections on port 8080 should be flagged with FANIN
        let flagged_8080: Vec<_> = conns
            .iter()
            .filter(|c| c.local_port == 8080)
            .collect();
        assert!(flagged_8080.iter().any(|c| c.flag_labels.iter().any(|l| l.starts_with("FANIN"))));

        assert!(summary.max_fanin_port.is_some());
        let (port, count) = summary.max_fanin_port.as_ref().expect("should be set");
        assert_eq!(*port, 8080);
        assert_eq!(*count, 20);
    }

    // -----------------------------------------------------------------------
    // Connections-per-PID detection (HIGH-PID)
    // -----------------------------------------------------------------------

    #[test]
    fn flag_high_pid_outlier() {
        let mut conns = Vec::new();
        // 10 PIDs with 1 connection each
        for i in 0..10 {
            conns.push(make_conn("10.0.0.1", 80, 50000 + i, i.into()));
        }
        // One PID with 30 connections (outlier)
        for i in 0..30 {
            conns.push(make_conn(&format!("10.0.2.{i}"), 80, 60000, 999));
        }

        let mut alerts = Vec::new();
        let summary = flag_memory_connections(&mut conns, &mut alerts);

        // Connections for PID 999 should be flagged with HIGH-PID
        let flagged_999: Vec<_> = conns.iter().filter(|c| c.pid == 999).collect();
        assert!(flagged_999.iter().any(|c| c.flag_labels.iter().any(|l| l.starts_with("HIGH-PID"))));

        assert!(summary.max_conns_pid.is_some());
        let (pid, count) = summary.max_conns_pid.as_ref().expect("should be set");
        assert_eq!(*pid, 999);
        assert_eq!(*count, 30);
    }

    // -----------------------------------------------------------------------
    // Scatter detection (SCATTER)
    // -----------------------------------------------------------------------

    #[test]
    fn flag_scatter_outlier() {
        let mut conns = Vec::new();
        // 10 PIDs each talking to 1 unique IP
        for i in 0..10 {
            conns.push(make_conn(&format!("10.0.0.{i}"), 80, 50000, i.into()));
        }
        // One PID talking to 25 unique IPs (outlier)
        for i in 0..25 {
            conns.push(make_conn(&format!("10.1.0.{i}"), 80, 60000, 999));
        }

        let mut alerts = Vec::new();
        let summary = flag_memory_connections(&mut conns, &mut alerts);

        // PID 999's connections should be flagged with SCATTER
        let flagged_999: Vec<_> = conns.iter().filter(|c| c.pid == 999).collect();
        assert!(flagged_999.iter().any(|c| c.flag_labels.iter().any(|l| l.starts_with("SCATTER"))));

        assert!(summary.max_unique_ips_pid.is_some());
        let (pid, count) = summary.max_unique_ips_pid.as_ref().expect("should be set");
        assert_eq!(*pid, 999);
        assert_eq!(*count, 25);
    }

    // -----------------------------------------------------------------------
    // Multiple flags on same connection
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_flags_on_same_connection() {
        let mut conns = Vec::new();
        // 10 normal connections (1 each to different IPs, different PIDs)
        for i in 0..10 {
            conns.push(make_conn(&format!("10.0.0.{i}"), 80, 50000 + i, i.into()));
        }
        // One connection that hits multiple outlier conditions:
        // - C2-PORT (port 4444)
        // - FANOUT (many connections to same IP, added below)
        // - HIGH-PID (many connections from same PID, added below)
        // - SCATTER (many unique IPs from same PID, need different approach)
        // Let's make PID 999 have 20 connections to port 4444 on 10.0.0.99
        for _ in 0..20 {
            conns.push(make_conn("10.0.0.99", 4444, 60000, 999));
        }

        let mut alerts = Vec::new();
        let _summary = flag_memory_connections(&mut conns, &mut alerts);

        // PID 999's connections should have multiple flags
        let flagged_999: Vec<_> = conns.iter().filter(|c| c.pid == 999).collect();
        let first = &flagged_999[0];
        assert!(first.flag_labels.contains(&"C2-PORT".to_string()));
        // Should also have FANOUT and/or HIGH-PID depending on threshold
        assert!(first.flag_labels.len() >= 2, "expected multiple flags, got: {:?}", first.flag_labels);
    }

    // -----------------------------------------------------------------------
    // No outliers when all values are equal
    // -----------------------------------------------------------------------

    #[test]
    fn no_outliers_when_uniform() {
        // All PIDs have exactly 2 connections to the same 2 IPs
        let mut conns = Vec::new();
        for pid in 0..5 {
            conns.push(make_conn("10.0.0.1", 80, 50000, pid));
            conns.push(make_conn("10.0.0.2", 80, 50001, pid));
        }

        let mut alerts = Vec::new();
        let summary = flag_memory_connections(&mut conns, &mut alerts);

        // No statistical outliers (all uniform)
        // Only C2-PORT flags might appear if port 80 is in the list (it's not)
        let stat_flagged = conns
            .iter()
            .filter(|c| c.flag_labels.iter().any(|l| l != "C2-PORT"))
            .count();
        assert_eq!(stat_flagged, 0, "no statistical outliers expected in uniform data");
        assert_eq!(summary.flagged_count, 0);
    }

    // -----------------------------------------------------------------------
    // Alert generation
    // -----------------------------------------------------------------------

    #[test]
    fn alert_generated_for_c2_port() {
        let mut conns = vec![make_conn("10.0.0.1", 4444, 54321, 1234)];
        let mut alerts = Vec::new();
        flag_memory_connections(&mut conns, &mut alerts);

        assert!(alerts.iter().any(|a| {
            a.severity == AlertSeverity::Critical
                && a.category == "memory-network"
                && a.message.contains("suspicious port")
        }));
    }

    #[test]
    fn summary_alert_generated_when_flags_present() {
        let mut conns = vec![make_conn("10.0.0.1", 4444, 54321, 1234)];
        let mut alerts = Vec::new();
        flag_memory_connections(&mut conns, &mut alerts);

        assert!(alerts.iter().any(|a| {
            a.severity == AlertSeverity::Warning
                && a.message.contains("flagged as anomalous")
        }));
    }

    #[test]
    fn no_alerts_when_clean() {
        let mut conns = vec![
            make_conn("10.0.0.1", 443, 54321, 100),
            make_conn("10.0.0.2", 80, 54322, 101),
        ];
        let mut alerts = Vec::new();
        let summary = flag_memory_connections(&mut conns, &mut alerts);

        assert_eq!(summary.flagged_count, 0);
        assert!(alerts.is_empty());
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn single_connection_no_outliers() {
        let mut conns = vec![make_conn("10.0.0.1", 80, 54321, 100)];
        let mut alerts = Vec::new();
        let summary = flag_memory_connections(&mut conns, &mut alerts);

        // Single value can't be an outlier (stddev = 0, threshold = value)
        assert_eq!(summary.flagged_count, 0);
        assert_eq!(summary.total_connections, 1);
    }

    #[test]
    fn listen_sockets_excluded_from_fanout() {
        // LISTEN sockets have remote_addr = "0.0.0.0" -- should be excluded from fan-out
        let mut conns = vec![
            MemConnectionEntry {
                protocol: MemProtocol::Tcp,
                local_addr: "0.0.0.0".into(),
                local_port: 22,
                remote_addr: "0.0.0.0".into(),
                remote_port: 0,
                state: MemConnectionState::Listen,
                pid: 100,
                flag_labels: Vec::new(),
            },
            make_conn("10.0.0.1", 80, 54321, 101),
        ];
        let mut alerts = Vec::new();
        let summary = flag_memory_connections(&mut conns, &mut alerts);

        // LISTEN socket should not contribute to fanout or scatter
        assert_eq!(summary.total_connections, 2);
    }

    // -----------------------------------------------------------------------
    // suspicious_port_set
    // -----------------------------------------------------------------------

    #[test]
    fn suspicious_port_set_contains_known_ports() {
        let ports = suspicious_port_set();
        // Metasploit default
        assert!(ports.contains(&4444), "4444 should be in suspicious ports");
        // Another well-known C2 port
        assert!(ports.contains(&1337), "1337 should be in suspicious ports");
    }
}
```

- [ ] **Step 3: Run tests to verify they compile and pass**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p rt-navigator memory_network:: -- --nocapture 2>&1 | tail -30`

Expected: All tests PASS. The flagging function and tests are self-contained.

- [ ] **Step 4: Run full workspace tests + clippy**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1 | tail -10`
Run: `/Users/4n6h4x0r/.cargo/bin/cargo clippy --workspace -- -D warnings 2>&1 | tail -10`

Expected: All tests pass. Zero clippy warnings.

- [ ] **Step 5: Commit**

```bash
cd /Users/4n6h4x0r/src/RapidTriage
git add crates/rt-navigator/src/investigation/alerts/memory_network.rs crates/rt-navigator/src/investigation/alerts/mod.rs
git commit --no-gpg-sign -m "feat(alerts): add 4-metric network anomaly detection for memory dumps

Implement flag_memory_connections() with statistical outlier detection
(mean + 2*stddev) across 4 metrics: fan-out per remote IP, fan-in per
local port, connections per PID, unique IPs per PID. Also flags
connections to known-suspicious ports (C2-PORT) from existing SIGMA list.

Flag labels: C2-PORT, FANOUT(n), FANIN(n), HIGH-PID(n), SCATTER(n).
Generates Critical alerts for C2-PORT matches and Warning summary alert
for any flagged connections. 20 unit tests."
```

---

### Task 6: Wire Memory Network Alerts into Alert Engine

**Files:**
- Modify: `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/src/investigation/alerts/engine.rs` (lines 17-18, 28, 60+)

- [ ] **Step 1: Write a failing test**

Add to the `#[cfg(test)]` module at the bottom of `engine.rs`:

```rust
    #[test]
    fn detect_alerts_accepts_memory_connections() {
        use crate::investigation::memory::{MemConnectionEntry, MemConnectionState, MemProtocol};
        let mut mem_conns = vec![MemConnectionEntry {
            protocol: MemProtocol::Tcp,
            local_addr: "192.168.1.100".into(),
            local_port: 54321,
            remote_addr: "10.0.0.1".into(),
            remote_port: 4444,
            state: MemConnectionState::Established,
            pid: 1234,
            flag_labels: Vec::new(),
        }];
        let input = empty_input();
        let (alerts, summary) = detect_alerts_with_memory(&input, &mut mem_conns);
        // C2-PORT flag should be set
        assert!(mem_conns[0].flag_labels.contains(&"C2-PORT".to_string()));
        assert!(alerts.iter().any(|a| a.category == "memory-network"));
        assert!(summary.is_some());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p rt-navigator detect_alerts_accepts_memory_connections -- --nocapture 2>&1 | tail -20`

Expected: FAIL -- `detect_alerts_with_memory` doesn't exist.

- [ ] **Step 3: Add detect_alerts_with_memory function (GREEN)**

In `engine.rs`, add the import at the top:

```rust
use super::memory_network::flag_memory_connections;
use crate::investigation::memory::{MemConnectionEntry, NetworkFlagSummary};
```

Add a new public function after `detect_alerts()`:

```rust
/// Run all alert heuristics including memory network anomaly detection.
///
/// This is an extension of `detect_alerts()` that additionally runs the
/// 4-metric network anomaly flagging on memory dump connections. The
/// `memory_connections` slice is mutated in-place to add flag labels.
///
/// Returns the alert list and an optional `NetworkFlagSummary`.
#[must_use]
pub fn detect_alerts_with_memory(
    input: &AlertInput<'_>,
    memory_connections: &mut [MemConnectionEntry],
) -> (Vec<Alert>, Option<NetworkFlagSummary>) {
    let mut alerts = detect_alerts(input);

    let summary = if memory_connections.is_empty() {
        None
    } else {
        Some(flag_memory_connections(memory_connections, &mut alerts))
    };

    // Re-sort after adding memory alerts
    alerts.sort_by_key(|a| a.severity);

    (alerts, summary)
}
```

Export it from `mod.rs`:

In `alerts/mod.rs`, change the `pub use engine::` line to:

```rust
pub use engine::{anomalies_to_alerts, detect_alerts, detect_alerts_with_memory};
```

- [ ] **Step 4: Run tests to verify GREEN**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p rt-navigator detect_alerts_accepts_memory_connections -- --nocapture 2>&1 | tail -20`

Expected: PASS.

- [ ] **Step 5: Run full workspace tests + clippy**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1 | tail -10`
Run: `/Users/4n6h4x0r/.cargo/bin/cargo clippy --workspace -- -D warnings 2>&1 | tail -10`

Expected: All tests pass. Zero clippy warnings.

- [ ] **Step 6: Commit**

```bash
cd /Users/4n6h4x0r/src/RapidTriage
git add crates/rt-navigator/src/investigation/alerts/engine.rs crates/rt-navigator/src/investigation/alerts/mod.rs
git commit --no-gpg-sign -m "feat(alerts): wire memory network anomaly detection into alert engine

Add detect_alerts_with_memory() that extends detect_alerts() with
4-metric memory connection flagging. Returns (Vec<Alert>, Option<NetworkFlagSummary>).
Exported from alerts mod for use by memory_loader."
```

---

### Task 7: Memory Dump Loader (memory_loader.rs) -- RED

**Files:**
- Create: `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/src/investigation/memory_loader.rs`
- Modify: `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/src/investigation/mod.rs` (line 5)

This module handles dump detection and walker invocation. Archive decompression (.zip/.7z) is handled transparently by `memf-format::open_dump()` — this module just passes file paths through.

- [ ] **Step 1: Register the module**

In `mod.rs`, add after the `pub mod memory;` line:

```rust
pub mod memory_loader;
```

- [ ] **Step 2: Create memory_loader.rs with implementation and tests**

Create `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/src/investigation/memory_loader.rs`:

```rust
//! Memory dump detection and walker invocation.
//!
//! Scans a UAC collection's `memory_dump/` directory for memory dumps.
//! Probes files via `memf_format::open_dump()` which handles archive
//! decompression (.zip/.7z) transparently. Runs OS-specific walkers
//! and populates the memory fields of `InvestigationData`.

use std::fs;
use std::path::{Path, PathBuf};

use memf_format::MachineType;

use super::memory::{
    MemConnectionEntry, MemLibraryEntry, MemModuleEntry, MemProcessEntry, MemThreadEntry,
    MemoryDumpInfo, OsProfile,
};

/// Known file extensions that may contain memory dumps.
///
/// Includes both raw dump formats and archive formats (.zip, .7z) since
/// `memf_format::open_dump()` handles archive decompression transparently.
const KNOWN_EXTENSIONS: &[&str] = &[
    "lime", "avml", "dmp", "vmem", "vmss", "vmsn", "raw", "mem", "img", "core",
    "zip", "7z",
];

/// Result of loading a memory dump from a UAC collection.
#[derive(Debug)]
pub struct MemoryLoadResult {
    /// Metadata about the dump.
    pub info: MemoryDumpInfo,
    /// Processes extracted from the dump.
    pub processes: Vec<MemProcessEntry>,
    /// Network connections extracted from the dump.
    pub connections: Vec<MemConnectionEntry>,
    /// Kernel modules/drivers extracted from the dump.
    pub modules: Vec<MemModuleEntry>,
    /// Loaded libraries (DLLs/shared objects).
    pub libraries: Vec<MemLibraryEntry>,
    /// Threads extracted from the dump.
    pub threads: Vec<MemThreadEntry>,
}

/// Scan a UAC collection directory for memory dumps.
///
/// Looks in `{extracted_root}/memory_dump/` for dump files. Tries each file
/// with a known extension via `memf_format::open_dump()`, which handles
/// .zip/.7z archive decompression transparently.
///
/// Returns the path to the first recognized dump file.
pub fn find_memory_dump(extracted_root: &Path) -> Option<PathBuf> {
    let memory_dir = extracted_root.join("memory_dump");
    if !memory_dir.is_dir() {
        return None;
    }

    let entries = match fs::read_dir(&memory_dir) {
        Ok(e) => e,
        Err(_) => return None,
    };

    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    files.sort();

    // Try open_dump() on files with known extensions.
    // open_dump() handles .zip/.7z archives transparently.
    for file in &files {
        if is_known_extension(file) && probe_dump(file) {
            return Some(file.clone());
        }
    }

    None
}

/// Check if a file has a known dump or archive extension.
fn is_known_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| KNOWN_EXTENSIONS.contains(&e.to_lowercase().as_str()))
        .unwrap_or(false)
}

/// Probe whether a file is a recognized memory dump format.
///
/// This calls `memf_format::open_dump()` which handles .zip/.7z
/// archive decompression transparently.
fn probe_dump(path: &Path) -> bool {
    memf_format::open_dump(path).is_ok()
}

/// Load a memory dump: open it, detect OS, run walkers, return results.
///
/// This is the main entry point called from `load_uac_collection()`.
pub fn load_memory_dump(dump_path: &Path) -> Option<MemoryLoadResult> {
    let provider = memf_format::open_dump(dump_path).ok()?;
    let metadata = provider.metadata();

    // Determine OS and architecture from metadata
    let machine_type = metadata.as_ref().and_then(|m| m.machine_type);
    let arch = match machine_type {
        Some(MachineType::Amd64) => "AMD64".to_string(),
        Some(MachineType::I386) => "x86".to_string(),
        Some(MachineType::Aarch64) => "ARM64".to_string(),
        None => "Unknown".to_string(),
    };

    let format_name = provider.format_name().to_string();
    let total_size: u64 = provider.ranges().iter().map(|r| r.len()).sum();

    // Detect OS from metadata (Windows crash dumps have os_version)
    let os_version = metadata.as_ref().and_then(|m| m.os_version);
    let has_windows_metadata = os_version.is_some()
        || metadata.as_ref().and_then(|m| m.ps_active_process_head).is_some();

    if has_windows_metadata {
        load_windows_dump(dump_path, &arch, &format_name, total_size, &metadata)
    } else {
        load_linux_dump(dump_path, &arch, &format_name, total_size)
    }
}

/// Load a Windows memory dump using memf-windows walkers.
fn load_windows_dump(
    dump_path: &Path,
    arch: &str,
    format_name: &str,
    total_size: u64,
    metadata: &Option<memf_format::DumpMetadata>,
) -> Option<MemoryLoadResult> {
    // Windows walkers need an ObjectReader + symbols, which require
    // PDB resolution. For now, we attempt to walk using metadata-embedded
    // addresses (PsActiveProcessHead, PsLoadedModuleList from crash dump header).
    //
    // Full PDB-based walking will be enhanced in Phase 3E-C/D.
    // For now, return the dump info with empty walker results if we can't
    // bootstrap the reader.

    let info = MemoryDumpInfo {
        os: OsProfile::Windows,
        arch: arch.to_string(),
        dump_format: format_name.to_string(),
        dump_path: dump_path.to_path_buf(),
        physical_memory_size: Some(total_size),
    };

    // TODO(Phase 3E-C): Wire up memf-windows walkers with PDB symbol resolution.
    // For now, we just detect the dump and report metadata.
    // The walker integration requires an ObjectReader with symbols loaded,
    // which depends on the PDB download/cache pipeline from memf-symbols.
    let _ = metadata; // Will be used when walkers are wired

    Some(MemoryLoadResult {
        info,
        processes: Vec::new(),
        connections: Vec::new(),
        modules: Vec::new(),
        libraries: Vec::new(),
        threads: Vec::new(),
    })
}

/// Load a Linux memory dump using memf-linux walkers.
fn load_linux_dump(
    dump_path: &Path,
    arch: &str,
    format_name: &str,
    total_size: u64,
) -> Option<MemoryLoadResult> {
    let info = MemoryDumpInfo {
        os: OsProfile::Linux,
        arch: arch.to_string(),
        dump_format: format_name.to_string(),
        dump_path: dump_path.to_path_buf(),
        physical_memory_size: Some(total_size),
    };

    // TODO(Phase 3E-C): Wire up memf-linux WalkerPlugin with ISF/BTF symbols.
    // Linux walkers require symbol information (ISF JSON or BTF) loaded into
    // an ObjectReader. The full pipeline will be wired in Phase 3E-C.
    // For now, we detect the dump and report metadata.

    Some(MemoryLoadResult {
        info,
        processes: Vec::new(),
        connections: Vec::new(),
        modules: Vec::new(),
        libraries: Vec::new(),
        threads: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Extension detection
    // -----------------------------------------------------------------------

    #[test]
    fn is_known_extension_recognizes_lime() {
        assert!(is_known_extension(Path::new("/tmp/mem.lime")));
    }

    #[test]
    fn is_known_extension_recognizes_dmp() {
        assert!(is_known_extension(Path::new("/tmp/memory.dmp")));
    }

    #[test]
    fn is_known_extension_recognizes_vmem() {
        assert!(is_known_extension(Path::new("/tmp/snapshot.vmem")));
    }

    #[test]
    fn is_known_extension_recognizes_zip() {
        assert!(is_known_extension(Path::new("/tmp/dump.zip")));
    }

    #[test]
    fn is_known_extension_recognizes_7z() {
        assert!(is_known_extension(Path::new("/tmp/dump.7z")));
    }

    #[test]
    fn is_known_extension_case_insensitive() {
        assert!(is_known_extension(Path::new("/tmp/MEMORY.DMP")));
        assert!(is_known_extension(Path::new("/tmp/dump.LiME")));
        assert!(is_known_extension(Path::new("/tmp/archive.ZIP")));
    }

    #[test]
    fn is_known_extension_rejects_unknown() {
        assert!(!is_known_extension(Path::new("/tmp/file.txt")));
        assert!(!is_known_extension(Path::new("/tmp/file.exe")));
        assert!(!is_known_extension(Path::new("/tmp/file.tar.gz")));
        assert!(!is_known_extension(Path::new("/tmp/file.rar")));
    }

    #[test]
    fn is_known_extension_no_extension() {
        assert!(!is_known_extension(Path::new("/tmp/memdump")));
    }

    // -----------------------------------------------------------------------
    // find_memory_dump -- no memory_dump directory
    // -----------------------------------------------------------------------

    #[test]
    fn find_memory_dump_no_dir() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let result = find_memory_dump(temp.path());
        assert!(result.is_none());
    }

    #[test]
    fn find_memory_dump_empty_dir() {
        let temp = tempfile::tempdir().expect("create temp dir");
        fs::create_dir_all(temp.path().join("memory_dump")).expect("create dir");
        let result = find_memory_dump(temp.path());
        assert!(result.is_none());
    }

    #[test]
    fn find_memory_dump_unrecognized_file() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let mem_dir = temp.path().join("memory_dump");
        fs::create_dir_all(&mem_dir).expect("create dir");
        // Write a file with .dmp extension but invalid content
        fs::write(mem_dir.join("fake.dmp"), b"not a real dump").expect("write file");
        let result = find_memory_dump(temp.path());
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // KNOWN_EXTENSIONS coverage
    // -----------------------------------------------------------------------

    #[test]
    fn known_extensions_includes_dump_formats() {
        for ext in &["lime", "avml", "dmp", "vmem", "vmss", "vmsn", "raw", "mem", "img", "core"] {
            assert!(
                KNOWN_EXTENSIONS.contains(ext),
                "Missing dump extension: {ext}"
            );
        }
    }

    #[test]
    fn known_extensions_includes_archive_formats() {
        assert!(KNOWN_EXTENSIONS.contains(&"zip"));
        assert!(KNOWN_EXTENSIONS.contains(&"7z"));
    }

    // -----------------------------------------------------------------------
    // MemoryLoadResult construction
    // -----------------------------------------------------------------------

    #[test]
    fn memory_load_result_empty() {
        let result = MemoryLoadResult {
            info: MemoryDumpInfo {
                os: OsProfile::Linux,
                arch: "AMD64".into(),
                dump_format: "LiME".into(),
                dump_path: PathBuf::from("/tmp/test.lime"),
                physical_memory_size: Some(1024),
            },
            processes: Vec::new(),
            connections: Vec::new(),
            modules: Vec::new(),
            libraries: Vec::new(),
            threads: Vec::new(),
        };
        assert_eq!(result.info.os, OsProfile::Linux);
        assert!(result.processes.is_empty());
        assert!(result.connections.is_empty());
    }
}
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p rt-navigator memory_loader:: -- --nocapture 2>&1 | tail -30`

Expected: All tests PASS.

- [ ] **Step 4: Run full workspace tests + clippy**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1 | tail -10`
Run: `/Users/4n6h4x0r/.cargo/bin/cargo clippy --workspace -- -D warnings 2>&1 | tail -10`

Expected: All tests pass. Zero clippy warnings.

- [ ] **Step 5: Commit**

```bash
cd /Users/4n6h4x0r/src/RapidTriage
git add crates/rt-navigator/src/investigation/memory_loader.rs crates/rt-navigator/src/investigation/mod.rs
git commit --no-gpg-sign -m "feat(memory): add memory dump loader with detection and format probing

Add memory_loader.rs with find_memory_dump() for UAC collection scanning
and load_memory_dump() entry point. Archive decompression (.zip/.7z) is
handled transparently by memf_format::open_dump(). OS detection uses
dump metadata.

Walker invocation is stubbed for Phase 3E-C (requires symbol resolution).
Dump detection is fully functional. 12 unit tests."
```

---

### Task 8: Wire Memory Loader into load_uac_collection()

**Files:**
- Modify: `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/src/investigation/data.rs`

- [ ] **Step 1: Write a failing test (RED)**

Add to the `#[cfg(test)]` module at the bottom of `data.rs`:

```rust
    #[test]
    fn load_uac_collection_without_memory_dump() {
        // A UAC collection without memory_dump/ dir should leave memory fields empty
        let temp = tempfile::tempdir().expect("create temp dir");
        let data = load_uac_collection(temp.path(), None);
        assert!(data.memory_info.is_none());
        assert!(data.memory_processes.is_empty());
        assert!(data.memory_connections.is_empty());
        assert!(data.network_flags.is_none());
    }
```

- [ ] **Step 2: Run test to see if it passes**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test -p rt-navigator load_uac_collection_without_memory_dump -- --nocapture 2>&1 | tail -20`

Expected: This should PASS with the current code since memory fields default to `None`/empty. This validates the baseline.

- [ ] **Step 3: Add memory loading to load_uac_collection() (GREEN)**

In `data.rs`, add the import at the top:

```rust
use super::memory_loader::{find_memory_dump, load_memory_dump};
use super::alerts::detect_alerts_with_memory;
```

Note: No `tempfile` import needed — archive decompression is handled inside `memf-format::open_dump()`.

In `load_uac_collection()`, replace the alert detection and InvestigationData construction block. After the timeline is built and sorted (around line 185), replace:

```rust
    let alert_input = AlertInput {
        ...
    };
    let alerts = detect_alerts(&alert_input);

    InvestigationData {
        ...
    }
```

with:

```rust
    // ----- Attempt memory dump loading -----
    // find_memory_dump() scans memory_dump/ dir, open_dump() handles .zip/.7z transparently
    let mem_result = find_memory_dump(extracted_root)
        .and_then(|dump_path| load_memory_dump(&dump_path));

    let mut memory_connections = mem_result
        .as_ref()
        .map(|r| r.connections.clone())
        .unwrap_or_default();

    // ----- Run alert detection (with memory network anomalies if present) -----
    let alert_input = AlertInput {
        bodyfile: &bodyfile_entries,
        network: &network_conns,
        processes: &processes,
        crontabs: &crontabs,
        chkrootkit: &chkrootkit_findings,
        rootkit_findings: &rootkit_findings,
        configs: &config_files,
        hashes: &hashes,
        packages: &packages,
        logins: &logins,
        windows_events: &[],
    };
    let (alerts, network_flags) =
        detect_alerts_with_memory(&alert_input, &mut memory_connections);

    InvestigationData {
        metadata,
        alerts,
        timeline,
        mft_tree: None,
        anomaly_index: None,
        network: network_conns,
        processes,
        crontabs,
        logins,
        packages,
        hashes,
        chkrootkit: chkrootkit_findings,
        rootkit_findings,
        configs: config_files,
        artifact_counts: HashMap::new(),
        memory_info: mem_result.as_ref().map(|r| r.info.clone()),
        memory_processes: mem_result
            .as_ref()
            .map(|r| r.processes.clone())
            .unwrap_or_default(),
        memory_connections,
        memory_modules: mem_result
            .as_ref()
            .map(|r| r.modules.clone())
            .unwrap_or_default(),
        memory_libraries: mem_result
            .as_ref()
            .map(|r| r.libraries.clone())
            .unwrap_or_default(),
        memory_threads: mem_result
            .as_ref()
            .map(|r| r.threads.clone())
            .unwrap_or_default(),
        network_flags,
    }
```

**Note:** Remove the old `use super::alerts::{detect_alerts, Alert, AlertInput};` import and update to include `detect_alerts_with_memory`:

```rust
use super::alerts::{detect_alerts_with_memory, Alert, AlertInput};
```

Keep `detect_alerts` imported if other code still uses it (e.g. tests, velociraptor loader).

- [ ] **Step 4: Run tests**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1 | tail -10`
Run: `/Users/4n6h4x0r/.cargo/bin/cargo clippy --workspace -- -D warnings 2>&1 | tail -10`

Expected: All tests pass. The baseline test confirms memory fields are empty when no dump is present.

- [ ] **Step 5: Commit**

```bash
cd /Users/4n6h4x0r/src/RapidTriage
git add crates/rt-navigator/src/investigation/data.rs
git commit --no-gpg-sign -m "feat(data): wire memory dump loader into UAC collection pipeline

load_uac_collection() now scans for memory dumps in the extracted UAC
directory, probes for recognized formats (archive decompression handled
transparently by memf-format), and populates InvestigationData memory
fields. Uses detect_alerts_with_memory() for combined traditional +
memory network anomaly alert detection."
```

---

### Task 9: Integration Tests with Synthetic Data

**Files:**
- Modify: `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/src/investigation/data.rs` (test module)
- Modify: `/Users/4n6h4x0r/src/RapidTriage/crates/rt-navigator/src/investigation/alerts/memory_network.rs` (test module)

- [ ] **Step 1: Add integration test for memory loader with invalid dump**

Add to the `#[cfg(test)]` module in `data.rs`:

```rust
    #[test]
    fn load_uac_collection_with_memory_dump_dir_no_valid_dump() {
        // A UAC collection with memory_dump/ dir but no valid dump files
        // open_dump() will reject the invalid content regardless of extension
        let temp = tempfile::tempdir().expect("create temp dir");
        let mem_dir = temp.path().join("memory_dump");
        std::fs::create_dir_all(&mem_dir).expect("create dir");
        std::fs::write(mem_dir.join("fake.dmp"), b"not a dump").expect("write");
        let data = load_uac_collection(temp.path(), None);
        assert!(data.memory_info.is_none());
    }
```

- [ ] **Step 2: Add integration test for memory anomaly flagging end-to-end**

Add to the `#[cfg(test)]` module in `memory_network.rs`:

```rust
    #[test]
    fn end_to_end_flag_and_summary() {
        // Simulate a realistic scenario: 50 normal connections + 1 C2 outlier
        let mut conns = Vec::new();
        for i in 0..50 {
            conns.push(make_conn(
                &format!("10.0.{}.{}", i / 256, i % 256),
                443,
                50000 + i,
                (100 + i / 5).into(),
            ));
        }
        // C2 connection: suspicious port, many to same IP, from single PID
        for _ in 0..15 {
            conns.push(make_conn("185.100.87.202", 4444, 60000, 666));
        }

        let mut alerts = Vec::new();
        let summary = flag_memory_connections(&mut conns, &mut alerts);

        assert_eq!(summary.total_connections, 65);
        assert!(summary.flagged_count > 0);
        // The C2 connections should all be flagged
        let c2_flagged = conns
            .iter()
            .filter(|c| c.remote_addr == "185.100.87.202" && !c.flag_labels.is_empty())
            .count();
        assert_eq!(c2_flagged, 15);
        // Should have Critical alerts for C2-PORT
        assert!(alerts.iter().any(|a| a.severity == AlertSeverity::Critical));
    }
```

- [ ] **Step 3: Run tests**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1 | tail -10`
Run: `/Users/4n6h4x0r/.cargo/bin/cargo clippy --workspace -- -D warnings 2>&1 | tail -10`

Expected: All tests pass. Zero clippy warnings.

- [ ] **Step 4: Commit**

```bash
cd /Users/4n6h4x0r/src/RapidTriage
git add crates/rt-navigator/src/investigation/data.rs crates/rt-navigator/src/investigation/alerts/memory_network.rs
git commit --no-gpg-sign -m "test: add integration tests for memory loader and anomaly detection

Add load_uac_collection test for memory_dump/ dir with no valid dump.
Add end-to-end test for realistic connection scenario with C2 outlier
detection across all 4 metrics."
```

---

### Task 10: Final Verification and Cleanup

**Files:** All modified files

- [ ] **Step 1: Run full workspace tests**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1 | tail -20`

Expected: All tests pass (existing + new).

- [ ] **Step 2: Run clippy**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo clippy --workspace -- -D warnings 2>&1 | tail -20`

Expected: Zero warnings.

- [ ] **Step 3: Run cargo fmt**

Run: `/Users/4n6h4x0r/.cargo/bin/cargo fmt --all -- --check 2>&1 | tail -10`

Expected: No formatting issues.

- [ ] **Step 4: Verify test counts**

Count new tests added:
- `memory.rs`: ~22 tests (type conversions, filetime, display impls)
- `memory_network.rs`: ~20 tests (mean/stddev, flagging metrics, alerts, edge cases)
- `memory_loader.rs`: ~12 tests (extension detection, find_dump, load result construction)
- `data.rs`: ~4 tests (memory field defaults, debug, loader wiring)
- `engine.rs`: ~1 test (detect_alerts_with_memory)

Total new: ~59 tests.

Run: `/Users/4n6h4x0r/.cargo/bin/cargo test --workspace 2>&1 | grep 'test result'`

Expected: Previous test count + ~59 new tests, all passing.

- [ ] **Step 5: Verify file structure**

Confirm these files exist:
```
crates/rt-navigator/src/investigation/memory.rs          (NEW)
crates/rt-navigator/src/investigation/memory_loader.rs   (NEW)
crates/rt-navigator/src/investigation/alerts/memory_network.rs (NEW)
```

Confirm these files were modified:
```
Cargo.toml
Cargo.lock
crates/rt-navigator/Cargo.toml
crates/rt-navigator/src/investigation/data.rs
crates/rt-navigator/src/investigation/mod.rs
crates/rt-navigator/src/investigation/alerts/mod.rs
crates/rt-navigator/src/investigation/alerts/engine.rs
crates/rt-navigator/src/investigation/views/mod.rs
```

- [ ] **Step 6: Run any `#[ignore]` tests manually (real data)**

If test dump files are available on the system:

```bash
# Only if test data exists:
/Users/4n6h4x0r/.cargo/bin/cargo test --workspace -- --ignored 2>&1 | tail -20
```

- [ ] **Step 7: Final commit if any cleanup was needed**

```bash
cd /Users/4n6h4x0r/src/RapidTriage
git add -A
git commit --no-gpg-sign -m "chore: final cleanup for Phase 3E-A/B integration

Ensure all tests pass, clippy clean, formatting correct."
```

---

## Summary of Changes

### 3E-A: Core Integration + Data Layer
1. **Workspace dependencies** -- 6 memf crates added to RapidTriage (no archive deps — decompression in memf-format)
2. **Unified memory types** -- `memory.rs` with 7 types, 6 enums, `From` conversions
3. **InvestigationData extension** -- 7 new fields for memory forensic data
4. **WorkbenchView extension** -- 4 new variants (MemProcesses, MemNetwork, MemModules, MemLibraries)
5. **Memory dump loader** -- Detection, format probing (archive decompression in memf-format), OS detection
6. **UAC pipeline wiring** -- `load_uac_collection()` scans for and loads memory dumps

### 3E-B: Network Anomaly Detection
1. **4-metric flagging algorithm** -- Fan-out/fan-in/connections-per-PID/scatter
2. **Statistical outlier detection** -- mean + 2*stddev threshold
3. **Suspicious port floor** -- Reuses existing SIGMA-sourced port list (C2-PORT flags)
4. **Alert integration** -- `detect_alerts_with_memory()` extends existing alert pipeline
5. **NetworkFlagSummary** -- Pre-computed aggregate statistics for dashboard display

### What's Left for Phase 3E-C/D
- TUI panels for MemProcesses, MemNetwork, MemModules, MemLibraries views
- Full walker invocation (requires symbol resolution pipeline from memf-symbols)
- Dashboard enhancements (process timeline chart, network volume strip)
- Cross-panel linking (select process -> filter connections)
- Real-data integration tests with test corpus dumps
