//! Pure heuristic classifiers for Linux forensic artifacts.
//!
//! This module consolidates all `classify_*` functions from the individual
//! walker modules into one discoverable, collectively-testable location.
//!
//! Each function is a pure heuristic: it takes only primitive values and
//! returns `bool` or a tuple — no `ObjectReader` dependency.
//!
//! The original walker modules re-export every symbol from here so all
//! existing call sites continue to compile unchanged.

// ---------------------------------------------------------------------------
// BPF program classification
// ---------------------------------------------------------------------------

/// Classify whether a BPF program type/name combination is suspicious.
///
/// Returns `true` for kprobe, lsm, raw_tracepoint_writable programs, and
/// unnamed tracing/raw_tracepoint programs.
pub fn classify_bpf_program(prog_type: &str, name: &str) -> bool {
    match prog_type {
        // kprobe can hook arbitrary kernel functions — always suspicious.
        "kprobe" => true,

        // Unnamed tracing/raw_tracepoint programs suggest evasion.
        "tracing" | "raw_tracepoint" => name.is_empty(),

        // raw_tracepoint_writable can modify tracepoint arguments — always suspicious.
        "raw_tracepoint_writable" => true,

        // LSM programs can override security decisions.
        "lsm" => true,

        // Everything else (socket_filter, xdp, tracepoint, etc.) is
        // considered benign by default at the type level.
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Capabilities classification
// ---------------------------------------------------------------------------

/// Capability bit constants (from include/uapi/linux/capability.h).
const CAP_NET_RAW: u64 = 1 << 13;
const CAP_SYS_MODULE: u64 = 1 << 16;
const CAP_SYS_PTRACE: u64 = 1 << 19;
const CAP_SYS_ADMIN: u64 = 1 << 21;

/// Capabilities considered suspicious when held by a non-root process.
const SUSPICIOUS_CAPS: &[(u64, &str)] = &[
    (CAP_SYS_ADMIN, "CAP_SYS_ADMIN"),
    (CAP_SYS_PTRACE, "CAP_SYS_PTRACE"),
    (CAP_SYS_MODULE, "CAP_SYS_MODULE"),
    (CAP_NET_RAW, "CAP_NET_RAW"),
];

/// Classify whether a non-root process holds suspicious Linux capabilities.
///
/// Returns `(is_suspicious, suspicious_cap_names)`. Root (uid == 0) is never
/// flagged.
pub fn classify_capabilities(effective: u64, uid: u32) -> (bool, Vec<String>) {
    // Root is never suspicious -- it's expected to have all caps.
    if uid == 0 {
        return (false, Vec::new());
    }

    let mut suspicious_names = Vec::new();
    for &(cap_bit, cap_label) in SUSPICIOUS_CAPS {
        if effective & cap_bit != 0 {
            suspicious_names.push(cap_label.to_string());
        }
    }

    let is_suspicious = !suspicious_names.is_empty();
    (is_suspicious, suspicious_names)
}

// ---------------------------------------------------------------------------
// Cgroup classification
// ---------------------------------------------------------------------------

/// Classify whether a cgroup path indicates a container runtime.
///
/// Returns `(in_container, container_id)`. Recognises Docker, LXC, Kubernetes
/// and containerd path prefixes.
pub fn classify_cgroup(path: &str) -> (bool, String) {
    const RUNTIME_PREFIXES: &[&str] = &["/docker/", "/lxc/", "/kubepods/", "/containerd/"];

    for prefix in RUNTIME_PREFIXES {
        if let Some(idx) = path.find(prefix) {
            let after_prefix = &path[idx + prefix.len()..];
            // Extract the container ID: take everything up to the next '/' or end.
            let id = after_prefix.split('/').next().unwrap_or("").to_string();
            return (true, id);
        }
    }

    (false, String::new())
}

// ---------------------------------------------------------------------------
// AF-info hook classification
// ---------------------------------------------------------------------------

/// Classify whether a network protocol handler function pointer has been hooked.
///
/// Returns `true` when the address is non-zero and outside the kernel text range
/// `[kernel_start, kernel_end]`.
pub fn classify_afinfo_hook(hook_addr: u64, kernel_start: u64, kernel_end: u64) -> bool {
    if hook_addr == 0 {
        return false;
    }
    !(kernel_start <= hook_addr && hook_addr <= kernel_end)
}

// ---------------------------------------------------------------------------
// Shared credentials classification
// ---------------------------------------------------------------------------

/// Heuristic: PIDs <= 2 are typically kernel threads (idle, kthreadd).
fn is_likely_kernel_thread_heuristic(pid: u32) -> bool {
    pid <= 2
}

/// Classify whether shared `struct cred` pointers indicate credential theft.
///
/// Returns `true` when a non-kernel-thread shares credentials with init (PID 1)
/// or when unrelated processes share credentials.
pub fn classify_shared_creds(pid: u32, shared_with: &[u32], uid: u32) -> bool {
    // Sharing with init (pid 1) by a non-kernel-thread is suspicious.
    if shared_with.contains(&1) && pid != 1 {
        // uid 0 kernel threads sharing with init is expected (kernel cred)
        if uid == 0 && is_likely_kernel_thread_heuristic(pid) {
            return false;
        }
        return true;
    }

    // If all participants are uid-0 kernel threads, benign.
    if uid == 0 && is_likely_kernel_thread_heuristic(pid) {
        return false;
    }

    // Conservatively flag any remaining sharing as suspicious.
    !shared_with.is_empty()
}

// ---------------------------------------------------------------------------
// IDT entry classification
// ---------------------------------------------------------------------------

/// Classify whether an IDT handler address has been hooked.
///
/// Returns `true` when the address is non-zero and outside `[kernel_start, kernel_end]`.
pub fn classify_idt_entry(handler_addr: u64, kernel_start: u64, kernel_end: u64) -> bool {
    if handler_addr == 0 {
        return false;
    }
    !(kernel_start <= handler_addr && handler_addr <= kernel_end)
}

// ---------------------------------------------------------------------------
// Container escape classification
// ---------------------------------------------------------------------------

/// Kernel thread comm prefixes that are never suspicious.
const KERNEL_THREAD_COMMS: &[&str] = &["kthread", "kworker", "migration", "ksoftirqd", "rcu_"];

/// Classify whether a process indicator suggests a container escape attempt.
///
/// Returns `false` for kernel threads regardless of indicator.
pub fn classify_container_escape(comm: &str, indicator: &str) -> bool {
    let is_kernel = KERNEL_THREAD_COMMS
        .iter()
        .any(|prefix| comm.starts_with(prefix));
    if is_kernel {
        return false;
    }
    matches!(indicator, "namespace_mismatch" | "host_mount_access")
}

// ---------------------------------------------------------------------------
// Deleted executable classification
// ---------------------------------------------------------------------------

/// Package manager process names considered benign even when running deleted executables.
const KNOWN_BENIGN_COMMS: &[&str] = &[
    "apt",
    "apt-get",
    "apt-check",
    "aptd",
    "dpkg",
    "dpkg-deb",
    "yum",
    "dnf",
    "rpm",
    "rpmdb",
    "packagekitd",
    "unattended-upgr",
];

/// Classify whether a process running from a deleted executable is suspicious.
///
/// Returns `false` for kernel threads, package manager processes, and processes
/// with empty paths/names.
pub fn classify_deleted_exe(exe_path: &str, comm: &str) -> bool {
    // Not deleted at all -> not suspicious
    if !exe_path.contains("(deleted)") {
        return false;
    }

    // Empty exe path -> kernel thread, not suspicious
    if exe_path.is_empty() {
        return false;
    }

    // Empty comm -> likely kernel thread, not suspicious
    if comm.is_empty() {
        return false;
    }

    // Check against known-benign process names
    let comm_lower = comm.to_lowercase();
    for &benign in KNOWN_BENIGN_COMMS {
        if comm_lower == benign {
            return false;
        }
    }

    // All other deleted executables are suspicious
    true
}

// ---------------------------------------------------------------------------
// Hidden dentry classification
// ---------------------------------------------------------------------------

/// File extensions considered suspicious when found in linked dentries.
const SUSPICIOUS_EXTENSIONS: &[&str] = &[".so", ".py", ".sh", ".elf", ".bin"];

/// Classify whether a dentry is hidden or suspicious.
///
/// Returns `true` when `nlink == 0` (unlinked file still mapped) or when the
/// filename has a suspicious extension despite being linked.
pub fn classify_hidden_dentry(nlink: u32, filename: &str) -> bool {
    // Empty filename → kernel internal file, not suspicious.
    if filename.is_empty() {
        return false;
    }

    let name_lower = filename.to_lowercase();

    // File still in the directory tree → check only for suspicious extensions.
    if nlink > 0 {
        return SUSPICIOUS_EXTENSIONS
            .iter()
            .any(|ext| name_lower.ends_with(ext));
    }

    // nlink == 0 → file is unlinked (hidden), always suspicious.
    true
}

// ---------------------------------------------------------------------------
// eBPF map classification
// ---------------------------------------------------------------------------

/// eBPF map name substrings associated with known rootkits.
const SUSPICIOUS_MAP_NAMES: &[&str] = &[
    "rootkit", "hide_", "hook", "intercept", "stealth", "secret", "covert",
    "keylog", "exfil",
];

/// Classify whether an eBPF map is suspicious.
///
/// Flags high-risk map types (perf_event_array=3, ringbuf=26) and maps whose
/// names match known rootkit patterns.
pub fn classify_ebpf_map(map_type: u32, name: &str, _value_size: u32) -> bool {
    let name_lower = name.to_lowercase();
    let suspicious_name = SUSPICIOUS_MAP_NAMES.iter().any(|p| name_lower.contains(p));

    // perf_event_array (3) and ringbuf (26) are high-risk exfiltration channels
    let high_risk_type = matches!(map_type, 3 | 26);

    suspicious_name || high_risk_type
}

// ---------------------------------------------------------------------------
// Ftrace hook classification
// ---------------------------------------------------------------------------

/// Classify whether an ftrace function pointer is outside the kernel text range.
///
/// Returns `true` when `func < stext || func >= etext`.
pub fn classify_ftrace_hook(func: u64, stext: u64, etext: u64) -> bool {
    func < stext || func >= etext
}

// ---------------------------------------------------------------------------
// Futex classification
// ---------------------------------------------------------------------------

/// Classify whether a futex entry is suspicious.
///
/// Returns `true` for excessive waiter counts (> 1000) or kernel-space keys
/// owned by a userspace process.
pub fn classify_futex(key_address: u64, owner_pid: u32, waiter_count: u32) -> bool {
    waiter_count > 1000 || (key_address > 0x7FFF_FFFF_FFFF && owner_pid > 0)
}

// ---------------------------------------------------------------------------
// io_uring classification
// ---------------------------------------------------------------------------

/// io_uring opcode for sending a message (IORING_OP_SENDMSG).
const IORING_OP_SENDMSG: u8 = 9;
/// io_uring opcode for receiving a message (IORING_OP_RECVMSG).
const IORING_OP_RECVMSG: u8 = 10;
/// io_uring opcode for establishing a connection (IORING_OP_CONNECT).
const IORING_OP_CONNECT: u8 = 16;

/// Sensitive opcodes that bypass seccomp when used with an active filter.
const SENSITIVE_OPCODES: &[u8] = &[IORING_OP_SENDMSG, IORING_OP_RECVMSG, IORING_OP_CONNECT];

/// Classify whether an io_uring submission is suspicious.
///
/// Returns `false` when seccomp is disabled; returns `true` when seccomp is
/// active and the opcode list contains a sensitive syscall.
pub fn classify_io_uring(opcodes: &[u8], seccomp_mode: u32) -> bool {
    if seccomp_mode == 0 {
        return false;
    }
    opcodes.iter().any(|op| SENSITIVE_OPCODES.contains(op))
}

// ---------------------------------------------------------------------------
// I/O memory region classification
// ---------------------------------------------------------------------------

/// Classify whether an `/proc/iomem` region entry is suspicious.
///
/// Flags empty names on large regions, non-ASCII names, and regions that
/// overlap the kernel text range without the expected name.
pub fn classify_iomem(name: &str, start: u64, end: u64) -> bool {
    // Empty name on a large region (> 1 MiB) is suspicious.
    let size = end.saturating_sub(start);
    if name.is_empty() && size > 1024 * 1024 {
        return true;
    }

    // Name with unusual characters (control chars or non-ASCII) is suspicious.
    if name.chars().any(|c| c.is_control() || !c.is_ascii()) {
        return true;
    }

    // Region overlapping kernel text range but not named "Kernel code".
    const KERNEL_TEXT_START: u64 = 0xffff_ffff_8100_0000;
    const KERNEL_TEXT_END: u64 = 0xffff_ffff_8200_0000;
    if start < KERNEL_TEXT_END && end > KERNEL_TEXT_START && name != "Kernel code" {
        return true;
    }

    false
}

// ---------------------------------------------------------------------------
// Kernel timer classification
// ---------------------------------------------------------------------------

/// Classify whether a kernel timer callback is outside the kernel text range.
///
/// Returns `false` for null pointers; `true` when the callback is outside
/// `[kernel_start, kernel_end]`.
pub fn classify_kernel_timer(function: u64, kernel_start: u64, kernel_end: u64) -> bool {
    if function == 0 {
        return false;
    }
    // Suspicious if outside kernel text range
    !(function >= kernel_start && function <= kernel_end)
}

// ---------------------------------------------------------------------------
// Keyboard notifier classification
// ---------------------------------------------------------------------------

/// Classify whether a keyboard notifier callback is outside the kernel text range.
///
/// Returns `true` when `notifier_call < stext || notifier_call >= etext`.
pub fn classify_notifier(notifier_call: u64, stext: u64, etext: u64) -> bool {
    notifier_call < stext || notifier_call >= etext
}

// ---------------------------------------------------------------------------
// Kernel message classification
// ---------------------------------------------------------------------------

/// Suspicious patterns in kernel log messages.
const SUSPICIOUS_KMSG_PATTERNS: &[&str] = &[
    "rootkit",
    "hide",
    "call trace",
    "kernel bug",
    "general protection",
];

/// Classify whether a kernel log message matches known suspicious patterns.
pub fn classify_kmsg(text: &str) -> bool {
    let lower = text.to_lowercase();
    SUSPICIOUS_KMSG_PATTERNS.iter().any(|p| lower.contains(p))
}

// ---------------------------------------------------------------------------
// Kernel thread classification
// ---------------------------------------------------------------------------

/// Minimum address for the kernel address space on x86_64.
const KERNEL_SPACE_MIN: u64 = 0xFFFF_0000_0000_0000;

/// Check whether a name looks like random hex characters (rootkit-generated).
///
/// Returns `true` if the name contains a run of 8+ hex digits.
fn looks_like_hex_name(name: &str) -> bool {
    let mut run = 0u32;
    for ch in name.chars() {
        if ch.is_ascii_hexdigit() {
            run += 1;
            if run >= 8 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Classify whether a kernel thread entry looks suspicious.
///
/// Returns `(is_suspicious, reason)`. Flags unnamed threads, threads with
/// userspace start-function addresses, and hex-pattern names.
pub fn classify_kthread(name: &str, start_fn_addr: u64) -> (bool, Option<String>) {
    // Check 1: unnamed kernel thread
    if name.is_empty() {
        return (true, Some("unnamed kernel thread".into()));
    }

    // Check 1b: known-benign kernel thread comm prefix — short-circuit to benign
    if KERNEL_THREAD_COMMS.iter().any(|p| name.starts_with(p)) {
        return (false, None);
    }

    // Check 2: start function in userspace range
    if start_fn_addr != 0 && start_fn_addr < KERNEL_SPACE_MIN {
        return (
            true,
            Some(format!(
                "thread function at userspace address {start_fn_addr:#x}"
            )),
        );
    }

    // Check 3: name looks like random hex (rootkit-generated)
    if looks_like_hex_name(name) {
        return (
            true,
            Some(format!("name '{name}' contains suspicious hex pattern")),
        );
    }

    (false, None)
}

// ---------------------------------------------------------------------------
// LD_PRELOAD classification
// ---------------------------------------------------------------------------

/// Parse a colon-or-whitespace-separated LD_PRELOAD value into individual paths.
fn parse_ld_preload(value: &str) -> Vec<String> {
    value
        .split(|c: char| c == ':' || c.is_ascii_whitespace())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Check whether a single library path looks suspicious.
fn is_suspicious_ld_path(path: &str, safe_prefixes: &[&str]) -> bool {
    if path.starts_with("/tmp/") || path == "/tmp" {
        return true;
    }
    if path.starts_with("/dev/shm/") || path == "/dev/shm" {
        return true;
    }
    if path
        .split('/')
        .any(|component| !component.is_empty() && component.starts_with('.'))
    {
        return true;
    }
    if !safe_prefixes.iter().any(|prefix| path.starts_with(prefix)) {
        return true;
    }
    false
}

/// Classify whether an `LD_PRELOAD` value references a suspicious library path.
///
/// Returns `true` when any library in the colon/space-separated list resides
/// outside standard system library directories or in staging directories.
pub fn classify_ld_preload(value: &str) -> bool {
    const SAFE_PREFIXES: &[&str] = &[
        "/usr/lib/",
        "/usr/lib64/",
        "/usr/lib32/",
        "/usr/local/lib/",
        "/usr/local/lib64/",
        "/lib/",
        "/lib64/",
        "/lib32/",
    ];

    let libraries = parse_ld_preload(value);
    libraries
        .iter()
        .any(|lib| is_suspicious_ld_path(lib, SAFE_PREFIXES))
}

// ---------------------------------------------------------------------------
// Shared library classification
// ---------------------------------------------------------------------------

/// Classify whether a mapped library path is suspicious.
///
/// Flags deleted libraries, libraries in `/tmp`, `/dev/shm`, and libraries
/// with suspicious extensions.
pub fn classify_library(lib_path: &str) -> bool {
    let path = lib_path.trim();

    // Unlinked libraries still mapped in memory.
    if path.ends_with("(deleted)") {
        return true;
    }

    // Strip " (deleted)" suffix for remaining checks.
    let clean = path.strip_suffix(" (deleted)").unwrap_or(path);

    // World-writable staging directories.
    if clean.starts_with("/tmp/")
        || clean == "/tmp"
        || clean.starts_with("/dev/shm/")
        || clean == "/dev/shm"
        || clean.starts_with("/var/tmp/")
        || clean == "/var/tmp"
    {
        return true;
    }

    // Hidden file (basename starts with '.').
    if let Some(basename) = clean.rsplit('/').next() {
        if basename.starts_with('.') && !basename.is_empty() {
            return true;
        }
    }

    // Not a standard shared library name.
    if !clean.ends_with(".so") && !clean.contains(".so.") {
        return true;
    }

    false
}

// ---------------------------------------------------------------------------
// memfd classification
// ---------------------------------------------------------------------------

/// Known-benign memfd name prefixes.
const BENIGN_MEMFD_PREFIXES: &[&str] = &[
    "shm",
    "pulseaudio",
    "wayland",
    "dbus",
    "chrome",
    "firefox",
    "v8",
];

/// Suspicious memfd name substrings (case-insensitive).
const SUSPICIOUS_MEMFD_NAMES: &[&str] =
    &["payload", "shellcode", "stage", "loader", "inject", "hack"];

/// Classify whether a `memfd_create` file is suspicious.
///
/// Executable anonymous memory is always suspicious. Empty names and names
/// matching known rootkit patterns are also flagged.
pub fn classify_memfd(name: &str, is_executable: bool) -> bool {
    // Executable anonymous memory is always suspicious.
    if is_executable {
        return true;
    }

    let name_lower = name.to_lowercase();

    // Known-benign prefixes override everything else.
    for prefix in BENIGN_MEMFD_PREFIXES {
        if name_lower.starts_with(prefix) {
            return false;
        }
    }

    // Empty name → evasion attempt.
    if name.is_empty() {
        return true;
    }

    // Suspicious substrings.
    for s in SUSPICIOUS_MEMFD_NAMES {
        if name_lower.contains(s) {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Kernel module visibility classification
// ---------------------------------------------------------------------------

/// Classify whether a kernel module is hidden by cross-referencing three views.
///
/// Returns `true` when the module is present in at least one view but absent
/// from at least one other (partial visibility = hidden).
pub fn classify_module_visibility(
    in_module_list: bool,
    in_kobj_list: bool,
    in_memory_map: bool,
) -> bool {
    let present_count = [in_module_list, in_kobj_list, in_memory_map]
        .iter()
        .filter(|&&v| v)
        .count();

    // Hidden if present in at least one view but not all three
    present_count > 0 && present_count < 3
}

// ---------------------------------------------------------------------------
// Mount classification
// ---------------------------------------------------------------------------

/// Classify whether a mount entry is suspicious.
///
/// Flags unusual tmpfs/ramfs mounts and overlay mounts outside known container
/// runtime paths.
pub fn classify_mount(fs_type: &str, dev_name: &str, mnt_root: &str) -> bool {
    let _ = dev_name;
    match fs_type {
        "tmpfs" | "ramfs" => {
            !matches!(
                mnt_root,
                "/tmp" | "/run" | "/dev/shm" | "/run/lock" | "/run/user" | "/"
            ) && !mnt_root.starts_with("/run/")
                && !mnt_root.starts_with("/tmp/")
                && !mnt_root.starts_with("/dev/")
        }
        "overlay" | "overlayfs" => {
            !mnt_root.starts_with("/var/lib/docker")
                && !mnt_root.starts_with("/var/lib/containerd")
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// OOM victim classification
// ---------------------------------------------------------------------------

/// Process names considered suspicious OOM victims (security/monitoring daemons).
const SUSPICIOUS_OOM_NAMES: &[&str] = &[
    "auditd",
    "sshd",
    "systemd",
    "journald",
    "rsyslogd",
    "containerd",
    "dockerd",
];

/// Classify whether an OOM-killed process is suspicious.
///
/// Flags processes with names matching known attacker tools and processes with
/// very low PIDs (< 100).
pub fn classify_oom_victim(comm: &str, pid: u32) -> bool {
    let lower = comm.to_ascii_lowercase();
    SUSPICIOUS_OOM_NAMES.iter().any(|n| lower.contains(n)) || pid < 100
}

// ---------------------------------------------------------------------------
// PAM hook classification
// ---------------------------------------------------------------------------

/// Known system PAM library directory prefixes.
const SYSTEM_LIB_PREFIXES: &[&str] =
    &["/lib", "/usr/lib", "/usr/lib64", "/lib64", "/usr/local/lib"];

/// Classify whether a PAM library path is suspicious.
///
/// Returns `true` when the path contains "pam" (case-insensitive) and does not
/// start with a known system library directory.
pub fn classify_pam_hook(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let lower = path.to_lowercase();
    if !lower.contains("pam") {
        return false;
    }
    !SYSTEM_LIB_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

// ---------------------------------------------------------------------------
// perf_event classification
// ---------------------------------------------------------------------------

/// Classify whether a `perf_event` is suspicious.
///
/// Flags RAW PMU access (type 4) and certain cache event configurations (type 3).
pub fn classify_perf_event(event_type: u32, config: u64) -> bool {
    match event_type {
        3 => (config & 0xFF) <= 2, // L1D (0) or LL (2) cache events
        4 => true,                 // RAW PMU access always suspicious from userspace
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// psaux classification
// ---------------------------------------------------------------------------

/// Linux `PF_KTHREAD` flag — set on kernel threads.
const PF_KTHREAD: u64 = 0x0020_0000;
/// Process virtual size threshold above which a process is suspicious.
const VSIZE_ABUSE_THRESHOLD: u64 = 100 * 1024 * 1024 * 1024;

/// Classify whether process auxiliary state is suspicious.
///
/// Flags impossible combinations: zombie root processes, non-root kernel
/// threads, and processes with extremely large virtual address spaces.
pub fn classify_psaux(state: u64, uid: u32, flags: u64, vsize: u64) -> bool {
    if state == 16 && uid == 0 {
        return true;
    }
    if (flags & PF_KTHREAD) != 0 && uid != 0 {
        return true;
    }
    if vsize > VSIZE_ABUSE_THRESHOLD {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// ptrace classification
// ---------------------------------------------------------------------------

/// Well-known debugger/tracer binaries that are expected to ptrace.
const KNOWN_DEBUGGERS: &[&str] = &["gdb", "lldb", "strace", "ltrace", "valgrind", "perf"];

/// High-value target processes — tracing these by a non-debugger is suspicious.
const HIGH_VALUE_TARGETS: &[&str] = &["sshd", "login", "passwd", "sudo", "su", "gpg-agent"];

/// Classify whether a ptrace relationship is suspicious.
///
/// Flags tracers with empty names, tracers of high-value system processes, and
/// self-tracing processes.
pub fn classify_ptrace(tracer_name: &str, tracee_name: &str) -> bool {
    if tracer_name.is_empty() {
        return true;
    }
    if KNOWN_DEBUGGERS.iter().any(|&d| d == tracer_name) {
        return false;
    }
    if HIGH_VALUE_TARGETS.iter().any(|&t| t == tracee_name) {
        return true;
    }
    if tracer_name == tracee_name {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Raw socket classification
// ---------------------------------------------------------------------------

/// Known-benign process names that legitimately use `AF_PACKET` sockets.
const BENIGN_AF_PACKET: &[&str] = &[
    "tcpdump", "wireshark", "dumpcap", "dhclient", "dhcpcd", "arping", "ping", "ping6",
];

/// Known-benign process names that legitimately use `SOCK_RAW` sockets.
const BENIGN_SOCK_RAW: &[&str] = &["ping", "ping6", "traceroute", "traceroute6", "arping"];

/// Classify whether a raw socket is suspicious.
///
/// Promiscuous sockets are always suspicious. AF_PACKET sockets owned by
/// non-standard utilities are flagged.
pub fn classify_raw_socket(comm: &str, socket_type: &str, is_promiscuous: bool) -> bool {
    if is_promiscuous {
        return true;
    }

    let comm_lower = comm.to_lowercase();

    if socket_type == "AF_PACKET" {
        return !BENIGN_AF_PACKET.iter().any(|&b| comm_lower == b);
    }

    if socket_type == "SOCK_RAW" {
        return !BENIGN_SOCK_RAW.iter().any(|&b| comm_lower == b);
    }

    false
}

// ---------------------------------------------------------------------------
// Signal handler classification
// ---------------------------------------------------------------------------

/// Classify whether a signal handler configuration is suspicious.
///
/// Flags SIG_IGN for SIGTERM/SIGHUP (anti-termination), custom handlers for
/// SIGSEGV (self-healing), and any SIGKILL handler (rootkit indicator).
pub fn classify_signal_handler(signal: u32, handler: u64) -> bool {
    match signal {
        // SIGTERM or SIGHUP ignored -> anti-termination
        15 | 1 => handler == 1,
        // SIGSEGV with custom handler -> self-healing malware
        11 => handler != 0 && handler != 1,
        // SIGKILL tampered -> kernel rootkit (normally impossible)
        9 => handler != 0,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// systemd unit classification
// ---------------------------------------------------------------------------

/// ExecStart patterns considered suspicious.
const SUSPICIOUS_EXEC_PATTERNS: &[&str] = &[
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "curl",
    "wget",
    "bash -c",
    "sh -c",
    "python",
    "perl",
    "ruby",
    "nc ",
    "ncat",
    "base64",
];

/// ExecStart prefixes considered safe.
const SAFE_EXEC_PREFIXES: &[&str] = &["/usr/", "/bin/", "/sbin/", "/lib/"];

/// Known safe unit name prefixes.
const KNOWN_SAFE_UNITS: &[&str] = &["systemd-", "NetworkManager", "dbus", "cron", "ssh"];

/// Unit file extensions used for hex-name detection.
const UNIT_EXTENSIONS: &[&str] = &[".service", ".timer", ".socket", ".path", ".mount"];

/// Classify whether a systemd unit is suspicious.
///
/// Returns `false` for known-safe unit names and safe `ExecStart` prefixes.
pub fn classify_systemd_unit(unit_name: &str, exec_start: &str) -> bool {
    // Known safe units are never suspicious.
    if KNOWN_SAFE_UNITS
        .iter()
        .any(|prefix| unit_name.starts_with(prefix))
    {
        return false;
    }

    // Safe ExecStart prefix — not suspicious.
    if SAFE_EXEC_PREFIXES
        .iter()
        .any(|prefix| exec_start.starts_with(prefix))
    {
        return false;
    }

    // Suspicious ExecStart patterns.
    if SUSPICIOUS_EXEC_PATTERNS
        .iter()
        .any(|pat| exec_start.contains(pat))
    {
        return true;
    }

    // Randomized name: strip extension, check if remainder is 8+ lowercase hex chars.
    let stem = UNIT_EXTENSIONS
        .iter()
        .find_map(|ext| unit_name.strip_suffix(ext))
        .unwrap_or(unit_name);
    if stem.len() >= 8
        && stem
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return true;
    }

    false
}

// ---------------------------------------------------------------------------
// tmpfs file classification
// ---------------------------------------------------------------------------

/// Classify whether a tmpfs file is suspicious.
///
/// Flags executable regular files and hidden files (names starting with `.`).
pub fn classify_tmpfs_file(filename: &str, mode: u32) -> bool {
    // S_IFREG = 0o100000; S_IFMT = 0o170000
    let is_regular_file = (mode & 0o170_000) == 0o100_000;
    let is_exec = is_regular_file && (mode & 0o111) != 0;
    let is_hidden = filename.starts_with('.') && filename.len() > 1;
    is_exec || is_hidden
}

// ---------------------------------------------------------------------------
// Unix socket classification
// ---------------------------------------------------------------------------

/// Classify whether a Unix domain socket is suspicious.
///
/// Flags abstract sockets owned by high-uid processes and sockets in staging
/// directories.
pub fn classify_unix_socket(path: &str, owner_pid: u32) -> bool {
    let is_abstract = path.is_empty() || path.starts_with('@');
    if is_abstract && owner_pid >= 1000 {
        return true;
    }
    if path.starts_with("/tmp") || path.starts_with("/dev/shm") {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Zombie/orphan classification
// ---------------------------------------------------------------------------

/// Daemon names considered suspicious when found as orphan processes.
const SUSPICIOUS_DAEMON_NAMES: &[&str] = &[
    "sshd", "httpd", "nginx", "apache", "mysqld", "postgres", "redis", "memcached", "mongod",
    "named", "bind", "cupsd", "cron", "atd",
];

/// Classify whether a zombie or orphan process is suspicious.
///
/// Flags zombie processes re-parented to init and orphan processes with names
/// matching known attacker tools.
pub fn classify_zombie_orphan(is_zombie: bool, is_orphan: bool, ppid: u32, comm: &str) -> bool {
    if is_zombie && ppid == 1 {
        return true;
    }
    if is_orphan {
        let lower = comm.to_lowercase();
        if SUSPICIOUS_DAEMON_NAMES
            .iter()
            .any(|&name| lower.contains(name))
        {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- classify_bpf_program ---

    #[test]
    fn heuristics_bpf_kprobe_is_suspicious() {
        assert!(classify_bpf_program("kprobe", "my_hook"));
    }

    #[test]
    fn heuristics_bpf_lsm_is_suspicious() {
        assert!(classify_bpf_program("lsm", ""));
    }

    #[test]
    fn heuristics_bpf_xdp_benign() {
        assert!(!classify_bpf_program("xdp", "firewall"));
    }

    #[test]
    fn heuristics_bpf_unnamed_tracing_suspicious() {
        assert!(classify_bpf_program("tracing", ""));
    }

    #[test]
    fn heuristics_bpf_named_tracing_benign() {
        assert!(!classify_bpf_program("tracing", "named_prog"));
    }

    // --- classify_capabilities ---

    #[test]
    fn heuristics_capabilities_root_never_suspicious() {
        let (susp, names) = classify_capabilities(u64::MAX, 0);
        assert!(!susp);
        assert!(names.is_empty());
    }

    #[test]
    fn heuristics_capabilities_non_root_sys_admin_suspicious() {
        let cap_sys_admin: u64 = 1 << 21;
        let (susp, names) = classify_capabilities(cap_sys_admin, 1000);
        assert!(susp);
        assert!(!names.is_empty());
    }

    #[test]
    fn heuristics_capabilities_non_root_no_caps_benign() {
        let (susp, names) = classify_capabilities(0, 1000);
        assert!(!susp);
        assert!(names.is_empty());
    }

    // --- classify_cgroup ---

    #[test]
    fn heuristics_cgroup_docker_detected() {
        let (in_container, id) = classify_cgroup("/docker/abc123def456");
        assert!(in_container);
        assert_eq!(id, "abc123def456");
    }

    #[test]
    fn heuristics_cgroup_bare_root_not_container() {
        let (in_container, id) = classify_cgroup("/");
        assert!(!in_container);
        assert!(id.is_empty());
    }

    // --- classify_afinfo_hook ---

    #[test]
    fn heuristics_afinfo_null_not_hooked() {
        assert!(!classify_afinfo_hook(0, 0xffff0000, 0xffff8000));
    }

    #[test]
    fn heuristics_afinfo_in_range_benign() {
        assert!(!classify_afinfo_hook(0xffff1000, 0xffff0000, 0xffff8000));
    }

    #[test]
    fn heuristics_afinfo_outside_range_suspicious() {
        assert!(classify_afinfo_hook(0x0000_dead_beef, 0xffff0000, 0xffff8000));
    }

    // --- classify_shared_creds ---

    #[test]
    fn heuristics_shared_creds_userspace_shares_with_init_suspicious() {
        assert!(classify_shared_creds(500, &[1], 1000));
    }

    #[test]
    fn heuristics_shared_creds_empty_list_benign() {
        assert!(!classify_shared_creds(500, &[], 1000));
    }

    #[test]
    fn heuristics_shared_creds_kernel_thread_shares_with_init_benign() {
        // pid 2 (kthreadd), uid 0 shares with init — expected
        assert!(!classify_shared_creds(2, &[1], 0));
    }

    // --- classify_idt_entry ---

    #[test]
    fn heuristics_idt_null_not_hooked() {
        assert!(!classify_idt_entry(0, 0xffff0000, 0xffff8000));
    }

    #[test]
    fn heuristics_idt_in_kernel_range_benign() {
        assert!(!classify_idt_entry(0xffff2000, 0xffff0000, 0xffff8000));
    }

    #[test]
    fn heuristics_idt_outside_range_suspicious() {
        assert!(classify_idt_entry(0x1234, 0xffff0000, 0xffff8000));
    }

    // --- classify_container_escape ---

    #[test]
    fn heuristics_container_escape_namespace_mismatch_suspicious() {
        assert!(classify_container_escape("bash", "namespace_mismatch"));
    }

    #[test]
    fn heuristics_container_escape_kernel_thread_benign() {
        assert!(!classify_container_escape("kworker/0:0", "namespace_mismatch"));
    }

    #[test]
    fn heuristics_container_escape_unknown_indicator_benign() {
        assert!(!classify_container_escape("bash", "some_other_thing"));
    }

    // --- classify_deleted_exe ---

    #[test]
    fn heuristics_deleted_exe_not_deleted_benign() {
        assert!(!classify_deleted_exe("/usr/bin/bash", "bash"));
    }

    #[test]
    fn heuristics_deleted_exe_suspicious() {
        assert!(classify_deleted_exe("/tmp/evil (deleted)", "evil"));
    }

    #[test]
    fn heuristics_deleted_exe_empty_comm_benign() {
        assert!(!classify_deleted_exe("/tmp/x (deleted)", ""));
    }

    // --- classify_hidden_dentry ---

    #[test]
    fn heuristics_hidden_dentry_nlink_zero_suspicious() {
        assert!(classify_hidden_dentry(0, "normal.txt"));
    }

    #[test]
    fn heuristics_hidden_dentry_empty_filename_benign() {
        assert!(!classify_hidden_dentry(0, ""));
    }

    #[test]
    fn heuristics_hidden_dentry_linked_no_suspicious_ext_benign() {
        assert!(!classify_hidden_dentry(1, "readme.txt"));
    }

    // --- classify_ebpf_map ---

    #[test]
    fn heuristics_ebpf_map_ringbuf_suspicious() {
        // map_type 26 = ringbuf — high-risk exfiltration channel
        assert!(classify_ebpf_map(26, "benign_name", 8));
    }

    #[test]
    fn heuristics_ebpf_map_perf_event_array_suspicious() {
        assert!(classify_ebpf_map(3, "benign_name", 8));
    }

    #[test]
    fn heuristics_ebpf_map_hash_benign_name_benign() {
        // map_type 1 = hash, benign name
        assert!(!classify_ebpf_map(1, "counters", 8));
    }

    // --- classify_ftrace_hook ---

    #[test]
    fn heuristics_ftrace_in_text_benign() {
        assert!(!classify_ftrace_hook(0x1000, 0x1000, 0x2000));
    }

    #[test]
    fn heuristics_ftrace_outside_text_suspicious() {
        assert!(classify_ftrace_hook(0x500, 0x1000, 0x2000));
    }

    // --- classify_futex ---

    #[test]
    fn heuristics_futex_high_waiter_count_suspicious() {
        assert!(classify_futex(0x1000, 0, 1001));
    }

    #[test]
    fn heuristics_futex_normal_benign() {
        assert!(!classify_futex(0x1000, 0, 5));
    }

    #[test]
    fn heuristics_futex_kernel_key_userspace_owner_suspicious() {
        assert!(classify_futex(0xffff_0000_0000, 1234, 0));
    }

    // --- classify_io_uring ---

    #[test]
    fn heuristics_io_uring_no_seccomp_benign() {
        assert!(!classify_io_uring(&[1, 2, 3], 0));
    }

    #[test]
    fn heuristics_io_uring_no_opcodes_benign() {
        assert!(!classify_io_uring(&[], 1));
    }

    // --- classify_iomem ---

    #[test]
    fn heuristics_iomem_kernel_code_name_benign() {
        assert!(!classify_iomem(
            "Kernel code",
            0xffff_ffff_8100_0000,
            0xffff_ffff_8180_0000
        ));
    }

    #[test]
    fn heuristics_iomem_empty_name_small_region_benign() {
        // Under 1 MiB — not suspicious
        assert!(!classify_iomem("", 0, 1024));
    }

    #[test]
    fn heuristics_iomem_empty_name_large_region_suspicious() {
        assert!(classify_iomem("", 0, 2 * 1024 * 1024));
    }

    // --- classify_kernel_timer ---

    #[test]
    fn heuristics_kernel_timer_null_benign() {
        assert!(!classify_kernel_timer(0, 0xffff0000, 0xffff8000));
    }

    #[test]
    fn heuristics_kernel_timer_in_range_benign() {
        assert!(!classify_kernel_timer(0xffff1000, 0xffff0000, 0xffff8000));
    }

    #[test]
    fn heuristics_kernel_timer_outside_range_suspicious() {
        assert!(classify_kernel_timer(0x1234, 0xffff0000, 0xffff8000));
    }

    // --- classify_notifier ---

    #[test]
    fn heuristics_notifier_in_text_benign() {
        assert!(!classify_notifier(0x1000, 0x1000, 0x2000));
    }

    #[test]
    fn heuristics_notifier_below_stext_suspicious() {
        assert!(classify_notifier(0x500, 0x1000, 0x2000));
    }

    // --- classify_kmsg ---

    #[test]
    fn heuristics_kmsg_normal_message_benign() {
        assert!(!classify_kmsg("USB device connected"));
    }

    // --- classify_kthread ---

    #[test]
    fn heuristics_kthread_empty_name_suspicious() {
        let (susp, reason) = classify_kthread("", 0xffff_8000_0000);
        assert!(susp);
        assert!(reason.is_some());
    }

    #[test]
    fn heuristics_kthread_named_kernel_fn_benign() {
        let (susp, _) = classify_kthread("kworker/0:0", 0xffff_8000_1234);
        assert!(!susp);
    }

    // --- classify_ld_preload ---

    #[test]
    fn heuristics_ld_preload_tmp_path_suspicious() {
        assert!(classify_ld_preload("/tmp/evil.so"));
    }

    #[test]
    fn heuristics_ld_preload_system_lib_benign() {
        assert!(!classify_ld_preload("/usr/lib/libfoo.so"));
    }

    // --- classify_library ---

    #[test]
    fn heuristics_library_deleted_suspicious() {
        assert!(classify_library("/usr/lib/libfoo.so (deleted)"));
    }

    #[test]
    fn heuristics_library_normal_benign() {
        assert!(!classify_library("/usr/lib/libc.so.6"));
    }

    #[test]
    fn heuristics_library_tmp_suspicious() {
        assert!(classify_library("/tmp/inject.so"));
    }

    // --- classify_memfd ---

    #[test]
    fn heuristics_memfd_executable_suspicious() {
        assert!(classify_memfd("legit_name", true));
    }

    #[test]
    fn heuristics_memfd_empty_name_suspicious() {
        assert!(classify_memfd("", false));
    }

    // --- classify_module_visibility ---

    #[test]
    fn heuristics_module_visibility_all_present_benign() {
        assert!(!classify_module_visibility(true, true, true));
    }

    #[test]
    fn heuristics_module_visibility_partial_hidden() {
        assert!(classify_module_visibility(true, false, true));
    }

    #[test]
    fn heuristics_module_visibility_all_absent_benign() {
        // Not found anywhere — not suspicious, just absent
        assert!(!classify_module_visibility(false, false, false));
    }

    // --- classify_mount ---

    #[test]
    fn heuristics_mount_known_tmpfs_root_benign() {
        assert!(!classify_mount("tmpfs", "tmpfs", "/tmp"));
    }

    #[test]
    fn heuristics_mount_unknown_tmpfs_suspicious() {
        assert!(classify_mount("tmpfs", "tmpfs", "/secret_staging"));
    }

    #[test]
    fn heuristics_mount_ext4_benign() {
        assert!(!classify_mount("ext4", "/dev/sda1", "/"));
    }

    // --- classify_oom_victim ---

    #[test]
    fn heuristics_oom_victim_low_pid_suspicious() {
        assert!(classify_oom_victim("bash", 5));
    }

    #[test]
    fn heuristics_oom_victim_normal_benign() {
        assert!(!classify_oom_victim("chrome", 5000));
    }

    // --- classify_pam_hook ---

    #[test]
    fn heuristics_pam_hook_empty_benign() {
        assert!(!classify_pam_hook(""));
    }

    #[test]
    fn heuristics_pam_hook_system_lib_benign() {
        assert!(!classify_pam_hook("/lib/x86_64-linux-gnu/libpam.so.0"));
    }

    #[test]
    fn heuristics_pam_hook_tmp_suspicious() {
        assert!(classify_pam_hook("/tmp/fakepam.so"));
    }

    // --- classify_perf_event ---

    #[test]
    fn heuristics_perf_event_raw_pmu_suspicious() {
        assert!(classify_perf_event(4, 0));
    }

    #[test]
    fn heuristics_perf_event_software_benign() {
        assert!(!classify_perf_event(1, 0));
    }

    // --- classify_psaux ---

    #[test]
    fn heuristics_psaux_zombie_root_suspicious() {
        // state=16 (zombie), uid=0
        assert!(classify_psaux(16, 0, 0, 0));
    }

    #[test]
    fn heuristics_psaux_normal_process_benign() {
        assert!(!classify_psaux(1, 1000, 0, 4096));
    }

    // --- classify_ptrace ---

    #[test]
    fn heuristics_ptrace_empty_tracer_suspicious() {
        assert!(classify_ptrace("", "bash"));
    }

    #[test]
    fn heuristics_ptrace_gdb_tracing_bash_benign() {
        assert!(!classify_ptrace("gdb", "bash"));
    }

    // --- classify_raw_socket ---

    #[test]
    fn heuristics_raw_socket_promiscuous_suspicious() {
        assert!(classify_raw_socket("tcpdump", "AF_PACKET", true));
    }

    #[test]
    fn heuristics_raw_socket_tcpdump_not_promiscuous_benign() {
        assert!(!classify_raw_socket("tcpdump", "AF_PACKET", false));
    }

    // --- classify_signal_handler ---

    #[test]
    fn heuristics_signal_handler_sigterm_ignored_suspicious() {
        // handler=1 (SIG_IGN) for SIGTERM (15)
        assert!(classify_signal_handler(15, 1));
    }

    #[test]
    fn heuristics_signal_handler_sigterm_default_benign() {
        assert!(!classify_signal_handler(15, 0));
    }

    #[test]
    fn heuristics_signal_handler_sigkill_nonzero_suspicious() {
        assert!(classify_signal_handler(9, 0x1234));
    }

    // --- classify_systemd_unit ---

    #[test]
    fn heuristics_systemd_unit_suspicious_exec_start() {
        assert!(classify_systemd_unit("evil.service", "/tmp/backdoor.sh"));
    }

    // --- classify_tmpfs_file ---

    #[test]
    fn heuristics_tmpfs_file_executable_regular_suspicious() {
        // S_IFREG | executable: 0o100755
        assert!(classify_tmpfs_file("payload", 0o100_755));
    }

    #[test]
    fn heuristics_tmpfs_file_hidden_suspicious() {
        assert!(classify_tmpfs_file(".hidden", 0o100_644));
    }

    #[test]
    fn heuristics_tmpfs_file_normal_benign() {
        assert!(!classify_tmpfs_file("readme.txt", 0o100_644));
    }

    // --- classify_unix_socket ---

    #[test]
    fn heuristics_unix_socket_abstract_high_uid_suspicious() {
        // Abstract socket (empty path), owner_pid >= 1000
        assert!(classify_unix_socket("", 1234));
    }

    #[test]
    fn heuristics_unix_socket_system_path_benign() {
        assert!(!classify_unix_socket("/var/run/docker.sock", 500));
    }

    #[test]
    fn heuristics_unix_socket_tmp_suspicious() {
        assert!(classify_unix_socket("/tmp/evil.sock", 500));
    }

    // --- classify_zombie_orphan ---

    #[test]
    fn heuristics_zombie_orphan_reparented_to_init_suspicious() {
        assert!(classify_zombie_orphan(true, false, 1, "bash"));
    }

    #[test]
    fn heuristics_zombie_orphan_normal_benign() {
        assert!(!classify_zombie_orphan(false, false, 1234, "chrome"));
    }
}
