//! Output types for Linux forensic walkers.

use std::fmt;

/// State of a Linux process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// TASK_RUNNING (0).
    Running,
    /// TASK_INTERRUPTIBLE (1).
    Sleeping,
    /// TASK_UNINTERRUPTIBLE (2).
    DiskSleep,
    /// __TASK_STOPPED (4).
    Stopped,
    /// __TASK_TRACED (8).
    Traced,
    /// EXIT_ZOMBIE (32).
    Zombie,
    /// EXIT_DEAD (16).
    Dead,
    /// Unknown or unrecognized state value.
    Unknown(i64),
}

impl ProcessState {
    /// Parse a Linux task state value.
    pub fn from_raw(value: i64) -> Self {
        match value {
            0 => Self::Running,
            1 => Self::Sleeping,
            2 => Self::DiskSleep,
            4 => Self::Stopped,
            8 => Self::Traced,
            16 => Self::Dead,
            32 => Self::Zombie,
            _ => Self::Unknown(value),
        }
    }
}

impl fmt::Display for ProcessState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Running => write!(f, "R (running)"),
            Self::Sleeping => write!(f, "S (sleeping)"),
            Self::DiskSleep => write!(f, "D (disk sleep)"),
            Self::Stopped => write!(f, "T (stopped)"),
            Self::Traced => write!(f, "t (traced)"),
            Self::Zombie => write!(f, "Z (zombie)"),
            Self::Dead => write!(f, "X (dead)"),
            Self::Unknown(v) => write!(f, "? ({v})"),
        }
    }
}

/// Information about a Linux process extracted from `task_struct`.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID.
    pub pid: u64,
    /// Parent process ID.
    pub ppid: u64,
    /// Process command name (`task_struct.comm`, max 16 chars).
    pub comm: String,
    /// Process state.
    pub state: ProcessState,
    /// Virtual address of the `task_struct`.
    pub vaddr: u64,
    /// Page table root (CR3) from `mm->pgd`, if available.
    pub cr3: Option<u64>,
    /// Process start time in nanoseconds since boot.
    /// Prefers `real_start_time` (CLOCK_BOOTTIME, includes suspend) for
    /// timeline accuracy; falls back to `start_time` (CLOCK_MONOTONIC) on
    /// older kernels. Zero if neither field is in the profile.
    pub start_time: u64,
}

/// Network protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// TCP (IPv4).
    Tcp,
    /// UDP (IPv4).
    Udp,
    /// TCP (IPv6).
    Tcp6,
    /// UDP (IPv6).
    Udp6,
    /// Unix domain socket.
    Unix,
    /// Raw socket.
    Raw,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Tcp6 => write!(f, "TCP6"),
            Self::Udp6 => write!(f, "UDP6"),
            Self::Unix => write!(f, "UNIX"),
            Self::Raw => write!(f, "RAW"),
        }
    }
}

/// TCP connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// TCP_ESTABLISHED (1).
    Established,
    /// TCP_SYN_SENT (2).
    SynSent,
    /// TCP_SYN_RECV (3).
    SynRecv,
    /// TCP_FIN_WAIT1 (4).
    FinWait1,
    /// TCP_FIN_WAIT2 (5).
    FinWait2,
    /// TCP_TIME_WAIT (6).
    TimeWait,
    /// TCP_CLOSE (7).
    Close,
    /// TCP_CLOSE_WAIT (8).
    CloseWait,
    /// TCP_LAST_ACK (9).
    LastAck,
    /// TCP_LISTEN (10).
    Listen,
    /// TCP_CLOSING (11).
    Closing,
    /// Unknown state.
    Unknown(u8),
}

impl ConnectionState {
    /// Parse a raw TCP state value.
    pub fn from_raw(value: u8) -> Self {
        match value {
            1 => Self::Established,
            2 => Self::SynSent,
            3 => Self::SynRecv,
            4 => Self::FinWait1,
            5 => Self::FinWait2,
            6 => Self::TimeWait,
            7 => Self::Close,
            8 => Self::CloseWait,
            9 => Self::LastAck,
            10 => Self::Listen,
            11 => Self::Closing,
            _ => Self::Unknown(value),
        }
    }
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Established => write!(f, "ESTABLISHED"),
            Self::SynSent => write!(f, "SYN_SENT"),
            Self::SynRecv => write!(f, "SYN_RECV"),
            Self::FinWait1 => write!(f, "FIN_WAIT1"),
            Self::FinWait2 => write!(f, "FIN_WAIT2"),
            Self::TimeWait => write!(f, "TIME_WAIT"),
            Self::Close => write!(f, "CLOSE"),
            Self::CloseWait => write!(f, "CLOSE_WAIT"),
            Self::LastAck => write!(f, "LAST_ACK"),
            Self::Listen => write!(f, "LISTEN"),
            Self::Closing => write!(f, "CLOSING"),
            Self::Unknown(v) => write!(f, "UNKNOWN({v})"),
        }
    }
}

/// Information about a network connection extracted from kernel memory.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Network protocol.
    pub protocol: Protocol,
    /// Local IP address as string.
    pub local_addr: String,
    /// Local port.
    pub local_port: u16,
    /// Remote IP address as string.
    pub remote_addr: String,
    /// Remote port.
    pub remote_port: u16,
    /// Connection state (TCP only).
    pub state: ConnectionState,
    /// PID of the owning process, if determinable.
    pub pid: Option<u64>,
}

/// State of a kernel module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleState {
    /// MODULE_STATE_LIVE.
    Live,
    /// MODULE_STATE_COMING.
    Coming,
    /// MODULE_STATE_GOING.
    Going,
    /// MODULE_STATE_UNFORMED.
    Unformed,
    /// Unknown state.
    Unknown(u32),
}

impl ModuleState {
    /// Parse a raw module state value.
    pub fn from_raw(value: u32) -> Self {
        match value {
            0 => Self::Live,
            1 => Self::Coming,
            2 => Self::Going,
            3 => Self::Unformed,
            _ => Self::Unknown(value),
        }
    }
}

impl fmt::Display for ModuleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Live => write!(f, "Live"),
            Self::Coming => write!(f, "Coming"),
            Self::Going => write!(f, "Going"),
            Self::Unformed => write!(f, "Unformed"),
            Self::Unknown(v) => write!(f, "Unknown({v})"),
        }
    }
}

/// Information about a loaded kernel module.
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    /// Module name.
    pub name: String,
    /// Base virtual address of the module's core section.
    pub base_addr: u64,
    /// Size of the module's core section in bytes.
    pub size: u64,
    /// Module state.
    pub state: ModuleState,
}

// ---------------------------------------------------------------------------
// Process tree types
// ---------------------------------------------------------------------------

/// A process tree entry with depth annotation for display.
///
/// Used by [`crate::process::build_pstree`] to produce a flat, depth-annotated
/// list from a process list, suitable for rendering as an indented tree.
#[derive(Debug, Clone)]
pub struct PsTreeEntry {
    /// The process information.
    pub process: ProcessInfo,
    /// Tree depth (0 = root, 1 = child of root, etc.).
    pub depth: u32,
}

// ---------------------------------------------------------------------------
// Thread types
// ---------------------------------------------------------------------------

/// Information about a Linux thread extracted from `task_struct`.
///
/// In Linux, threads are `task_struct` entries linked via the `thread_group`
/// list. Each thread has its own PID (acting as TID) while sharing the
/// same `tgid` (thread group ID, i.e. the process PID).
#[derive(Debug, Clone)]
pub struct ThreadInfo {
    /// Thread group ID (the process PID, from `task_struct.tgid`).
    pub tgid: u64,
    /// Thread ID (the thread's own PID, from `task_struct.pid`).
    pub tid: u64,
    /// Thread command name (`task_struct.comm`).
    pub comm: String,
    /// Thread state.
    pub state: ProcessState,
}

// ---------------------------------------------------------------------------
// VMA / memory map types
// ---------------------------------------------------------------------------

/// Permission flags for a virtual memory area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct VmaFlags {
    /// VM_READ (0x1).
    pub read: bool,
    /// VM_WRITE (0x2).
    pub write: bool,
    /// VM_EXEC (0x4).
    pub exec: bool,
    /// VM_SHARED (0x8).
    pub shared: bool,
}

impl VmaFlags {
    /// Parse Linux `vm_flags` bitmask.
    pub fn from_raw(flags: u64) -> Self {
        Self {
            read: flags & 0x1 != 0,
            write: flags & 0x2 != 0,
            exec: flags & 0x4 != 0,
            shared: flags & 0x8 != 0,
        }
    }
}

impl fmt::Display for VmaFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}{}",
            if self.read { 'r' } else { '-' },
            if self.write { 'w' } else { '-' },
            if self.exec { 'x' } else { '-' },
            if self.shared { 's' } else { 'p' },
        )
    }
}

/// Information about a process virtual memory area.
#[derive(Debug, Clone)]
pub struct VmaInfo {
    /// PID of the owning process.
    pub pid: u64,
    /// Process name.
    pub comm: String,
    /// VMA start virtual address.
    pub start: u64,
    /// VMA end virtual address.
    pub end: u64,
    /// Permission flags.
    pub flags: VmaFlags,
    /// File page offset (`vm_pgoff`).
    pub pgoff: u64,
    /// Whether the VMA is file-backed.
    pub file_backed: bool,
}

// ---------------------------------------------------------------------------
// File descriptor types
// ---------------------------------------------------------------------------

/// Information about an open file descriptor.
#[derive(Debug, Clone)]
pub struct FileDescriptorInfo {
    /// PID of the owning process.
    pub pid: u64,
    /// Process name.
    pub comm: String,
    /// File descriptor number.
    pub fd: u32,
    /// File path (from dentry, if resolvable).
    pub path: String,
    /// Inode number, if available.
    pub inode: Option<u64>,
    /// File position (f_pos).
    pub pos: u64,
}

// ---------------------------------------------------------------------------
// Environment variable types
// ---------------------------------------------------------------------------

/// A single environment variable from a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvVarInfo {
    /// PID of the owning process.
    pub pid: u64,
    /// Process name.
    pub comm: String,
    /// Variable name (e.g. "PATH").
    pub key: String,
    /// Variable value.
    pub value: String,
}

// ---------------------------------------------------------------------------
// Command line types
// ---------------------------------------------------------------------------

/// Process command line extracted from `mm_struct.arg_start`..`arg_end`.
///
/// The kernel stores argv as null-separated strings in the process's
/// address space. This struct holds the reconstructed full command line
/// with arguments joined by spaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdlineInfo {
    /// Process ID.
    pub pid: u64,
    /// Process name (`task_struct.comm`).
    pub comm: String,
    /// Full command line (argv entries joined with spaces).
    pub cmdline: String,
}

// ---------------------------------------------------------------------------
// Malfind types
// ---------------------------------------------------------------------------

/// A suspicious memory region detected by malfind analysis.
#[derive(Debug, Clone)]
pub struct MalfindInfo {
    /// PID of the owning process.
    pub pid: u64,
    /// Process name.
    pub comm: String,
    /// VMA start address.
    pub start: u64,
    /// VMA end address.
    pub end: u64,
    /// VMA permission flags.
    pub flags: VmaFlags,
    /// Why this region is suspicious.
    pub reason: String,
    /// First 64 bytes of the region (hex dump).
    pub header_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Mount / filesystem types
// ---------------------------------------------------------------------------

/// Information about a mounted filesystem.
#[derive(Debug, Clone)]
pub struct MountInfo {
    /// Device name or source.
    pub dev_name: String,
    /// Mount point path.
    pub mount_point: String,
    /// Filesystem type (e.g. "ext4", "tmpfs").
    pub fs_type: String,
}

// ---------------------------------------------------------------------------
// Syscall table types
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Bash history types
// ---------------------------------------------------------------------------

/// A recovered bash command history entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BashHistoryInfo {
    /// PID of the bash process.
    pub pid: u64,
    /// Process name (usually "bash").
    pub comm: String,
    /// The command text.
    pub command: String,
    /// Unix timestamp when the command was recorded, if available.
    pub timestamp: Option<i64>,
    /// Index of this entry in the history.
    pub index: u64,
}

// ---------------------------------------------------------------------------
// Process cross-view types (psxview)
// ---------------------------------------------------------------------------

/// Cross-view process visibility information for DKOM detection.
#[derive(Debug, Clone)]
pub struct PsxViewInfo {
    /// Process ID.
    pub pid: u64,
    /// Process name.
    pub comm: String,
    /// Whether the process was found in the task_struct linked list.
    pub in_task_list: bool,
    /// Whether the process was found in the PID hash table.
    pub in_pid_hash: bool,
}

// ---------------------------------------------------------------------------
// TTY check types
// ---------------------------------------------------------------------------

/// Information about a TTY operations function pointer check.
#[derive(Debug, Clone)]
pub struct TtyCheckInfo {
    /// TTY device name.
    pub name: String,
    /// Operation name (e.g. "write", "ioctl").
    pub operation: String,
    /// Handler function address.
    pub handler: u64,
    /// Whether this handler appears hooked (outside kernel text).
    pub hooked: bool,
}

// ---------------------------------------------------------------------------
// Kernel inline hook types
// ---------------------------------------------------------------------------

/// Information about a potential inline kernel function hook.
#[derive(Debug, Clone)]
pub struct KernelHookInfo {
    /// Symbol name of the checked function.
    pub symbol: String,
    /// Function address.
    pub address: u64,
    /// Type of hook detected (e.g. "jmp", "call", "none").
    pub hook_type: String,
    /// Target address of the hook, if determinable.
    pub target: Option<u64>,
    /// Whether this appears suspicious.
    pub suspicious: bool,
}

// ---------------------------------------------------------------------------
// ELF info types
// ---------------------------------------------------------------------------

/// ELF object type from the ELF header `e_type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfType {
    /// ET_NONE (0).
    None,
    /// ET_REL (1).
    Relocatable,
    /// ET_EXEC (2).
    Executable,
    /// ET_DYN (3) — shared object / PIE executable.
    SharedObject,
    /// ET_CORE (4).
    Core,
    /// Unknown type.
    Unknown(u16),
}

impl ElfType {
    /// Parse ELF `e_type` value.
    pub fn from_raw(value: u16) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Relocatable,
            2 => Self::Executable,
            3 => Self::SharedObject,
            4 => Self::Core,
            _ => Self::Unknown(value),
        }
    }
}

impl fmt::Display for ElfType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "NONE"),
            Self::Relocatable => write!(f, "REL"),
            Self::Executable => write!(f, "EXEC"),
            Self::SharedObject => write!(f, "DYN"),
            Self::Core => write!(f, "CORE"),
            Self::Unknown(v) => write!(f, "UNKNOWN({v})"),
        }
    }
}

/// Information about an ELF binary found in process memory.
#[derive(Debug, Clone)]
pub struct ElfInfo {
    /// PID of the process.
    pub pid: u64,
    /// Process name.
    pub comm: String,
    /// VMA start address where ELF was found.
    pub vma_start: u64,
    /// ELF type.
    pub elf_type: ElfType,
    /// Machine architecture (e.g. EM_X86_64 = 62).
    pub machine: u16,
    /// Entry point address.
    pub entry_point: u64,
}

// ---------------------------------------------------------------------------
// Hidden module types
// ---------------------------------------------------------------------------

/// Information about a potentially hidden kernel module.
#[derive(Debug, Clone)]
pub struct HiddenModuleInfo {
    /// Module name.
    pub name: String,
    /// Base virtual address.
    pub base_addr: u64,
    /// Module size in bytes.
    pub size: u64,
    /// Whether found in the modules linked list.
    pub in_modules_list: bool,
    /// Whether found via kset/sysfs walk.
    pub in_sysfs: bool,
}

// ---------------------------------------------------------------------------
// Syscall table types
// ---------------------------------------------------------------------------

/// Information about a syscall table entry.
#[derive(Debug, Clone)]
pub struct SyscallInfo {
    /// Syscall number.
    pub number: u64,
    /// Address of the handler function.
    pub handler: u64,
    /// Whether this entry appears hooked (doesn't match known symbol).
    pub hooked: bool,
    /// Name of the expected handler, if known.
    pub expected_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Boot time estimation
// ---------------------------------------------------------------------------

/// Source of a boot time estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootTimeSource {
    /// Derived from kernel timekeeper (wall_to_monotonic + offs_boot).
    Timekeeper,
    /// User-provided via --btime flag (e.g., from /proc/stat btime).
    UserProvided,
}

impl std::fmt::Display for BootTimeSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timekeeper => write!(f, "timekeeper"),
            Self::UserProvided => write!(f, "user-provided"),
        }
    }
}

/// A single boot time estimate from a specific source.
#[derive(Debug, Clone)]
pub struct BootTimeEstimate {
    /// Where this estimate came from.
    pub source: BootTimeSource,
    /// Unix epoch seconds of the estimated boot time.
    pub boot_epoch_secs: i64,
}

/// Aggregated boot time information from multiple sources.
///
/// Holds all collected estimates and detects inconsistencies between
/// them (clock manipulation indicator in DFIR). The `best_estimate`
/// is the first (highest-priority) source's epoch value.
#[derive(Debug, Clone)]
pub struct BootTimeInfo {
    /// Best estimated boot epoch (Unix seconds), if any source was available.
    pub best_estimate: Option<i64>,
    /// All collected estimates for cross-validation.
    pub estimates: Vec<BootTimeEstimate>,
    /// Whether sources disagree beyond the drift threshold (60s).
    pub inconsistent: bool,
    /// Maximum drift between any two sources, in seconds.
    pub max_drift_secs: i64,
}

/// Drift threshold (seconds) for boot time inconsistency detection.
const BOOT_TIME_DRIFT_THRESHOLD: i64 = 60;

impl BootTimeInfo {
    /// Build from a collection of estimates.
    ///
    /// The first estimate is treated as highest-priority ("best").
    /// Inconsistency is flagged when any pair of estimates differs
    /// by more than 60 seconds.
    pub fn from_estimates(estimates: Vec<BootTimeEstimate>) -> Self {
        let best_estimate = estimates.first().map(|e| e.boot_epoch_secs);

        let mut max_drift: i64 = 0;
        for i in 0..estimates.len() {
            for j in (i + 1)..estimates.len() {
                let drift = (estimates[i].boot_epoch_secs - estimates[j].boot_epoch_secs).abs();
                if drift > max_drift {
                    max_drift = drift;
                }
            }
        }

        Self {
            best_estimate,
            estimates,
            inconsistent: max_drift > BOOT_TIME_DRIFT_THRESHOLD,
            max_drift_secs: max_drift,
        }
    }

    /// Convert boot-relative nanoseconds to absolute Unix epoch seconds.
    ///
    /// Returns `None` if no boot time estimate is available.
    pub fn absolute_secs(&self, boot_ns: u64) -> Option<i64> {
        self.best_estimate
            .map(|epoch| {
                let boot_secs = i64::try_from(boot_ns / 1_000_000_000).unwrap_or(i64::MAX);
                epoch + boot_secs
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vma_flags_from_raw() {
        let f = VmaFlags::from_raw(0x5); // read + exec
        assert!(f.read);
        assert!(!f.write);
        assert!(f.exec);
        assert!(!f.shared);
    }

    #[test]
    fn vma_flags_display() {
        assert_eq!(VmaFlags::from_raw(0x7).to_string(), "rwxp"); // r+w+x, private
        assert_eq!(VmaFlags::from_raw(0x1).to_string(), "r--p");
        assert_eq!(VmaFlags::from_raw(0xF).to_string(), "rwxs"); // shared
        assert_eq!(VmaFlags::from_raw(0x0).to_string(), "---p");
    }

    #[test]
    fn process_state_from_raw() {
        assert_eq!(ProcessState::from_raw(0), ProcessState::Running);
        assert_eq!(ProcessState::from_raw(1), ProcessState::Sleeping);
        assert_eq!(ProcessState::from_raw(2), ProcessState::DiskSleep);
        assert_eq!(ProcessState::from_raw(4), ProcessState::Stopped);
        assert_eq!(ProcessState::from_raw(8), ProcessState::Traced);
        assert_eq!(ProcessState::from_raw(16), ProcessState::Dead);
        assert_eq!(ProcessState::from_raw(32), ProcessState::Zombie);
        assert!(matches!(
            ProcessState::from_raw(99),
            ProcessState::Unknown(99)
        ));
    }

    #[test]
    fn process_state_display() {
        assert_eq!(ProcessState::Running.to_string(), "R (running)");
        assert_eq!(ProcessState::Sleeping.to_string(), "S (sleeping)");
        assert_eq!(ProcessState::DiskSleep.to_string(), "D (disk sleep)");
        assert_eq!(ProcessState::Stopped.to_string(), "T (stopped)");
        assert_eq!(ProcessState::Traced.to_string(), "t (traced)");
        assert_eq!(ProcessState::Dead.to_string(), "X (dead)");
        assert_eq!(ProcessState::Zombie.to_string(), "Z (zombie)");
        assert_eq!(ProcessState::Unknown(42).to_string(), "? (42)");
    }

    #[test]
    fn connection_state_from_raw() {
        assert_eq!(ConnectionState::from_raw(1), ConnectionState::Established);
        assert_eq!(ConnectionState::from_raw(2), ConnectionState::SynSent);
        assert_eq!(ConnectionState::from_raw(3), ConnectionState::SynRecv);
        assert_eq!(ConnectionState::from_raw(4), ConnectionState::FinWait1);
        assert_eq!(ConnectionState::from_raw(5), ConnectionState::FinWait2);
        assert_eq!(ConnectionState::from_raw(6), ConnectionState::TimeWait);
        assert_eq!(ConnectionState::from_raw(7), ConnectionState::Close);
        assert_eq!(ConnectionState::from_raw(8), ConnectionState::CloseWait);
        assert_eq!(ConnectionState::from_raw(9), ConnectionState::LastAck);
        assert_eq!(ConnectionState::from_raw(10), ConnectionState::Listen);
        assert_eq!(ConnectionState::from_raw(11), ConnectionState::Closing);
        assert!(matches!(
            ConnectionState::from_raw(99),
            ConnectionState::Unknown(99)
        ));
    }

    #[test]
    fn connection_state_display() {
        assert_eq!(ConnectionState::Established.to_string(), "ESTABLISHED");
        assert_eq!(ConnectionState::SynSent.to_string(), "SYN_SENT");
        assert_eq!(ConnectionState::SynRecv.to_string(), "SYN_RECV");
        assert_eq!(ConnectionState::FinWait1.to_string(), "FIN_WAIT1");
        assert_eq!(ConnectionState::FinWait2.to_string(), "FIN_WAIT2");
        assert_eq!(ConnectionState::TimeWait.to_string(), "TIME_WAIT");
        assert_eq!(ConnectionState::Close.to_string(), "CLOSE");
        assert_eq!(ConnectionState::CloseWait.to_string(), "CLOSE_WAIT");
        assert_eq!(ConnectionState::LastAck.to_string(), "LAST_ACK");
        assert_eq!(ConnectionState::Listen.to_string(), "LISTEN");
        assert_eq!(ConnectionState::Closing.to_string(), "CLOSING");
        assert_eq!(ConnectionState::Unknown(42).to_string(), "UNKNOWN(42)");
    }

    #[test]
    fn module_state_from_raw() {
        assert_eq!(ModuleState::from_raw(0), ModuleState::Live);
        assert_eq!(ModuleState::from_raw(1), ModuleState::Coming);
        assert_eq!(ModuleState::from_raw(2), ModuleState::Going);
        assert_eq!(ModuleState::from_raw(3), ModuleState::Unformed);
        assert!(matches!(
            ModuleState::from_raw(99),
            ModuleState::Unknown(99)
        ));
    }

    #[test]
    fn module_state_display() {
        assert_eq!(ModuleState::Live.to_string(), "Live");
        assert_eq!(ModuleState::Coming.to_string(), "Coming");
        assert_eq!(ModuleState::Going.to_string(), "Going");
        assert_eq!(ModuleState::Unformed.to_string(), "Unformed");
        assert_eq!(ModuleState::Unknown(42).to_string(), "Unknown(42)");
    }

    #[test]
    fn protocol_display() {
        assert_eq!(Protocol::Tcp.to_string(), "TCP");
        assert_eq!(Protocol::Udp.to_string(), "UDP");
        assert_eq!(Protocol::Tcp6.to_string(), "TCP6");
        assert_eq!(Protocol::Udp6.to_string(), "UDP6");
        assert_eq!(Protocol::Unix.to_string(), "UNIX");
        assert_eq!(Protocol::Raw.to_string(), "RAW");
    }

    #[test]
    fn elf_type_from_raw() {
        assert_eq!(ElfType::from_raw(0), ElfType::None);
        assert_eq!(ElfType::from_raw(1), ElfType::Relocatable);
        assert_eq!(ElfType::from_raw(2), ElfType::Executable);
        assert_eq!(ElfType::from_raw(3), ElfType::SharedObject);
        assert_eq!(ElfType::from_raw(4), ElfType::Core);
        assert!(matches!(ElfType::from_raw(99), ElfType::Unknown(99)));
    }

    #[test]
    fn elf_type_display() {
        assert_eq!(ElfType::None.to_string(), "NONE");
        assert_eq!(ElfType::Relocatable.to_string(), "REL");
        assert_eq!(ElfType::Executable.to_string(), "EXEC");
        assert_eq!(ElfType::SharedObject.to_string(), "DYN");
        assert_eq!(ElfType::Core.to_string(), "CORE");
        assert_eq!(ElfType::Unknown(42).to_string(), "UNKNOWN(42)");
    }

    // --- Boot time types ---

    #[test]
    fn boot_time_source_display() {
        assert_eq!(BootTimeSource::Timekeeper.to_string(), "timekeeper");
        assert_eq!(BootTimeSource::UserProvided.to_string(), "user-provided");
    }

    #[test]
    fn from_estimates_empty_has_no_best() {
        let info = BootTimeInfo::from_estimates(vec![]);
        assert_eq!(info.best_estimate, None);
        assert!(!info.inconsistent);
        assert_eq!(info.max_drift_secs, 0);
    }

    #[test]
    fn from_estimates_single_source() {
        let info = BootTimeInfo::from_estimates(vec![BootTimeEstimate {
            source: BootTimeSource::Timekeeper,
            boot_epoch_secs: 1_712_000_000,
        }]);
        assert_eq!(info.best_estimate, Some(1_712_000_000));
        assert!(!info.inconsistent);
        assert_eq!(info.max_drift_secs, 0);
    }

    #[test]
    fn from_estimates_consistent_sources() {
        let info = BootTimeInfo::from_estimates(vec![
            BootTimeEstimate {
                source: BootTimeSource::Timekeeper,
                boot_epoch_secs: 1_712_000_000,
            },
            BootTimeEstimate {
                source: BootTimeSource::UserProvided,
                boot_epoch_secs: 1_712_000_030, // 30s drift (< 60s threshold)
            },
        ]);
        assert_eq!(info.best_estimate, Some(1_712_000_000));
        assert!(!info.inconsistent);
        assert_eq!(info.max_drift_secs, 30);
    }

    #[test]
    fn from_estimates_inconsistent_sources() {
        let info = BootTimeInfo::from_estimates(vec![
            BootTimeEstimate {
                source: BootTimeSource::Timekeeper,
                boot_epoch_secs: 1_712_000_000,
            },
            BootTimeEstimate {
                source: BootTimeSource::UserProvided,
                boot_epoch_secs: 1_712_000_120, // 120s drift (> 60s threshold)
            },
        ]);
        assert_eq!(info.best_estimate, Some(1_712_000_000));
        assert!(info.inconsistent);
        assert_eq!(info.max_drift_secs, 120);
    }

    #[test]
    fn absolute_secs_with_boot_epoch() {
        let info = BootTimeInfo::from_estimates(vec![BootTimeEstimate {
            source: BootTimeSource::UserProvided,
            boot_epoch_secs: 1_712_000_000,
        }]);
        // 500ms after boot → epoch + 0 (sub-second truncates)
        assert_eq!(info.absolute_secs(500_000_000), Some(1_712_000_000));
        // 3600s after boot
        assert_eq!(info.absolute_secs(3_600_000_000_000), Some(1_712_003_600));
    }

    #[test]
    fn absolute_secs_without_boot_epoch() {
        let info = BootTimeInfo::from_estimates(vec![]);
        assert_eq!(info.absolute_secs(500_000_000), None);
    }
}
