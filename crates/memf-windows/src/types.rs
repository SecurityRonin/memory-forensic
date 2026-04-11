//! Output types for Windows forensic walkers.
//!
//! These types represent the forensic artifacts extracted from Windows
//! kernel memory structures: processes, threads, drivers, and DLLs.

use std::fmt;

/// Windows thread scheduling state.
///
/// Maps to the `KTHREAD_STATE` enum in the Windows kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    /// Thread has been initialized but not yet started.
    Initialized,
    /// Thread is ready to run.
    Ready,
    /// Thread is currently executing on a processor.
    Running,
    /// Thread is selected to run next on a processor.
    Standby,
    /// Thread has terminated.
    Terminated,
    /// Thread is waiting for an event.
    Waiting,
    /// Thread is transitioning between states.
    Transition,
    /// Thread is ready but deferred for scheduling.
    DeferredReady,
    /// Obsolete gate-wait state.
    GateWaitObsolete,
    /// Thread is waiting for its process to be swapped in.
    WaitingForProcessInSwap,
    /// Unknown or unrecognized state value.
    Unknown(u32),
}

impl ThreadState {
    /// Convert a raw Windows `KTHREAD_STATE` value to a `ThreadState`.
    pub fn from_raw(value: u32) -> Self {
        match value {
            0 => Self::Initialized,
            1 => Self::Ready,
            2 => Self::Running,
            3 => Self::Standby,
            4 => Self::Terminated,
            5 => Self::Waiting,
            6 => Self::Transition,
            7 => Self::DeferredReady,
            8 => Self::GateWaitObsolete,
            9 => Self::WaitingForProcessInSwap,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for ThreadState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initialized => write!(f, "Initialized"),
            Self::Ready => write!(f, "Ready"),
            Self::Running => write!(f, "Running"),
            Self::Standby => write!(f, "Standby"),
            Self::Terminated => write!(f, "Terminated"),
            Self::Waiting => write!(f, "Waiting"),
            Self::Transition => write!(f, "Transition"),
            Self::DeferredReady => write!(f, "DeferredReady"),
            Self::GateWaitObsolete => write!(f, "GateWaitObsolete"),
            Self::WaitingForProcessInSwap => write!(f, "WaitingForProcessInSwap"),
            Self::Unknown(v) => write!(f, "Unknown({v})"),
        }
    }
}

/// Information about a Windows process extracted from `_EPROCESS`.
#[derive(Debug, Clone)]
pub struct WinProcessInfo {
    /// Process ID (`UniqueProcessId`).
    pub pid: u64,
    /// Parent process ID (`InheritedFromUniqueProcessId`).
    pub ppid: u64,
    /// Image file name from `ImageFileName` (up to 15 chars).
    pub image_name: String,
    /// Process creation time as Windows FILETIME.
    pub create_time: u64,
    /// Process exit time as Windows FILETIME (0 if still running).
    pub exit_time: u64,
    /// Page directory base (CR3) from `_KPROCESS.DirectoryTableBase`.
    pub cr3: u64,
    /// Address of the Process Environment Block.
    pub peb_addr: u64,
    /// Virtual address of this `_EPROCESS` in kernel memory.
    pub vaddr: u64,
    /// Number of threads in this process.
    pub thread_count: u32,
    /// Whether this is a WoW64 (32-bit on 64-bit) process.
    pub is_wow64: bool,
}

/// Information about a Windows thread extracted from `_ETHREAD`/`_KTHREAD`.
#[derive(Debug, Clone)]
pub struct WinThreadInfo {
    /// Thread ID from `_CLIENT_ID.UniqueThread`.
    pub tid: u64,
    /// Owning process ID from `_CLIENT_ID.UniqueProcess`.
    pub pid: u64,
    /// Thread creation time as Windows FILETIME.
    pub create_time: u64,
    /// Thread start address (`Win32StartAddress`).
    pub start_address: u64,
    /// Thread Environment Block address.
    pub teb_addr: u64,
    /// Current scheduling state.
    pub state: ThreadState,
    /// Virtual address of this `_ETHREAD` in kernel memory.
    pub vaddr: u64,
}

/// Information about a Windows kernel driver extracted from `_KLDR_DATA_TABLE_ENTRY`.
#[derive(Debug, Clone)]
pub struct WinDriverInfo {
    /// Base name of the driver module.
    pub name: String,
    /// Full path to the driver file on disk.
    pub full_path: String,
    /// Base address where the driver is loaded in kernel memory.
    pub base_addr: u64,
    /// Size of the driver image in bytes.
    pub size: u64,
    /// Virtual address of the `_KLDR_DATA_TABLE_ENTRY` structure.
    pub vaddr: u64,
}

/// Information about a loaded DLL extracted from `_LDR_DATA_TABLE_ENTRY`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WinDllInfo {
    /// Base name of the DLL.
    pub name: String,
    /// Full path to the DLL file on disk.
    pub full_path: String,
    /// Base address where the DLL is loaded.
    pub base_addr: u64,
    /// Size of the DLL image in bytes.
    pub size: u64,
    /// Load order index (position in the `InLoadOrderModuleList`).
    pub load_order: u32,
}

/// Cross-reference result from walking all three PEB LDR module lists.
///
/// Each boolean indicates whether the DLL was found in that particular list.
/// A legitimate DLL is typically present in all three; absence from one or more
/// lists suggests unlinking (a common DLL-hiding technique).
#[derive(Debug, Clone)]
pub struct LdrModuleInfo {
    /// Base address where the DLL is loaded.
    pub base_addr: u64,
    /// Base name of the DLL (e.g. `ntdll.dll`).
    pub name: String,
    /// Full path to the DLL file.
    pub full_path: String,
    /// Present in `InLoadOrderModuleList`.
    pub in_load: bool,
    /// Present in `InMemoryOrderModuleList`.
    pub in_mem: bool,
    /// Present in `InInitializationOrderModuleList`.
    pub in_init: bool,
}

/// Command line extracted from a Windows process's PEB.
#[derive(Debug, Clone)]
pub struct WinCmdlineInfo {
    /// Process ID.
    pub pid: u64,
    /// Image file name from `_EPROCESS.ImageFileName`.
    pub image_name: String,
    /// Full command line from `_RTL_USER_PROCESS_PARAMETERS.CommandLine`.
    pub cmdline: String,
}

/// Environment variable from a Windows process's PEB.
#[derive(Debug, Clone)]
pub struct WinEnvVarInfo {
    /// Process ID.
    pub pid: u64,
    /// Image file name from `_EPROCESS.ImageFileName`.
    pub image_name: String,
    /// Environment variable name.
    pub variable: String,
    /// Environment variable value.
    pub value: String,
}

/// Process tree entry with depth for hierarchical display.
#[derive(Debug, Clone)]
pub struct WinPsTreeEntry {
    /// The process information.
    pub process: WinProcessInfo,
    /// Tree depth (0 = root, 1 = child of root, etc.).
    pub depth: u32,
}

/// PEB masquerade detection result.
#[derive(Debug, Clone)]
pub struct WinPebMasqueradeInfo {
    /// Process ID.
    pub pid: u64,
    /// Image file name from `_EPROCESS.ImageFileName`.
    pub eprocess_name: String,
    /// Image path name from PEB `_RTL_USER_PROCESS_PARAMETERS.ImagePathName`.
    pub peb_image_path: String,
    /// Whether the names mismatch (potential masquerade).
    pub suspicious: bool,
}

/// IRP hook detection for a single dispatch entry in a driver object.
#[derive(Debug, Clone)]
pub struct WinIrpHookInfo {
    /// Driver name from `_DRIVER_OBJECT.DriverName`.
    pub driver_name: String,
    /// Virtual address of the `_DRIVER_OBJECT`.
    pub driver_obj_addr: u64,
    /// IRP major function index (0..27).
    pub irp_index: u8,
    /// Human-readable IRP name (e.g., `IRP_MJ_CREATE`).
    pub irp_name: String,
    /// Target address the IRP dispatch points to.
    pub target_addr: u64,
    /// Name of the module containing the target, if identified.
    pub target_module: Option<String>,
    /// Whether the target is outside all known modules (suspicious).
    pub suspicious: bool,
}

/// SSDT hook detection result for a single system service entry.
#[derive(Debug, Clone)]
pub struct WinSsdtHookInfo {
    /// System service index (syscall number).
    pub index: u32,
    /// Absolute address the SSDT entry resolves to.
    pub target_addr: u64,
    /// Name of the module containing the target, if identified.
    pub target_module: Option<String>,
    /// Whether the target is outside ntoskrnl (suspicious).
    pub suspicious: bool,
}

/// Kernel callback registration entry.
#[derive(Debug, Clone)]
pub struct WinCallbackInfo {
    /// Type of callback (e.g., "CreateProcess", "CreateThread", "LoadImage").
    pub callback_type: String,
    /// Array index (slot) within the callback array.
    pub index: u32,
    /// Address of the registered callback function.
    pub address: u64,
    /// Name of the module containing the callback, if identified.
    pub owning_module: Option<String>,
}

/// Virtual Address Descriptor (VAD) entry from `_MMVAD_SHORT`.
#[derive(Debug, Clone)]
pub struct WinVadInfo {
    /// Process ID owning this VAD.
    pub pid: u64,
    /// Image file name of the owning process.
    pub image_name: String,
    /// Start virtual address of the region (StartingVpn << 12).
    pub start_vaddr: u64,
    /// End virtual address of the region (EndingVpn << 12 | 0xFFF).
    pub end_vaddr: u64,
    /// Page protection (raw `VadFlags.Protection` value).
    pub protection: u32,
    /// Human-readable protection string (e.g., "PAGE_EXECUTE_READWRITE").
    pub protection_str: String,
    /// Whether this VAD is private (not mapped from a file).
    pub is_private: bool,
}

/// Suspicious memory region detected via VAD analysis.
#[derive(Debug, Clone)]
pub struct WinMalfindInfo {
    /// Process ID.
    pub pid: u64,
    /// Image file name of the owning process.
    pub image_name: String,
    /// Start virtual address of the suspicious region.
    pub start_vaddr: u64,
    /// End virtual address of the suspicious region.
    pub end_vaddr: u64,
    /// Human-readable protection string.
    pub protection_str: String,
    /// First 64 bytes of the region (for PE header detection).
    pub first_bytes: Vec<u8>,
}

/// Windows TCP connection state (`MIB_TCP_STATE` values).
///
/// Maps to the `MIB_TCP_STATE` enum used by the Windows TCP/IP stack.
/// Values are 1-indexed (unlike most Windows enums).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinTcpState {
    /// Connection closed.
    Closed,
    /// Listening for incoming connections.
    Listen,
    /// SYN sent, awaiting SYN-ACK.
    SynSent,
    /// SYN received, awaiting ACK.
    SynReceived,
    /// Connection established.
    Established,
    /// FIN sent, waiting for ACK or FIN.
    FinWait1,
    /// FIN acknowledged, waiting for remote FIN.
    FinWait2,
    /// Remote FIN received, waiting for local close.
    CloseWait,
    /// Both sides closing simultaneously.
    Closing,
    /// FIN sent after receiving remote FIN, awaiting final ACK.
    LastAck,
    /// Waiting for sufficient time to ensure remote received ACK.
    TimeWait,
    /// Waiting for all packets to be received before deletion.
    DeleteTcb,
    /// Unknown or unrecognized state value.
    Unknown(u32),
}

impl WinTcpState {
    /// Convert a raw Windows `MIB_TCP_STATE` value to a `WinTcpState`.
    pub fn from_raw(value: u32) -> Self {
        match value {
            1 => Self::Closed,
            2 => Self::Listen,
            3 => Self::SynSent,
            4 => Self::SynReceived,
            5 => Self::Established,
            6 => Self::FinWait1,
            7 => Self::FinWait2,
            8 => Self::CloseWait,
            9 => Self::Closing,
            10 => Self::LastAck,
            11 => Self::TimeWait,
            12 => Self::DeleteTcb,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for WinTcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "CLOSED"),
            Self::Listen => write!(f, "LISTENING"),
            Self::SynSent => write!(f, "SYN_SENT"),
            Self::SynReceived => write!(f, "SYN_RCVD"),
            Self::Established => write!(f, "ESTABLISHED"),
            Self::FinWait1 => write!(f, "FIN_WAIT1"),
            Self::FinWait2 => write!(f, "FIN_WAIT2"),
            Self::CloseWait => write!(f, "CLOSE_WAIT"),
            Self::Closing => write!(f, "CLOSING"),
            Self::LastAck => write!(f, "LAST_ACK"),
            Self::TimeWait => write!(f, "TIME_WAIT"),
            Self::DeleteTcb => write!(f, "DELETE_TCB"),
            Self::Unknown(v) => write!(f, "Unknown({v})"),
        }
    }
}

/// Windows network connection from `_TCP_ENDPOINT`.
#[derive(Debug, Clone)]
pub struct WinConnectionInfo {
    /// Protocol string (e.g., `"TCPv4"`).
    pub protocol: String,
    /// Local IP address as dotted-decimal string.
    pub local_addr: String,
    /// Local port number.
    pub local_port: u16,
    /// Remote IP address as dotted-decimal string.
    pub remote_addr: String,
    /// Remote port number.
    pub remote_port: u16,
    /// TCP connection state.
    pub state: WinTcpState,
    /// Owning process ID from `_EPROCESS.UniqueProcessId`.
    pub pid: u64,
    /// Owning process name from `_EPROCESS.ImageFileName`.
    pub process_name: String,
    /// Connection creation time as Windows FILETIME.
    pub create_time: u64,
}

/// Process SID (Security Identifier) information for privilege escalation detection.
///
/// Maps each process to its token's user SID, resolves well-known SIDs to
/// human-readable names, and flags suspicious security contexts (e.g. a
/// user-spawned process running as SYSTEM). Equivalent to Volatility's
/// `getsids` plugin. MITRE ATT&CK T1078/T1134.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProcessSidInfo {
    /// Process ID.
    pub pid: u32,
    /// Image file name from `_EPROCESS.ImageFileName`.
    pub process_name: String,
    /// User SID string (e.g. `S-1-5-18`).
    pub user_sid: String,
    /// Human-readable name for the SID (e.g. `SYSTEM`), or the raw SID if unknown.
    pub sid_name: String,
    /// Integrity level label (e.g. `System`, `High`, `Medium`, `Low`).
    pub integrity_level: String,
    /// Whether this process-SID combination is suspicious (potential privilege escalation).
    pub is_suspicious: bool,
}

/// Process token and privilege information.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WinTokenInfo {
    /// Process ID.
    pub pid: u64,
    /// Image file name from `_EPROCESS.ImageFileName`.
    pub image_name: String,
    /// Enabled privilege bitmask from `_SEP_TOKEN_PRIVILEGES.Enabled`.
    pub privileges_enabled: u64,
    /// Present privilege bitmask from `_SEP_TOKEN_PRIVILEGES.Present`.
    pub privileges_present: u64,
    /// Human-readable names of enabled privileges.
    pub privilege_names: Vec<String>,
    /// Session ID from `_EPROCESS.SessionId` (if available).
    pub session_id: u32,
    /// User SID string from `_TOKEN.UserAndGroups[0]` (e.g. `S-1-5-18`).
    pub user_sid: String,
}

/// Process hollowing detection result.
///
/// Compares the PE header at `PEB.ImageBaseAddress` against the expected
/// image for each process. If the memory at the image base lacks a valid
/// MZ/PE signature or the PE `SizeOfImage` doesn't match, the process
/// may have been hollowed (original code replaced with malicious payload).
#[derive(Debug, Clone, serde::Serialize)]
pub struct WinHollowingInfo {
    /// Process ID.
    pub pid: u64,
    /// Image file name from `_EPROCESS.ImageFileName`.
    pub image_name: String,
    /// `PEB.ImageBaseAddress` value.
    pub image_base: u64,
    /// Whether a valid MZ header was found at `ImageBaseAddress`.
    pub has_mz: bool,
    /// Whether a valid PE signature (`PE\0\0`) was found at the PE offset.
    pub has_pe: bool,
    /// `SizeOfImage` from the PE optional header (0 if PE header invalid).
    pub pe_size_of_image: u32,
    /// Expected image size from the first DLL entry in `InLoadOrderModuleList` (0 if unavailable).
    pub ldr_size_of_image: u64,
    /// Whether this process appears hollowed (suspicious).
    pub suspicious: bool,
    /// Human-readable reason for the suspicion.
    pub reason: String,
}

/// Windows handle table entry extracted from `_HANDLE_TABLE`.
///
/// Each process has an object table (`_EPROCESS.ObjectTable`) containing
/// handles to kernel objects (files, registry keys, mutexes, etc.).
/// The `object_type` field is derived from `_OBJECT_HEADER.TypeIndex`
/// looked up in `ObTypeIndexTable`.
#[derive(Debug, Clone)]
pub struct WinHandleInfo {
    /// Process ID owning this handle.
    pub pid: u64,
    /// Image file name of the owning process.
    pub image_name: String,
    /// Handle value (index × 4, starting at 4).
    pub handle_value: u32,
    /// Address of the `_OBJECT_HEADER` (ObjectPointerBits decoded).
    pub object_addr: u64,
    /// Kernel object type name (e.g., "File", "Key", "Mutant").
    pub object_type: String,
    /// Granted access mask from `_HANDLE_TABLE_ENTRY.GrantedAccessBits`.
    pub granted_access: u32,
}

/// A named mutex/mutant found in the object manager.
///
/// Malware frequently creates named mutexes to ensure single-instance
/// execution. Enumerating these from memory is a key DFIR artifact.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MutantInfo {
    /// Name of the mutant from `_OBJECT_HEADER_NAME_INFO`.
    pub name: String,
    /// PID of the owning process (from `_ETHREAD.Cid.UniqueProcess`).
    pub owner_pid: u64,
    /// Thread ID of the owning thread (from `_ETHREAD.Cid.UniqueThread`).
    pub owner_thread_id: u64,
    /// Whether the mutant has been abandoned (owner thread terminated).
    pub abandoned: bool,
}

// ── DNS resolver cache types ──────────────────────────────────────────

/// DNS record type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum DnsRecordType {
    /// A record (IPv4 address).
    A,
    /// AAAA record (IPv6 address).
    Aaaa,
    /// CNAME (canonical name alias).
    Cname,
    /// PTR (pointer / reverse DNS).
    Ptr,
    /// MX (mail exchange).
    Mx,
    /// SRV (service locator).
    Srv,
    /// SOA (start of authority).
    Soa,
    /// NS (name server).
    Ns,
    /// TXT record.
    Txt,
    /// Unknown or unsupported record type.
    Unknown(u16),
}

impl DnsRecordType {
    /// Convert a raw DNS type value to a `DnsRecordType`.
    pub fn from_raw(value: u16) -> Self {
        match value {
            1 => Self::A,
            28 => Self::Aaaa,
            5 => Self::Cname,
            12 => Self::Ptr,
            15 => Self::Mx,
            33 => Self::Srv,
            6 => Self::Soa,
            2 => Self::Ns,
            16 => Self::Txt,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::Aaaa => write!(f, "AAAA"),
            Self::Cname => write!(f, "CNAME"),
            Self::Ptr => write!(f, "PTR"),
            Self::Mx => write!(f, "MX"),
            Self::Srv => write!(f, "SRV"),
            Self::Soa => write!(f, "SOA"),
            Self::Ns => write!(f, "NS"),
            Self::Txt => write!(f, "TXT"),
            Self::Unknown(v) => write!(f, "Unknown({v})"),
        }
    }
}

/// A cached DNS record found in the Windows DNS resolver cache.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DnsCacheEntry {
    /// Domain name that was resolved.
    pub name: String,
    /// DNS record type.
    pub record_type: DnsRecordType,
    /// Resolved data (e.g., IP address string for A/AAAA, hostname for CNAME).
    pub data: String,
    /// TTL in seconds at time of caching.
    pub ttl: u32,
}

// ── Registry hive types ──────────────────────────────────────────────

/// A loaded Windows registry hive extracted from `_CMHIVE`.
///
/// The Windows Configuration Manager maintains a linked list of all
/// loaded registry hives via `CmpHiveListHead`. Each entry is a
/// `_CMHIVE` structure containing the hive file paths, base address,
/// and storage sizes.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegistryHive {
    /// Virtual address of the `_CMHIVE` structure.
    pub base_addr: u64,
    /// Full registry path (e.g., `\REGISTRY\MACHINE\SYSTEM`).
    pub file_full_path: String,
    /// User-mode file path (e.g., `\??\C:\Windows\System32\config\SYSTEM`).
    pub file_user_name: String,
    /// Pointer to the actual hive data (`_HHIVE` base block).
    pub hive_addr: u64,
    /// Size of stable (non-volatile) storage in bytes.
    pub stable_length: u32,
    /// Size of volatile storage in bytes.
    pub volatile_length: u32,
}

// ── Service enumeration types ────────────────────────────────────────

/// Service state (`dwCurrentState` from `SERVICE_STATUS`).
///
/// Maps to the `SERVICE_STATE` constants used by the Windows
/// Service Control Manager (SCM).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ServiceState {
    /// The service is not running (SERVICE_STOPPED = 1).
    Stopped,
    /// The service is starting (SERVICE_START_PENDING = 2).
    StartPending,
    /// The service is stopping (SERVICE_STOP_PENDING = 3).
    StopPending,
    /// The service is running (SERVICE_RUNNING = 4).
    Running,
    /// The service continue is pending (SERVICE_CONTINUE_PENDING = 5).
    ContinuePending,
    /// The service pause is pending (SERVICE_PAUSE_PENDING = 6).
    PausePending,
    /// The service is paused (SERVICE_PAUSED = 7).
    Paused,
    /// Unknown or unrecognized state value.
    Unknown(u32),
}

impl ServiceState {
    /// Convert a raw Windows `dwCurrentState` value to a `ServiceState`.
    pub fn from_raw(value: u32) -> Self {
        match value {
            1 => Self::Stopped,
            2 => Self::StartPending,
            3 => Self::StopPending,
            4 => Self::Running,
            5 => Self::ContinuePending,
            6 => Self::PausePending,
            7 => Self::Paused,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for ServiceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stopped => write!(f, "STOPPED"),
            Self::StartPending => write!(f, "START_PENDING"),
            Self::StopPending => write!(f, "STOP_PENDING"),
            Self::Running => write!(f, "RUNNING"),
            Self::ContinuePending => write!(f, "CONTINUE_PENDING"),
            Self::PausePending => write!(f, "PAUSE_PENDING"),
            Self::Paused => write!(f, "PAUSED"),
            Self::Unknown(v) => write!(f, "Unknown({v})"),
        }
    }
}

/// Service start type (`dwStartType`).
///
/// Maps to the `SERVICE_START_TYPE` constants used by the Windows
/// Service Control Manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ServiceStartType {
    /// Loaded by the boot loader (SERVICE_BOOT_START = 0).
    BootStart,
    /// Started during kernel initialization (SERVICE_SYSTEM_START = 1).
    SystemStart,
    /// Started automatically by the SCM (SERVICE_AUTO_START = 2).
    AutoStart,
    /// Started on demand (SERVICE_DEMAND_START = 3).
    DemandStart,
    /// Cannot be started (SERVICE_DISABLED = 4).
    Disabled,
    /// Unknown or unrecognized start type value.
    Unknown(u32),
}

impl ServiceStartType {
    /// Convert a raw Windows `dwStartType` value to a `ServiceStartType`.
    pub fn from_raw(value: u32) -> Self {
        match value {
            0 => Self::BootStart,
            1 => Self::SystemStart,
            2 => Self::AutoStart,
            3 => Self::DemandStart,
            4 => Self::Disabled,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for ServiceStartType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BootStart => write!(f, "BOOT_START"),
            Self::SystemStart => write!(f, "SYSTEM_START"),
            Self::AutoStart => write!(f, "AUTO_START"),
            Self::DemandStart => write!(f, "DEMAND_START"),
            Self::Disabled => write!(f, "DISABLED"),
            Self::Unknown(v) => write!(f, "Unknown({v})"),
        }
    }
}

/// A Windows service record found in SCM memory.
///
/// Extracted from `_SERVICE_RECORD` structures maintained by the
/// Service Control Manager (`services.exe`). These structures are
/// linked via a doubly-linked list (`ServiceList` field).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceInfo {
    /// Service name (short internal name, e.g., `"Dnscache"`).
    pub name: String,
    /// Display name shown in the Services MMC snap-in.
    pub display_name: String,
    /// Current service state (running, stopped, etc.).
    pub state: ServiceState,
    /// How the service is started (boot, auto, demand, disabled).
    pub start_type: ServiceStartType,
    /// Service type bitmask (`dwServiceType`).
    pub service_type: u32,
    /// Path to the service binary (`ImagePath`).
    pub image_path: String,
    /// Account under which the service runs (e.g., `"LocalSystem"`).
    pub object_name: String,
    /// Process ID of the running service (from `SERVICE_STATUS_PROCESS`).
    pub pid: u32,
}

// ── Event log (EVTX) chunk types ────────────────────────────────────

/// Metadata for a single Windows Event Log (EVTX) chunk recovered from memory.
///
/// Windows Event Log files use the `.evtx` binary format, where the file
/// body is split into 64 KiB chunks. Each chunk starts with the ASCII
/// magic `ElfChnk\0` and contains a sequence of event records. Recovering
/// these chunks from a memory dump lets investigators reconstruct event
/// log entries that may no longer exist on disk (e.g., after log clearing
/// or anti-forensic tampering).
#[derive(Debug, Clone, serde::Serialize)]
pub struct EvtxChunkInfo {
    /// Virtual address where the chunk was found in the memory dump.
    pub offset: u64,
    /// First event record number in this chunk.
    pub first_event_id: u64,
    /// Last event record number in this chunk.
    pub last_event_id: u64,
    /// Earliest timestamp in this chunk (Windows FILETIME, 100-ns ticks since 1601-01-01).
    pub first_timestamp: u64,
    /// Latest timestamp in this chunk (Windows FILETIME).
    pub last_timestamp: u64,
    /// Number of event records found in this chunk.
    pub record_count: u32,
    /// Log channel name if identifiable (e.g., `"Security"`, `"System"`), otherwise `"Unknown"`.
    pub channel: String,
}

// ── Pool tag scanning types ─────────────────────────────────────────

/// A pool tag tracking entry from the kernel's pool allocation tracker.
///
/// The Windows kernel maintains per-tag allocation statistics in the
/// `PoolTrackTable` (or `PoolBigPageTable`). Each entry records how many
/// allocations and frees have occurred for a given 4-character ASCII tag,
/// along with the total bytes currently consumed. Pool tags are a key
/// forensic artifact — they reveal what kernel objects are allocated and
/// can surface rootkit allocations using non-standard tags.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PoolTagEntry {
    /// 4-character ASCII pool tag (e.g., "Proc", "Thre", "File").
    pub tag: String,
    /// Pool type string: "Paged", "NonPaged", or "NonPagedExecute".
    pub pool_type: String,
    /// Number of active allocations with this tag.
    pub allocation_count: u64,
    /// Number of frees with this tag.
    pub free_count: u64,
    /// Total bytes currently used by allocations with this tag.
    pub bytes_used: u64,
    /// Human-readable description if this is a well-known tag.
    pub description: Option<String>,
}

/// Information about a Windows file object extracted from `_FILE_OBJECT`.
///
/// File objects represent open file handles in the kernel.  Each
/// `_FILE_OBJECT` tracks the filename, device chain, access rights,
/// and sharing disposition.  Enumerating these is a key DFIR artifact
/// for understanding what files were open at the time of capture.
#[derive(Debug, Clone, serde::Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct FileObjectInfo {
    /// Virtual address of the `_FILE_OBJECT` in kernel memory.
    pub object_addr: u64,
    /// File name from `_FILE_OBJECT.FileName` (`_UNICODE_STRING`).
    pub file_name: String,
    /// Device name resolved from the `DeviceObject` chain.
    pub device_name: String,
    /// Access mask (granted access from the handle table entry).
    pub access_mask: u32,
    /// `_FILE_OBJECT.Flags` field.
    pub flags: u32,
    /// File size (`CurrentByteOffset` if available, else 0).
    pub size: u64,
    /// Whether a delete operation is pending.
    pub delete_pending: bool,
    /// Shared read access disposition.
    pub shared_read: bool,
    /// Shared write access disposition.
    pub shared_write: bool,
    /// Shared delete access disposition.
    pub shared_delete: bool,
}

// ── Direct syscall detection types ──────────────────────────────────

/// Information about a detected direct or indirect system call invocation.
///
/// When malware calls Nt* functions directly via the `syscall`/`sysenter`
/// instruction instead of through `ntdll.dll`, it bypasses usermode EDR
/// hooks. This struct captures per-thread syscall metadata that reveals
/// such bypass techniques (SysWhispers, HellsGate, Halo's Gate, Heaven's Gate).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DirectSyscallInfo {
    /// Process ID of the owning process.
    pub pid: u32,
    /// Image name of the owning process.
    pub process_name: String,
    /// Thread ID that performed the syscall.
    pub thread_id: u32,
    /// Virtual address of the syscall/sysenter instruction.
    pub syscall_address: u64,
    /// NT syscall number (SSN).
    pub syscall_number: u32,
    /// Technique identifier (e.g., `"direct_syscall"`, `"indirect_syscall"`,
    /// `"heavens_gate"`).
    pub technique: String,
    /// Whether the syscall instruction resides within ntdll.dll's address range.
    pub in_ntdll: bool,
    /// Whether this syscall invocation is considered suspicious.
    pub is_suspicious: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_state_from_raw() {
        assert_eq!(ThreadState::from_raw(0), ThreadState::Initialized);
        assert_eq!(ThreadState::from_raw(1), ThreadState::Ready);
        assert_eq!(ThreadState::from_raw(2), ThreadState::Running);
        assert_eq!(ThreadState::from_raw(3), ThreadState::Standby);
        assert_eq!(ThreadState::from_raw(4), ThreadState::Terminated);
        assert_eq!(ThreadState::from_raw(5), ThreadState::Waiting);
        assert_eq!(ThreadState::from_raw(6), ThreadState::Transition);
        assert_eq!(ThreadState::from_raw(7), ThreadState::DeferredReady);
        assert_eq!(ThreadState::from_raw(8), ThreadState::GateWaitObsolete);
        assert_eq!(
            ThreadState::from_raw(9),
            ThreadState::WaitingForProcessInSwap
        );
        assert_eq!(ThreadState::from_raw(42), ThreadState::Unknown(42));
        assert_eq!(ThreadState::from_raw(255), ThreadState::Unknown(255));
    }

    #[test]
    fn thread_state_display() {
        assert_eq!(ThreadState::Initialized.to_string(), "Initialized");
        assert_eq!(ThreadState::Ready.to_string(), "Ready");
        assert_eq!(ThreadState::Running.to_string(), "Running");
        assert_eq!(ThreadState::Standby.to_string(), "Standby");
        assert_eq!(ThreadState::Terminated.to_string(), "Terminated");
        assert_eq!(ThreadState::Waiting.to_string(), "Waiting");
        assert_eq!(ThreadState::Transition.to_string(), "Transition");
        assert_eq!(ThreadState::DeferredReady.to_string(), "DeferredReady");
        assert_eq!(
            ThreadState::GateWaitObsolete.to_string(),
            "GateWaitObsolete"
        );
        assert_eq!(
            ThreadState::WaitingForProcessInSwap.to_string(),
            "WaitingForProcessInSwap"
        );
        assert_eq!(ThreadState::Unknown(99).to_string(), "Unknown(99)");
    }

    #[test]
    fn tcp_state_from_raw_values() {
        assert_eq!(WinTcpState::from_raw(1), WinTcpState::Closed);
        assert_eq!(WinTcpState::from_raw(2), WinTcpState::Listen);
        assert_eq!(WinTcpState::from_raw(3), WinTcpState::SynSent);
        assert_eq!(WinTcpState::from_raw(4), WinTcpState::SynReceived);
        assert_eq!(WinTcpState::from_raw(5), WinTcpState::Established);
        assert_eq!(WinTcpState::from_raw(6), WinTcpState::FinWait1);
        assert_eq!(WinTcpState::from_raw(7), WinTcpState::FinWait2);
        assert_eq!(WinTcpState::from_raw(8), WinTcpState::CloseWait);
        assert_eq!(WinTcpState::from_raw(9), WinTcpState::Closing);
        assert_eq!(WinTcpState::from_raw(10), WinTcpState::LastAck);
        assert_eq!(WinTcpState::from_raw(11), WinTcpState::TimeWait);
        assert_eq!(WinTcpState::from_raw(12), WinTcpState::DeleteTcb);
        assert_eq!(WinTcpState::from_raw(42), WinTcpState::Unknown(42));
        assert_eq!(WinTcpState::from_raw(0), WinTcpState::Unknown(0));
    }

    #[test]
    fn tcp_state_display_strings() {
        assert_eq!(WinTcpState::Closed.to_string(), "CLOSED");
        assert_eq!(WinTcpState::Listen.to_string(), "LISTENING");
        assert_eq!(WinTcpState::SynSent.to_string(), "SYN_SENT");
        assert_eq!(WinTcpState::SynReceived.to_string(), "SYN_RCVD");
        assert_eq!(WinTcpState::Established.to_string(), "ESTABLISHED");
        assert_eq!(WinTcpState::FinWait1.to_string(), "FIN_WAIT1");
        assert_eq!(WinTcpState::FinWait2.to_string(), "FIN_WAIT2");
        assert_eq!(WinTcpState::CloseWait.to_string(), "CLOSE_WAIT");
        assert_eq!(WinTcpState::Closing.to_string(), "CLOSING");
        assert_eq!(WinTcpState::LastAck.to_string(), "LAST_ACK");
        assert_eq!(WinTcpState::TimeWait.to_string(), "TIME_WAIT");
        assert_eq!(WinTcpState::DeleteTcb.to_string(), "DELETE_TCB");
        assert_eq!(WinTcpState::Unknown(99).to_string(), "Unknown(99)");
    }

    #[test]
    fn dns_record_type_from_raw() {
        assert_eq!(DnsRecordType::from_raw(1), DnsRecordType::A);
        assert_eq!(DnsRecordType::from_raw(28), DnsRecordType::Aaaa);
        assert_eq!(DnsRecordType::from_raw(5), DnsRecordType::Cname);
        assert_eq!(DnsRecordType::from_raw(12), DnsRecordType::Ptr);
        assert_eq!(DnsRecordType::from_raw(15), DnsRecordType::Mx);
        assert_eq!(DnsRecordType::from_raw(33), DnsRecordType::Srv);
        assert_eq!(DnsRecordType::from_raw(6), DnsRecordType::Soa);
        assert_eq!(DnsRecordType::from_raw(2), DnsRecordType::Ns);
        assert_eq!(DnsRecordType::from_raw(16), DnsRecordType::Txt);
        assert_eq!(DnsRecordType::from_raw(999), DnsRecordType::Unknown(999));
    }

    #[test]
    fn dns_record_type_display() {
        assert_eq!(DnsRecordType::A.to_string(), "A");
        assert_eq!(DnsRecordType::Aaaa.to_string(), "AAAA");
        assert_eq!(DnsRecordType::Cname.to_string(), "CNAME");
        assert_eq!(DnsRecordType::Ptr.to_string(), "PTR");
        assert_eq!(DnsRecordType::Mx.to_string(), "MX");
        assert_eq!(DnsRecordType::Srv.to_string(), "SRV");
        assert_eq!(DnsRecordType::Soa.to_string(), "SOA");
        assert_eq!(DnsRecordType::Ns.to_string(), "NS");
        assert_eq!(DnsRecordType::Txt.to_string(), "TXT");
        assert_eq!(DnsRecordType::Unknown(42).to_string(), "Unknown(42)");
    }
}
