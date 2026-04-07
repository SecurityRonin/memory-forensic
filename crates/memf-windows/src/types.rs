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
#[derive(Debug, Clone)]
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

/// Process token and privilege information.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
}
