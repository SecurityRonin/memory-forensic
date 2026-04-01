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
}
