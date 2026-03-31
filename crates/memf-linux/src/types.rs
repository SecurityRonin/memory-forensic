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

#[cfg(test)]
mod tests {
    use super::*;

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
}
