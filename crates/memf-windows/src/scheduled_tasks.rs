//! Windows scheduled task persistence detection.
//!
//! Scheduled tasks are a common persistence mechanism — malware creates tasks
//! that survive reboot via `schtasks.exe` or COM-based APIs. The Task Scheduler
//! service stores task definitions in `_TASK_ENTRY` structures accessible
//! through the `TaskSchedulerService` or `ubpm` kernel objects.
//!
//! Enumerating scheduled tasks from memory captures tasks that may have been
//! deleted from disk but remain in the service's in-memory cache.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;

/// Maximum number of scheduled task entries to walk (safety limit).
const MAX_TASKS: usize = 4096;

/// Information about a scheduled task recovered from kernel memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScheduledTaskInfo {
    /// Task name (e.g., "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan").
    pub name: String,
    /// Task path in the Task Scheduler namespace.
    pub path: String,
    /// Action command line (what the task executes).
    pub action: String,
    /// Task author.
    pub author: String,
    /// Whether the task is currently enabled.
    pub enabled: bool,
    /// Last run time (FILETIME).
    pub last_run_time: u64,
    /// Next run time (FILETIME).
    pub next_run_time: u64,
    /// Whether this task looks suspicious.
    pub is_suspicious: bool,
}

/// Classify a scheduled task as suspicious.
///
/// Returns `true` for tasks that match patterns commonly used for persistence:
/// - Action contains encoded commands (powershell -enc, cmd /c)
/// - Task in unusual paths (not under \Microsoft\Windows)
/// - Action references temp directories or user-writable locations
pub fn classify_scheduled_task(name: &str, action: &str) -> bool {
    if name.is_empty() || action.is_empty() {
        return false;
    }

    let action_lower = action.to_ascii_lowercase();

    // Encoded/obfuscated commands
    if action_lower.contains("-enc") || action_lower.contains("-encodedcommand") {
        return true;
    }

    // Commands from suspicious locations
    if action_lower.contains("\\temp\\")
        || action_lower.contains("\\tmp\\")
        || action_lower.contains("\\appdata\\")
        || action_lower.contains("\\downloads\\")
        || action_lower.contains("\\public\\")
    {
        return true;
    }

    // Known suspicious patterns
    if action_lower.contains("mshta") || action_lower.contains("regsvr32 /s /n /u /i:") {
        return true;
    }

    // Task in non-standard path with script execution
    let name_lower = name.to_ascii_lowercase();
    if !name_lower.starts_with("\\microsoft\\") && !name_lower.starts_with("microsoft\\") {
        if action_lower.contains("powershell")
            || action_lower.contains("wscript")
            || action_lower.contains("cscript")
        {
            return true;
        }
    }

    false
}

/// Enumerate scheduled tasks from the Task Scheduler service memory.
///
/// Looks up `UbpmTaskEnumerator` or `TaskSchedulerService` to find
/// in-memory task definitions. Returns an empty `Vec` if the required
/// symbols are not present.
pub fn walk_scheduled_tasks<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
) -> crate::Result<Vec<ScheduledTaskInfo>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    /// No scheduled task symbol → empty Vec.
    #[test]
    fn walk_scheduled_tasks_no_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("_TASK_ENTRY", 0x80)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_scheduled_tasks(&reader).unwrap();
        assert!(result.is_empty());
    }

    /// Benign Microsoft tasks are not suspicious.
    #[test]
    fn classify_benign_microsoft_task() {
        assert!(!classify_scheduled_task(
            "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan",
            "C:\\Windows\\System32\\usoclient.exe StartScan"
        ));
    }

    /// Tasks with encoded PowerShell commands are suspicious.
    #[test]
    fn classify_suspicious_encoded_command() {
        assert!(classify_scheduled_task(
            "\\CustomTask",
            "powershell.exe -enc ZQBjAGgAbwAgACIAaABlAGwAbABvACIA"
        ));
    }

    /// Tasks executing from temp directories are suspicious.
    #[test]
    fn classify_suspicious_temp_path() {
        assert!(classify_scheduled_task(
            "\\Microsoft\\Windows\\MyTask",
            "C:\\Users\\admin\\AppData\\Local\\Temp\\malware.exe"
        ));
    }

    /// Non-Microsoft tasks running PowerShell are suspicious.
    #[test]
    fn classify_suspicious_nonstandard_powershell() {
        assert!(classify_scheduled_task(
            "\\UpdateChecker",
            "powershell.exe -File C:\\Scripts\\update.ps1"
        ));
    }

    /// Empty name or action is not suspicious.
    #[test]
    fn classify_empty_not_suspicious() {
        assert!(!classify_scheduled_task("", ""));
        assert!(!classify_scheduled_task("\\Task", ""));
        assert!(!classify_scheduled_task("", "cmd.exe"));
    }
}
