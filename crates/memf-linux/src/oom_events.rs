//! OOM (Out-of-Memory) kill event recovery from the kernel log buffer.
//!
//! Scans the `__log_buf` printk ring buffer for OOM kill messages
//! ("Out of memory: Killed process") and extracts structured event info.
//! Events that killed security/monitoring processes are flagged as suspicious.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about an OOM kill event recovered from kernel logs.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OomEventInfo {
    /// PID of the process that was OOM-killed.
    pub victim_pid: u32,
    /// Command name of the killed process.
    pub victim_comm: String,
    /// OOM score adjustment at time of kill.
    pub oom_score_adj: i16,
    /// Total virtual memory in kilobytes.
    pub total_vm_kb: u64,
    /// Resident set size in kilobytes.
    pub rss_kb: u64,
    /// Timestamp in nanoseconds from the printk record.
    pub timestamp_ns: u64,
    /// Source of the OOM event (e.g. "oom_kill_process", "mem_cgroup_oom").
    pub reason: String,
    /// True when the victim is a security/monitoring process or has PID < 100.
    pub is_suspicious: bool,
}

/// Well-known process names whose OOM-death is considered suspicious.
const SUSPICIOUS_PROCESS_NAMES: &[&str] = &[
    "auditd",
    "sshd",
    "systemd",
    "journald",
    "rsyslogd",
    "containerd",
    "dockerd",
];

/// Classify whether an OOM kill event is suspicious.
///
/// Suspicious when the victim command matches a security/monitoring daemon
/// name, or the victim PID is below 100 (likely a critical system process).
pub fn classify_oom_victim(comm: &str, pid: u32) -> bool {
    let lower = comm.to_ascii_lowercase();
    SUSPICIOUS_PROCESS_NAMES.iter().any(|n| lower.contains(n)) || pid < 100
}

/// Parse a single OOM kill log line and return `(pid, comm, oom_score_adj, total_vm_kb, rss_kb)`.
///
/// Expected format (kernel 4.x+):
/// `Out of memory: Killed process 1234 (comm) score 567 total-vm:89012kB, anon-rss:12345kB, ...`
fn parse_oom_line(line: &str) -> Option<(u32, String, i16, u64, u64)> {
    if !line.contains("Out of memory: Kill") {
        return None;
    }

    // Extract PID: "process <pid> "
    let pid = {
        let marker = "process ";
        let start = line.find(marker)? + marker.len();
        let end = line[start..].find(' ')? + start;
        line[start..end].trim().parse::<u32>().ok()?
    };

    // Extract comm: parenthesised token after the PID.
    let comm = {
        let needle = format!("{pid} (");
        let after_pid = line.find(&needle)?;
        let paren_start = after_pid + needle.len();
        let paren_end = paren_start + line[paren_start..].find(')')?;
        line[paren_start..paren_end].to_string()
    };

    // Extract oom_score_adj proxy from "score <n>".
    let score_adj: i16 = if let Some(pos) = line.find("score ") {
        let s = pos + "score ".len();
        let e = s + line[s..]
            .find(|c: char| !c.is_ascii_digit() && c != '-')
            .unwrap_or(0);
        line[s..e].trim().parse::<i16>().unwrap_or(0)
    } else {
        0
    };

    let total_vm_kb = extract_kb(line, "total-vm:");
    let rss_kb = extract_kb(line, "anon-rss:");

    Some((pid, comm, score_adj, total_vm_kb, rss_kb))
}

/// Extract a `<label><value>kB` numeric value from a log line.
fn extract_kb(line: &str, label: &str) -> u64 {
    let pos = match line.find(label) {
        Some(p) => p + label.len(),
        None => return 0,
    };
    let end = line[pos..]
        .find(|c: char| !c.is_ascii_digit())
        .map(|e| pos + e)
        .unwrap_or(line.len());
    line[pos..end].trim().parse::<u64>().unwrap_or(0)
}

/// Maximum number of kmsg records to scan (runaway protection).
const MAX_RECORDS: usize = 8192;
/// Maximum kmsg ring buffer size to read.
const MAX_BUF_LEN: usize = 1 << 18; // 256 KiB

/// Walk the kernel log ring buffer for OOM kill events.
///
/// Returns `Ok(Vec::new())` when the `__log_buf` symbol is absent (graceful
/// degradation — mirrors the pattern used in `kmsg.rs`).
pub fn walk_oom_events<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<OomEventInfo>> {
    let buf_addr = match reader.symbols().symbol_address("__log_buf") {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };

    // Read log_buf_len if available; default to 4096.
    let buf_len: usize = reader
        .symbols()
        .symbol_address("log_buf_len")
        .and_then(|a| {
            reader
                .read_bytes(a, 4)
                .ok()
                .and_then(|b| b.try_into().ok())
                .map(u32::from_le_bytes)
                .map(|v| v as usize)
        })
        .unwrap_or(4096)
        .min(MAX_BUF_LEN);

    let raw = match reader.read_bytes(buf_addr, buf_len) {
        Ok(b) => b,
        Err(_) => return Ok(Vec::new()),
    };

    let mut results = Vec::new();
    let mut offset = 0usize;
    let mut record_count = 0usize;

    while offset + 16 <= raw.len() && record_count < MAX_RECORDS {
        // printk_log header (kernel 3.x+):
        //  u64 ts_nsec     @ 0
        //  u16 len         @ 8
        //  u16 text_len    @ 10
        //  u16 dict_len    @ 12
        //  u8  facility    @ 14
        //  u8  flags_level @ 15
        let ts_nsec = u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap());
        let len = u16::from_le_bytes(raw[offset + 8..offset + 10].try_into().unwrap()) as usize;
        let text_len =
            u16::from_le_bytes(raw[offset + 10..offset + 12].try_into().unwrap()) as usize;

        if len == 0 || offset + len > raw.len() {
            break;
        }

        let text_start = offset + 16;
        if text_start + text_len <= raw.len() {
            let text = std::str::from_utf8(&raw[text_start..text_start + text_len])
                .unwrap_or("")
                .trim_end_matches('\0');

            if let Some((pid, comm, score_adj, total_vm_kb, rss_kb)) = parse_oom_line(text) {
                let is_suspicious = classify_oom_victim(&comm, pid);
                let reason = if text.contains("memory cgroup") || text.contains("mem_cgroup") {
                    "mem_cgroup_oom".to_string()
                } else {
                    "oom_kill_process".to_string()
                };
                results.push(OomEventInfo {
                    victim_pid: pid,
                    victim_comm: comm,
                    oom_score_adj: score_adj,
                    total_vm_kb,
                    rss_kb,
                    timestamp_ns: ts_nsec,
                    reason,
                    is_suspicious,
                });
            }
        }

        offset += len;
        record_count += 1;
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_no_symbol_reader() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn classify_oom_kill_of_auditd_suspicious() {
        assert!(
            classify_oom_victim("auditd", 1234),
            "OOM kill of auditd must be suspicious"
        );
    }

    #[test]
    fn classify_oom_kill_of_sshd_suspicious() {
        assert!(
            classify_oom_victim("sshd", 500),
            "OOM kill of sshd must be suspicious"
        );
    }

    #[test]
    fn classify_oom_kill_of_low_pid_suspicious() {
        assert!(
            classify_oom_victim("kworker", 42),
            "OOM kill of PID < 100 must be suspicious"
        );
    }

    #[test]
    fn classify_oom_kill_of_user_process_benign() {
        assert!(
            !classify_oom_victim("chrome", 9999),
            "OOM kill of a regular user process must not be suspicious"
        );
    }

    #[test]
    fn classify_oom_kill_of_containerd_suspicious() {
        assert!(
            classify_oom_victim("containerd", 2000),
            "OOM kill of containerd must be suspicious"
        );
    }

    #[test]
    fn parse_oom_line_extracts_pid_and_comm() {
        let line = "Out of memory: Killed process 4321 (myapp) score 100 total-vm:204800kB, anon-rss:102400kB, file-rss:0kB";
        let (pid, comm, _score, total_vm, rss) = parse_oom_line(line).unwrap();
        assert_eq!(pid, 4321);
        assert_eq!(comm, "myapp");
        assert_eq!(total_vm, 204800);
        assert_eq!(rss, 102400);
    }

    #[test]
    fn parse_oom_line_returns_none_for_non_oom() {
        assert!(parse_oom_line("normal kernel log message").is_none());
    }

    #[test]
    fn walk_oom_events_no_symbol_returns_empty() {
        let reader = make_no_symbol_reader();
        let result = walk_oom_events(&reader).unwrap();
        assert!(
            result.is_empty(),
            "no __log_buf symbol → empty vec expected"
        );
    }
}
