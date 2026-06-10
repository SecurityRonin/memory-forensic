//! Library prevalence analysis for LD_PRELOAD rootkit detection.

/// A shared library and how widely it is mapped across processes — the core
/// signal for LD_PRELOAD-style rootkit detection: a malicious preload is injected
/// into *every* process, so an unusually high prevalence is suspicious.
#[derive(Debug)]
pub struct GloballyLoadedLibrary {
    /// Filesystem path of the shared object (e.g. `/usr/lib/evil.so`).
    pub path: String,
    /// Number of inspected PIDs that have this library mapped.
    pub present_in_pid_count: usize,
    /// Total number of PIDs inspected (the prevalence denominator).
    pub total_pids_checked: usize,
    /// Fraction of inspected processes mapping this library, in `[0.0, 1.0]`.
    pub prevalence: f64,
    /// Optional ELF capability analysis of the library, when available.
    pub elf_report: Option<crate::elf_analysis::ElfCapabilityReport>,
}

/// One row of Volatility's `linux.elfs` output — a memory-mapped ELF image in a
/// process, used as an alternative prevalence source to `/proc/<pid>/maps`.
#[derive(Debug, Clone)]
pub struct VolatilityElfEntry {
    /// Owning process id.
    pub pid: u32,
    /// Owning process name.
    pub process_name: String,
    /// Mapping start virtual address.
    pub start: u64,
    /// Mapping end virtual address.
    pub end: u64,
    /// Filesystem path of the mapped ELF image.
    pub path: String,
}

/// Rank shared objects by how many inspected processes map them, keeping only
/// `.so` libraries whose prevalence meets `threshold` — the LD_PRELOAD candidates.
pub fn find_globally_loaded_libraries(
    proc_maps: &[(u32, Vec<String>)],
    threshold: f64,
) -> Vec<GloballyLoadedLibrary> {
    use std::collections::HashMap;
    let total = proc_maps.len();
    if total == 0 {
        return vec![];
    }
    let mut counts: HashMap<String, usize> = HashMap::new();
    for (_, paths) in proc_maps {
        let unique: std::collections::HashSet<&str> = paths.iter().map(String::as_str).collect();
        for p in unique {
            *counts.entry(p.to_string()).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .filter(|(path, count)| {
            (path.ends_with(".so") || path.contains(".so."))
                && (*count as f64 / total as f64) >= threshold
        })
        .map(|(path, count)| {
            let prevalence = count as f64 / total as f64;
            GloballyLoadedLibrary {
                path,
                present_in_pid_count: count,
                total_pids_checked: total,
                prevalence,
                elf_report: None,
            }
        })
        .collect()
}

/// Parse Volatility `linux.elfs` TSV output into [`VolatilityElfEntry`] rows
/// (skips the header and blank/comment lines; tolerant of short rows).
pub fn parse_linux_elfs_tsv(content: &str) -> Vec<VolatilityElfEntry> {
    content
        .lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|line| {
            let cols: Vec<&str> = line.splitn(5, '\t').collect();
            if cols.len() < 5 {
                return None;
            }
            Some(VolatilityElfEntry {
                pid: cols[0].trim().parse().ok()?,
                process_name: cols[1].trim().to_string(),
                start: u64::from_str_radix(cols[2].trim().trim_start_matches("0x"), 16).ok()?,
                end: u64::from_str_radix(cols[3].trim().trim_start_matches("0x"), 16).ok()?,
                path: cols[4].trim().to_string(),
            })
        })
        .collect()
}

/// Prevalence ranking from [`VolatilityElfEntry`] rows: each path's fraction of
/// distinct PIDs mapping it, filtered by `threshold`. Returns `(path, prevalence)`.
pub fn find_globally_loaded_from_elfs(
    entries: &[VolatilityElfEntry],
    threshold: f64,
) -> Vec<(String, f64)> {
    use std::collections::HashMap;
    let mut pid_sets: HashMap<&str, std::collections::HashSet<u32>> = HashMap::new();
    for e in entries {
        pid_sets.entry(&e.path).or_default().insert(e.pid);
    }
    let total_pids: std::collections::HashSet<u32> = entries.iter().map(|e| e.pid).collect();
    let n = total_pids.len() as f64;
    if n == 0.0 {
        return vec![];
    }
    let mut result: Vec<(String, f64)> = pid_sets
        .into_iter()
        .filter_map(|(path, pids)| {
            let prevalence = pids.len() as f64 / n;
            if prevalence >= threshold {
                Some((path.to_string(), prevalence))
            } else {
                None
            }
        })
        .collect();
    result.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_globally_loaded_empty_input_returns_empty() {
        let result = find_globally_loaded_libraries(&[], 0.9);
        assert!(result.is_empty());
    }

    #[test]
    fn find_globally_loaded_library_in_all_pids_found() {
        let maps = vec![
            (1u32, vec!["/lib/evil.so".to_string(), "/lib/libc.so.6".to_string()]),
            (2u32, vec!["/lib/evil.so".to_string(), "/lib/libc.so.6".to_string()]),
            (3u32, vec!["/lib/evil.so".to_string(), "/lib/libpthread.so.0".to_string()]),
        ];
        let result = find_globally_loaded_libraries(&maps, 1.0);
        let paths: Vec<&str> = result.iter().map(|l| l.path.as_str()).collect();
        assert!(paths.contains(&"/lib/evil.so"), "evil.so present in all pids should be found");
    }

    #[test]
    fn find_globally_loaded_library_in_half_pids_below_threshold() {
        let maps = vec![
            (1u32, vec!["/lib/half.so".to_string()]),
            (2u32, vec!["/lib/other.so".to_string()]),
        ];
        // 50% prevalence should be excluded at threshold=0.9
        let result = find_globally_loaded_libraries(&maps, 0.9);
        let paths: Vec<&str> = result.iter().map(|l| l.path.as_str()).collect();
        assert!(!paths.contains(&"/lib/half.so"), "half.so at 50% should not pass 90% threshold");
    }

    #[test]
    fn find_globally_loaded_respects_threshold_parameter() {
        let maps = vec![
            (1u32, vec!["/lib/half.so".to_string()]),
            (2u32, vec!["/lib/half.so".to_string()]),
            (3u32, vec!["/lib/other.so".to_string()]),
            (4u32, vec!["/lib/other.so".to_string()]),
        ];
        // 50% threshold → both should appear (half.so in 50% of pids)
        let result = find_globally_loaded_libraries(&maps, 0.5);
        assert!(!result.is_empty(), "at 50% threshold, libraries at 50% prevalence should appear");
        let result_75 = find_globally_loaded_libraries(&maps, 0.75);
        let paths_75: Vec<&str> = result_75.iter().map(|l| l.path.as_str()).collect();
        assert!(!paths_75.contains(&"/lib/half.so"), "at 75% threshold, 50% library should be excluded");
    }

    #[test]
    fn parse_linux_elfs_tsv_empty_returns_empty() {
        assert!(parse_linux_elfs_tsv("").is_empty());
    }

    #[test]
    fn parse_linux_elfs_tsv_parses_pid_and_path() {
        let tsv = "PID\tProcess\tStart\tEnd\tFile\n\
                   1234\tbash\t0x7f000000\t0x7f001000\t/lib/evil.so\n";
        let entries = parse_linux_elfs_tsv(tsv);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].pid, 1234);
        assert_eq!(entries[0].path, "/lib/evil.so");
        assert_eq!(entries[0].process_name, "bash");
    }

    #[test]
    fn parse_linux_elfs_tsv_skips_header_line() {
        let tsv = "PID\tProcess\tStart\tEnd\tFile\n";
        let entries = parse_linux_elfs_tsv(tsv);
        assert!(entries.is_empty(), "header-only TSV should parse to empty vec");
    }

    #[test]
    fn parse_linux_elfs_tsv_handles_hex_addresses() {
        let tsv = "PID\tProcess\tStart\tEnd\tFile\n\
                   42\tinit\t0xdeadbeef\t0xdeadc0de\t/lib/x.so\n";
        let entries = parse_linux_elfs_tsv(tsv);
        assert_eq!(entries[0].start, 0xdeadbeef);
        assert_eq!(entries[0].end, 0xdeadc0de);
    }

    #[test]
    fn find_globally_loaded_from_elfs_library_in_all_pids() {
        let entries = vec![
            VolatilityElfEntry { pid: 1, process_name: "a".into(), start: 0, end: 0, path: "/lib/evil.so".into() },
            VolatilityElfEntry { pid: 2, process_name: "b".into(), start: 0, end: 0, path: "/lib/evil.so".into() },
            VolatilityElfEntry { pid: 3, process_name: "c".into(), start: 0, end: 0, path: "/lib/evil.so".into() },
        ];
        let result = find_globally_loaded_from_elfs(&entries, 1.0);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "/lib/evil.so");
        assert!((result[0].1 - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn find_globally_loaded_from_elfs_sorted_by_prevalence() {
        let entries = vec![
            VolatilityElfEntry { pid: 1, process_name: "a".into(), start: 0, end: 0, path: "/lib/always.so".into() },
            VolatilityElfEntry { pid: 2, process_name: "b".into(), start: 0, end: 0, path: "/lib/always.so".into() },
            VolatilityElfEntry { pid: 1, process_name: "a".into(), start: 0, end: 0, path: "/lib/sometimes.so".into() },
        ];
        let result = find_globally_loaded_from_elfs(&entries, 0.1);
        assert!(result.len() >= 2, "both libraries should appear at 10% threshold");
        // Sorted descending: always.so (100%) before sometimes.so (50%)
        assert_eq!(result[0].0, "/lib/always.so");
    }
}
