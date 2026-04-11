//! Linux ptrace relationship detection for debugging/injection analysis.
//!
//! `ptrace` is the Linux debugging/tracing syscall. Attackers use it for
//! process injection (`PTRACE_POKETEXT`), anti-debugging (tracing themselves),
//! and credential theft (intercepting syscalls of privileged processes).
//!
//! This module detects active ptrace relationships by inspecting
//! `task_struct.ptrace` flags and comparing `parent` vs `real_parent`
//! pointers (ptrace reparents the tracee under the tracer).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{ProcessInfo, Result};

/// Well-known debugger/tracer binaries that are expected to ptrace.
const KNOWN_DEBUGGERS: &[&str] = &["gdb", "lldb", "strace", "ltrace", "valgrind", "perf"];

/// High-value target processes -- tracing these by a non-debugger is suspicious.
const HIGH_VALUE_TARGETS: &[&str] = &["sshd", "login", "passwd", "sudo", "su", "gpg-agent"];

/// A detected ptrace relationship between a tracer and a tracee process.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PtraceRelationship {
    pub tracer_pid: u32,
    pub tracer_name: String,
    pub tracee_pid: u32,
    pub tracee_name: String,
    pub is_suspicious: bool,
}

/// Classify whether a ptrace relationship is suspicious.
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

/// Scan for active ptrace relationships across the given process list.
pub fn scan_ptrace_relationships<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    processes: &[ProcessInfo],
) -> Result<Vec<PtraceRelationship>> {
    if processes.is_empty() {
        return Ok(Vec::new());
    }

    let mut results = Vec::new();

    for proc in processes {
        match read_ptrace_info(reader, proc) {
            Ok(Some(rel)) => results.push(rel),
            Ok(None) => continue,
            Err(_) => continue,
        }
    }

    Ok(results)
}

fn read_ptrace_info<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    proc: &ProcessInfo,
) -> Result<Option<PtraceRelationship>> {
    let ptrace_flags: u32 = reader.read_field(proc.vaddr, "task_struct", "ptrace")?;
    if ptrace_flags == 0 {
        return Ok(None);
    }

    let parent_ptr: u64 = reader.read_pointer(proc.vaddr, "task_struct", "parent")?;
    let real_parent_ptr: u64 = reader.read_pointer(proc.vaddr, "task_struct", "real_parent")?;

    if parent_ptr == real_parent_ptr || parent_ptr == 0 {
        return Ok(None);
    }

    let tracer_pid: u32 = reader.read_field::<u32>(parent_ptr, "task_struct", "pid")?;
    let tracer_name = reader.read_field_string(parent_ptr, "task_struct", "comm", 16)?;

    let tracee_name = proc.comm.clone();
    let is_suspicious = classify_ptrace(&tracer_name, &tracee_name);

    Ok(Some(PtraceRelationship {
        tracer_pid,
        tracer_name,
        tracee_pid: proc.pid as u32,
        tracee_name,
        is_suspicious,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::PageTableBuilder;
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_reader(
        isf: &IsfBuilder,
        builder: PageTableBuilder,
    ) -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let json = isf.build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();
        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[allow(dead_code)]
    fn fake_process(pid: u64, comm: &str, vaddr: u64) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: 1,
            comm: comm.to_string(),
            state: crate::types::ProcessState::Running,
            vaddr,
            cr3: None,
            start_time: 0,
        }
    }

    #[test]
    fn classify_gdb_tracing_anything_is_benign() {
        assert!(!classify_ptrace("gdb", "target_app"));
    }

    #[test]
    fn classify_strace_tracing_bash_is_benign() {
        assert!(!classify_ptrace("strace", "bash"));
    }

    #[test]
    fn classify_unknown_tracing_sshd_is_suspicious() {
        assert!(classify_ptrace("evil_inject", "sshd"));
    }

    #[test]
    fn classify_unknown_tracing_passwd_is_suspicious() {
        assert!(classify_ptrace("malware", "passwd"));
    }

    #[test]
    fn classify_self_tracing_by_non_debugger_is_suspicious() {
        assert!(classify_ptrace("sneaky", "sneaky"));
    }

    #[test]
    fn classify_empty_tracer_name_is_suspicious() {
        assert!(classify_ptrace("", "victim"));
    }

    #[test]
    fn classify_normal_process_tracing_normal_process_is_benign() {
        assert!(!classify_ptrace("my_app", "helper_proc"));
    }

    #[test]
    fn scan_ptrace_empty_processes_returns_empty_vec() {
        let isf = IsfBuilder::new();
        let ptb = PageTableBuilder::new();
        let reader = make_reader(&isf, ptb);

        let result = scan_ptrace_relationships(&reader, &[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn scan_ptrace_unreadable_task_struct_skips_process() {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 256)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "ptrace", 8, "unsigned int")
            .add_field("task_struct", "parent", 16, "pointer")
            .add_field("task_struct", "real_parent", 24, "pointer")
            .add_field("task_struct", "comm", 32, "char");
        let ptb = PageTableBuilder::new();
        let reader = make_reader(&isf, ptb);

        let proc = fake_process(100, "bash", 0xDEAD_0000_0000_0000);
        let result = scan_ptrace_relationships(&reader, &[proc]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn scan_ptrace_zero_ptrace_flags_skips_process() {
        use memf_core::test_builders::flags as ptf;

        let task_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let task_paddr: u64 = 0x0080_0000;

        let mut data = vec![0u8; 512];
        data[0..4].copy_from_slice(&200u32.to_le_bytes());
        data[8..12].copy_from_slice(&0u32.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 256)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "ptrace", 8, "unsigned int")
            .add_field("task_struct", "parent", 16, "pointer")
            .add_field("task_struct", "real_parent", 24, "pointer")
            .add_field("task_struct", "comm", 32, "char");
        let ptb = PageTableBuilder::new()
            .map_4k(task_vaddr, task_paddr, ptf::WRITABLE)
            .write_phys(task_paddr, &data);
        let reader = make_reader(&isf, ptb);

        let proc = fake_process(200, "bash", task_vaddr);
        let result = scan_ptrace_relationships(&reader, &[proc]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn classify_ptrace_lldb_is_benign() {
        assert!(!classify_ptrace("lldb", "target"));
    }

    #[test]
    fn classify_ptrace_ltrace_is_benign() {
        assert!(!classify_ptrace("ltrace", "any"));
    }

    #[test]
    fn classify_ptrace_valgrind_is_benign() {
        assert!(!classify_ptrace("valgrind", "leaky"));
    }

    #[test]
    fn classify_ptrace_perf_is_benign() {
        assert!(!classify_ptrace("perf", "app"));
    }

    #[test]
    fn classify_ptrace_unknown_tracing_login_suspicious() {
        assert!(classify_ptrace("injector", "login"));
    }

    #[test]
    fn classify_ptrace_unknown_tracing_sudo_suspicious() {
        assert!(classify_ptrace("spyware", "sudo"));
    }

    #[test]
    fn classify_ptrace_unknown_tracing_su_suspicious() {
        assert!(classify_ptrace("spyware", "su"));
    }

    #[test]
    fn classify_ptrace_unknown_tracing_gpg_agent_suspicious() {
        assert!(classify_ptrace("spyware", "gpg-agent"));
    }

    #[test]
    fn scan_ptrace_nonzero_flags_parent_equals_real_parent_skipped() {
        use memf_core::test_builders::flags as ptf;

        let task_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let task_paddr: u64 = 0x0090_0000;
        let parent_vaddr: u64 = 0xFFFF_8000_0030_0000;

        let mut data = vec![0u8; 512];
        data[8..12].copy_from_slice(&1u32.to_le_bytes());
        data[16..24].copy_from_slice(&parent_vaddr.to_le_bytes());
        data[24..32].copy_from_slice(&parent_vaddr.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 256)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "ptrace", 8, "unsigned int")
            .add_field("task_struct", "parent", 16, "pointer")
            .add_field("task_struct", "real_parent", 24, "pointer")
            .add_field("task_struct", "comm", 32, "char");
        let ptb = PageTableBuilder::new()
            .map_4k(task_vaddr, task_paddr, ptf::WRITABLE)
            .write_phys(task_paddr, &data);
        let reader = make_reader(&isf, ptb);

        let proc = fake_process(300, "victim", task_vaddr);
        let result = scan_ptrace_relationships(&reader, &[proc]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn scan_ptrace_nonzero_flags_parent_is_null_skipped() {
        use memf_core::test_builders::flags as ptf;

        let task_vaddr: u64 = 0xFFFF_8000_0040_0000;
        let task_paddr: u64 = 0x00A0_0000;

        let mut data = vec![0u8; 512];
        data[8..12].copy_from_slice(&1u32.to_le_bytes());
        data[16..24].copy_from_slice(&0u64.to_le_bytes());
        data[24..32].copy_from_slice(&0xFFFF_8000_0050_0000u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 256)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "ptrace", 8, "unsigned int")
            .add_field("task_struct", "parent", 16, "pointer")
            .add_field("task_struct", "real_parent", 24, "pointer")
            .add_field("task_struct", "comm", 32, "char");
        let ptb = PageTableBuilder::new()
            .map_4k(task_vaddr, task_paddr, ptf::WRITABLE)
            .write_phys(task_paddr, &data);
        let reader = make_reader(&isf, ptb);

        let proc = fake_process(400, "victim", task_vaddr);
        let result = scan_ptrace_relationships(&reader, &[proc]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn scan_ptrace_detects_reparented_tracer() {
        use memf_core::test_builders::flags as ptf;

        let tracee_vaddr: u64 = 0xFFFF_8000_0060_0000;
        let tracee_paddr: u64 = 0x00C0_0000;
        let tracer_vaddr: u64 = 0xFFFF_8000_0061_0000;
        let tracer_paddr: u64 = 0x00C1_0000;
        let real_parent_vaddr: u64 = 0xFFFF_8000_0062_0000;

        let mut tracee_data = vec![0u8; 512];
        tracee_data[0..4].copy_from_slice(&555u64.to_le_bytes()[..4]);
        tracee_data[8..12].copy_from_slice(&1u32.to_le_bytes());
        tracee_data[16..24].copy_from_slice(&tracer_vaddr.to_le_bytes());
        tracee_data[24..32].copy_from_slice(&real_parent_vaddr.to_le_bytes());
        tracee_data[32..36].copy_from_slice(b"sshd");

        let mut tracer_data = vec![0u8; 512];
        tracer_data[0..8].copy_from_slice(&777u64.to_le_bytes());
        tracer_data[32..40].copy_from_slice(b"injector");

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 256)
            .add_field("task_struct", "pid", 0, "long")
            .add_field("task_struct", "ptrace", 8, "unsigned int")
            .add_field("task_struct", "parent", 16, "pointer")
            .add_field("task_struct", "real_parent", 24, "pointer")
            .add_field("task_struct", "comm", 32, "char");

        let ptb = PageTableBuilder::new()
            .map_4k(tracee_vaddr, tracee_paddr, ptf::WRITABLE)
            .write_phys(tracee_paddr, &tracee_data)
            .map_4k(tracer_vaddr, tracer_paddr, ptf::WRITABLE)
            .write_phys(tracer_paddr, &tracer_data);

        let reader = make_reader(&isf, ptb);

        let proc = fake_process(555, "sshd", tracee_vaddr);
        let result = scan_ptrace_relationships(&reader, &[proc]).unwrap();

        assert_eq!(result.len(), 1, "reparenting detected → one relationship");
        let rel = &result[0];
        assert_eq!(rel.tracer_pid, 777);
        assert_eq!(rel.tracer_name, "injector");
        assert_eq!(rel.tracee_pid, 555);
        assert_eq!(rel.tracee_name, "sshd");
        assert!(rel.is_suspicious);
    }

    #[test]
    fn ptrace_relationship_serializes() {
        let rel = PtraceRelationship {
            tracer_pid: 42,
            tracer_name: "evil".to_string(),
            tracee_pid: 100,
            tracee_name: "sshd".to_string(),
            is_suspicious: true,
        };
        let json = serde_json::to_string(&rel).unwrap();
        assert!(json.contains("\"tracer_pid\":42"));
        assert!(json.contains("\"is_suspicious\":true"));
    }
}
