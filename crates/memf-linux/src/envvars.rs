//! Linux process environment variable walker.
//!
//! Reads environment variables from `mm_struct.env_start`..`env_end`
//! for each process. The environment region contains null-separated
//! `KEY=VALUE\0` strings. Requires that the memory pages are accessible
//! through the ObjectReader's VAS (typically the process's own CR3).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{EnvVarInfo, Error, Result};

/// Maximum environment region size to read (256 KiB safety limit).
const MAX_ENV_SIZE: u64 = 256 * 1024;

/// Walk environment variables for all processes in the task list.
pub fn walk_envvars<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<EnvVarInfo>> {
    let init_task_addr = reader
        .symbols()
        .symbol_address("init_task")
        .ok_or_else(|| Error::Walker("symbol 'init_task' not found".into()))?;

    let tasks_offset = reader
        .symbols()
        .field_offset("task_struct", "tasks")
        .ok_or_else(|| Error::Walker("task_struct.tasks field not found".into()))?;

    let head_vaddr = init_task_addr + tasks_offset;
    let task_addrs = reader.walk_list(head_vaddr, "task_struct", "tasks")?;

    let mut all_vars = Vec::new();

    collect_process_envvars(reader, init_task_addr, &mut all_vars);

    for &task_addr in &task_addrs {
        collect_process_envvars(reader, task_addr, &mut all_vars);
    }

    Ok(all_vars)
}

fn collect_process_envvars<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
    out: &mut Vec<EnvVarInfo>,
) {
    let mm_ptr: u64 = match reader.read_field(task_addr, "task_struct", "mm") {
        Ok(v) => v,
        Err(_) => return,
    };
    if mm_ptr == 0 {
        return;
    }

    if let Ok(vars) = walk_process_envvars(reader, task_addr) {
        out.extend(vars);
    }
}

/// Walk environment variables for a single process.
pub fn walk_process_envvars<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
) -> Result<Vec<EnvVarInfo>> {
    let pid: u32 = reader.read_field(task_addr, "task_struct", "pid")?;
    let comm = reader.read_field_string(task_addr, "task_struct", "comm", 16)?;
    let mm_ptr: u64 = reader.read_field(task_addr, "task_struct", "mm")?;

    if mm_ptr == 0 {
        return Err(Error::Walker(format!(
            "task {comm} (PID {pid}) has NULL mm (kernel thread)"
        )));
    }

    let env_start: u64 = reader.read_field(mm_ptr, "mm_struct", "env_start")?;
    let env_end: u64 = reader.read_field(mm_ptr, "mm_struct", "env_end")?;

    if env_start == 0 || env_end <= env_start {
        return Ok(Vec::new());
    }

    let size = (env_end - env_start).min(MAX_ENV_SIZE);
    let data = reader.read_bytes(env_start, size as usize)?;

    Ok(parse_env_region(&data, u64::from(pid), &comm))
}

fn parse_env_region(data: &[u8], pid: u64, comm: &str) -> Vec<EnvVarInfo> {
    let mut vars = Vec::new();

    for chunk in data.split(|&b| b == 0) {
        if chunk.is_empty() {
            continue;
        }
        let s = String::from_utf8_lossy(chunk);
        if let Some(eq_pos) = s.find('=') {
            let key = s[..eq_pos].to_string();
            let value = s[eq_pos + 1..].to_string();
            vars.push(EnvVarInfo {
                pid,
                comm: comm.to_string(),
                key,
                value,
            });
        }
    }

    vars
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_test_reader(
        data: &[u8],
        vaddr: u64,
        paddr: u64,
        extra_mappings: &[(u64, u64, &[u8])],
    ) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "state", 4, "long")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "mm", 48, "pointer")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_struct("mm_struct", 128)
            .add_field("mm_struct", "pgd", 0, "pointer")
            .add_field("mm_struct", "env_start", 64, "unsigned long")
            .add_field("mm_struct", "env_end", 72, "unsigned long")
            .add_symbol("init_task", vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let mut builder = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, data);

        for &(ev, ep, edata) in extra_mappings {
            builder = builder
                .map_4k(ev, ep, flags::WRITABLE)
                .write_phys(ep, edata);
        }

        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn walk_single_process_envvars() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..36].copy_from_slice(b"bash");
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes());

        let env_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let env_paddr: u64 = 0x0090_0000;
        data[0x200..0x208].copy_from_slice(&0x1000u64.to_le_bytes());
        data[0x240..0x248].copy_from_slice(&env_vaddr.to_le_bytes());
        let env_data = b"HOME=/root\0PATH=/usr/bin:/bin\0SHELL=/bin/bash\0";
        let env_end = env_vaddr + env_data.len() as u64;
        data[0x248..0x250].copy_from_slice(&env_end.to_le_bytes());

        let reader = make_test_reader(
            &data,
            vaddr,
            paddr,
            &[(env_vaddr, env_paddr, env_data.as_slice())],
        );
        let vars = walk_envvars(&reader).unwrap();

        assert_eq!(vars.len(), 3);
        assert_eq!(vars[0].pid, 1);
        assert_eq!(vars[0].comm, "bash");
        assert_eq!(vars[0].key, "HOME");
        assert_eq!(vars[0].value, "/root");
        assert_eq!(vars[1].key, "PATH");
        assert_eq!(vars[1].value, "/usr/bin:/bin");
        assert_eq!(vars[2].key, "SHELL");
        assert_eq!(vars[2].value, "/bin/bash");
    }

    #[test]
    fn walk_envvars_skips_kernel_threads() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..41].copy_from_slice(b"swapper/0");
        data[48..56].copy_from_slice(&0u64.to_le_bytes());

        let reader = make_test_reader(&data, vaddr, paddr, &[]);
        let vars = walk_envvars(&reader).unwrap();
        assert!(vars.is_empty());
    }

    #[test]
    fn walk_process_envvars_null_mm_returns_error() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        data[48..56].copy_from_slice(&0u64.to_le_bytes());

        let reader = make_test_reader(&data, vaddr, paddr, &[]);
        let result = walk_process_envvars(&reader, vaddr);
        assert!(result.is_err());
    }

    #[test]
    fn parse_env_region_handles_malformed_entries() {
        let data = b"GOOD=value\0MALFORMED\0ALSO_GOOD=ok\0";
        let vars = parse_env_region(data, 1, "test");

        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0].key, "GOOD");
        assert_eq!(vars[0].value, "value");
        assert_eq!(vars[1].key, "ALSO_GOOD");
        assert_eq!(vars[1].value, "ok");
    }

    #[test]
    fn parse_env_region_empty() {
        let vars = parse_env_region(&[], 1, "test");
        assert!(vars.is_empty());
    }

    #[test]
    fn missing_init_task_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 64)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 8, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_envvars(&reader);
        assert!(result.is_err());
    }
}
