//! Linux process command line walker.
//!
//! Reads process command lines from `mm_struct.arg_start`..`arg_end`
//! for each process. The argument region contains null-separated argv
//! strings. Kernel threads (NULL mm) are silently skipped.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{CmdlineInfo, Error, Result};

/// Maximum argument region size to read (256 KiB safety limit).
const MAX_ARG_SIZE: u64 = 256 * 1024;

/// Walk command lines for all processes in the task list.
pub fn walk_cmdlines<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<CmdlineInfo>> {
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

    let mut cmdlines = Vec::new();

    if let Ok(info) = walk_process_cmdline(reader, init_task_addr) {
        cmdlines.push(info);
    }

    for &task_addr in &task_addrs {
        if let Ok(info) = walk_process_cmdline(reader, task_addr) {
            cmdlines.push(info);
        }
    }

    Ok(cmdlines)
}

/// Read command line for a single process.
pub fn walk_process_cmdline<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    task_addr: u64,
) -> Result<CmdlineInfo> {
    let pid: u32 = reader.read_field(task_addr, "task_struct", "pid")?;
    let comm = reader.read_field_string(task_addr, "task_struct", "comm", 16)?;
    let mm_ptr: u64 = reader.read_field(task_addr, "task_struct", "mm")?;

    if mm_ptr == 0 {
        return Err(Error::Walker(format!(
            "task {comm} (PID {pid}) has NULL mm (kernel thread)"
        )));
    }

    let arg_start: u64 = reader.read_field(mm_ptr, "mm_struct", "arg_start")?;
    let arg_end: u64 = reader.read_field(mm_ptr, "mm_struct", "arg_end")?;

    if arg_start == 0 || arg_end <= arg_start {
        return Ok(CmdlineInfo {
            pid: u64::from(pid),
            comm,
            cmdline: String::new(),
        });
    }

    let size = (arg_end - arg_start).min(MAX_ARG_SIZE);
    let data = reader.read_bytes(arg_start, size as usize)?;

    Ok(CmdlineInfo {
        pid: u64::from(pid),
        comm,
        cmdline: parse_arg_region(&data),
    })
}

/// Parse null-separated argv entries into a single space-joined string.
fn parse_arg_region(data: &[u8]) -> String {
    let args: Vec<&str> = data
        .split(|&b| b == 0)
        .filter_map(|chunk| {
            if chunk.is_empty() {
                None
            } else {
                Some(std::str::from_utf8(chunk).unwrap_or_default())
            }
        })
        .collect();
    args.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
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
            .add_field("mm_struct", "arg_start", 64, "unsigned long")
            .add_field("mm_struct", "arg_end", 72, "unsigned long")
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
    fn single_process_cmdline() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        data[0..4].copy_from_slice(&100u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..36].copy_from_slice(b"sshd");
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes());

        let arg_vaddr: u64 = 0xFFFF_8000_0020_0000;
        data[0x200..0x208].copy_from_slice(&0x1000u64.to_le_bytes());
        data[0x240..0x248].copy_from_slice(&arg_vaddr.to_le_bytes());
        let arg_data = b"/usr/sbin/sshd\0-D\0-p\02222\0";
        let arg_end = arg_vaddr + arg_data.len() as u64;
        data[0x248..0x250].copy_from_slice(&arg_end.to_le_bytes());

        let arg_paddr: u64 = 0x0090_0000;
        let reader = make_test_reader(
            &data,
            vaddr,
            paddr,
            &[(arg_vaddr, arg_paddr, arg_data.as_slice())],
        );

        let result = walk_process_cmdline(&reader, vaddr).unwrap();
        assert_eq!(result.pid, 100);
        assert_eq!(result.comm, "sshd");
        assert_eq!(result.cmdline, "/usr/sbin/sshd -D -p 2222");
    }

    #[test]
    fn kernel_thread_returns_error() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        data[0..4].copy_from_slice(&2u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..40].copy_from_slice(b"kthreadd");
        data[48..56].copy_from_slice(&0u64.to_le_bytes());

        let reader = make_test_reader(&data, vaddr, paddr, &[]);
        let result = walk_process_cmdline(&reader, vaddr);
        assert!(result.is_err());
    }

    #[test]
    fn empty_arg_region() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        data[0..4].copy_from_slice(&50u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..36].copy_from_slice(b"node");
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes());

        data[0x200..0x208].copy_from_slice(&0x1000u64.to_le_bytes());
        data[0x240..0x248].copy_from_slice(&0u64.to_le_bytes());
        data[0x248..0x250].copy_from_slice(&0u64.to_le_bytes());

        let reader = make_test_reader(&data, vaddr, paddr, &[]);
        let result = walk_process_cmdline(&reader, vaddr).unwrap();
        assert_eq!(result.pid, 50);
        assert_eq!(result.cmdline, "");
    }

    #[test]
    fn walk_cmdlines_skips_kernel_threads() {
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
        let cmdlines = walk_cmdlines(&reader).unwrap();
        assert!(cmdlines.is_empty());
    }

    #[test]
    fn parse_arg_region_joins_with_spaces() {
        let result = parse_arg_region(b"python3\0-m\0http.server\08080\0");
        assert_eq!(result, "python3 -m http.server 8080");
    }

    #[test]
    fn parse_arg_region_single_arg() {
        let result = parse_arg_region(b"/bin/bash\0");
        assert_eq!(result, "/bin/bash");
    }

    #[test]
    fn parse_arg_region_empty() {
        let result = parse_arg_region(b"");
        assert_eq!(result, "");
    }

    #[test]
    fn walk_cmdlines_missing_tasks_field_returns_error() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let data = vec![0u8; 4096];

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_struct("mm_struct", 128)
            .add_field("mm_struct", "pgd", 0, "pointer")
            .add_field("mm_struct", "arg_start", 64, "unsigned long")
            .add_field("mm_struct", "arg_end", 72, "unsigned long")
            .add_symbol("init_task", vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_cmdlines(&reader);
        assert!(result.is_err(), "missing tasks field must produce an error");
    }

    #[test]
    fn walk_process_cmdline_arg_end_before_arg_start_returns_empty() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        data[0..4].copy_from_slice(&77u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..37].copy_from_slice(b"proc\0");
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes());

        data[0x200..0x208].copy_from_slice(&0x1000u64.to_le_bytes());
        data[0x240..0x248].copy_from_slice(&0x5000u64.to_le_bytes());
        data[0x248..0x250].copy_from_slice(&0x4000u64.to_le_bytes());

        let reader = make_test_reader(&data, vaddr, paddr, &[]);
        let result = walk_process_cmdline(&reader, vaddr).unwrap();
        assert_eq!(result.pid, 77);
        assert_eq!(
            result.cmdline, "",
            "arg_end <= arg_start must produce empty cmdline"
        );
    }

    #[test]
    fn parse_arg_region_consecutive_nulls_filtered() {
        let result = parse_arg_region(b"arg0\0\0arg2\0");
        assert_eq!(result, "arg0 arg2");
    }

    #[test]
    fn cmdline_info_clone_eq() {
        let a = CmdlineInfo {
            pid: 1,
            comm: "bash".to_string(),
            cmdline: "bash -c true".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
        let dbg = format!("{:?}", a);
        assert!(dbg.contains("bash"));
    }

    #[test]
    fn walk_cmdlines_two_processes_both_pushed() {
        let tasks_off: u64 = 16u64;
        let mm_off: u64 = 48u64;
        let arg_off_in_mm: u64 = 64u64;
        let arg_end_off_in_mm: u64 = 72u64;

        let init_vaddr: u64 = 0xFFFF_8000_0040_0000;
        let init_paddr: u64 = 0x0040_0000;
        let task2_vaddr: u64 = 0xFFFF_8000_0041_0000;
        let task2_paddr: u64 = 0x0041_0000;
        let mm1_vaddr: u64 = 0xFFFF_8000_0042_0000;
        let mm1_paddr: u64 = 0x0042_0000;
        let mm2_vaddr: u64 = 0xFFFF_8000_0043_0000;
        let mm2_paddr: u64 = 0x0043_0000;
        let arg1_vaddr: u64 = 0xFFFF_8000_0044_0000;
        let arg1_paddr: u64 = 0x0044_0000;
        let arg2_vaddr: u64 = 0xFFFF_8000_0045_0000;
        let arg2_paddr: u64 = 0x0045_0000;

        let arg1_data = b"/sbin/init\0";
        let arg2_data = b"/bin/sh\0-c\0true\0";

        let mut page1 = vec![0u8; 4096];
        page1[0..4].copy_from_slice(&1u32.to_le_bytes());
        let task2_tasks_vaddr = task2_vaddr + tasks_off;
        page1[tasks_off as usize..tasks_off as usize + 8]
            .copy_from_slice(&task2_tasks_vaddr.to_le_bytes());
        page1[24..32].copy_from_slice(&(init_vaddr + tasks_off).to_le_bytes());
        page1[32..36].copy_from_slice(b"init");
        page1[mm_off as usize..mm_off as usize + 8].copy_from_slice(&mm1_vaddr.to_le_bytes());

        let mut page2 = vec![0u8; 4096];
        page2[0..4].copy_from_slice(&2u32.to_le_bytes());
        let init_tasks_vaddr = init_vaddr + tasks_off;
        page2[tasks_off as usize..tasks_off as usize + 8]
            .copy_from_slice(&init_tasks_vaddr.to_le_bytes());
        page2[24..32].copy_from_slice(&(task2_vaddr + tasks_off).to_le_bytes());
        page2[32..34].copy_from_slice(b"sh");
        page2[mm_off as usize..mm_off as usize + 8].copy_from_slice(&mm2_vaddr.to_le_bytes());

        let mut mm1_page = vec![0u8; 4096];
        mm1_page[arg_off_in_mm as usize..arg_off_in_mm as usize + 8]
            .copy_from_slice(&arg1_vaddr.to_le_bytes());
        let arg1_end = arg1_vaddr + arg1_data.len() as u64;
        mm1_page[arg_end_off_in_mm as usize..arg_end_off_in_mm as usize + 8]
            .copy_from_slice(&arg1_end.to_le_bytes());

        let mut mm2_page = vec![0u8; 4096];
        mm2_page[arg_off_in_mm as usize..arg_off_in_mm as usize + 8]
            .copy_from_slice(&arg2_vaddr.to_le_bytes());
        let arg2_end = arg2_vaddr + arg2_data.len() as u64;
        mm2_page[arg_end_off_in_mm as usize..arg_end_off_in_mm as usize + 8]
            .copy_from_slice(&arg2_end.to_le_bytes());

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
            .add_field("mm_struct", "arg_start", 64, "unsigned long")
            .add_field("mm_struct", "arg_end", 72, "unsigned long")
            .add_symbol("init_task", init_vaddr)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(init_vaddr, init_paddr, flags::WRITABLE)
            .write_phys(init_paddr, &page1)
            .map_4k(task2_vaddr, task2_paddr, flags::WRITABLE)
            .write_phys(task2_paddr, &page2)
            .map_4k(mm1_vaddr, mm1_paddr, flags::WRITABLE)
            .write_phys(mm1_paddr, &mm1_page)
            .map_4k(mm2_vaddr, mm2_paddr, flags::WRITABLE)
            .write_phys(mm2_paddr, &mm2_page)
            .map_4k(arg1_vaddr, arg1_paddr, flags::WRITABLE)
            .write_phys(arg1_paddr, arg1_data.as_slice())
            .map_4k(arg2_vaddr, arg2_paddr, flags::WRITABLE)
            .write_phys(arg2_paddr, arg2_data.as_slice())
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader: ObjectReader<SyntheticPhysMem> = ObjectReader::new(vas, Box::new(resolver));

        let result = walk_cmdlines(&reader).unwrap();
        assert_eq!(
            result.len(),
            2,
            "both init_task and task2 should have cmdlines"
        );
        let pids: Vec<u64> = result.iter().map(|r| r.pid).collect();
        assert!(pids.contains(&1), "init_task (pid=1) must be in results");
        assert!(pids.contains(&2), "task2 (pid=2) must be in results");
        let init_cmdline = result.iter().find(|r| r.pid == 1).unwrap();
        assert_eq!(init_cmdline.cmdline, "/sbin/init");
        let sh_cmdline = result.iter().find(|r| r.pid == 2).unwrap();
        assert_eq!(sh_cmdline.cmdline, "/bin/sh -c true");
    }
}
