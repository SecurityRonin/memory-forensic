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
///
/// For each process, reads `mm_struct.arg_start`..`arg_end` and joins
/// the null-separated argv entries with spaces. Kernel threads are skipped.
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

    // Include init_task itself
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

    // task_struct layout:
    //   pid       @ 0   (int, 4 bytes)
    //   state     @ 4   (long, 8 bytes)
    //   tasks     @ 16  (list_head, 16 bytes)
    //   comm      @ 32  (char, 16 bytes)
    //   mm        @ 48  (pointer, 8 bytes)
    //   total: 128
    //
    // mm_struct layout:
    //   pgd       @ 0   (pointer, 8 bytes)
    //   arg_start @ 64  (unsigned long, 8 bytes)
    //   arg_end   @ 72  (unsigned long, 8 bytes)
    //   total: 128

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

    /// Single process with multi-arg command line: "/usr/sbin/sshd\0-D\0-p\02222\0"
    /// Should produce: "/usr/sbin/sshd -D -p 2222"
    #[test]
    fn single_process_cmdline() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // task_struct: PID 100, "sshd"
        data[0..4].copy_from_slice(&100u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes()); // tasks.next → self
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes()); // tasks.prev → self
        data[32..36].copy_from_slice(b"sshd");
        let mm_addr = vaddr + 0x200;
        data[48..56].copy_from_slice(&mm_addr.to_le_bytes()); // mm ptr

        // mm_struct at +0x200
        let arg_vaddr: u64 = 0xFFFF_8000_0020_0000;
        data[0x200..0x208].copy_from_slice(&0x1000u64.to_le_bytes()); // pgd
        data[0x240..0x248].copy_from_slice(&arg_vaddr.to_le_bytes()); // arg_start
        let arg_data = b"/usr/sbin/sshd\0-D\0-p\02222\0";
        let arg_end = arg_vaddr + arg_data.len() as u64;
        data[0x248..0x250].copy_from_slice(&arg_end.to_le_bytes()); // arg_end

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

    /// Kernel thread (mm == NULL) should produce an error.
    #[test]
    fn kernel_thread_returns_error() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        data[0..4].copy_from_slice(&2u32.to_le_bytes()); // PID 2
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..40].copy_from_slice(b"kthreadd");
        // mm = 0 (kernel thread)
        data[48..56].copy_from_slice(&0u64.to_le_bytes());

        let reader = make_test_reader(&data, vaddr, paddr, &[]);
        let result = walk_process_cmdline(&reader, vaddr);
        assert!(result.is_err());
    }

    /// Empty arg region (arg_start == arg_end) should produce empty cmdline.
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

        // mm_struct with arg_start == 0 (no args)
        data[0x200..0x208].copy_from_slice(&0x1000u64.to_le_bytes());
        data[0x240..0x248].copy_from_slice(&0u64.to_le_bytes()); // arg_start = 0
        data[0x248..0x250].copy_from_slice(&0u64.to_le_bytes()); // arg_end = 0

        let reader = make_test_reader(&data, vaddr, paddr, &[]);
        let result = walk_process_cmdline(&reader, vaddr).unwrap();
        assert_eq!(result.pid, 50);
        assert_eq!(result.cmdline, "");
    }

    /// walk_cmdlines iterates the full task list and skips kernel threads.
    #[test]
    fn walk_cmdlines_skips_kernel_threads() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mut data = vec![0u8; 4096];

        // init_task (PID 0, kernel thread, mm=NULL)
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        let tasks_addr = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_addr.to_le_bytes()); // self-loop
        data[24..32].copy_from_slice(&tasks_addr.to_le_bytes());
        data[32..41].copy_from_slice(b"swapper/0");
        data[48..56].copy_from_slice(&0u64.to_le_bytes()); // mm = NULL

        let reader = make_test_reader(&data, vaddr, paddr, &[]);
        let cmdlines = walk_cmdlines(&reader).unwrap();
        // kernel thread skipped → empty
        assert!(cmdlines.is_empty());
    }

    /// parse_arg_region joins null-separated entries with spaces.
    #[test]
    fn parse_arg_region_joins_with_spaces() {
        let result = parse_arg_region(b"python3\0-m\0http.server\08080\0");
        assert_eq!(result, "python3 -m http.server 8080");
    }

    /// parse_arg_region handles single argument (no nulls except trailing).
    #[test]
    fn parse_arg_region_single_arg() {
        let result = parse_arg_region(b"/bin/bash\0");
        assert_eq!(result, "/bin/bash");
    }

    /// parse_arg_region handles empty input.
    #[test]
    fn parse_arg_region_empty() {
        let result = parse_arg_region(b"");
        assert_eq!(result, "");
    }
}
