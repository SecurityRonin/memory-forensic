//! Detect fileless payloads loaded via `memfd_create(2)`.
//!
//! `memfd_create` creates an anonymous file living only in RAM. Malware uses
//! this to load shellcode or staged payloads without touching disk. The file
//! descriptor appears in the process's open-fd table with a dentry name of
//! `memfd:<name>` (e.g. `memfd:payload`).
//!
//! MITRE ATT&CK: T1055.009 — Process Injection: Process Hollowing (via anonymous memory).

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;
use serde::Serialize;

use crate::Result;

/// Information about an open `memfd_create` file descriptor.
#[derive(Debug, Clone, Serialize)]
pub struct MemfdInfo {
    /// Process ID.
    pub pid: u32,
    /// Process command name (`task_struct.comm`, max 16 chars).
    pub comm: String,
    /// Name given to `memfd_create`, e.g. `"payload"` (without the `memfd:` prefix).
    pub memfd_name: String,
    /// Total byte size of all VMAs backed by this memfd.
    pub size_bytes: u64,
    /// Whether any VMA backed by this memfd is mapped executable (`PROT_EXEC`).
    pub is_executable: bool,
    /// Whether this memfd is considered suspicious.
    pub is_suspicious: bool,
}

/// Classify whether a memfd mapping is suspicious.
pub fn classify_memfd(_name: &str, _is_executable: bool) -> bool {
    todo!("RED: implement classify_memfd")
}

/// Walk the task list and collect information about open `memfd_create` file descriptors.
pub fn walk_memfd_create<P: PhysicalMemoryProvider>(
    _reader: &ObjectReader<P>,
) -> Result<Vec<MemfdInfo>> {
    todo!("RED: implement walk_memfd_create")
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // -----------------------------------------------------------------------
    // classify_memfd unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn classify_memfd_executable_is_suspicious() {
        assert!(
            classify_memfd("harmless", true),
            "an executable memfd mapping must always be suspicious"
        );
    }

    #[test]
    fn classify_memfd_shellcode_name_is_suspicious() {
        assert!(
            classify_memfd("shellcode", false),
            "a memfd named 'shellcode' must be suspicious"
        );
    }

    #[test]
    fn classify_memfd_empty_name_is_suspicious() {
        assert!(
            classify_memfd("", false),
            "an anonymous memfd with empty name must be suspicious (evasion)"
        );
    }

    #[test]
    fn classify_memfd_pulseaudio_benign() {
        assert!(
            !classify_memfd("pulseaudio-shm", false),
            "a non-executable memfd named 'pulseaudio-shm' must not be suspicious"
        );
    }

    #[test]
    fn classify_memfd_payload_name_is_suspicious() {
        assert!(
            classify_memfd("payload", false),
            "a memfd named 'payload' must be suspicious"
        );
    }

    #[test]
    fn classify_memfd_wayland_benign() {
        assert!(
            !classify_memfd("wayland-shm", false),
            "a non-executable memfd named 'wayland-shm' must not be suspicious"
        );
    }

    // -----------------------------------------------------------------------
    // walk_memfd_create integration tests
    // -----------------------------------------------------------------------

    fn make_reader_no_init_task() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    fn make_reader_no_memfd() -> ObjectReader<SyntheticPhysMem> {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;

        let mut data = vec![0u8; 4096];
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        let tasks_next = vaddr + 16;
        data[16..24].copy_from_slice(&tasks_next.to_le_bytes());
        data[24..32].copy_from_slice(&tasks_next.to_le_bytes());
        data[32..37].copy_from_slice(b"init\0");
        data[48..56].copy_from_slice(&0u64.to_le_bytes());

        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 16, "list_head")
            .add_field("task_struct", "comm", 32, "char")
            .add_field("task_struct", "mm", 48, "pointer")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("init_task", vaddr)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr, &data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn walk_memfd_missing_init_task_returns_empty() {
        let reader = make_reader_no_init_task();
        let result = walk_memfd_create(&reader).expect("should not error");
        assert!(
            result.is_empty(),
            "missing init_task symbol must yield empty result (graceful degradation)"
        );
    }

    #[test]
    fn walk_memfd_no_memfd_processes_returns_empty() {
        let reader = make_reader_no_memfd();
        let result = walk_memfd_create(&reader).expect("should not error");
        assert!(
            result.is_empty(),
            "a kernel thread with mm==NULL must not produce any memfd results"
        );
    }
}
