#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Windows kernel memory forensic walkers.
//!
//! Provides process, thread, driver, and DLL enumeration
//! by walking Windows NT kernel data structures in physical memory dumps.

pub mod alpc;
pub mod amcache;
pub mod amsi_bypass;
pub mod apc_injection;
pub mod atom_table;
pub mod bigpools;
pub mod bitlocker_keys;
pub mod cachedump;
pub mod callbacks;
pub mod clipboard;
pub mod clr_heap;
pub mod cmdline;
pub mod com_hijacking;
pub mod consoles;
pub mod correlate;
pub mod crashinfo;
pub mod debug_registers;
pub mod desktops;
pub mod device_tree;
pub mod direct_syscalls;
pub mod dkom_detect;
pub mod dll;
pub mod dns_cache;
pub mod dpapi_keys;
pub mod driver;
pub mod driver_irp;
pub mod dse_bypass;
pub mod envvars;
pub mod etw;
pub mod etw_patch;
pub mod evtx;
pub mod fiber_fls;
pub mod filescan;
pub mod getsids;
pub mod handles;
pub mod hashdump;
pub mod heap_spray;
pub mod hollowing;
pub mod iat_hooks;
pub mod kerberos_tickets;
pub mod ldrmodules;
pub mod lsadump;
pub mod mbr_scan;
pub mod messagehooks;
pub mod mutant;
pub mod network;
pub mod ntlm_ssp;
pub mod object_directory;
pub mod pe_version_info;
pub mod peb_masquerade;
pub mod pipes;
pub mod pool_scan;
pub mod pool_tag;
pub mod prefetch;
pub mod process;
pub mod psxview;
pub mod psxview_cid;
pub mod rdp_sessions;
pub mod registry;
pub mod registry_keys;
pub mod sam;
pub mod scheduled_tasks;
pub mod section_object;
pub mod service;
pub mod sessions;
pub mod shellbags;
pub mod shimcache;
pub mod skeleton_key;
pub mod ssdt;
pub mod suspicious_threads;
pub mod svc_diff;
pub mod symlinks;
pub mod sysinfo;
pub mod thread;
pub mod timers;
pub mod tls_callbacks;
pub mod token;
pub mod token_impersonation;
pub mod typed_urls;
pub mod types;
pub mod unicode;
pub mod userassist;
pub mod vad;
pub mod wmi;
pub mod wmi_persistence;
pub mod wow64_anomaly;

#[cfg(test)]
pub mod testing;

pub use types::*;

/// Error type for memf-windows operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Core memory reading error.
    #[error("core error: {0}")]
    Core(#[from] memf_core::Error),

    /// Symbol resolution error.
    #[error("symbol error: {0}")]
    Symbol(#[from] memf_symbols::Error),

    /// Walker-specific error.
    #[error("walker error: {0}")]
    Walker(String),

    /// A required kernel symbol was not found in the ISF.
    #[error("kernel symbol not found: {name}")]
    MissingKernelSymbol { name: String },

    /// A required struct field was not found in the ISF.
    #[error("ISF missing field: {struct_name}.{field_name}")]
    MissingField { struct_name: String, field_name: String },

    /// A walker-specific failure with context.
    #[error("walker '{walker}' failed: {reason}")]
    WalkFailed { walker: &'static str, reason: String },

    /// A list walk failure with context.
    #[error("list walk failed in walker '{walker}': {reason}")]
    ListWalkFailed { walker: &'static str, reason: String },
}

/// A Result alias for memf-windows.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_walker() {
        let e = Error::Walker("test error".into());
        assert_eq!(e.to_string(), "walker error: test error");
    }

    #[test]
    fn error_missing_kernel_symbol_contains_name() {
        let e = Error::MissingKernelSymbol { name: "init_task".to_owned() };
        assert!(e.to_string().contains("init_task"));
    }

    #[test]
    fn error_missing_field_contains_struct_and_field() {
        let e = Error::MissingField {
            struct_name: "task_struct".to_owned(),
            field_name: "mm".to_owned(),
        };
        assert!(e.to_string().contains("task_struct"));
        assert!(e.to_string().contains("mm"));
    }

    #[test]
    fn error_walk_failed_contains_walker_name() {
        let e = Error::WalkFailed {
            walker: "walk_processes",
            reason: "list corrupted".to_owned(),
        };
        assert!(e.to_string().contains("walk_processes"));
    }

    #[test]
    fn error_from_core() {
        let core_err = memf_core::Error::PageNotPresent(0x1000);
        let e: Error = Error::from(core_err);
        assert!(matches!(e, Error::Core(_)));
        assert!(e.to_string().contains("0x"));
    }

    #[test]
    fn error_from_symbol() {
        let sym_err = memf_symbols::Error::NotFound("_EPROCESS".into());
        let e: Error = Error::from(sym_err);
        assert!(matches!(e, Error::Symbol(_)));
        assert!(e.to_string().contains("_EPROCESS"));
    }

    /// Integration test: walk processes, then walk threads for each process.
    #[test]
    fn process_then_thread_enumeration() {
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Layout: PsActiveProcessHead at vaddr 0xFFFF_8000_0010_0000
        // _EPROCESS (System, pid=4) at vaddr 0xFFFF_8000_0020_0000
        // _KTHREAD at vaddr 0xFFFF_8000_0030_0000
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let eproc_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let kthread_vaddr: u64 = 0xFFFF_8000_0030_0000;

        let head_paddr: u64 = 0x0080_0000;
        let eproc_paddr: u64 = 0x0090_0000;
        let kthread_paddr: u64 = 0x00A0_0000;

        let mut head_data = vec![0u8; 4096];
        let mut eproc_data = vec![0u8; 4096];
        let mut kthread_data = vec![0u8; 4096];

        // _LIST_ENTRY offsets: Flink@0, Blink@8
        let active_links_off: u64 = 0x448;

        // PsActiveProcessHead: Flink → eproc.ActiveProcessLinks
        let eproc_links = eproc_vaddr + active_links_off;
        head_data[0..8].copy_from_slice(&eproc_links.to_le_bytes()); // Flink
        head_data[8..16].copy_from_slice(&eproc_links.to_le_bytes()); // Blink

        // _EPROCESS at eproc_paddr
        // Pcb@0x0 is _KPROCESS: DirectoryTableBase@0x28, ThreadListHead@0x30
        eproc_data[0x28..0x30].copy_from_slice(&0x1AB000u64.to_le_bytes()); // CR3
                                                                            // ThreadListHead: Flink → kthread.ThreadListEntry
        let thread_list_entry_off: u64 = 0x2F8;
        let kthread_list_entry = kthread_vaddr + thread_list_entry_off;
        let thread_list_head = eproc_vaddr + 0x30; // Pcb@0 + ThreadListHead@0x30
        eproc_data[0x30..0x38].copy_from_slice(&kthread_list_entry.to_le_bytes()); // Flink
        eproc_data[0x38..0x40].copy_from_slice(&kthread_list_entry.to_le_bytes()); // Blink

        // CreateTime@0x430, ExitTime@0x438
        eproc_data[0x430..0x438].copy_from_slice(&132800000000000000u64.to_le_bytes());
        eproc_data[0x438..0x440].copy_from_slice(&0u64.to_le_bytes());
        // UniqueProcessId@0x440
        eproc_data[0x440..0x448].copy_from_slice(&4u64.to_le_bytes());
        // ActiveProcessLinks@0x448: Flink → head, Blink → head
        eproc_data[0x448..0x450].copy_from_slice(&head_vaddr.to_le_bytes()); // Flink back to head
        eproc_data[0x450..0x458].copy_from_slice(&head_vaddr.to_le_bytes()); // Blink
                                                                             // InheritedFromUniqueProcessId@0x540
        eproc_data[0x540..0x548].copy_from_slice(&0u64.to_le_bytes());
        // Peb@0x550
        eproc_data[0x550..0x558].copy_from_slice(&0u64.to_le_bytes());
        // ImageFileName@0x5A8 (15 bytes max)
        eproc_data[0x5A8..0x5AE].copy_from_slice(b"System");

        // _KTHREAD at kthread_paddr
        // Teb@0xF0
        eproc_data[0x28..0x30].copy_from_slice(&0x1AB000u64.to_le_bytes());
        // ThreadListEntry@0x2F8: Flink → back to ThreadListHead
        kthread_data[0x2F8..0x300].copy_from_slice(&thread_list_head.to_le_bytes()); // Flink
        kthread_data[0x300..0x308].copy_from_slice(&thread_list_head.to_le_bytes()); // Blink
                                                                                     // Teb@0xF0
        kthread_data[0xF0..0xF8].copy_from_slice(&0u64.to_le_bytes());
        // Win32StartAddress@0x680
        kthread_data[0x680..0x688].copy_from_slice(&0x7FF600001000u64.to_le_bytes());
        // CreateTime@0x688
        kthread_data[0x688..0x690].copy_from_slice(&132800000000000000u64.to_le_bytes());
        // _ETHREAD.Cid@0x620: UniqueProcess@0, UniqueThread@8
        kthread_data[0x620..0x628].copy_from_slice(&4u64.to_le_bytes()); // PID
        kthread_data[0x628..0x630].copy_from_slice(&8u64.to_le_bytes()); // TID

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr, eproc_paddr, flags::WRITABLE)
            .map_4k(eproc_vaddr + 0x1000, eproc_paddr + 0x1000, flags::WRITABLE)
            .map_4k(kthread_vaddr, kthread_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_data)
            .write_phys(eproc_paddr, &eproc_data)
            .write_phys(kthread_paddr, &kthread_data)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = memf_core::object_reader::ObjectReader::new(vas, Box::new(resolver));

        // Walk processes
        let procs = process::walk_processes(&reader, head_vaddr).unwrap();
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].pid, 4);
        assert_eq!(procs[0].image_name, "System");
        assert_eq!(procs[0].cr3, 0x1AB000);

        // Walk threads for System process
        let threads = thread::walk_threads(&reader, eproc_vaddr, 4).unwrap();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].tid, 8);
        assert_eq!(threads[0].pid, 4);
    }

    /// Integration test: driver list walking uses correct struct layouts.
    #[test]
    fn driver_list_with_unicode_names() {
        use memf_core::test_builders::{flags, PageTableBuilder};
        use memf_core::vas::{TranslationMode, VirtualAddressSpace};
        use memf_symbols::isf::IsfResolver;
        use memf_symbols::test_builders::IsfBuilder;

        fn utf16le(s: &str) -> Vec<u8> {
            s.encode_utf16().flat_map(u16::to_le_bytes).collect()
        }

        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        // Layout:
        // PsLoadedModuleList head at vaddr 0xFFFF_8000_0010_0000
        // _KLDR_DATA_TABLE_ENTRY at vaddr 0xFFFF_8000_0020_0000
        // String data at vaddr 0xFFFF_8000_0020_1000
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let entry_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let strings_vaddr: u64 = 0xFFFF_8000_0020_1000;

        let head_paddr: u64 = 0x0080_0000;
        let entry_paddr: u64 = 0x0090_0000;
        let strings_paddr: u64 = 0x0091_0000;

        let mut head_data = vec![0u8; 4096];
        let mut entry_data = vec![0u8; 4096];
        let mut string_data = vec![0u8; 4096];

        // Head: Flink → entry.InLoadOrderLinks
        head_data[0..8].copy_from_slice(&entry_vaddr.to_le_bytes());
        head_data[8..16].copy_from_slice(&entry_vaddr.to_le_bytes());

        // Entry InLoadOrderLinks@0: Flink → head (circular, single entry)
        entry_data[0..8].copy_from_slice(&head_vaddr.to_le_bytes());
        entry_data[8..16].copy_from_slice(&head_vaddr.to_le_bytes());
        // DllBase@48
        entry_data[48..56].copy_from_slice(&0xFFFFF80000000000u64.to_le_bytes());
        // SizeOfImage@64
        entry_data[64..68].copy_from_slice(&0x800000u32.to_le_bytes());

        // FullDllName@72 (_UNICODE_STRING: Length@0, MaxLen@2, Buffer@8)
        let full_name = utf16le("\\SystemRoot\\system32\\ntoskrnl.exe");
        let full_len = full_name.len() as u16;
        entry_data[72..74].copy_from_slice(&full_len.to_le_bytes());
        entry_data[74..76].copy_from_slice(&(full_len + 2).to_le_bytes());
        let full_buf_vaddr = strings_vaddr;
        entry_data[80..88].copy_from_slice(&full_buf_vaddr.to_le_bytes());

        // BaseDllName@88
        let base_name = utf16le("ntoskrnl.exe");
        let base_len = base_name.len() as u16;
        entry_data[88..90].copy_from_slice(&base_len.to_le_bytes());
        entry_data[90..92].copy_from_slice(&(base_len + 2).to_le_bytes());
        let base_buf_vaddr = strings_vaddr + 0x100;
        entry_data[96..104].copy_from_slice(&base_buf_vaddr.to_le_bytes());

        // Write string data
        string_data[0..full_name.len()].copy_from_slice(&full_name);
        string_data[0x100..0x100 + base_name.len()].copy_from_slice(&base_name);

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(entry_vaddr, entry_paddr, flags::WRITABLE)
            .map_4k(strings_vaddr, strings_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_data)
            .write_phys(entry_paddr, &entry_data)
            .write_phys(strings_paddr, &string_data)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = memf_core::object_reader::ObjectReader::new(vas, Box::new(resolver));

        let drivers = driver::walk_drivers(&reader, head_vaddr).unwrap();
        assert_eq!(drivers.len(), 1);
        assert_eq!(drivers[0].name, "ntoskrnl.exe");
        assert!(drivers[0].full_path.contains("ntoskrnl.exe"));
        assert_eq!(drivers[0].base_addr, 0xFFFFF80000000000);
        assert_eq!(drivers[0].size, 0x800000);
    }
}
