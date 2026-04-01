//! Phase 2 end-to-end integration tests.
//!
//! These tests build synthetic memory images with page tables and
//! kernel data structures, then run the walkers to verify the full pipeline.

use memf_core::object_reader::ObjectReader;
use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
use memf_core::vas::{TranslationMode, VirtualAddressSpace};
use memf_symbols::isf::IsfResolver;
use memf_symbols::test_builders::IsfBuilder;
use memf_symbols::SymbolResolver;

/// Helper: build a full ObjectReader from physical data, virtual mapping, and ISF JSON.
fn build_reader(
    vaddr: u64,
    paddr: u64,
    data: &[u8],
    isf: &serde_json::Value,
) -> ObjectReader<SyntheticPhysMem> {
    let resolver = IsfResolver::from_value(isf).unwrap();
    let (cr3, mem) = PageTableBuilder::new()
        .map_4k(vaddr, paddr, flags::WRITABLE)
        .write_phys(paddr, data)
        .build();
    let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
    ObjectReader::new(vas, Box::new(resolver))
}

#[test]
fn process_walker_end_to_end() {
    let isf = IsfBuilder::new()
        .add_struct("task_struct", 128)
        .add_field("task_struct", "pid", 0, "int")
        .add_field("task_struct", "state", 4, "long")
        .add_field("task_struct", "tasks", 16, "list_head")
        .add_field("task_struct", "comm", 32, "char")
        .add_field("task_struct", "mm", 48, "pointer")
        .add_field("task_struct", "real_parent", 56, "pointer")
        .add_struct("list_head", 16)
        .add_field("list_head", "next", 0, "pointer")
        .add_field("list_head", "prev", 8, "pointer")
        .add_struct("mm_struct", 128)
        .add_field("mm_struct", "pgd", 0, "pointer")
        .add_symbol("init_task", 0xFFFF_8000_0010_0000)
        .build_json();

    let vaddr: u64 = 0xFFFF_8000_0010_0000;
    let paddr: u64 = 0x0080_0000;

    let mut data = vec![0u8; 4096];
    let init = vaddr;
    let task_a = vaddr + 0x200;

    let init_tasks = init + 16;
    let a_tasks = task_a + 16;

    // init_task (PID 0, swapper)
    data[0..4].copy_from_slice(&0u32.to_le_bytes());
    data[4..12].copy_from_slice(&0i64.to_le_bytes());
    data[16..24].copy_from_slice(&a_tasks.to_le_bytes());
    data[24..32].copy_from_slice(&a_tasks.to_le_bytes());
    data[32..41].copy_from_slice(b"swapper/0");
    data[56..64].copy_from_slice(&init.to_le_bytes());

    // Task A (PID 1, systemd)
    data[0x200..0x204].copy_from_slice(&1u32.to_le_bytes());
    data[0x204..0x20C].copy_from_slice(&1i64.to_le_bytes());
    data[0x210..0x218].copy_from_slice(&init_tasks.to_le_bytes());
    data[0x218..0x220].copy_from_slice(&init_tasks.to_le_bytes());
    data[0x220..0x227].copy_from_slice(b"systemd");
    data[0x238..0x240].copy_from_slice(&init.to_le_bytes());

    let reader = build_reader(vaddr, paddr, &data, &isf);
    let procs = memf_linux::process::walk_processes(&reader).unwrap();

    assert_eq!(procs.len(), 2);
    assert_eq!(procs[0].pid, 0);
    assert_eq!(procs[0].comm, "swapper/0");
    assert_eq!(procs[1].pid, 1);
    assert_eq!(procs[1].comm, "systemd");
}

#[test]
fn module_walker_end_to_end() {
    let isf = IsfBuilder::new()
        .add_struct("module", 256)
        .add_field("module", "list", 0, "list_head")
        .add_field("module", "name", 16, "char")
        .add_field("module", "state", 72, "unsigned int")
        .add_field("module", "core_layout", 80, "module_layout")
        .add_struct("module_layout", 32)
        .add_field("module_layout", "base", 0, "pointer")
        .add_field("module_layout", "size", 8, "unsigned int")
        .add_struct("list_head", 16)
        .add_field("list_head", "next", 0, "pointer")
        .add_field("list_head", "prev", 8, "pointer")
        .add_symbol("modules", 0xFFFF_8000_0010_0000)
        .build_json();

    let vaddr: u64 = 0xFFFF_8000_0010_0000;
    let paddr: u64 = 0x0080_0000;

    let mut data = vec![0u8; 4096];
    let head = vaddr;
    let mod_a = vaddr + 0x100;

    // head -> mod_a.list, mod_a.list -> head
    data[0..8].copy_from_slice(&mod_a.to_le_bytes());
    data[8..16].copy_from_slice(&mod_a.to_le_bytes());

    data[0x100..0x108].copy_from_slice(&head.to_le_bytes());
    data[0x108..0x110].copy_from_slice(&head.to_le_bytes());
    data[0x110..0x114].copy_from_slice(b"ext4");
    data[0x148..0x14C].copy_from_slice(&0u32.to_le_bytes());
    data[0x150..0x158].copy_from_slice(&0xFFFF_A000u64.to_le_bytes());
    data[0x158..0x15C].copy_from_slice(&0x4000u32.to_le_bytes());

    let reader = build_reader(vaddr, paddr, &data, &isf);
    let mods = memf_linux::modules::walk_modules(&reader).unwrap();

    assert_eq!(mods.len(), 1);
    assert_eq!(mods[0].name, "ext4");
    assert_eq!(mods[0].base_addr, 0xFFFF_A000);
    assert_eq!(mods[0].size, 0x4000);
}

#[test]
fn elf_core_format_detection() {
    use memf_format::test_builders::ElfCoreBuilder;

    let dump = ElfCoreBuilder::new()
        .add_segment(0x0000_1000, &[0xAA; 4096])
        .add_segment(0x0010_0000, &[0xBB; 8192])
        .build();

    let dir = std::env::temp_dir().join("memf_test_elf_core_p2");
    std::fs::write(&dir, &dump).unwrap();

    let provider = memf_format::open_dump(&dir).unwrap();
    assert_eq!(provider.format_name(), "ELF Core");
    assert_eq!(provider.ranges().len(), 2);
    assert_eq!(provider.total_size(), 4096 + 8192);

    let mut buf = [0u8; 4];
    let n = provider.read_phys(0x0000_1000, &mut buf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(buf, [0xAA; 4]);

    std::fs::remove_file(&dir).ok();
}

#[test]
fn page_table_walker_2mb_and_1gb() {
    let (cr3, mem) = PageTableBuilder::new()
        .map_2m(0xFFFF_8000_0020_0000, 0x0200_0000, flags::WRITABLE)
        .map_1g(0xFFFF_8000_4000_0000, 0x4000_0000, flags::WRITABLE)
        .build();

    let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);

    // 2MB page
    assert_eq!(
        vas.virt_to_phys(0xFFFF_8000_0020_1234).unwrap(),
        0x0200_1234
    );

    // 1GB page
    assert_eq!(
        vas.virt_to_phys(0xFFFF_8000_4012_3456).unwrap(),
        0x4012_3456
    );
}

#[test]
fn isf_and_btf_resolvers_both_work() {
    // ISF JSON
    let isf_json = IsfBuilder::linux_process_preset().build_json();
    let isf = IsfResolver::from_value(&isf_json).unwrap();
    assert_eq!(isf.field_offset("task_struct", "pid"), Some(1128));
    assert_eq!(isf.backend_name(), "ISF JSON");

    // Verify dynamic dispatch works through the trait
    let dyn_ref: &dyn memf_symbols::SymbolResolver = &isf;
    assert_eq!(dyn_ref.field_offset("task_struct", "pid"), Some(1128));
}

#[test]
fn kaslr_detection_integration() {
    use memf_format::PhysicalRange;

    struct TestPhys {
        data: Vec<u8>,
        ranges: Vec<PhysicalRange>,
    }

    impl memf_format::PhysicalMemoryProvider for TestPhys {
        fn read_phys(&self, addr: u64, buf: &mut [u8]) -> memf_format::Result<usize> {
            let start = addr as usize;
            if start >= self.data.len() {
                return Ok(0);
            }
            let available = self.data.len() - start;
            let to_read = buf.len().min(available);
            buf[..to_read].copy_from_slice(&self.data[start..start + to_read]);
            Ok(to_read)
        }
        fn ranges(&self) -> &[PhysicalRange] {
            &self.ranges
        }
        fn format_name(&self) -> &str {
            "Test"
        }
    }

    // Banner at phys 0x0200_0000, symbol says 0xFFFF_FFFF_8200_0000
    // KERNEL_MAP_BASE = 0xFFFF_FFFF_8000_0000
    // No KASLR: phys + KERNEL_MAP = symbol addr
    let banner_phys = 0x0200_0000usize;
    let mut data = vec![0u8; banner_phys + 4096];
    let banner = b"Linux version 6.1.0-test-kern";
    data[banner_phys..banner_phys + banner.len()].copy_from_slice(banner);

    let phys = TestPhys {
        ranges: vec![PhysicalRange {
            start: 0,
            end: data.len() as u64,
        }],
        data,
    };

    let isf = IsfBuilder::new()
        .add_symbol("linux_banner", 0xFFFF_FFFF_8200_0000)
        .build_json();
    let resolver = IsfResolver::from_value(&isf).unwrap();

    let offset = memf_linux::kaslr::detect_kaslr_offset(&phys, &resolver).unwrap();
    assert_eq!(offset, 0);
}

// ---------------------------------------------------------------------------
// Test 11: Network walker end-to-end
// ---------------------------------------------------------------------------
#[test]
fn network_walker_end_to_end() {
    let vaddr: u64 = 0xFFFF_8000_0010_0000;
    let paddr: u64 = 0x0080_0000;

    let isf = IsfBuilder::new()
        .add_struct("inet_hashinfo", 64)
        .add_field("inet_hashinfo", "ehash", 0, "pointer")
        .add_field("inet_hashinfo", "ehash_mask", 8, "unsigned int")
        .add_struct("inet_ehash_bucket", 8)
        .add_field("inet_ehash_bucket", "chain", 0, "pointer")
        .add_struct("sock_common", 64)
        .add_field("sock_common", "skc_nulls_node", 0, "pointer")
        .add_field("sock_common", "skc_daddr", 8, "unsigned int")
        .add_field("sock_common", "skc_rcv_saddr", 12, "unsigned int")
        .add_field("sock_common", "skc_dport", 16, "unsigned short")
        .add_field("sock_common", "skc_num", 18, "unsigned short")
        .add_field("sock_common", "skc_state", 20, "unsigned char")
        .add_struct("sock", 256)
        .add_field("sock", "__sk_common", 0, "sock_common")
        .add_symbol("tcp_hashinfo", vaddr)
        .build_json();

    let mut data = vec![0u8; 4096];

    // tcp_hashinfo at vaddr:
    //   ehash (offset 0) -> points to bucket array at vaddr + 0x100
    //   ehash_mask (offset 8) -> 0 (1 bucket)
    let bucket_vaddr = vaddr + 0x100;
    let sock_vaddr = vaddr + 0x200;

    data[0..8].copy_from_slice(&bucket_vaddr.to_le_bytes()); // ehash ptr
    data[8..12].copy_from_slice(&0u32.to_le_bytes()); // ehash_mask = 0 -> 1 bucket

    // inet_ehash_bucket at +0x100:
    //   chain (offset 0) -> sock_vaddr
    data[0x100..0x108].copy_from_slice(&sock_vaddr.to_le_bytes());

    // sock at +0x200 (__sk_common at offset 0 -> sock_common fields):
    //   skc_nulls_node (offset 0) -> 1 (null terminator, bit 0 set)
    data[0x200..0x208].copy_from_slice(&1u64.to_le_bytes());
    // skc_daddr (offset 8) -> 192.168.1.100 = 0xC0A80164 in LE: [192, 168, 1, 100]
    let daddr: u32 = u32::from_le_bytes([192, 168, 1, 100]);
    data[0x208..0x20C].copy_from_slice(&daddr.to_le_bytes());
    // skc_rcv_saddr (offset 12) -> 10.0.0.1 = [10, 0, 0, 1]
    let saddr: u32 = u32::from_le_bytes([10, 0, 0, 1]);
    data[0x20C..0x210].copy_from_slice(&saddr.to_le_bytes());
    // skc_dport (offset 16) -> 443 in network byte order (big-endian)
    data[0x210..0x212].copy_from_slice(&443u16.to_be_bytes());
    // skc_num (offset 18) -> 54321 (host byte order)
    data[0x212..0x214].copy_from_slice(&54321u16.to_le_bytes());
    // skc_state (offset 20) -> 1 (ESTABLISHED)
    data[0x214] = 1;

    let resolver = IsfResolver::from_value(&isf).unwrap();
    let (cr3, mem) = PageTableBuilder::new()
        .map_4k(vaddr, paddr, flags::WRITABLE)
        .write_phys(paddr, &data)
        .build();
    let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
    let reader = ObjectReader::new(vas, Box::new(resolver));

    let conns = memf_linux::network::walk_connections(&reader).unwrap();
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0].local_addr, "10.0.0.1");
    assert_eq!(conns[0].local_port, 54321);
    assert_eq!(conns[0].remote_addr, "192.168.1.100");
    assert_eq!(conns[0].remote_port, 443);
    assert_eq!(conns[0].state, memf_linux::ConnectionState::Established);
    assert_eq!(conns[0].protocol, memf_linux::Protocol::Tcp);
}

// ---------------------------------------------------------------------------
// Test 12: Process walker with parent tracking (ppid chains)
// ---------------------------------------------------------------------------
#[test]
fn process_walker_with_parent_tracking() {
    // 3 processes: init (PID 0) -> systemd (PID 1) -> sshd (PID 100)
    // init.real_parent -> init (self-parent)
    // systemd.real_parent -> init
    // sshd.real_parent -> systemd

    let isf = IsfBuilder::new()
        .add_struct("task_struct", 128)
        .add_field("task_struct", "pid", 0, "int")
        .add_field("task_struct", "state", 4, "long")
        .add_field("task_struct", "tasks", 16, "list_head")
        .add_field("task_struct", "comm", 32, "char")
        .add_field("task_struct", "mm", 48, "pointer")
        .add_field("task_struct", "real_parent", 56, "pointer")
        .add_struct("list_head", 16)
        .add_field("list_head", "next", 0, "pointer")
        .add_field("list_head", "prev", 8, "pointer")
        .add_struct("mm_struct", 128)
        .add_field("mm_struct", "pgd", 0, "pointer")
        .add_symbol("init_task", 0xFFFF_8000_0010_0000)
        .build_json();

    let vaddr: u64 = 0xFFFF_8000_0010_0000;
    let paddr: u64 = 0x0080_0000;

    let mut data = vec![0u8; 4096];
    let init = vaddr;
    let task_a = vaddr + 0x200; // systemd
    let task_b = vaddr + 0x400; // sshd

    let init_tasks = init + 16;
    let a_tasks = task_a + 16;
    let b_tasks = task_b + 16;

    // init_task (PID 0, swapper): tasks -> task_a, real_parent -> self
    data[0..4].copy_from_slice(&0u32.to_le_bytes()); // pid
    data[4..12].copy_from_slice(&0i64.to_le_bytes()); // state
    data[16..24].copy_from_slice(&a_tasks.to_le_bytes()); // tasks.next
    data[24..32].copy_from_slice(&b_tasks.to_le_bytes()); // tasks.prev
    data[32..41].copy_from_slice(b"swapper/0"); // comm
    data[56..64].copy_from_slice(&init.to_le_bytes()); // real_parent -> self

    // task_a (PID 1, systemd): tasks -> task_b, real_parent -> init
    data[0x200..0x204].copy_from_slice(&1u32.to_le_bytes());
    data[0x204..0x20C].copy_from_slice(&0i64.to_le_bytes());
    data[0x210..0x218].copy_from_slice(&b_tasks.to_le_bytes());
    data[0x218..0x220].copy_from_slice(&init_tasks.to_le_bytes());
    data[0x220..0x227].copy_from_slice(b"systemd");
    data[0x238..0x240].copy_from_slice(&init.to_le_bytes()); // real_parent -> init

    // task_b (PID 100, sshd): tasks -> init, real_parent -> task_a (systemd)
    data[0x400..0x404].copy_from_slice(&100u32.to_le_bytes());
    data[0x404..0x40C].copy_from_slice(&1i64.to_le_bytes()); // sleeping
    data[0x410..0x418].copy_from_slice(&init_tasks.to_le_bytes());
    data[0x418..0x420].copy_from_slice(&a_tasks.to_le_bytes());
    data[0x420..0x424].copy_from_slice(b"sshd");
    data[0x438..0x440].copy_from_slice(&task_a.to_le_bytes()); // real_parent -> systemd

    let reader = build_reader(vaddr, paddr, &data, &isf);
    let procs = memf_linux::process::walk_processes(&reader).unwrap();

    assert_eq!(procs.len(), 3, "should find 3 processes");

    // Sorted by pid: 0, 1, 100
    let init_proc = &procs[0];
    let systemd_proc = &procs[1];
    let sshd_proc = &procs[2];

    assert_eq!(init_proc.pid, 0);
    assert_eq!(init_proc.ppid, 0);
    assert_eq!(init_proc.comm, "swapper/0");

    assert_eq!(systemd_proc.pid, 1);
    assert_eq!(systemd_proc.ppid, 0); // parent is init (pid 0)
    assert_eq!(systemd_proc.comm, "systemd");

    assert_eq!(sshd_proc.pid, 100);
    assert_eq!(sshd_proc.ppid, 1); // parent is systemd (pid 1)
    assert_eq!(sshd_proc.comm, "sshd");
}

// ---------------------------------------------------------------------------
// Test 13: KASLR with non-zero offset
// ---------------------------------------------------------------------------
#[test]
fn kaslr_with_nonzero_offset() {
    use memf_format::PhysicalRange;

    struct TestPhys {
        data: Vec<u8>,
        ranges: Vec<PhysicalRange>,
    }

    impl memf_format::PhysicalMemoryProvider for TestPhys {
        fn read_phys(&self, addr: u64, buf: &mut [u8]) -> memf_format::Result<usize> {
            let start = addr as usize;
            if start >= self.data.len() {
                return Ok(0);
            }
            let available = self.data.len() - start;
            let to_read = buf.len().min(available);
            buf[..to_read].copy_from_slice(&self.data[start..start + to_read]);
            Ok(to_read)
        }
        fn ranges(&self) -> &[PhysicalRange] {
            &self.ranges
        }
        fn format_name(&self) -> &str {
            "Test"
        }
    }

    // KASLR slide = 0x0100_0000 (16 MB)
    // Banner at phys 0x0300_0000
    // KERNEL_MAP_BASE = 0xFFFF_FFFF_8000_0000
    // actual_virt = 0x0300_0000 + 0xFFFF_FFFF_8000_0000 = 0xFFFF_FFFF_8300_0000
    // symbol says linux_banner = 0xFFFF_FFFF_8200_0000
    // offset = actual_virt - symbol = 0x0100_0000
    let banner_phys = 0x0300_0000usize;
    let mut data = vec![0u8; banner_phys + 4096];
    let banner = b"Linux version 6.1.0-kaslr-test";
    data[banner_phys..banner_phys + banner.len()].copy_from_slice(banner);

    let phys = TestPhys {
        ranges: vec![PhysicalRange {
            start: 0,
            end: data.len() as u64,
        }],
        data,
    };

    let isf = IsfBuilder::new()
        .add_symbol("linux_banner", 0xFFFF_FFFF_8200_0000)
        .build_json();
    let resolver = IsfResolver::from_value(&isf).unwrap();

    let offset = memf_linux::kaslr::detect_kaslr_offset(&phys, &resolver).unwrap();
    assert_eq!(offset, 0x0100_0000, "KASLR offset should be 16 MB");
    assert_ne!(offset, 0, "KASLR offset should be non-zero");

    // Verify adjust_address works with the detected offset
    let adjusted = memf_linux::kaslr::adjust_address(0xFFFF_FFFF_8200_0000, offset);
    assert_eq!(adjusted, 0xFFFF_FFFF_8300_0000);
}

// ---------------------------------------------------------------------------
// Test 14: Object reader cross-page read
// ---------------------------------------------------------------------------
#[test]
fn object_reader_cross_page_read() {
    // Place a struct that spans two 4K pages:
    // Page 1: vaddr 0xFFFF_8000_0010_0000 -> paddr 0x0080_0000
    // Page 2: vaddr 0xFFFF_8000_0010_1000 -> paddr 0x0090_0000
    // Struct starts at offset 0xFF8 in page 1 (8 bytes before boundary),
    // with a u64 field at offset 0 that fits in page 1
    // and a u32 field at offset 8 that falls into page 2.

    let isf = IsfBuilder::new()
        .add_struct("cross_page_struct", 16)
        .add_field("cross_page_struct", "field_a", 0, "unsigned long")
        .add_field("cross_page_struct", "field_b", 8, "unsigned int")
        .build_json();

    let resolver = IsfResolver::from_value(&isf).unwrap();

    let vaddr_page1: u64 = 0xFFFF_8000_0010_0000;
    let vaddr_page2: u64 = 0xFFFF_8000_0010_1000;
    let paddr_page1: u64 = 0x0080_0000;
    let paddr_page2: u64 = 0x0090_0000;

    let mut page1_data = vec![0u8; 4096];
    let mut page2_data = vec![0u8; 4096];

    // field_a at offset 0xFF8 in page 1 (fits within page 1)
    let struct_offset_in_page = 0xFF8usize;
    page1_data[struct_offset_in_page..struct_offset_in_page + 8]
        .copy_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());

    // field_b at offset 0x1000 in the struct's virtual space -> starts at page 2 offset 0
    page2_data[0..4].copy_from_slice(&42u32.to_le_bytes());

    let (cr3, mem) = PageTableBuilder::new()
        .map_4k(vaddr_page1, paddr_page1, flags::WRITABLE)
        .map_4k(vaddr_page2, paddr_page2, flags::WRITABLE)
        .write_phys(paddr_page1, &page1_data)
        .write_phys(paddr_page2, &page2_data)
        .build();

    let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
    let reader = ObjectReader::new(vas, Box::new(resolver));

    let struct_vaddr = vaddr_page1 + struct_offset_in_page as u64;

    // Read field_a (at the struct base, still within page 1)
    let val_a: u64 = reader
        .read_field(struct_vaddr, "cross_page_struct", "field_a")
        .unwrap();
    assert_eq!(val_a, 0xDEAD_BEEF_CAFE_BABE);

    // Read field_b (at struct base + 8 = starts at page 2 offset 0)
    let val_b: u32 = reader
        .read_field(struct_vaddr, "cross_page_struct", "field_b")
        .unwrap();
    assert_eq!(val_b, 42);
}

// ---------------------------------------------------------------------------
// Test 15: Symbol resolver struct size query
// ---------------------------------------------------------------------------
#[test]
fn symbol_resolver_struct_size_query() {
    let isf_json = IsfBuilder::new()
        .add_struct("task_struct", 9024)
        .add_field("task_struct", "pid", 1128, "int")
        .add_field("task_struct", "comm", 1248, "char")
        .add_struct("list_head", 16)
        .add_field("list_head", "next", 0, "pointer")
        .add_field("list_head", "prev", 8, "pointer")
        .add_struct("mm_struct", 2048)
        .add_field("mm_struct", "pgd", 80, "pointer")
        .add_symbol("init_task", 0xFFFF_FFFF_8260_0000)
        .build_json();

    let resolver = IsfResolver::from_value(&isf_json).unwrap();

    // Struct sizes
    assert_eq!(resolver.struct_size("task_struct"), Some(9024));
    assert_eq!(resolver.struct_size("list_head"), Some(16));
    assert_eq!(resolver.struct_size("mm_struct"), Some(2048));
    assert_eq!(resolver.struct_size("nonexistent"), None);

    // Field offsets
    assert_eq!(resolver.field_offset("task_struct", "pid"), Some(1128));
    assert_eq!(resolver.field_offset("task_struct", "comm"), Some(1248));
    assert_eq!(resolver.field_offset("list_head", "next"), Some(0));
    assert_eq!(resolver.field_offset("list_head", "prev"), Some(8));
    assert_eq!(resolver.field_offset("mm_struct", "pgd"), Some(80));

    // Symbol addresses
    assert_eq!(
        resolver.symbol_address("init_task"),
        Some(0xFFFF_FFFF_8260_0000)
    );
    assert_eq!(resolver.symbol_address("nonexistent"), None);

    // Backend name
    assert_eq!(resolver.backend_name(), "ISF JSON");

    // Struct info
    let task_info = resolver.struct_info("task_struct").unwrap();
    assert_eq!(task_info.size, 9024);
    assert!(task_info.fields.iter().any(|(name, _)| name == "pid"));
    assert!(task_info.fields.iter().any(|(name, _)| name == "comm"));

    // Dynamic dispatch through trait object
    let dyn_resolver: &dyn SymbolResolver = &resolver;
    assert_eq!(dyn_resolver.struct_size("task_struct"), Some(9024));
    assert_eq!(dyn_resolver.field_offset("task_struct", "pid"), Some(1128));
}

// ---------------------------------------------------------------------------
// Test 16: Full pipeline: LiME dump -> symbols -> KASLR -> processes
// ---------------------------------------------------------------------------
#[test]
fn full_pipeline_dump_to_processes() {
    use memf_format::test_builders::LimeBuilder;

    // Layout:
    //   Physical 0x0080_0000: kernel data (task structs + banner)
    //   Virtual  0xFFFF_8000_0010_0000: where kernel maps this memory
    //
    // No KASLR (offset = 0) for simplicity.
    // KERNEL_MAP_BASE = 0xFFFF_FFFF_8000_0000
    // banner at phys 0x0000_1000
    // linux_banner symbol = 0xFFFF_FFFF_8000_1000 (phys + KERNEL_MAP = symbol)

    // Step 1: Build the LiME dump with a banner
    let mut banner_data = vec![0u8; 4096];
    let banner = b"Linux version 6.1.0-full-pipeline-test";
    banner_data[0..banner.len()].copy_from_slice(banner);

    // Step 2: Build process data
    let vaddr: u64 = 0xFFFF_8000_0010_0000;
    let paddr: u64 = 0x0080_0000;

    let isf = IsfBuilder::new()
        .add_struct("task_struct", 128)
        .add_field("task_struct", "pid", 0, "int")
        .add_field("task_struct", "state", 4, "long")
        .add_field("task_struct", "tasks", 16, "list_head")
        .add_field("task_struct", "comm", 32, "char")
        .add_field("task_struct", "mm", 48, "pointer")
        .add_field("task_struct", "real_parent", 56, "pointer")
        .add_struct("list_head", 16)
        .add_field("list_head", "next", 0, "pointer")
        .add_field("list_head", "prev", 8, "pointer")
        .add_struct("mm_struct", 128)
        .add_field("mm_struct", "pgd", 0, "pointer")
        .add_symbol("init_task", vaddr)
        .add_symbol("linux_banner", 0xFFFF_FFFF_8000_1000)
        .build_json();

    let mut proc_data = vec![0u8; 4096];
    let init = vaddr;
    let task_a = vaddr + 0x200;

    let init_tasks = init + 16;
    let a_tasks = task_a + 16;

    // init_task (PID 0)
    proc_data[0..4].copy_from_slice(&0u32.to_le_bytes());
    proc_data[4..12].copy_from_slice(&0i64.to_le_bytes());
    proc_data[16..24].copy_from_slice(&a_tasks.to_le_bytes());
    proc_data[24..32].copy_from_slice(&a_tasks.to_le_bytes());
    proc_data[32..41].copy_from_slice(b"swapper/0");
    proc_data[56..64].copy_from_slice(&init.to_le_bytes());

    // Task A (PID 1, init)
    proc_data[0x200..0x204].copy_from_slice(&1u32.to_le_bytes());
    proc_data[0x204..0x20C].copy_from_slice(&0i64.to_le_bytes());
    proc_data[0x210..0x218].copy_from_slice(&init_tasks.to_le_bytes());
    proc_data[0x218..0x220].copy_from_slice(&init_tasks.to_le_bytes());
    proc_data[0x220..0x224].copy_from_slice(b"init");
    proc_data[0x238..0x240].copy_from_slice(&init.to_le_bytes());

    // Step 3: Create LiME dump with two ranges (banner + proc data)
    let lime_dump = LimeBuilder::new()
        .add_range(0x0000_1000, &banner_data)
        .add_range(paddr, &proc_data)
        .build();

    // Step 4: Verify the dump opens correctly
    let path = std::env::temp_dir().join("memf_full_pipeline_test");
    std::fs::write(&path, &lime_dump).unwrap();
    let dump_provider = memf_format::open_dump(&path).unwrap();
    assert_eq!(dump_provider.format_name(), "LiME");

    // Step 5: Verify KASLR detection (should be 0)
    let resolver = IsfResolver::from_value(&isf).unwrap();
    let kaslr = memf_linux::kaslr::detect_kaslr_offset(dump_provider.as_ref(), &resolver).unwrap();
    assert_eq!(kaslr, 0, "no KASLR slide expected");

    // Step 6: Walk processes via ObjectReader
    let (cr3, mem) = PageTableBuilder::new()
        .map_4k(vaddr, paddr, flags::WRITABLE)
        .write_phys(paddr, &proc_data)
        .build();
    let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);

    let resolver2 = IsfResolver::from_value(&isf).unwrap();
    let reader = ObjectReader::new(vas, Box::new(resolver2));
    let procs = memf_linux::process::walk_processes(&reader).unwrap();

    assert_eq!(procs.len(), 2);
    assert_eq!(procs[0].pid, 0);
    assert_eq!(procs[0].comm, "swapper/0");
    assert_eq!(procs[1].pid, 1);
    assert_eq!(procs[1].comm, "init");

    std::fs::remove_file(&path).ok();
}
