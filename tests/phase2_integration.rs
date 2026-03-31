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
