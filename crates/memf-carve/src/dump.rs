//! The Plane-V multi-process carve driver: carve every process in a memory dump.

use forensic_carve::{CarveOptions, Carver, SweptItem};
use memf_core::object_reader::ObjectReader;
use memf_core::vas::VirtualAddressSpace;
use memf_format::PhysicalMemoryProvider;
use memf_windows::vad::walk_vad_tree;
use memf_windows::{Error, Result, WinProcessInfo, WinVadInfo};

use crate::attribution::MemAttribution;
use crate::driver::carve_process;

/// One process resolved to the pieces a Plane-V carve needs: its **user** virtual
/// address space, its VAD regions, and coarse identity (pid / image name).
///
/// This is the seam between process *discovery* (owned by `memf-windows`) and the
/// carve: [`carve_dump`] consumes already-resolved views, so it is fully unit-
/// testable over synthetic address spaces without a live `_EPROCESS`/`VadRoot`
/// walk. [`carve_dump_from_processes`] is the thin resolver that produces views
/// from a real Windows process list.
pub struct ProcessView<P: PhysicalMemoryProvider> {
    /// The process's user virtual address space (built from its `cr3`/DirBase).
    pub vas: VirtualAddressSpace<P>,
    /// The process's VAD regions (from `walk_vad_tree`).
    pub vads: Vec<WinVadInfo>,
    /// Owning process id.
    pub pid: u64,
    /// Owning process image name.
    pub process: String,
}

/// Carve every process in an already-resolved set of [`ProcessView`]s (Plane-V).
///
/// Runs [`carve_process`] over each view and concatenates the results; every item
/// carries its owning process's pid / name on the region tag and is stamped
/// [`forensic_carve::RecoveryMethod::MemoryCarve`] (forced by `carve_process`).
/// Carvers are injected by the caller — this crate never depends on a parser.
pub fn carve_dump<P, I>(
    views: I,
    carvers: &[&dyn Carver],
    opts: &CarveOptions,
) -> Vec<SweptItem<MemAttribution>>
where
    P: PhysicalMemoryProvider,
    I: IntoIterator<Item = ProcessView<P>>,
{
    let mut items = Vec::new();
    for view in views {
        items.extend(carve_process(
            &view.vas,
            &view.vads,
            view.pid,
            &view.process,
            carvers,
            opts,
        ));
    }
    items
}

/// Resolve each Windows process to a [`ProcessView`], then carve the whole dump.
///
/// For every user process (non-null `Peb`) the kernel `reader` resolves
/// `_EPROCESS.VadRoot` and walks its VAD tree, and the process's **user** VAS is
/// built from its own `cr3`/DirBase over a clone of the shared physical memory
/// (`P: Clone`). The physical bytes and translation mode are taken from the reader
/// itself, so the per-process VAS is guaranteed to read the *same* memory the
/// walker used — no way to pass a mismatched source.
///
/// Failures are separated by depth (fail-loud vs degrade-to-empty): a missing
/// `_EPROCESS.VadRoot` symbol is a **bootstrap** failure and surfaces as
/// [`Error::MissingField`]; a single process whose VAD tree is paged-out / smeared
/// is a **per-item** miss and is skipped so one torn process never aborts the dump.
///
/// # Boundary
///
/// Process *discovery* is not performed here — the caller supplies `processes`
/// (from [`memf_windows::process::walk_processes`]). This resolver is exercised
/// end-to-end against a real dump via an env-gated integration test; its unit
/// tests drive it over synthetic Windows fixtures.
pub fn carve_dump_from_processes<P>(
    reader: &ObjectReader<P>,
    processes: &[WinProcessInfo],
    carvers: &[&dyn Carver],
    opts: &CarveOptions,
) -> Result<Vec<SweptItem<MemAttribution>>>
where
    P: PhysicalMemoryProvider + Clone,
{
    // Bootstrap: the VadRoot offset is a prerequisite for EVERY process. A missing
    // symbol must fail loud, never collapse into an empty "no artifacts" result.
    let vad_root_offset = reader
        .symbols()
        .field_offset("_EPROCESS", "VadRoot")
        .ok_or(Error::MissingField {
            struct_name: "_EPROCESS".to_string(),
            field_name: "VadRoot".to_string(),
        })?;
    let mode = reader.vas().mode();

    let mut views = Vec::new();
    for proc in processes {
        if proc.peb_addr == 0 {
            continue; // kernel / minimal processes carry no user VAD tree
        }
        let vad_root_addr = proc.vaddr.wrapping_add(vad_root_offset);
        // A per-process miss (paged-out / corrupt VAD tree) is degrade-to-empty AFTER
        // the validated bootstrap: skip the one process, never abort the dump.
        let Ok(vads) = walk_vad_tree(reader, vad_root_addr, proc.pid, &proc.image_name) else {
            continue;
        };
        let vas = VirtualAddressSpace::new(reader.vas().physical().clone(), proc.cr3, mode);
        views.push(ProcessView {
            vas,
            vads,
            pid: proc.pid,
            process: proc.image_name.clone(),
        });
    }

    Ok(carve_dump(views, carvers, opts))
}

#[cfg(test)]
mod tests {
    use crate::dump::{carve_dump, carve_dump_from_processes, ProcessView};
    use forensic_carve::{
        CarveContext, CarveOptions, CarvedItem, Carver, RecoveryMethod, Signature,
    };
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;
    use memf_windows::{WinProcessInfo, WinVadInfo};

    /// A minimal test carver: `b"ZZ!!"` magic (a bare `ZZ` alone must not emit),
    /// echoing the driver's forced recovery method.
    struct ZzCarver;
    const ZZ_SIG: [Signature; 1] = [Signature::new(b"ZZ", 0)];

    impl Carver for ZzCarver {
        fn format(&self) -> &'static str {
            "zztest"
        }
        fn signatures(&self) -> &[Signature] {
            &ZZ_SIG
        }
        fn max_window(&self) -> u64 {
            16
        }
        fn carve(&self, window: &[u8], ctx: &CarveContext) -> Vec<CarvedItem> {
            if window.len() >= 4 && &window[..2] == b"ZZ" && &window[2..4] == b"!!" {
                vec![CarvedItem::artifact_bytes(
                    "zztest",
                    ctx.base_offset(),
                    1.0,
                    ctx.recovery_method(),
                    window[..4].to_vec(),
                )]
            } else {
                Vec::new()
            }
        }
    }

    const ART_OFF: u64 = 0x100; // artifact sits mid-page

    /// One process's VAS: `vart` (page-aligned) mapped to `pa`, artifact mid-page.
    fn vas_with_artifact(vart: u64, pa: u64) -> VirtualAddressSpace<SyntheticPhysMem> {
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vart, pa, flags::WRITABLE)
            .write_phys(pa + ART_OFF, b"ZZ!!\xDE\xAD\xBE\xEF")
            .build();
        VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel)
    }

    fn one_vad(pid: u64, name: &str, vart: u64) -> Vec<WinVadInfo> {
        vec![WinVadInfo {
            pid,
            image_name: name.to_string(),
            start_vaddr: vart,
            end_vaddr: vart | 0xFFF, // one page, inclusive end
            protection: 6,
            protection_str: String::new(),
            is_private: true,
        }]
    }

    #[test]
    fn carve_dump_carves_every_process_and_attributes_each_to_its_pid() {
        let view_a = ProcessView {
            vas: vas_with_artifact(0x0002_0000, 0x0090_0000),
            vads: one_vad(100, "alpha.exe", 0x0002_0000),
            pid: 100,
            process: "alpha.exe".to_string(),
        };
        let view_b = ProcessView {
            vas: vas_with_artifact(0x0003_0000, 0x0090_0000),
            vads: one_vad(200, "beta.exe", 0x0003_0000),
            pid: 200,
            process: "beta.exe".to_string(),
        };
        let carver = ZzCarver;
        let carvers: [&dyn Carver; 1] = [&carver];
        let opts = CarveOptions::default(); // defaults to UnallocatedCarve — must be forced

        let items = carve_dump(vec![view_a, view_b], &carvers, &opts);

        assert_eq!(items.len(), 2, "one artifact carved from each process");
        let pids: Vec<u64> = items.iter().map(|i| i.region.pid).collect();
        assert!(pids.contains(&100), "process 100 attributed");
        assert!(pids.contains(&200), "process 200 attributed");
        for it in &items {
            assert_eq!(it.item.format(), "zztest");
            assert_eq!(
                it.item.recovery_method(),
                RecoveryMethod::MemoryCarve,
                "the memory medium forces MemoryCarve"
            );
        }
        let alpha = items.iter().find(|i| i.region.pid == 100).unwrap();
        assert_eq!(alpha.region.process, "alpha.exe");
        assert_eq!(alpha.offset, 0x0002_0000 + ART_OFF);
    }

    // _MMVAD_SHORT direct layout (windows_kernel_preset): Left@0x0, Right@0x8,
    // StartingVpn@0x18, EndingVpn@0x20, Flags@0x30; _RTL_AVL_TREE.Root@0x0.
    const VAD_STARTING_VPN: usize = 0x18;
    const VAD_ENDING_VPN: usize = 0x20;
    const VAD_FLAGS: usize = 0x30;

    /// End-to-end resolver over a synthetic Windows fixture.
    ///
    /// The test builder has a single cr3 (`0`), so the kernel VAS the walker reads
    /// and the per-process user VAS built from `proc.cr3` collapse into one address
    /// space — that is why the artifact mapped for the VAD walker is also reachable
    /// through the process VAS. A real dump keeps kernel cr3 and `proc.cr3`
    /// separate; that split is exercised only against a real dump (env-gated).
    #[test]
    fn carve_dump_from_processes_resolves_vads_builds_user_vas_and_carves() {
        const VAD_PAGE_VA: u64 = 0xFFFF_8000_0010_0000; // kernel VA of _RTL_AVL_TREE + node
        const VAD_PAGE_PA: u64 = 0x0080_0000;
        const NODE_OFF: usize = 0x100; // _MMVAD_SHORT offset within the page
        const ART_VA: u64 = 0x0010_0000; // user region start = StartingVpn(0x100) << 12
        const ART_PA: u64 = 0x00A0_0000;

        let mut page = vec![0u8; 4096];
        let root_vaddr = VAD_PAGE_VA + NODE_OFF as u64;
        page[0..8].copy_from_slice(&root_vaddr.to_le_bytes()); // _RTL_AVL_TREE.Root
        page[NODE_OFF + VAD_STARTING_VPN..NODE_OFF + VAD_STARTING_VPN + 8]
            .copy_from_slice(&0x100u64.to_le_bytes());
        page[NODE_OFF + VAD_ENDING_VPN..NODE_OFF + VAD_ENDING_VPN + 8]
            .copy_from_slice(&0x100u64.to_le_bytes());
        let vad_flags = 6u32 << 3; // protection index 6 at Win8+ bit position 3
        page[NODE_OFF + VAD_FLAGS..NODE_OFF + VAD_FLAGS + 4]
            .copy_from_slice(&vad_flags.to_le_bytes());

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(VAD_PAGE_VA, VAD_PAGE_PA, flags::WRITABLE)
            .write_phys(VAD_PAGE_PA, &page)
            .map_4k(ART_VA, ART_PA, flags::WRITABLE)
            .write_phys(ART_PA + ART_OFF, b"ZZ!!\xDE\xAD\xBE\xEF")
            .build();
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let vad_root_offset = reader
            .symbols()
            .field_offset("_EPROCESS", "VadRoot")
            .unwrap();
        // eproc + VadRoot offset must land on the _RTL_AVL_TREE page.
        let eproc_vaddr = VAD_PAGE_VA.wrapping_sub(vad_root_offset);

        let proc = WinProcessInfo {
            pid: 100,
            ppid: 0,
            image_name: "alpha.exe".to_string(),
            create_time: 0,
            exit_time: 0,
            cr3,
            peb_addr: 1, // non-zero: a user process, not skipped as kernel
            vaddr: eproc_vaddr,
            thread_count: 0,
            is_wow64: false,
            handle_count: 0,
            session_id: 0,
        };

        let carver = ZzCarver;
        let carvers: [&dyn Carver; 1] = [&carver];
        let items = carve_dump_from_processes(&reader, &[proc], &carvers, &CarveOptions::default())
            .unwrap();

        assert_eq!(items.len(), 1, "the process's VAD artifact is carved");
        assert_eq!(items[0].region.pid, 100);
        assert_eq!(items[0].region.process, "alpha.exe");
        assert_eq!(items[0].item.recovery_method(), RecoveryMethod::MemoryCarve);
        assert_eq!(items[0].offset, ART_VA + ART_OFF);
    }

    /// Per-process misses degrade to nothing (never abort the dump): a kernel
    /// process (`peb_addr == 0`) is skipped, and a user process whose `VadRoot`
    /// points at unmapped memory has its VAD walk fail and is skipped too.
    #[test]
    fn carve_dump_from_processes_skips_kernel_and_unresolvable_processes() {
        let isf = IsfBuilder::windows_kernel_preset().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let make_proc = |pid: u64, peb: u64, vaddr: u64| WinProcessInfo {
            pid,
            ppid: 0,
            image_name: "p.exe".to_string(),
            create_time: 0,
            exit_time: 0,
            cr3,
            peb_addr: peb,
            vaddr,
            thread_count: 0,
            is_wow64: false,
            handle_count: 0,
            session_id: 0,
        };
        let kernel = make_proc(4, 0, 0); // peb_addr == 0 → skipped
        let smeared = make_proc(200, 1, 0); // VadRoot at unmapped VA → walk fails → skipped

        let carver = ZzCarver;
        let carvers: [&dyn Carver; 1] = [&carver];
        let items = carve_dump_from_processes(
            &reader,
            &[kernel, smeared],
            &carvers,
            &CarveOptions::default(),
        )
        .unwrap();

        assert!(
            items.is_empty(),
            "no carveable process → empty, not an error"
        );
    }

    /// An ISF lacking `_EPROCESS.VadRoot` is a bootstrap failure, not a silent
    /// empty result: the resolver errors loudly before touching any process.
    #[test]
    fn carve_dump_from_processes_errors_when_vadroot_symbol_missing() {
        let isf = IsfBuilder::new().add_struct("_EPROCESS", 2048).build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let carver = ZzCarver;
        let carvers: [&dyn Carver; 1] = [&carver];
        let result = carve_dump_from_processes(&reader, &[], &carvers, &CarveOptions::default());

        assert!(
            matches!(
                result,
                Err(memf_windows::Error::MissingField { ref struct_name, ref field_name })
                    if struct_name == "_EPROCESS" && field_name == "VadRoot"
            ),
            "missing VadRoot must surface as MissingField, got {result:?}"
        );
    }
}
