//! The Plane-V carve driver: sweep one process's virtual address space.

use forensic_carve::{sweep, CarveOptions, Carver, RecoveryMethod, SweptItem};
use memf_core::vas::VirtualAddressSpace;
use memf_format::PhysicalMemoryProvider;
use memf_windows::WinVadInfo;

use crate::attribution::{process_regions, MemAttribution};
use crate::region_source::VaRegionSource;

/// Carve one process's virtual address space (Plane-V).
///
/// Builds a [`VaRegionSource`] over `vas`, enumerates the process's VAD regions, and
/// runs [`forensic_carve::sweep`] — the engine does detection and
/// materialize-around-hit through the source's `read_at`, so this driver only wires
/// the memory medium. The sweep's recovery method is **forced** to
/// [`RecoveryMethod::MemoryCarve`] regardless of `opts.recovery_method`, so the same
/// (medium-agnostic) carvers stamp `MemoryCarve` here.
///
/// Carvers are injected by the caller (a binary force-links parser crates and passes
/// [`forensic_carve::registered_carvers`]); this crate never depends on a parser.
pub fn carve_process<P: PhysicalMemoryProvider>(
    vas: &VirtualAddressSpace<P>,
    vads: &[WinVadInfo],
    pid: u64,
    process: &str,
    carvers: &[&dyn Carver],
    opts: &CarveOptions,
) -> Vec<SweptItem<MemAttribution>> {
    let source = VaRegionSource::new(vas);
    let regions = process_regions(vads, pid, process);
    // The memory medium owns its recovery method — force it regardless of what the
    // caller set, so the medium-agnostic carvers stamp MemoryCarve.
    let opts = CarveOptions {
        recovery_method: RecoveryMethod::MemoryCarve,
        ..opts.clone()
    };
    sweep(&source, regions, carvers, &opts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_carve::{CarveContext, CarvedItem, Signature};
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::TranslationMode;

    /// A minimal test carver: `b"ZZ"` magic, validates a second byte pair before
    /// emitting (a bare magic alone must not), echoes the driver's recovery method.
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

    const VART: u64 = 0x0002_0000; // page-aligned region start
    const PA: u64 = 0x0090_0000;
    const ART_OFF: u64 = 0x100; // artifact sits mid-region

    fn vas_with_artifact() -> VirtualAddressSpace<SyntheticPhysMem> {
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(VART, PA, flags::WRITABLE)
            .write_phys(PA + ART_OFF, b"ZZ!!\xDE\xAD\xBE\xEF")
            .build();
        VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel)
    }

    fn one_vad() -> Vec<WinVadInfo> {
        vec![WinVadInfo {
            pid: 4321,
            image_name: "evil.exe".to_string(),
            start_vaddr: VART,
            end_vaddr: VART | 0xFFF, // one page, inclusive end
            protection: 6,
            protection_str: String::new(),
            is_private: true,
        }]
    }

    #[test]
    fn carves_artifact_from_process_vas_and_stamps_memory_carve() {
        let vas = vas_with_artifact();
        let vads = one_vad();
        let carver = ZzCarver;
        let carvers: [&dyn Carver; 1] = [&carver];
        // opts default to UnallocatedCarve — the driver must FORCE MemoryCarve.
        let opts = CarveOptions::default();

        let items = carve_process(&vas, &vads, 4321, "evil.exe", &carvers, &opts);

        assert_eq!(items.len(), 1, "one ZZ artifact carved from the VAD");
        let hit = &items[0];
        assert_eq!(hit.item.format(), "zztest");
        assert_eq!(hit.item.recovery_method(), RecoveryMethod::MemoryCarve);
        assert_eq!(hit.offset, VART + ART_OFF);
        // coarse attribution rides back out on the region tag
        assert_eq!(hit.region.pid, 4321);
        assert_eq!(hit.region.process, "evil.exe");
        assert_eq!(hit.region.va_start, VART);
        assert_eq!(hit.region.protection, 6);
        assert!(hit.region.is_private);
    }
}
