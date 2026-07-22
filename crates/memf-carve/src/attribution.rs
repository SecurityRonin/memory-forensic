//! Coarse memory attribution and per-process VAD → region enumeration.

use forensic_carve::Region;
use memf_windows::WinVadInfo;

/// The medium-specific attribution tag carried on every carved item from a memory
/// sweep (the `R` in [`forensic_carve::Region`] / [`forensic_carve::SweptItem`]).
///
/// Attribution is **coarse** by construction: the VAD walker
/// ([`memf_windows::vad::walk_vad_tree`]) exposes only owner PID, region VA span,
/// protection index, and a private flag — there is no Heap/Stack/MappedFile
/// classification, so none is invented here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemAttribution {
    /// Owning process id.
    pub pid: u64,
    /// Owning process image name.
    pub process: String,
    /// Start virtual address of the VAD region the item was found in.
    pub va_start: u64,
    /// Raw `VadFlags.Protection` index (see `memf_windows` protection table).
    pub protection: u32,
    /// Whether the VAD is a private allocation (not file-backed).
    pub is_private: bool,
}

/// Map a process's VAD entries to sweepable [`forensic_carve::Region`]s, one per VAD,
/// each tagged with coarse [`MemAttribution`].
///
/// `pid` / `process` identify the owning process for the tag; per-region VA span,
/// protection, and private flag come from each [`WinVadInfo`]. The region length is
/// inclusive-end-corrected (a VAD's `end_vaddr` is the last addressable byte, i.e.
/// `... | 0xFFF`).
#[must_use]
pub fn process_regions(
    vads: &[WinVadInfo],
    pid: u64,
    process: &str,
) -> Vec<Region<MemAttribution>> {
    // stub — replaced in GREEN
    let _ = (vads, pid, process);
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vad(start: u64, end: u64, protection: u32, is_private: bool) -> WinVadInfo {
        WinVadInfo {
            pid: 4321,
            image_name: "evil.exe".to_string(),
            start_vaddr: start,
            end_vaddr: end,
            protection,
            protection_str: String::new(),
            is_private,
        }
    }

    #[test]
    fn maps_each_vad_to_a_region_with_coarse_attribution() {
        let vads = vec![
            vad(0x0001_0000, 0x0001_2FFF, 6, true), // 3 pages, EXEC_RW, private
            vad(0x7FFE_0000, 0x7FFE_0FFF, 4, false), // 1 page, READWRITE, mapped
        ];
        let regions = process_regions(&vads, 4321, "evil.exe");

        assert_eq!(regions.len(), 2);

        assert_eq!(regions[0].start, 0x0001_0000);
        assert_eq!(regions[0].len, 0x3000); // inclusive end 0x12FFF -> 3 pages
        assert_eq!(regions[0].tag.pid, 4321);
        assert_eq!(regions[0].tag.process, "evil.exe");
        assert_eq!(regions[0].tag.va_start, 0x0001_0000);
        assert_eq!(regions[0].tag.protection, 6);
        assert!(regions[0].tag.is_private);

        assert_eq!(regions[1].start, 0x7FFE_0000);
        assert_eq!(regions[1].len, 0x1000);
        assert_eq!(regions[1].tag.protection, 4);
        assert!(!regions[1].tag.is_private);
    }
}
