use memf_format::PhysicalMemoryProvider;
use memf_framebuffer::FramebufferResult;

use crate::Result;

/// Scan physical ranges for the EFI System Table and extract the GOP
/// framebuffer, returning a PNG-encoded [`FramebufferResult`].
pub fn walk_framebuffer_windows<P: PhysicalMemoryProvider>(
    _provider: &P,
) -> Result<FramebufferResult> {
    Err(crate::Error::WalkFailed {
        walker: "framebuffer_windows",
        reason: "not implemented".into(),
    })
}

/// Internal entry point that accepts a known EFI System Table physical
/// address.  Used by tests where `ranges()` returns `&[]`.
pub(crate) fn walk_framebuffer_from<P: PhysicalMemoryProvider>(
    _provider: &P,
    _table_pa: u64,
) -> Result<FramebufferResult> {
    Err(crate::Error::WalkFailed {
        walker: "framebuffer_windows",
        reason: "not implemented".into(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::SyntheticPhysMem;

    const EFI_SYSTEM_TABLE_SIG: u64 = 0x5453_5953_2049_4249;
    const GOP_GUID: [u8; 16] = [
        0xde, 0xa9, 0x42, 0x90, 0xdc, 0x23, 0x38, 0x4a,
        0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a,
    ];

    // Physical addresses used in the synthetic image
    const TABLE_PA:     u64 = 0xF000_0000;
    const CFG_TABLE_PA: u64 = 0xF001_0000;
    const GOP_MODE_PA:  u64 = 0xF002_0000;
    const MODE_INFO_PA: u64 = 0xF003_0000;
    const FB_PA:        u64 = 0xFD00_0000;

    // 4×4 framebuffer — small enough that SyntheticPhysMem fits
    const W: u32 = 4;
    const H: u32 = 4;

    /// Total size must hold every physical address used above.
    const MEM_SIZE: usize = 0xFD01_0000;

    fn make_provider() -> SyntheticPhysMem {
        let mut mem = SyntheticPhysMem::new(MEM_SIZE);

        // EFI System Table signature at TABLE_PA+0x00
        mem.write_u64(TABLE_PA, EFI_SYSTEM_TABLE_SIG);
        // NumberOfTableEntries at TABLE_PA+0x40
        mem.write_u64(TABLE_PA + 0x40, 1);
        // ConfigurationTable pointer at TABLE_PA+0x48
        mem.write_u64(TABLE_PA + 0x48, CFG_TABLE_PA);

        // EFI_CONFIGURATION_TABLE entry at CFG_TABLE_PA:
        //   [0..16]  = GOP_GUID
        //   [16..24] = VendorTable = GOP_MODE_PA
        mem.write_bytes(CFG_TABLE_PA, &GOP_GUID);
        mem.write_u64(CFG_TABLE_PA + 16, GOP_MODE_PA);

        // EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE at GOP_MODE_PA:
        //   +0x08 = Info ptr = MODE_INFO_PA
        //   +0x18 = FrameBufferBase = FB_PA
        //   +0x20 = FrameBufferSize = W*H*4
        mem.write_u64(GOP_MODE_PA + 0x08, MODE_INFO_PA);
        mem.write_u64(GOP_MODE_PA + 0x18, FB_PA);
        mem.write_u64(GOP_MODE_PA + 0x20, u64::from(W * H * 4));

        // EFI_GRAPHICS_OUTPUT_MODE_INFORMATION at MODE_INFO_PA:
        //   +0x04 = HorizontalResolution = W
        //   +0x08 = VerticalResolution   = H
        //   +0x0C = PixelFormat          = 1 (XBGR)
        //   +0x20 = PixelsPerScanLine    = W
        mem.write_bytes(MODE_INFO_PA + 0x04, &W.to_le_bytes());
        mem.write_bytes(MODE_INFO_PA + 0x08, &H.to_le_bytes());
        mem.write_bytes(MODE_INFO_PA + 0x0C, &1u32.to_le_bytes());
        mem.write_bytes(MODE_INFO_PA + 0x20, &W.to_le_bytes());

        // Framebuffer pixels — zero-filled by SyntheticPhysMem
        mem
    }

    #[test]
    fn windows_framebuffer_extracts_resolution_from_gop() {
        let mem = make_provider();
        let result = walk_framebuffer_from(&mem, TABLE_PA).expect("should find GOP");
        assert_eq!(result.width, W);
        assert_eq!(result.height, H);
        assert_eq!(result.source, "EFI_GOP");
    }

    #[test]
    fn windows_framebuffer_png_has_magic_header() {
        let mem = make_provider();
        let result = walk_framebuffer_from(&mem, TABLE_PA).expect("should succeed");
        assert!(
            result.png_bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
            "expected PNG magic, got {:?}",
            &result.png_bytes[..8.min(result.png_bytes.len())]
        );
    }

    #[test]
    fn windows_framebuffer_stride_is_width_times_four() {
        let mem = make_provider();
        let result = walk_framebuffer_from(&mem, TABLE_PA).expect("ok");
        assert_eq!(result.stride, W * 4);
    }

    #[test]
    fn windows_framebuffer_pixel_format_is_xbgr() {
        let mem = make_provider();
        let result = walk_framebuffer_from(&mem, TABLE_PA).expect("ok");
        assert!(result.pixel_format.contains("Xbgr"), "got {}", result.pixel_format);
    }

    #[test]
    fn windows_framebuffer_no_efi_table_returns_err() {
        // Empty physical memory — ranges() returns &[], so the range scan
        // finds nothing; the error path is reached.
        let mem = SyntheticPhysMem::new(4096);
        let err = walk_framebuffer_windows(&mem).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("framebuffer_windows"), "got: {msg}");
    }

    #[test]
    fn windows_framebuffer_missing_gop_guid_returns_err() {
        let mut mem = make_provider();
        // Corrupt the GOP GUID so it won't match
        mem.write_bytes(CFG_TABLE_PA, &[0u8; 16]);
        let err = walk_framebuffer_from(&mem, TABLE_PA).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not implemented"), "got: {msg}");
    }
}
