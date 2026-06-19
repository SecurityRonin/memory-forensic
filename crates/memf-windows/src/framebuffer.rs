//! Windows session framebuffer extraction (win32k pool scan) — screen state at acquisition.
use memf_core::framebuffer::{encode_png, FramebufferResult, PixelFormat};
use memf_format::PhysicalMemoryProvider;

use crate::Result;

const EFI_SYSTEM_TABLE_SIG: u64 = 0x5453_5953_2049_4249;
const GOP_GUID: [u8; 16] = [
    0xde, 0xa9, 0x42, 0x90, 0xdc, 0x23, 0x38, 0x4a, 0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a,
];
const MAX_FB_BYTES: u64 = 32 * 1024 * 1024;

/// Scan physical ranges for the EFI System Table signature and extract the
/// GOP framebuffer, returning a PNG-encoded [`FramebufferResult`].
pub fn walk_framebuffer_windows<P: PhysicalMemoryProvider>(
    provider: &P,
) -> Result<FramebufferResult> {
    let table_pa = find_efi_system_table(provider)?;
    walk_framebuffer_from(provider, table_pa)
}

/// Internal entry point with a known EFI System Table physical address.
/// Used by tests where `ranges()` returns `&[]`.
pub(crate) fn walk_framebuffer_from<P: PhysicalMemoryProvider>(
    provider: &P,
    table_pa: u64,
) -> Result<FramebufferResult> {
    // Read ConfigurationTable count and pointer from the EFI System Table.
    let num_entries = read_u64_phys(provider, table_pa + 0x40)?;
    let config_table_pa = read_u64_phys(provider, table_pa + 0x48)?;

    // Walk the EFI_CONFIGURATION_TABLE array for the GOP GUID.
    let gop_mode_pa = find_gop_mode(provider, config_table_pa, num_entries as usize)?;

    // EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE fields.
    let fb_base = read_u64_phys(provider, gop_mode_pa + 0x18)?;
    let info_pa = read_u64_phys(provider, gop_mode_pa + 0x08)?;

    // EFI_GRAPHICS_OUTPUT_MODE_INFORMATION fields.
    let width = read_u32_phys(provider, info_pa + 0x04)?;
    let height = read_u32_phys(provider, info_pa + 0x08)?;
    let pf_id = read_u32_phys(provider, info_pa + 0x0C)?;
    let pps = read_u32_phys(provider, info_pa + 0x20)?;
    let stride = pps.saturating_mul(4);

    let pixel_format = match pf_id {
        0 => PixelFormat::Xrgb8888,
        1 => PixelFormat::Xbgr8888,
        _ => PixelFormat::Unknown(pf_id as u8),
    };

    let fb_size = u64::from(stride) * u64::from(height);
    if fb_size > MAX_FB_BYTES {
        return Err(crate::Error::WalkFailed {
            walker: "framebuffer_windows",
            reason: format!("framebuffer {fb_size} bytes exceeds 32 MiB cap"),
        });
    }

    let mut fb_bytes = vec![0u8; fb_size as usize];
    provider
        .read_phys(fb_base, &mut fb_bytes)
        .map_err(|_| crate::Error::WalkFailed {
            walker: "framebuffer_windows",
            reason: format!("cannot read {fb_size} bytes at PA {fb_base:#x}"),
        })?;

    let png_bytes = encode_png(&fb_bytes, width, height, pixel_format).map_err(|e| {
        crate::Error::WalkFailed {
            walker: "framebuffer_windows",
            reason: format!("PNG encode: {e}"),
        }
    })?;

    Ok(FramebufferResult {
        width,
        height,
        stride,
        pixel_format: format!("{pixel_format:?}"),
        phys_base: fb_base,
        source: "EFI_GOP".into(),
        png_bytes,
    })
}

/// Page-aligned scan of all physical ranges for the EFI System Table
/// signature `"IBI SYST"`.
fn find_efi_system_table<P: PhysicalMemoryProvider>(provider: &P) -> Result<u64> {
    let mut sig_buf = [0u8; 8];
    for range in provider.ranges() {
        let mut pa = range.start & !0xFFF; // page-align down
        while pa + 8 <= range.end {
            if provider.read_phys(pa, &mut sig_buf).is_ok()
                && u64::from_le_bytes(sig_buf) == EFI_SYSTEM_TABLE_SIG
            {
                return Ok(pa);
            }
            pa += 4096;
        }
    }
    Err(crate::Error::WalkFailed {
        walker: "framebuffer_windows",
        reason: "EFI System Table signature not found in physical ranges".into(),
    })
}

/// Walk `num_entries` × 24-byte EFI_CONFIGURATION_TABLE entries at
/// `config_table_pa`, returning the VendorTable pointer for the GOP GUID.
fn find_gop_mode<P: PhysicalMemoryProvider>(
    provider: &P,
    config_table_pa: u64,
    num_entries: usize,
) -> Result<u64> {
    for i in 0..num_entries.min(256) {
        let entry_pa = config_table_pa + (i as u64 * 24);
        let mut guid_buf = [0u8; 16];
        if provider.read_phys(entry_pa, &mut guid_buf).is_err() {
            break;
        }
        if guid_buf == GOP_GUID {
            return read_u64_phys(provider, entry_pa + 16);
        }
    }
    Err(crate::Error::WalkFailed {
        walker: "framebuffer_windows",
        reason: "EFI GOP protocol not found in configuration table".into(),
    })
}

fn read_u64_phys<P: PhysicalMemoryProvider>(p: &P, pa: u64) -> Result<u64> {
    let mut buf = [0u8; 8];
    p.read_phys(pa, &mut buf)
        .map_err(|_| crate::Error::WalkFailed {
            walker: "framebuffer_windows",
            reason: format!("read_phys failed at {pa:#x}"),
        })?;
    Ok(u64::from_le_bytes(buf))
}

fn read_u32_phys<P: PhysicalMemoryProvider>(p: &P, pa: u64) -> Result<u32> {
    let mut buf = [0u8; 4];
    p.read_phys(pa, &mut buf)
        .map_err(|_| crate::Error::WalkFailed {
            walker: "framebuffer_windows",
            reason: format!("read_phys failed at {pa:#x}"),
        })?;
    Ok(u32::from_le_bytes(buf))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::SyntheticPhysMem;

    const GOP_GUID_T: [u8; 16] = [
        0xde, 0xa9, 0x42, 0x90, 0xdc, 0x23, 0x38, 0x4a, 0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51,
        0x6a,
    ];

    // Physical addresses used in the synthetic image
    const TABLE_PA: u64 = 0xF000_0000;
    const CFG_TABLE_PA: u64 = 0xF001_0000;
    const GOP_MODE_PA: u64 = 0xF002_0000;
    const MODE_INFO_PA: u64 = 0xF003_0000;
    const FB_PA: u64 = 0xFD00_0000;

    // 4×4 framebuffer — small and fast
    const W: u32 = 4;
    const H: u32 = 4;

    /// Total size must hold FB_PA + pixel data.
    const MEM_SIZE: usize = 0xFD01_0000;

    fn make_provider() -> SyntheticPhysMem {
        let mut mem = SyntheticPhysMem::new(MEM_SIZE);

        // EFI System Table
        mem.write_u64(TABLE_PA, EFI_SYSTEM_TABLE_SIG);
        mem.write_u64(TABLE_PA + 0x40, 1); // NumberOfTableEntries
        mem.write_u64(TABLE_PA + 0x48, CFG_TABLE_PA); // ConfigurationTable ptr

        // EFI_CONFIGURATION_TABLE[0] = {GOP_GUID, GOP_MODE_PA}
        mem.write_bytes(CFG_TABLE_PA, &GOP_GUID_T);
        mem.write_u64(CFG_TABLE_PA + 16, GOP_MODE_PA);

        // EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE
        mem.write_u64(GOP_MODE_PA + 0x08, MODE_INFO_PA); // Info ptr
        mem.write_u64(GOP_MODE_PA + 0x18, FB_PA); // FrameBufferBase
        mem.write_u64(GOP_MODE_PA + 0x20, u64::from(W * H * 4)); // FrameBufferSize

        // EFI_GRAPHICS_OUTPUT_MODE_INFORMATION
        mem.write_bytes(MODE_INFO_PA + 0x04, &W.to_le_bytes()); // HorizontalResolution
        mem.write_bytes(MODE_INFO_PA + 0x08, &H.to_le_bytes()); // VerticalResolution
        mem.write_bytes(MODE_INFO_PA + 0x0C, &1u32.to_le_bytes()); // PixelFormat=XBGR
        mem.write_bytes(MODE_INFO_PA + 0x20, &W.to_le_bytes()); // PixelsPerScanLine

        // Framebuffer pixels are zero-filled by SyntheticPhysMem::new
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
        assert!(
            result.pixel_format.contains("Xbgr"),
            "got {}",
            result.pixel_format
        );
    }

    #[test]
    fn windows_framebuffer_no_efi_table_returns_err() {
        // ranges() returns &[] on SyntheticPhysMem — scan loop produces no
        // candidates, so the walker must return an appropriate error.
        let mem = SyntheticPhysMem::new(4096);
        let err = walk_framebuffer_windows(&mem).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("framebuffer_windows"), "got: {msg}");
    }

    #[test]
    fn windows_framebuffer_missing_gop_guid_returns_err() {
        let mut mem = make_provider();
        // Corrupt the GOP GUID so it won't match any entry
        mem.write_bytes(CFG_TABLE_PA, &[0u8; 16]);
        let err = walk_framebuffer_from(&mem, TABLE_PA).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("GOP protocol not found"), "got: {msg}");
    }
}
