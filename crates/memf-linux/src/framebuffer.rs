/// Linux framebuffer walker — reads `boot_params.screen_info` to locate the
/// EFI/VESA linear framebuffer and encode it as PNG.
///
/// Offsets within `boot_params` (screen_info is the first field, so these
/// are offsets from the boot_params symbol address):
///   +0x10  lfb_base        u32  — PA of linear framebuffer
///   +0x14  lfb_width       u16  — width in pixels
///   +0x16  lfb_height      u16  — height in pixels
///   +0x18  lfb_depth       u16  — bits per pixel (16, 24, or 32)
///   +0x1A  lfb_linelength  u32  — row stride in bytes
use memf_core::framebuffer::{encode_png, FramebufferResult, PixelFormat};
use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

const MAX_FB_BYTES: u64 = 32 * 1024 * 1024; // 32 MiB hard cap

const LFB_BASE_OFF:   u64 = 0x10;
const LFB_WIDTH_OFF:  u64 = 0x14;
const LFB_HEIGHT_OFF: u64 = 0x16;
const LFB_DEPTH_OFF:  u64 = 0x18;
const LFB_STRIDE_OFF: u64 = 0x1A;

/// Walk the Linux `boot_params.screen_info` structure to locate and capture
/// the linear framebuffer, returning a [`FramebufferResult`] with PNG bytes.
pub fn walk_framebuffer_linux<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
) -> Result<FramebufferResult> {
    let boot_params_va = reader.required_symbol("boot_params")
        .map_err(|_| crate::Error::WalkFailed {
            walker: "framebuffer",
            reason: "boot_params symbol not found".into(),
        })?;

    let lfb_base = {
        let b = reader.read_bytes(boot_params_va + LFB_BASE_OFF, 4)
            .map_err(|e| crate::Error::WalkFailed {
                walker: "framebuffer",
                reason: format!("read lfb_base: {e}"),
            })?;
        u64::from(b.try_into().map_or(0, u32::from_le_bytes))
    };

    let width = {
        let b = reader.read_bytes(boot_params_va + LFB_WIDTH_OFF, 2)
            .map_err(|e| crate::Error::WalkFailed {
                walker: "framebuffer",
                reason: format!("read lfb_width: {e}"),
            })?;
        u32::from(b.try_into().map_or(0, u16::from_le_bytes))
    };

    let height = {
        let b = reader.read_bytes(boot_params_va + LFB_HEIGHT_OFF, 2)
            .map_err(|e| crate::Error::WalkFailed {
                walker: "framebuffer",
                reason: format!("read lfb_height: {e}"),
            })?;
        u32::from(b.try_into().map_or(0, u16::from_le_bytes))
    };

    let depth = {
        let b = reader.read_bytes(boot_params_va + LFB_DEPTH_OFF, 2)
            .map_err(|e| crate::Error::WalkFailed {
                walker: "framebuffer",
                reason: format!("read lfb_depth: {e}"),
            })?;
        b.try_into().map_or(0, u16::from_le_bytes)
    };

    let stride = {
        let b = reader.read_bytes(boot_params_va + LFB_STRIDE_OFF, 4)
            .map_err(|e| crate::Error::WalkFailed {
                walker: "framebuffer",
                reason: format!("read lfb_linelength: {e}"),
            })?;
        b.try_into().map_or(0, u32::from_le_bytes)
    };

    if width == 0 || height == 0 || lfb_base == 0 {
        return Err(crate::Error::WalkFailed {
            walker: "framebuffer",
            reason: "screen_info has zero dimensions or base address".into(),
        });
    }

    let pixel_format = match depth {
        32 => PixelFormat::Xbgr8888,
        24 => PixelFormat::Bgr24,
        16 => PixelFormat::Rgb565,
        d  => PixelFormat::Unknown(d as u8),
    };

    let fb_size = u64::from(stride) * u64::from(height);
    if fb_size > MAX_FB_BYTES {
        return Err(crate::Error::WalkFailed {
            walker: "framebuffer",
            reason: format!("framebuffer size {fb_size} exceeds 32 MiB"),
        });
    }

    let mut fb_bytes = vec![0u8; fb_size as usize];
    reader.vas().physical().read_phys(lfb_base, &mut fb_bytes)
        .map_err(|_| crate::Error::WalkFailed {
            walker: "framebuffer",
            reason: format!("could not read {fb_size} bytes from PA {lfb_base:#x}"),
        })?;

    let png_bytes = encode_png(&fb_bytes, width, height, pixel_format)
        .map_err(|e| crate::Error::WalkFailed {
            walker: "framebuffer",
            reason: format!("PNG encode: {e}"),
        })?;

    Ok(FramebufferResult {
        width,
        height,
        stride,
        pixel_format: format!("{pixel_format:?}"),
        phys_base: lfb_base,
        source: "boot_params.screen_info".into(),
        png_bytes,
    })
}

#[cfg(test)]
mod tests {
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags as ptf, PageTableBuilder};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    use super::walk_framebuffer_linux;

    // -----------------------------------------------------------------------
    // Memory layout (all within the default 16 MiB SyntheticPhysMem):
    //   boot_params VA = 0xFFFF_8800_00A0_0000 → PA 0x00A0_0000 (10 MiB)
    //   framebuffer PA =                           0x00B0_0000 (11 MiB)
    //
    // screen_info offsets from boot_params base:
    //   +0x10  lfb_base        u32 LE = 0x00B0_0000
    //   +0x14  lfb_width       u16 LE = 4
    //   +0x16  lfb_height      u16 LE = 4
    //   +0x18  lfb_depth       u16 LE = 32
    //   +0x1A  lfb_linelength  u32 LE = 16  (4 px × 4 bytes)
    //
    // Pixel data: 4×4 × 4 bytes = 64 bytes of XBGR8888 at PA 0x00B0_0000.
    // -----------------------------------------------------------------------

    const BOOT_PARAMS_VA: u64 = 0xFFFF_8800_00A0_0000;
    const BOOT_PARAMS_PA: u64 = 0x00A0_0000; // 10 MiB
    const FB_PA:          u64 = 0x00B0_0000; // 11 MiB

    fn build_reader() -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let mut page = [0u8; 4096];

        // +0x10: lfb_base (u32 LE)
        page[0x10..0x14].copy_from_slice(&(FB_PA as u32).to_le_bytes());
        // +0x14: lfb_width (u16 LE) = 4
        page[0x14..0x16].copy_from_slice(&4u16.to_le_bytes());
        // +0x16: lfb_height (u16 LE) = 4
        page[0x16..0x18].copy_from_slice(&4u16.to_le_bytes());
        // +0x18: lfb_depth (u16 LE) = 32
        page[0x18..0x1a].copy_from_slice(&32u16.to_le_bytes());
        // +0x1A: lfb_linelength (u32 LE) = 16
        page[0x1a..0x1e].copy_from_slice(&16u32.to_le_bytes());

        // 4×4 pixels of XBGR8888
        let fb_data: Vec<u8> = [0x10u8, 0x20, 0x30, 0xFF].iter().copied().cycle().take(64).collect();

        let isf = IsfBuilder::new()
            .add_symbol("boot_params", BOOT_PARAMS_VA)
            .build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();

        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(BOOT_PARAMS_VA, BOOT_PARAMS_PA, ptf::WRITABLE)
            .write_phys(BOOT_PARAMS_PA, &page)
            .write_phys(FB_PA, &fb_data)
            .build();

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    fn build_reader_no_sym() -> ObjectReader<memf_core::test_builders::SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn linux_framebuffer_extracts_4x4_from_boot_params() {
        let reader = build_reader();
        let result = walk_framebuffer_linux(&reader).expect("should find framebuffer");
        assert_eq!(result.width, 4);
        assert_eq!(result.height, 4);
        assert_eq!(result.source, "boot_params.screen_info");
        assert_eq!(result.phys_base, FB_PA);
    }

    #[test]
    fn linux_framebuffer_png_output_has_png_magic() {
        let reader = build_reader();
        let result = walk_framebuffer_linux(&reader).expect("should succeed");
        assert!(
            result.png_bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
            "PNG magic not found; first bytes: {:?}",
            &result.png_bytes[..result.png_bytes.len().min(16)]
        );
    }

    #[test]
    fn linux_framebuffer_missing_symbol_returns_err() {
        let reader = build_reader_no_sym();
        let result = walk_framebuffer_linux(&reader);
        assert!(result.is_err(), "expected Err when boot_params symbol absent");
    }
}
