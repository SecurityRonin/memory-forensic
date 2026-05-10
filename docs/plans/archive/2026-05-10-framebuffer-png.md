# Framebuffer PNG Extraction Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Scan physical memory in a dump for active framebuffers (via Linux `boot_params.screen_info` metadata, Windows EFI GOP tables, or heuristic physical-range scanning), decode the pixel data, and write a PNG screenshot to disk.

**Architecture:** Four sequential tasks. Task 1 creates the `memf-framebuffer` library crate with PNG encoding. Task 2 implements the Linux walker via `boot_params.screen_info`. Task 3 implements the Windows walker via EFI GOP table scanning. Task 4 adds the `framebuffer` CLI subcommand to `src/main.rs`. Each task has RED→GREEN commits and no regressions.

**Tech Stack:** Rust 2021, `png = "0.17"` (pure Rust, zero native deps), existing `PhysicalMemoryProvider` trait, `ObjectReader` for virtual-address resolution, `SyntheticPhysMem` for unit tests.

**Commit convention:** `--no-gpg-sign`. RED commit then GREEN commit per task. `GITSIGN_CREDENTIAL_CACHE=/Users/4n6h4x0r/Library/Caches/sigstore/gitsign/cache.sock`.

---

## Background

### Physical memory infrastructure

`PhysicalMemoryProvider` (in `crates/memf-format/src/lib.rs`):
```rust
pub trait PhysicalMemoryProvider: Send + Sync {
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<usize>;
    fn ranges(&self) -> &[PhysicalRange];  // valid PA ranges
    fn total_size(&self) -> u64;
}
```

`SyntheticPhysMem` (test harness) supports `write_bytes(pa, data)` + `read_phys`. Its `ranges()` returns `&[]` — walkers must handle empty ranges gracefully.

### Linux screen_info

`boot_params.screen_info` is the first field of `struct boot_params` in kernel BSS. Relevant fields (all in `setup.h`):

| Field | Offset (within screen_info) | Type | Meaning |
|---|---|---|---|
| `lfb_base` | +0x10 | u32 | Physical address of linear framebuffer |
| `lfb_width` | +0x12 | u16 | Width in pixels |
| `lfb_height` | +0x14 | u16 | Height in pixels |
| `lfb_depth` | +0x16 | u16 | Bits per pixel |
| `lfb_linelength` | +0x18 | u32 | Row stride in bytes |

`boot_params` VA comes from the `boot_params` kernel symbol via `reader.required_symbol("boot_params")`.

### Windows EFI GOP

`EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE` (accessible from EFI System Table configuration table):
- `FrameBufferBase` (u64) — physical address
- `HorizontalResolution` (u32)
- `VerticalResolution` (u32)
- `PixelFormat` (u32): 0=RGBReserved8, 1=BGRReserved8, 2=BitMask, 3=BltOnly

EFI System Table signature: `0x5453595320494249` ("IBI SYST" in LE). Located by scanning physical ranges.

### Supported pixel formats

| Format | bpp | Conversion to RGB24 |
|---|---|---|
| XRGB8888 / RGBReserved8 | 32 | drop byte 3, swap R↔B |
| XBGR8888 / BGRReserved8 | 32 | drop byte 3 |
| RGB565 | 16 | expand 5-6-5 to 8-8-8 |
| BGR24 | 24 | swap R↔B |

---

## Task 1: `memf-framebuffer` crate — PNG encoder (TDD)

**Files:**
- Create: `crates/memf-framebuffer/Cargo.toml`
- Create: `crates/memf-framebuffer/src/lib.rs`
- Modify: `Cargo.toml` (workspace root) — add `png = "0.17"` and `memf-framebuffer` member

### Step 1: Add `png` to workspace

In `[workspace.dependencies]`:
```toml
png = "0.17"
```

In `[workspace.members]`:
```toml
"crates/memf-framebuffer",
```

### Step 2: Create `crates/memf-framebuffer/Cargo.toml`

```toml
[package]
name = "memf-framebuffer"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
thiserror.workspace = true
serde.workspace = true
png.workspace = true
```

### Step 3: Write RED tests in `src/lib.rs`

```rust
#[derive(Debug, Clone, serde::Serialize)]
pub struct FramebufferResult {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: String,
    pub phys_base: u64,
    pub source: String,
    /// PNG-encoded screenshot bytes. Not serialised to JSON (use --output-png).
    #[serde(skip)]
    pub png_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PixelFormat {
    Xrgb8888,
    Xbgr8888,
    Rgb565,
    Bgr24,
    Unknown(u8),
}

#[derive(Debug, thiserror::Error)]
pub enum FramebufferError {
    #[error("unsupported pixel format: {0:?}")]
    UnsupportedPixelFormat(PixelFormat),
    #[error("PNG encoding failed: {0}")]
    PngEncode(String),
    #[error("framebuffer too large: {size} bytes")]
    TooLarge { size: u64 },
    #[error("framebuffer not found")]
    NotFound,
    #[error("physical memory read failed")]
    ReadFailed,
}

/// Convert raw pixel bytes to RGB24 and encode as PNG.
pub fn encode_png(
    pixels: &[u8],
    width: u32,
    height: u32,
    format: PixelFormat,
) -> Result<Vec<u8>, FramebufferError> {
    todo!()
}

/// Convert raw pixel buffer to RGB24 bytes.
pub fn to_rgb24(pixels: &[u8], width: u32, height: u32, format: PixelFormat)
    -> Result<Vec<u8>, FramebufferError> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_png_produces_valid_png_header() {
        // 2x2 XBGR8888 gradient
        let pixels = vec![
            0x00, 0x00, 0xFF, 0xFF,  // red pixel (B=0, G=0, R=255, X=255)
            0x00, 0xFF, 0x00, 0xFF,  // green pixel
            0xFF, 0x00, 0x00, 0xFF,  // blue pixel
            0xFF, 0xFF, 0xFF, 0xFF,  // white pixel
        ];
        let png = encode_png(&pixels, 2, 2, PixelFormat::Xbgr8888)
            .expect("encode must succeed");
        assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"), "must have PNG magic header");
        assert!(png.len() > 20, "PNG must have more than just the header");
    }

    #[test]
    fn encode_png_empty_dimensions_returns_err_or_empty() {
        let result = encode_png(&[], 0, 0, PixelFormat::Xrgb8888);
        // Either returns empty PNG or an error — must not panic
        let _ = result;
    }

    #[test]
    fn to_rgb24_xbgr8888_swaps_rb_channels() {
        // XBGR8888: byte order is B, G, R, X
        let pixels = vec![0x10u8, 0x20, 0x30, 0xFF]; // B=0x10, G=0x20, R=0x30
        let rgb = to_rgb24(&pixels, 1, 1, PixelFormat::Xbgr8888).expect("ok");
        assert_eq!(rgb, vec![0x30, 0x20, 0x10]); // RGB24: R=0x30, G=0x20, B=0x10
    }

    #[test]
    fn to_rgb24_rgb565_expands_correctly() {
        // RGB565: 5 bits R, 6 bits G, 5 bits B packed in 2 bytes LE
        // Red = 0b11111_000000_00000 = 0xF800 → R=0xFF, G=0, B=0
        let pixels = vec![0x00u8, 0xF8]; // LE: low byte 0x00, high byte 0xF8 → value 0xF800
        let rgb = to_rgb24(&pixels, 1, 1, PixelFormat::Rgb565).expect("ok");
        assert_eq!(rgb[0], 0xFF, "R should be max");
        assert_eq!(rgb[1], 0x00, "G should be 0");
        assert_eq!(rgb[2], 0x00, "B should be 0");
    }

    #[test]
    fn pixel_format_unknown_returns_error_from_encode() {
        let pixels = vec![0u8; 4];
        let result = encode_png(&pixels, 1, 1, PixelFormat::Unknown(99));
        assert!(result.is_err());
    }
}
```

Run: `cargo test -p memf-framebuffer` — all tests must FAIL (todo!()). RED commit:
```bash
git commit --no-gpg-sign -m "test(fb): RED — framebuffer PNG encoder tests"
```

### Step 4: Implement `encode_png` and `to_rgb24`

```rust
pub fn to_rgb24(pixels: &[u8], width: u32, height: u32, format: PixelFormat)
    -> Result<Vec<u8>, FramebufferError>
{
    let n = (width * height) as usize;
    match format {
        PixelFormat::Xbgr8888 => {
            if pixels.len() < n * 4 { return Err(FramebufferError::ReadFailed); }
            Ok(pixels.chunks_exact(4).take(n)
                .flat_map(|p| [p[2], p[1], p[0]])  // XBGR → RGB
                .collect())
        }
        PixelFormat::Xrgb8888 => {
            if pixels.len() < n * 4 { return Err(FramebufferError::ReadFailed); }
            Ok(pixels.chunks_exact(4).take(n)
                .flat_map(|p| [p[0], p[1], p[2]])  // XRGB → RGB
                .collect())
        }
        PixelFormat::Bgr24 => {
            if pixels.len() < n * 3 { return Err(FramebufferError::ReadFailed); }
            Ok(pixels.chunks_exact(3).take(n)
                .flat_map(|p| [p[2], p[1], p[0]])  // BGR → RGB
                .collect())
        }
        PixelFormat::Rgb565 => {
            if pixels.len() < n * 2 { return Err(FramebufferError::ReadFailed); }
            Ok(pixels.chunks_exact(2).take(n)
                .flat_map(|p| {
                    let v = u16::from_le_bytes([p[0], p[1]]);
                    let r = ((v >> 11) & 0x1F) as u8;
                    let g = ((v >> 5) & 0x3F) as u8;
                    let b = (v & 0x1F) as u8;
                    // Expand 5→8, 6→8, 5→8
                    [(r << 3) | (r >> 2), (g << 2) | (g >> 4), (b << 3) | (b >> 2)]
                })
                .collect())
        }
        PixelFormat::Unknown(_) => Err(FramebufferError::UnsupportedPixelFormat(format)),
    }
}

pub fn encode_png(pixels: &[u8], width: u32, height: u32, format: PixelFormat)
    -> Result<Vec<u8>, FramebufferError>
{
    if width == 0 || height == 0 {
        return Ok(Vec::new());
    }
    let rgb = to_rgb24(pixels, width, height, format)?;
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, width, height);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header()
            .map_err(|e| FramebufferError::PngEncode(e.to_string()))?;
        writer.write_image_data(&rgb)
            .map_err(|e| FramebufferError::PngEncode(e.to_string()))?;
    }
    Ok(out)
}
```

### Step 5: GREEN commit

```bash
cargo test -p memf-framebuffer 2>&1 | tail -10
git add crates/memf-framebuffer/ Cargo.toml Cargo.lock
git commit --no-gpg-sign -m "feat(fb): GREEN — memf-framebuffer crate with PNG encoder and pixel format conversion"
```

---

## Task 2: Linux framebuffer walker (TDD)

**Files:**
- Create: `crates/memf-linux/src/framebuffer.rs`
- Modify: `crates/memf-linux/src/lib.rs` (add `pub mod framebuffer;`)
- Modify: `crates/memf-linux/Cargo.toml` (add `memf-framebuffer` dep)

### Step 1: Write RED tests

`screen_info` offsets within `boot_params` (Linux x86 `arch/x86/include/uapi/asm/bootparam.h`):
- `boot_params` starts at `boot_params` symbol VA
- `screen_info` is the first field (offset 0x00 within boot_params)
- Within `screen_info`: `lfb_base` at +0x10, `lfb_width` at +0x12, `lfb_height` at +0x14, `lfb_depth` at +0x16, `lfb_linelength` at +0x18

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::test_builders::IsfBuilder;
    use memf_symbols::isf::IsfResolver;
    use memf_framebuffer::PixelFormat;

    fn make_reader_with_framebuffer() -> (ObjectReader<impl PhysicalMemoryProvider + Clone>, u64) {
        // PA of framebuffer
        const FB_PA: u64 = 0xFD00_0000;
        const FB_WIDTH: u16 = 4;
        const FB_HEIGHT: u16 = 4;
        const FB_DEPTH: u16 = 32;
        const FB_STRIDE: u32 = FB_WIDTH as u32 * 4;

        let mut pt = PageTableBuilder::new();

        // boot_params VA → map to some PA
        const BOOT_PARAMS_VA: u64 = 0xFFFF_8800_0100_0000;
        const BOOT_PARAMS_PA: u64 = 0x0100_0000;
        pt.map(BOOT_PARAMS_VA, BOOT_PARAMS_PA);

        // Write screen_info at boot_params VA offset 0:
        let mut screen_info = [0u8; 0x40];
        screen_info[0x10..0x14].copy_from_slice(&(FB_PA as u32).to_le_bytes()); // lfb_base
        screen_info[0x12..0x14].copy_from_slice(&FB_WIDTH.to_le_bytes());       // lfb_width
        screen_info[0x14..0x16].copy_from_slice(&FB_HEIGHT.to_le_bytes());      // lfb_height
        screen_info[0x16..0x18].copy_from_slice(&FB_DEPTH.to_le_bytes());       // lfb_depth
        screen_info[0x18..0x1C].copy_from_slice(&FB_STRIDE.to_le_bytes());      // lfb_linelength

        pt.write_phys(BOOT_PARAMS_PA, &screen_info);

        // Write a 4x4 XBGR8888 gradient at FB_PA
        let mut fb_data = vec![0u8; (FB_WIDTH as usize * FB_HEIGHT as usize * 4)];
        for i in 0..(FB_WIDTH as usize * FB_HEIGHT as usize) {
            fb_data[i*4] = i as u8;     // B
            fb_data[i*4+1] = 0;         // G
            fb_data[i*4+2] = 0;         // R
            fb_data[i*4+3] = 0xFF;      // X
        }
        pt.write_phys(FB_PA, &fb_data);

        let cr3 = pt.build();
        let mem = pt.into_memory();

        let isf = IsfBuilder::linux_kernel_preset().with_symbol("boot_params", BOOT_PARAMS_VA).build_json();
        let resolver = IsfResolver::from_value(&isf).expect("valid ISF");
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        (reader, BOOT_PARAMS_VA)
    }

    #[test]
    fn linux_framebuffer_extracts_dimensions_from_boot_params() {
        let (reader, _) = make_reader_with_framebuffer();
        let result = walk_framebuffer_linux(&reader).expect("should find framebuffer");
        assert_eq!(result.width, 4);
        assert_eq!(result.height, 4);
        assert_eq!(result.source, "boot_params.screen_info");
    }

    #[test]
    fn linux_framebuffer_png_output_has_valid_header() {
        let (reader, _) = make_reader_with_framebuffer();
        let result = walk_framebuffer_linux(&reader).expect("should succeed");
        assert!(result.png_bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
    }

    #[test]
    fn linux_framebuffer_missing_symbol_returns_err() {
        // Reader with no boot_params symbol → must return Err gracefully
        let mut pt = PageTableBuilder::new();
        let _ = pt.build();
        let mem = pt.into_memory();
        let isf = IsfBuilder::linux_kernel_preset().build_json(); // no boot_params symbol
        let resolver = IsfResolver::from_value(&isf).expect("valid ISF");
        let vas = VirtualAddressSpace::new(mem, PageTableBuilder::CR3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));
        let result = walk_framebuffer_linux(&reader);
        assert!(result.is_err(), "must fail gracefully when boot_params absent");
    }
}
```

RED commit: `git commit --no-gpg-sign -m "test(fb): RED — Linux framebuffer walker tests"`

### Step 2: Implement `walk_framebuffer_linux`

```rust
use memf_framebuffer::{encode_png, FramebufferError, FramebufferResult, PixelFormat};

const MAX_FB_BYTES: u64 = 32 * 1024 * 1024; // 32 MiB cap

pub fn walk_framebuffer_linux<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
) -> Result<FramebufferResult> {
    // screen_info offsets within boot_params (x86 bootparam.h)
    const LFB_BASE_OFF: u64     = 0x10;
    const LFB_WIDTH_OFF: u64    = 0x12;
    const LFB_HEIGHT_OFF: u64   = 0x14;
    const LFB_DEPTH_OFF: u64    = 0x16;
    const LFB_STRIDE_OFF: u64   = 0x18;

    let boot_params_va = reader.required_symbol("boot_params")
        .map_err(|_| crate::Error::WalkFailed {
            walker: "framebuffer",
            reason: "boot_params symbol not found".into(),
        })?;

    let mut u32_buf = [0u8; 4];
    let mut u16_buf = [0u8; 2];

    reader.read_virt(boot_params_va + LFB_BASE_OFF, &mut u32_buf)?;
    let lfb_base = u32::from_le_bytes(u32_buf) as u64;

    reader.read_virt(boot_params_va + LFB_WIDTH_OFF, &mut u16_buf)?;
    let width = u16::from_le_bytes(u16_buf) as u32;

    reader.read_virt(boot_params_va + LFB_HEIGHT_OFF, &mut u16_buf)?;
    let height = u16::from_le_bytes(u16_buf) as u32;

    reader.read_virt(boot_params_va + LFB_DEPTH_OFF, &mut u16_buf)?;
    let depth = u16::from_le_bytes(u16_buf);

    reader.read_virt(boot_params_va + LFB_STRIDE_OFF, &mut u32_buf)?;
    let stride = u32::from_le_bytes(u32_buf);

    if width == 0 || height == 0 || lfb_base == 0 {
        return Err(crate::Error::WalkFailed {
            walker: "framebuffer",
            reason: "screen_info has zero dimensions or base address".into(),
        });
    }

    let pixel_format = match depth {
        32 => PixelFormat::Xbgr8888, // GOP default; could also be Xrgb8888
        24 => PixelFormat::Bgr24,
        16 => PixelFormat::Rgb565,
        d  => PixelFormat::Unknown(d as u8),
    };

    let fb_size = (stride as u64) * (height as u64);
    if fb_size > MAX_FB_BYTES {
        return Err(crate::Error::WalkFailed {
            walker: "framebuffer",
            reason: format!("framebuffer size {fb_size} exceeds 32 MiB cap"),
        });
    }

    let mut fb_bytes = vec![0u8; fb_size as usize];
    reader.provider().read_phys(lfb_base, &mut fb_bytes)
        .map_err(|_| crate::Error::WalkFailed {
            walker: "framebuffer",
            reason: format!("could not read {fb_size} bytes from PA {lfb_base:#x}"),
        })?;

    let png_bytes = encode_png(&fb_bytes, width, height, pixel_format)
        .map_err(|e| crate::Error::WalkFailed {
            walker: "framebuffer",
            reason: format!("PNG encode failed: {e}"),
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
```

### Step 3: GREEN commit

```bash
cargo test -p memf-linux framebuffer 2>&1 | tail -10
cargo test --workspace 2>&1 | tail -5
git add crates/memf-linux/src/framebuffer.rs crates/memf-linux/src/lib.rs crates/memf-linux/Cargo.toml
git commit --no-gpg-sign -m "feat(fb): GREEN — Linux framebuffer walker via boot_params.screen_info"
```

---

## Task 3: Windows framebuffer walker (TDD)

**Files:**
- Create: `crates/memf-windows/src/framebuffer.rs`
- Modify: `crates/memf-windows/src/lib.rs`
- Modify: `crates/memf-windows/Cargo.toml`

### Step 1: Write RED tests

```rust
#[test]
fn windows_framebuffer_finds_gop_mode_from_efi_system_table() {
    // Build synthetic physical memory with:
    // - EFI System Table at PA 0xF000_0000 with signature 0x5453595320494249
    // - ConfigurationTable entry with GOP GUID pointing to Mode struct
    // - Mode struct with FrameBufferBase=0xFD000000, 800x600, PixelFormat=1 (BGR)
    // Assert result.width=800, result.height=600
}

#[test]
fn windows_framebuffer_no_efi_table_returns_err() {
    // Empty physical memory → must fail gracefully
}
```

RED commit: `git commit --no-gpg-sign -m "test(fb): RED — Windows EFI GOP framebuffer walker tests"`

### Step 2: Implement EFI System Table scan

```rust
const EFI_SYSTEM_TABLE_SIG: u64 = 0x5453_5953_2049_4249; // "IBI SYST" LE
const GOP_GUID: [u8; 16] = [
    0xde, 0xa9, 0x42, 0x90, 0xdc, 0x23, 0x38, 0x4a,
    0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a,
];

pub fn walk_framebuffer_windows<P: PhysicalMemoryProvider + Clone>(
    reader: &ObjectReader<P>,
) -> Result<FramebufferResult> {
    // 1. Scan physical ranges for EFI System Table signature
    let provider = reader.provider();
    let mut sig_buf = [0u8; 8];
    let mut efi_table_pa: Option<u64> = None;

    'outer: for range in provider.ranges() {
        let mut pa = range.start;
        while pa + 8 <= range.end {
            if provider.read_phys(pa, &mut sig_buf).is_ok() {
                if u64::from_le_bytes(sig_buf) == EFI_SYSTEM_TABLE_SIG {
                    efi_table_pa = Some(pa);
                    break 'outer;
                }
            }
            pa += 4096; // page-aligned scan
        }
    }

    let table_pa = efi_table_pa.ok_or_else(|| crate::Error::WalkFailed {
        walker: "framebuffer_windows",
        reason: "EFI System Table not found in physical ranges".into(),
    })?;

    // 2. Read ConfigurationTable count + pointer from EFI System Table
    // EFI_SYSTEM_TABLE offsets (UEFI spec 2.10):
    //   +0x00: Hdr.Signature (u64)
    //   +0x40: NumberOfTableEntries (u64)
    //   +0x48: ConfigurationTable (u64 ptr to array of EFI_CONFIGURATION_TABLE)
    let mut u64_buf = [0u8; 8];
    provider.read_phys(table_pa + 0x40, &mut u64_buf)?;
    let num_entries = u64::from_le_bytes(u64_buf) as usize;
    provider.read_phys(table_pa + 0x48, &mut u64_buf)?;
    let config_table_pa = u64::from_le_bytes(u64_buf);

    // 3. Scan ConfigurationTable for GOP GUID
    // Each EFI_CONFIGURATION_TABLE = 16 bytes GUID + 8 bytes VendorTable ptr = 24 bytes
    let mut gop_mode_pa: Option<u64> = None;
    for i in 0..num_entries.min(256) {
        let entry_pa = config_table_pa + (i as u64 * 24);
        let mut guid_buf = [0u8; 16];
        if provider.read_phys(entry_pa, &mut guid_buf).is_err() { break; }
        if guid_buf == GOP_GUID {
            provider.read_phys(entry_pa + 16, &mut u64_buf)?;
            gop_mode_pa = Some(u64::from_le_bytes(u64_buf));
            break;
        }
    }

    let mode_pa = gop_mode_pa.ok_or_else(|| crate::Error::WalkFailed {
        walker: "framebuffer_windows",
        reason: "EFI GOP protocol not found in configuration table".into(),
    })?;

    // 4. Read EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE
    // +0x00: MaxMode (u32)
    // +0x04: Mode (u32)
    // +0x08: Info ptr (u64) → EFI_GRAPHICS_OUTPUT_MODE_INFORMATION
    // +0x10: SizeOfInfo (u64)
    // +0x18: FrameBufferBase (u64)
    // +0x20: FrameBufferSize (u64)
    provider.read_phys(mode_pa + 0x18, &mut u64_buf)?;
    let fb_base = u64::from_le_bytes(u64_buf);
    provider.read_phys(mode_pa + 0x08, &mut u64_buf)?;
    let info_pa = u64::from_le_bytes(u64_buf);

    // EFI_GRAPHICS_OUTPUT_MODE_INFORMATION:
    // +0x00: Version (u32)
    // +0x04: HorizontalResolution (u32)
    // +0x08: VerticalResolution (u32)
    // +0x0C: PixelFormat (u32)
    // +0x10: PixelInformation (EFI_PIXEL_BITMASK, 16 bytes)
    // +0x20: PixelsPerScanLine (u32)
    let mut u32_buf = [0u8; 4];
    provider.read_phys(info_pa + 0x04, &mut u32_buf)?;
    let width = u32::from_le_bytes(u32_buf);
    provider.read_phys(info_pa + 0x08, &mut u32_buf)?;
    let height = u32::from_le_bytes(u32_buf);
    provider.read_phys(info_pa + 0x0C, &mut u32_buf)?;
    let pixel_format_id = u32::from_le_bytes(u32_buf);
    provider.read_phys(info_pa + 0x20, &mut u32_buf)?;
    let pps = u32::from_le_bytes(u32_buf); // PixelsPerScanLine
    let stride = pps * 4; // 4 bytes per pixel (32-bit formats)

    let pixel_format = match pixel_format_id {
        0 => PixelFormat::Xrgb8888,
        1 => PixelFormat::Xbgr8888,
        _ => PixelFormat::Unknown(pixel_format_id as u8),
    };

    let fb_size = (stride as u64) * (height as u64);
    if fb_size > 32 * 1024 * 1024 {
        return Err(crate::Error::WalkFailed {
            walker: "framebuffer_windows",
            reason: format!("framebuffer size {fb_size} exceeds 32 MiB"),
        });
    }

    let mut fb_bytes = vec![0u8; fb_size as usize];
    provider.read_phys(fb_base, &mut fb_bytes).map_err(|_| crate::Error::WalkFailed {
        walker: "framebuffer_windows",
        reason: format!("could not read framebuffer at PA {fb_base:#x}"),
    })?;

    let png_bytes = encode_png(&fb_bytes, width, height, pixel_format)
        .map_err(|e| crate::Error::WalkFailed {
            walker: "framebuffer_windows",
            reason: format!("PNG encode: {e}"),
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
```

### Step 3: GREEN commit

```bash
cargo test -p memf-windows framebuffer 2>&1 | tail -10
cargo test --workspace 2>&1 | tail -5
git add crates/memf-windows/src/framebuffer.rs crates/memf-windows/src/lib.rs crates/memf-windows/Cargo.toml
git commit --no-gpg-sign -m "feat(fb): GREEN — Windows EFI GOP framebuffer walker"
```

---

## Task 4: `framebuffer` CLI subcommand in `src/main.rs` (TDD)

**Files:**
- Modify: `src/main.rs`
- Modify: `Cargo.toml` (add `memf-framebuffer` dep to `memf` binary)

### Step 1: Write RED test

In `src/main.rs` integration test (or `tests/cli.rs`):

```rust
#[test]
fn framebuffer_command_exists_in_help() {
    // Just check the subcommand is wired up
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_memf"))
        .args(["framebuffer", "--help"])
        .output()
        .expect("failed to run memf");
    assert!(output.status.success() || output.status.code() == Some(0));
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("dump") || help.contains("framebuffer"));
}
```

RED commit: `git commit --no-gpg-sign -m "test(fb): RED — framebuffer CLI subcommand test"`

### Step 2: Add `Framebuffer` subcommand

In `Commands` enum:
```rust
/// Extract and save a PNG screenshot from the physical memory framebuffer.
Framebuffer {
    /// Path to the memory dump file.
    #[arg(long)]
    dump: PathBuf,
    /// Optional ISF symbols path.
    #[arg(long)]
    symbols: Option<PathBuf>,
    /// Output format for metadata (json, table, ndjson).
    #[arg(long, default_value = "table")]
    output: OutputFormat,
    /// Write PNG bytes to this file (use - for stdout).
    #[arg(long)]
    png: Option<PathBuf>,
},
```

In the match arm:
```rust
Commands::Framebuffer { dump, symbols, output, png } => {
    let resolved = archive::resolve_dump(&dump)?;
    cmd_framebuffer(resolved.path(), symbols.as_deref(), output, png.as_deref(), resolved.is_extracted())
}
```

`cmd_framebuffer`: detect OS from `DumpMetadata.machine_type`, call `walk_framebuffer_linux` or `walk_framebuffer_windows`, emit metadata (width/height/source/phys_base) as JSON/table, write `png_bytes` to `--png` path.

### Step 3: GREEN commit

```bash
cargo build 2>&1 | grep "^error" | head -5
cargo test --workspace 2>&1 | tail -5
git add src/main.rs Cargo.toml Cargo.lock
git commit --no-gpg-sign -m "feat(fb): GREEN — framebuffer CLI subcommand with PNG output"
```

---

## Expected outcomes

| Capability | Before | After |
|---|---|---|
| Screenshot from Linux memory dump | none | PNG via `boot_params.screen_info` |
| Screenshot from Windows memory dump | none | PNG via EFI GOP scan |
| Pixel format conversion | none | XRGB, XBGR, RGB565, BGR24 |
| CLI integration | none | `memf framebuffer --dump X --png out.png` |
| Memory cap | — | 32 MiB max framebuffer |
