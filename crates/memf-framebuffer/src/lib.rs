#[derive(Debug, Clone, serde::Serialize)]
pub struct FramebufferResult {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: String,
    pub phys_base: u64,
    pub source: String,
    #[serde(skip)]
    pub png_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PixelFormat {
    Xrgb8888,
    Xbgr8888,
    Bgr24,
    Rgb565,
    Unknown(u8),
}

#[derive(Debug, thiserror::Error)]
pub enum FramebufferError {
    #[error("unsupported pixel format: {0:?}")]
    UnsupportedPixelFormat(PixelFormat),
    #[error("PNG encoding failed: {0}")]
    PngEncode(String),
    #[error("pixel buffer too small for {width}x{height} {format:?}")]
    BufferTooSmall { width: u32, height: u32, format: PixelFormat },
    #[error("framebuffer not found")]
    NotFound,
    #[error("physical memory read failed")]
    ReadFailed,
}

pub fn to_rgb24(pixels: &[u8], width: u32, height: u32, format: PixelFormat)
    -> Result<Vec<u8>, FramebufferError>
{
    if width == 0 || height == 0 {
        return Ok(Vec::new());
    }
    let n = (width * height) as usize;
    match format {
        PixelFormat::Xbgr8888 => {
            if pixels.len() < n * 4 {
                return Err(FramebufferError::BufferTooSmall { width, height, format });
            }
            Ok(pixels.chunks_exact(4).take(n)
                .flat_map(|p| [p[2], p[1], p[0]])
                .collect())
        }
        PixelFormat::Xrgb8888 => {
            if pixels.len() < n * 4 {
                return Err(FramebufferError::BufferTooSmall { width, height, format });
            }
            Ok(pixels.chunks_exact(4).take(n)
                .flat_map(|p| [p[0], p[1], p[2]])
                .collect())
        }
        PixelFormat::Bgr24 => {
            if pixels.len() < n * 3 {
                return Err(FramebufferError::BufferTooSmall { width, height, format });
            }
            Ok(pixels.chunks_exact(3).take(n)
                .flat_map(|p| [p[2], p[1], p[0]])
                .collect())
        }
        PixelFormat::Rgb565 => {
            if pixels.len() < n * 2 {
                return Err(FramebufferError::BufferTooSmall { width, height, format });
            }
            Ok(pixels.chunks_exact(2).take(n)
                .flat_map(|p| {
                    let v = u16::from_le_bytes([p[0], p[1]]);
                    let r5 = ((v >> 11) & 0x1F) as u8;
                    let g6 = ((v >> 5)  & 0x3F) as u8;
                    let b5 = (v         & 0x1F) as u8;
                    let r = (r5 << 3) | (r5 >> 2);
                    let g = (g6 << 2) | (g6 >> 4);
                    let b = (b5 << 3) | (b5 >> 2);
                    [r, g, b]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_png_produces_valid_png_header() {
        // 2x2 XBGR8888: B=i, G=0, R=0, X=0xFF for each pixel
        let pixels: Vec<u8> = (0u8..4).flat_map(|i| [i, 0, 0, 0xFF]).collect();
        let png = encode_png(&pixels, 2, 2, PixelFormat::Xbgr8888).expect("encode must succeed");
        assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"), "must have PNG magic");
        assert!(png.len() > 20);
    }

    #[test]
    fn encode_png_zero_dimensions_returns_empty() {
        let result = encode_png(&[], 0, 0, PixelFormat::Xrgb8888).expect("zero dims ok");
        assert!(result.is_empty());
    }

    #[test]
    fn to_rgb24_xbgr8888_swaps_channels() {
        // XBGR8888 byte order: [B, G, R, X]
        // pixel: B=0x10, G=0x20, R=0x30, X=0xFF
        let pixels = vec![0x10u8, 0x20, 0x30, 0xFF];
        let rgb = to_rgb24(&pixels, 1, 1, PixelFormat::Xbgr8888).expect("ok");
        // RGB24 output should be [R, G, B] = [0x30, 0x20, 0x10]
        assert_eq!(rgb, vec![0x30, 0x20, 0x10]);
    }

    #[test]
    fn to_rgb24_xrgb8888_preserves_rgb_order() {
        // XRGB8888: [R, G, B, X] — output RGB24 is same first 3 bytes
        let pixels = vec![0x10u8, 0x20, 0x30, 0xFF];
        let rgb = to_rgb24(&pixels, 1, 1, PixelFormat::Xrgb8888).expect("ok");
        assert_eq!(rgb, vec![0x10, 0x20, 0x30]);
    }

    #[test]
    fn to_rgb24_bgr24_swaps_rb() {
        // BGR24: [B, G, R] -> RGB24: [R, G, B]
        let pixels = vec![0x10u8, 0x20, 0x30];
        let rgb = to_rgb24(&pixels, 1, 1, PixelFormat::Bgr24).expect("ok");
        assert_eq!(rgb, vec![0x30, 0x20, 0x10]);
    }

    #[test]
    fn to_rgb24_rgb565_full_red_pixel() {
        // RGB565: 5R 6G 5B packed in 2 bytes LE
        // Full red: R=11111=0x1F, G=000000, B=00000 -> value = 0xF800
        // LE bytes: [0x00, 0xF8]
        let pixels = vec![0x00u8, 0xF8];
        let rgb = to_rgb24(&pixels, 1, 1, PixelFormat::Rgb565).expect("ok");
        // R should expand 0x1F -> 0xFF (shift left 3, fill low 2 bits)
        assert_eq!(rgb[0], 0xFF, "R should be max for full red");
        assert_eq!(rgb[1], 0x00, "G should be 0");
        assert_eq!(rgb[2], 0x00, "B should be 0");
    }

    #[test]
    fn to_rgb24_unknown_format_returns_error() {
        let pixels = vec![0u8; 4];
        let result = to_rgb24(&pixels, 1, 1, PixelFormat::Unknown(99));
        assert!(result.is_err());
    }

    #[test]
    fn to_rgb24_buffer_too_small_returns_error() {
        // 2x2 XBGR8888 needs 16 bytes, give only 4
        let pixels = vec![0u8; 4];
        let result = to_rgb24(&pixels, 2, 2, PixelFormat::Xbgr8888);
        assert!(result.is_err());
    }
}
