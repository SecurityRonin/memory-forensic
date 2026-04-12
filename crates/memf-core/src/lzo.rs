//! LZO1X-1 decompression for Linux kernel zram pages.
//!
//! Thin wrapper around the [`lzo1x`] crate, exposing a forensics-oriented API.
//! The Linux kernel stores the expected decompressed size in the zram slot header,
//! so callers always know the output size in advance.

/// Errors that can occur during LZO1X decompression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LzoError {
    /// The compressed input is malformed or truncated.
    InvalidInput,
    /// The destination buffer length does not match the decompressed data length.
    OutputLength,
}

impl std::fmt::Display for LzoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput => write!(f, "LZO invalid input"),
            Self::OutputLength => write!(f, "LZO output length mismatch"),
        }
    }
}

impl std::error::Error for LzoError {}

/// Decompress LZO1X-1 compressed data into `dst`.
///
/// The caller must provide a buffer of **exactly** the expected decompressed
/// size (e.g. 4096 bytes for a Linux zram page). Returns [`LzoError::OutputLength`]
/// if the actual decompressed size differs from `dst.len()`.
pub fn decompress(src: &[u8], dst: &mut [u8]) -> Result<(), LzoError> {
    lzo1x::decompress(src, dst).map_err(|e| match e {
        lzo1x::DecompressError::InvalidInput => LzoError::InvalidInput,
        lzo1x::DecompressError::OutputLength => LzoError::OutputLength,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip helper: compress with the lzo1x crate then decompress with ours.
    fn compress(data: &[u8]) -> Vec<u8> {
        lzo1x::compress(data, lzo1x::CompressLevel::default())
    }

    #[test]
    fn decompress_empty_data() {
        let input: &[u8] = &[];
        let compressed = compress(input);
        let mut dst = [];
        decompress(&compressed, &mut dst).unwrap();
    }

    #[test]
    fn decompress_short_literal() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let compressed = compress(&data);
        let mut dst = [0u8; 4];
        decompress(&compressed, &mut dst).unwrap();
        assert_eq!(dst, data);
    }

    #[test]
    fn decompress_repeated_bytes_match_copy() {
        let data = [b'A'; 32];
        let compressed = compress(&data);
        let mut dst = [0u8; 32];
        decompress(&compressed, &mut dst).unwrap();
        assert_eq!(dst, data);
    }

    #[test]
    fn decompress_full_kernel_page() {
        let data = vec![0x55u8; 4096];
        let compressed = compress(&data);
        let mut dst = vec![0u8; 4096];
        decompress(&compressed, &mut dst).unwrap();
        assert_eq!(dst, data);
    }

    #[test]
    fn decompress_invalid_input_errors() {
        let mut dst = [0u8; 4];
        let result = decompress(&[0xFF, 0xFF, 0xFF], &mut dst);
        assert_eq!(result, Err(LzoError::InvalidInput));
    }

    #[test]
    fn decompress_output_length_mismatch_errors() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let compressed = compress(&data);
        // dst is too small — expects OutputLength error
        let mut dst = [0u8; 2];
        let result = decompress(&compressed, &mut dst);
        assert_eq!(result, Err(LzoError::OutputLength));
    }

    #[test]
    fn decompress_empty_input_errors() {
        let mut dst = [0u8; 4];
        let result = decompress(&[], &mut dst);
        assert!(result.is_err());
    }
}
