//! LZO1X-1 decompression for Linux kernel zram pages.
//!
//! The Linux kernel uses LZO1X for zram (compressed swap) pages. This module
//! provides a safe decompressor compatible with the kernel's `lzo1x_decompress_safe`.

/// Errors that can occur during LZO1X decompression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LzoError {
    /// Read past end of input buffer.
    InputOverrun,
    /// Output exceeded the maximum allowed size.
    OutputOverrun,
    /// Match distance exceeds bytes produced so far (invalid back-reference).
    LookbehindOverrun,
    /// Other format or data error.
    Error,
}

impl std::fmt::Display for LzoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InputOverrun => write!(f, "LZO input overrun"),
            Self::OutputOverrun => write!(f, "LZO output overrun"),
            Self::LookbehindOverrun => write!(f, "LZO lookbehind overrun"),
            Self::Error => write!(f, "LZO format error"),
        }
    }
}

impl std::error::Error for LzoError {}

/// Decompress LZO1X-1 compressed data (Linux kernel variant).
///
/// Returns the decompressed bytes, or an error if the input is malformed.
pub fn decompress(input: &[u8]) -> Result<Vec<u8>, LzoError> {
    // Maximum output size for a 4KB kernel page
    decompress_with_limit(input, 4096)
}

/// Decompress LZO1X-1 compressed data with a custom output size limit.
pub fn decompress_with_limit(_input: &[u8], _max_output: usize) -> Result<Vec<u8>, LzoError> {
    todo!("LZO1X decompression not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompress_empty_eos_stream() {
        // EOS marker: [0x11, 0x00, 0x00]
        let input = [0x11, 0x00, 0x00];
        let result = decompress(&input).unwrap();
        assert!(result.is_empty(), "EOS-only stream should produce empty output");
    }

    #[test]
    fn decompress_short_literal_then_eos() {
        // First command byte < 16: literal run.
        // When first byte is 0, read next bytes for length.
        // But simpler: first byte 0x11 + N means N literal bytes (when N >= 1).
        // Actually for initial literal: if first byte >= 18, literal count = byte - 17.
        // So 0x15 (21) => 21 - 17 = 4 literal bytes
        let input = [
            0x15, // first byte = 21 >= 18, so literal run of 4 bytes
            0xDE, 0xAD, 0xBE, 0xEF, // 4 literal bytes
            0x11, 0x00, 0x00, // EOS
        ];
        let result = decompress(&input).unwrap();
        assert_eq!(result, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn decompress_longer_literal_then_eos() {
        // first byte = 24 => 24 - 17 = 7 literal bytes
        let mut input = vec![24u8]; // 7 literals
        input.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        input.extend_from_slice(&[0x11, 0x00, 0x00]); // EOS
        let result = decompress(&input).unwrap();
        assert_eq!(result, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    }

    #[test]
    fn decompress_match_copy() {
        // Emit 4 literal bytes "ABCD", then a match that copies from offset 4 (the start), length 4.
        // This should produce "ABCDABCD".
        //
        // Step 1: Initial literal. first byte = 21 (0x15) => 4 literals.
        // Step 2: After literals, we need a match command.
        //   A match with t >= 64 (two-byte match):
        //   byte = 0b_MMM_LL_DDD where:
        //     MMM = match_len - 2 (stored in bits 5-7), so for len=4: MMM=2 => bits 5-7 = 010
        //     LL = literal count after match (0 for us)
        //     DDD = distance high bits (bits 0-2)
        //   distance = (DDD << 8) | next_byte, where distance is 1-based offset from current output pos
        //   For distance=4: DDD=0, next_byte=3 (distance = 0*256 + 3 + 1 = 4)
        //   Wait - let me reconsider the kernel LZO format...
        //
        //   Actually: for t >= 64:
        //     match_len = (t >> 5) + 1  ... varies by implementation
        //   Let me use a simpler approach: compress known data with a reference compressor.
        //
        // Instead, let me hand-craft using the >=32 (M2) match format:
        //   byte1 in [32..64): M2 match
        //   len = (byte1 & 0x1F) + 2
        //   if (byte1 & 0x1F) == 0: read extra length bytes
        //   distance = ((next_byte >> 2) | (next_next_byte << 6)) + 1  ... no wait
        //
        // The simplest approach: produce known input/output pairs by referencing
        // the algorithm spec directly.
        //
        // Literal "AAAA" (4 bytes) then match copying those 4 bytes:
        // Initial: 0x15 (4 literals), 'A', 'A', 'A', 'A'
        // Match (>=32 format): byte = 0x20 | (len-2) = 0x20 | 2 = 0x22
        //   next two bytes encode distance: low byte = ((dist-1) << 2) | after_lit_count
        //   high byte = ((dist-1) >> 6)
        //   dist = 4: low = (3 << 2) | 0 = 12, high = 0
        // Then EOS: 0x11, 0x00, 0x00
        let input = [
            0x15,                     // 4 literal bytes
            b'A', b'A', b'A', b'A',  // literals
            0x22,                     // match: len = (0x22 & 0x1F) + 2 = 4, type M2 (>=32)
            0x0C, 0x00,              // distance encoding: low=12=(3<<2)|0, high=0 => dist=3+1=4... wait
            // Actually: distance = (low >> 2) + (high << 6) + 1
            // We want dist=4: (low>>2) + (high<<6) + 1 = 4 => (low>>2) + 0 = 3 => low>>2 = 3 => low = 12
            // But low also has bottom 2 bits = literal count after match. So low = 3<<2 | 0 = 12
            0x11, 0x00, 0x00,        // EOS
        ];
        let result = decompress(&input).unwrap();
        assert_eq!(result, b"AAAAAAAA");
    }

    #[test]
    fn decompress_input_overrun_errors() {
        // Truncated: says 4 literals but only 2 available
        let input = [0x15, 0xAA, 0xBB];
        let result = decompress(&input);
        assert_eq!(result, Err(LzoError::InputOverrun));
    }

    #[test]
    fn decompress_lookbehind_overrun_errors() {
        // Emit 4 literal bytes, then a match with distance > 4 (the output so far)
        // 4 literals: 0x15, then 4 bytes
        // Match >= 32: 0x22 (len=4), distance encoding for dist=10:
        //   (low>>2) + (high<<6) + 1 = 10 => low>>2 = 9 => low = 36, high = 0
        let input = [
            0x15,
            b'X', b'X', b'X', b'X',
            0x22,       // match len=4
            0x24, 0x00, // low=36 => dist = (36>>2) + 0 + 1 = 10 > 4 output bytes
            0x11, 0x00, 0x00,
        ];
        let result = decompress(&input);
        assert_eq!(result, Err(LzoError::LookbehindOverrun));
    }

    #[test]
    fn decompress_output_overrun_errors() {
        // Create input that would produce more than 4096 bytes
        // 18 literal bytes each pass... actually easiest: just set a small limit
        // and decompress something that exceeds it
        let input = [
            0x15,                     // 4 literal bytes
            0x01, 0x02, 0x03, 0x04,
            0x11, 0x00, 0x00,        // EOS
        ];
        // Use decompress_with_limit with a small limit
        let result = decompress_with_limit(&input, 2);
        assert_eq!(result, Err(LzoError::OutputOverrun));
    }

    #[test]
    fn decompress_empty_input_errors() {
        let result = decompress(&[]);
        assert!(result.is_err());
    }
}
