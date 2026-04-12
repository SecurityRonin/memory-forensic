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
/// Output is limited to 4096 bytes (one kernel page).
pub fn decompress(input: &[u8]) -> Result<Vec<u8>, LzoError> {
    decompress_with_limit(input, 4096)
}

/// Read the next byte from input, advancing the position.
fn next_byte(input: &[u8], ip: &mut usize) -> Result<u8, LzoError> {
    if *ip >= input.len() {
        return Err(LzoError::InputOverrun);
    }
    let b = input[*ip];
    *ip += 1;
    Ok(b)
}

/// Copy `count` literal bytes from input to output.
fn copy_literals(
    input: &[u8],
    ip: &mut usize,
    output: &mut Vec<u8>,
    count: usize,
    max_output: usize,
) -> Result<(), LzoError> {
    if *ip + count > input.len() {
        return Err(LzoError::InputOverrun);
    }
    if output.len() + count > max_output {
        return Err(LzoError::OutputOverrun);
    }
    output.extend_from_slice(&input[*ip..*ip + count]);
    *ip += count;
    Ok(())
}

/// Copy `count` bytes from a previous position in the output (match copy).
fn copy_match(
    output: &mut Vec<u8>,
    dist: usize,
    count: usize,
    max_output: usize,
) -> Result<(), LzoError> {
    if dist > output.len() || dist == 0 {
        return Err(LzoError::LookbehindOverrun);
    }
    if output.len() + count > max_output {
        return Err(LzoError::OutputOverrun);
    }
    let start = output.len() - dist;
    for i in 0..count {
        let b = output[start + i];
        output.push(b);
    }
    Ok(())
}

/// Read an extended length: skip zero bytes and accumulate.
fn read_extended_len(input: &[u8], ip: &mut usize, base: usize) -> Result<usize, LzoError> {
    let mut len = 0usize;
    loop {
        let b = next_byte(input, ip)?;
        if b != 0 {
            return Ok(len + base + b as usize);
        }
        len += 255;
    }
}

/// Decompress LZO1X-1 compressed data with a custom output size limit.
///
/// Follows the Linux kernel's `lzo1x_decompress_safe` algorithm with four
/// match types (M1-M4) and literal runs.
pub fn decompress_with_limit(input: &[u8], max_output: usize) -> Result<Vec<u8>, LzoError> {
    if input.is_empty() {
        return Err(LzoError::InputOverrun);
    }

    let mut output = Vec::with_capacity(max_output.min(4096));
    let mut ip = 0usize;

    let mut t = next_byte(input, &mut ip)? as usize;

    // Handle initial literal run
    if t > 17 {
        // First byte >= 18: literal run of (t - 17) bytes
        let lit_len = t - 17;
        copy_literals(input, &mut ip, &mut output, lit_len, max_output)?;
        t = next_byte(input, &mut ip)? as usize;
    } else if t < 16 {
        // First byte in [0..16): literal run with length encoding
        let lit_len = if t == 0 {
            read_extended_len(input, &mut ip, 15)? + 3
        } else {
            t + 3
        };
        copy_literals(input, &mut ip, &mut output, lit_len, max_output)?;
        t = next_byte(input, &mut ip)? as usize;
    }
    // If first byte in [16..18), fall through to main loop

    loop {
        let trailing_lits;

        if t >= 64 {
            // M2: short match (2-byte encoding)
            let match_len = ((t >> 5) & 0x07) + 2;
            let b = next_byte(input, &mut ip)? as usize;
            let dist = ((t & 0x1F) << 8) + b + 1;
            copy_match(&mut output, dist, match_len, max_output)?;
            trailing_lits = t & 0x03;
        } else if t >= 32 {
            // M3: medium match (3-byte encoding)
            let len_bits = (t & 0x1F) as usize;
            let match_len = if len_bits == 0 {
                read_extended_len(input, &mut ip, 31)? + 2
            } else {
                len_bits + 2
            };
            let low = next_byte(input, &mut ip)? as usize;
            let high = next_byte(input, &mut ip)? as usize;
            let dist = (low >> 2) + (high << 6) + 1;
            copy_match(&mut output, dist, match_len, max_output)?;
            trailing_lits = low & 0x03;
        } else if t >= 16 {
            // M4: long-distance match or EOS
            let len_bits = (t & 0x07) as usize;
            let match_len = if len_bits == 0 {
                read_extended_len(input, &mut ip, 7)? + 2
            } else {
                len_bits + 2
            };

            let low = next_byte(input, &mut ip)? as usize;
            let high = next_byte(input, &mut ip)? as usize;
            let m_off_raw = (low >> 2) + (high << 6) + ((t & 0x08) << 11);

            if m_off_raw == 0 {
                // End of stream
                break;
            }
            let dist = m_off_raw + 16384;
            copy_match(&mut output, dist, match_len, max_output)?;
            trailing_lits = low & 0x03;
        } else {
            // M1: shortest match (t < 16, only after prior output)
            let b = next_byte(input, &mut ip)? as usize;
            let dist = ((t >> 2) & 0x03) + b * 4 + 1;
            copy_match(&mut output, dist, 2, max_output)?;
            trailing_lits = t & 0x03;
        }

        // Copy trailing literals after the match
        if trailing_lits > 0 {
            copy_literals(input, &mut ip, &mut output, trailing_lits, max_output)?;
        }

        t = next_byte(input, &mut ip)? as usize;
    }

    Ok(output)
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
        // first byte >= 18: literal count = byte - 17
        // 0x15 (21) => 21 - 17 = 4 literal bytes
        let input = [
            0x15,
            0xDE, 0xAD, 0xBE, 0xEF,
            0x11, 0x00, 0x00,
        ];
        let result = decompress(&input).unwrap();
        assert_eq!(result, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn decompress_longer_literal_then_eos() {
        // first byte = 24 => 24 - 17 = 7 literal bytes
        let mut input = vec![24u8];
        input.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        input.extend_from_slice(&[0x11, 0x00, 0x00]);
        let result = decompress(&input).unwrap();
        assert_eq!(result, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    }

    #[test]
    fn decompress_match_copy() {
        // 4 literal bytes "AAAA", then M3 match copying 4 from distance 4 => "AAAAAAAA"
        // M3 (t>=32): byte = 0x20 | (len-2) = 0x22, next 2 bytes encode distance
        // dist = (low >> 2) + (high << 6) + 1; for dist=4: low=0x0C, high=0
        let input = [
            0x15,
            b'A', b'A', b'A', b'A',
            0x22,
            0x0C, 0x00,
            0x11, 0x00, 0x00,
        ];
        let result = decompress(&input).unwrap();
        assert_eq!(result, b"AAAAAAAA");
    }

    #[test]
    fn decompress_input_overrun_errors() {
        // Says 4 literals but only 2 available
        let input = [0x15, 0xAA, 0xBB];
        let result = decompress(&input);
        assert_eq!(result, Err(LzoError::InputOverrun));
    }

    #[test]
    fn decompress_lookbehind_overrun_errors() {
        // 4 literals, then M3 match with distance=10 > 4 output bytes
        // dist=10: (low>>2) + 1 = 10 => low = 36 (0x24)
        let input = [
            0x15,
            b'X', b'X', b'X', b'X',
            0x22,
            0x24, 0x00,
            0x11, 0x00, 0x00,
        ];
        let result = decompress(&input);
        assert_eq!(result, Err(LzoError::LookbehindOverrun));
    }

    #[test]
    fn decompress_output_overrun_errors() {
        let input = [
            0x15,
            0x01, 0x02, 0x03, 0x04,
            0x11, 0x00, 0x00,
        ];
        let result = decompress_with_limit(&input, 2);
        assert_eq!(result, Err(LzoError::OutputOverrun));
    }

    #[test]
    fn decompress_empty_input_errors() {
        let result = decompress(&[]);
        assert!(result.is_err());
    }
}
