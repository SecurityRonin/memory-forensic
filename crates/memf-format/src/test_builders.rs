//! Synthetic dump builders for unit tests.
//!
//! These are only compiled when `cfg(test)` is active or when explicitly
//! depended on by other test modules.

/// Build a synthetic LiME dump byte-by-byte.
///
/// Each range is serialised as a 32-byte header followed by raw payload data.
/// Header layout (all fields little-endian):
/// - 0x00: magic  = 0x4C694D45 (4 bytes)
/// - 0x04: version = 1          (4 bytes)
/// - 0x08: s_addr               (8 bytes)
/// - 0x10: e_addr (inclusive)   (8 bytes)
/// - 0x18: reserved             (8 bytes zeros)
#[derive(Default)]
pub struct LimeBuilder {
    ranges: Vec<(u64, Vec<u8>)>,
}

impl LimeBuilder {
    /// Create an empty builder.
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Add a physical memory range starting at `start` with the given `data`.
    pub fn add_range(mut self, start: u64, data: &[u8]) -> Self {
        self.ranges.push((start, data.to_vec()));
        self
    }

    /// Serialise all ranges into a complete LiME dump.
    pub fn build(self) -> Vec<u8> {
        const MAGIC: u32 = 0x4C694D45;
        const VERSION: u32 = 1;

        let mut out = Vec::new();
        for (start, data) in &self.ranges {
            let e_addr = start + data.len() as u64 - 1; // inclusive end
            out.extend_from_slice(&MAGIC.to_le_bytes());
            out.extend_from_slice(&VERSION.to_le_bytes());
            out.extend_from_slice(&start.to_le_bytes());
            out.extend_from_slice(&e_addr.to_le_bytes());
            out.extend_from_slice(&0u64.to_le_bytes()); // reserved
            out.extend_from_slice(data);
        }
        out
    }
}

/// Build a synthetic AVML dump byte-by-byte.
///
/// Each range is serialised as a 32-byte header followed by a Snappy-compressed
/// payload, then 8 trailing bytes encoding the uncompressed size as u64 LE.
/// Header layout (all fields little-endian):
/// - 0x00: magic   = 0x4C4D5641 (4 bytes)
/// - 0x04: version = 2           (4 bytes)
/// - 0x08: s_addr                (8 bytes)
/// - 0x10: e_addr (exclusive)    (8 bytes)
/// - 0x18: reserved              (8 bytes zeros)
#[derive(Default)]
pub struct AvmlBuilder {
    ranges: Vec<(u64, Vec<u8>)>,
}

impl AvmlBuilder {
    /// Create an empty builder.
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Add a physical memory range starting at `start` with the given `data`.
    pub fn add_range(mut self, start: u64, data: &[u8]) -> Self {
        self.ranges.push((start, data.to_vec()));
        self
    }

    /// Serialise all ranges into a complete AVML dump.
    pub fn build(self) -> Vec<u8> {
        const MAGIC: u32 = 0x4C4D5641;
        const VERSION: u32 = 2;

        let mut out = Vec::new();
        for (start, data) in &self.ranges {
            let e_addr = start + data.len() as u64; // exclusive end
            let uncompressed_size = data.len() as u64;

            let mut encoder = snap::raw::Encoder::new();
            let compressed = encoder.compress_vec(data).expect("snappy compress");

            out.extend_from_slice(&MAGIC.to_le_bytes());
            out.extend_from_slice(&VERSION.to_le_bytes());
            out.extend_from_slice(&start.to_le_bytes());
            out.extend_from_slice(&e_addr.to_le_bytes());
            out.extend_from_slice(&0u64.to_le_bytes()); // reserved
            out.extend_from_slice(&compressed);
            out.extend_from_slice(&uncompressed_size.to_le_bytes()); // trailer
        }
        out
    }
}
