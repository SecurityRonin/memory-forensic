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

/// Build a synthetic ELF core dump for testing.
#[derive(Default)]
pub struct ElfCoreBuilder {
    segments: Vec<(u64, Vec<u8>)>,
}

impl ElfCoreBuilder {
    /// Create a new empty builder.
    pub fn new() -> Self { Self { segments: Vec::new() } }

    /// Add a PT_LOAD segment at the given physical address with the given data.
    pub fn add_segment(mut self, paddr: u64, data: &[u8]) -> Self {
        self.segments.push((paddr, data.to_vec()));
        self
    }

    /// Build the ELF core dump as a byte vector.
    pub fn build(self) -> Vec<u8> {
        let ehdr_size: usize = 64;
        let phdr_size: usize = 56;
        let phdr_count = self.segments.len();
        let phdr_total = phdr_count * phdr_size;
        let data_start = ((ehdr_size + phdr_total + 0xFFF) / 0x1000) * 0x1000;
        let mut out = vec![0u8; data_start];

        // ELF header
        out[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        out[4] = 2; // ELFCLASS64
        out[5] = 1; // ELFDATA2LSB
        out[6] = 1; // EV_CURRENT
        out[16..18].copy_from_slice(&4u16.to_le_bytes()); // ET_CORE
        out[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        out[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        out[32..40].copy_from_slice(&(ehdr_size as u64).to_le_bytes()); // e_phoff
        out[52..54].copy_from_slice(&(ehdr_size as u16).to_le_bytes()); // e_ehsize
        out[54..56].copy_from_slice(&(phdr_size as u16).to_le_bytes()); // e_phentsize
        out[56..58].copy_from_slice(&(phdr_count as u16).to_le_bytes()); // e_phnum

        let mut current_offset = data_start;
        for (i, (paddr, data)) in self.segments.iter().enumerate() {
            let phdr_off = ehdr_size + i * phdr_size;
            out[phdr_off..phdr_off + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
            out[phdr_off + 4..phdr_off + 8].copy_from_slice(&6u32.to_le_bytes()); // PF_R|PF_W
            out[phdr_off + 8..phdr_off + 16].copy_from_slice(&(current_offset as u64).to_le_bytes());
            out[phdr_off + 24..phdr_off + 32].copy_from_slice(&paddr.to_le_bytes());
            out[phdr_off + 32..phdr_off + 40].copy_from_slice(&(data.len() as u64).to_le_bytes());
            out[phdr_off + 40..phdr_off + 48].copy_from_slice(&(data.len() as u64).to_le_bytes());
            out[phdr_off + 48..phdr_off + 56].copy_from_slice(&0x1000u64.to_le_bytes());
            out.resize(current_offset + data.len(), 0);
            out[current_offset..current_offset + data.len()].copy_from_slice(data);
            current_offset += data.len();
        }
        out
    }
}
