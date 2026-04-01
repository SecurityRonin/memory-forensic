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

/// Build a synthetic Windows 64-bit crash dump (`_DUMP_HEADER64`).
///
/// Produces an 8192-byte header followed by physical memory page data.
/// Supports both run-based (DumpType 0x01) and bitmap (DumpType 0x02/0x05) layouts.
///
/// Header layout (little-endian, key offsets):
/// - 0x000: "PAGE" magic (u32 = 0x4547_4150)
/// - 0x004: "DU64" signature (u32 = 0x3436_5544)
/// - 0x010: DirectoryTableBase / CR3 (u64)
/// - 0x020: PsLoadedModuleList (u64)
/// - 0x028: PsActiveProcessHead (u64)
/// - 0x030: MachineImageType (u32)
/// - 0x034: NumberProcessors (u32)
/// - 0x080: KdDebuggerDataBlock (u64)
/// - 0x088: PhysicalMemoryBlockBuffer — NumberOfRuns(u32) + pad(u32) + NumberOfPages(u64) + Runs[]
/// - 0xF98: DumpType (u32)
/// - 0xFA8: SystemTime (u64)
pub struct CrashDumpBuilder {
    runs: Vec<(u64, Vec<u8>)>,
    cr3: u64,
    ps_active_process_head: u64,
    ps_loaded_module_list: u64,
    kd_debugger_data_block: u64,
    machine_type: u32,
    num_processors: u32,
    dump_type: u32,
    system_time: u64,
}

impl Default for CrashDumpBuilder {
    fn default() -> Self {
        Self {
            runs: Vec::new(),
            cr3: 0x0018_7000,
            ps_active_process_head: 0xFFFFF802_1A2B3C40,
            ps_loaded_module_list: 0xFFFFF802_1A2B3D60,
            kd_debugger_data_block: 0xFFFFF802_1A000000,
            machine_type: 0x8664, // AMD64
            num_processors: 4,
            dump_type: 0x01, // Full (run-based)
            system_time: 0x01DA_5678_9ABC_DEF0,
        }
    }
}

impl CrashDumpBuilder {
    /// Create a builder with sensible AMD64 defaults (DumpType = Full / run-based).
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a physical memory run starting at `base_page` (PFN) with the given page `data`.
    /// `data.len()` must be a multiple of 4096.
    pub fn add_run(mut self, base_page: u64, data: &[u8]) -> Self {
        assert!(
            data.len() % 4096 == 0,
            "run data length must be a multiple of 4096"
        );
        self.runs.push((base_page, data.to_vec()));
        self
    }

    /// Set the CR3 / DirectoryTableBase value.
    pub fn cr3(mut self, val: u64) -> Self {
        self.cr3 = val;
        self
    }

    /// Set the PsActiveProcessHead virtual address.
    pub fn ps_active_process_head(mut self, val: u64) -> Self {
        self.ps_active_process_head = val;
        self
    }

    /// Set the PsLoadedModuleList virtual address.
    pub fn ps_loaded_module_list(mut self, val: u64) -> Self {
        self.ps_loaded_module_list = val;
        self
    }

    /// Set the KdDebuggerDataBlock virtual address.
    pub fn kd_debugger_data_block(mut self, val: u64) -> Self {
        self.kd_debugger_data_block = val;
        self
    }

    /// Set the MachineImageType (0x8664=AMD64, 0x014C=I386, 0xAA64=AArch64).
    pub fn machine_type(mut self, val: u32) -> Self {
        self.machine_type = val;
        self
    }

    /// Set the number of processors.
    pub fn num_processors(mut self, val: u32) -> Self {
        self.num_processors = val;
        self
    }

    /// Set the DumpType (0x01=Full, 0x02=Kernel/Bitmap, 0x05=Bitmap).
    pub fn dump_type(mut self, val: u32) -> Self {
        self.dump_type = val;
        self
    }

    /// Set the SystemTime value.
    pub fn system_time(mut self, val: u64) -> Self {
        self.system_time = val;
        self
    }

    /// Build the complete crash dump as a byte vector.
    pub fn build(self) -> Vec<u8> {
        const PAGE_MAGIC: u32 = 0x4547_4150; // "PAGE"
        const DU64_SIG: u32 = 0x3436_5544; // "DU64"
        const HEADER_SIZE: usize = 0x2000; // 8192 bytes
        const PAGE_SIZE: usize = 4096;

        let mut header = vec![0u8; HEADER_SIZE];

        // 0x000: PAGE magic
        header[0x000..0x004].copy_from_slice(&PAGE_MAGIC.to_le_bytes());
        // 0x004: DU64 signature
        header[0x004..0x008].copy_from_slice(&DU64_SIG.to_le_bytes());
        // 0x010: CR3 / DirectoryTableBase
        header[0x010..0x018].copy_from_slice(&self.cr3.to_le_bytes());
        // 0x020: PsLoadedModuleList
        header[0x020..0x028].copy_from_slice(&self.ps_loaded_module_list.to_le_bytes());
        // 0x028: PsActiveProcessHead
        header[0x028..0x030].copy_from_slice(&self.ps_active_process_head.to_le_bytes());
        // 0x030: MachineImageType
        header[0x030..0x034].copy_from_slice(&self.machine_type.to_le_bytes());
        // 0x034: NumberProcessors
        header[0x034..0x038].copy_from_slice(&self.num_processors.to_le_bytes());
        // 0x080: KdDebuggerDataBlock
        header[0x080..0x088].copy_from_slice(&self.kd_debugger_data_block.to_le_bytes());

        // 0x088: PhysicalMemoryBlockBuffer
        let num_runs = self.runs.len() as u32;
        let total_pages: u64 = self
            .runs
            .iter()
            .map(|(_, d)| (d.len() / PAGE_SIZE) as u64)
            .sum();
        // NumberOfRuns (u32) at 0x088
        header[0x088..0x08C].copy_from_slice(&num_runs.to_le_bytes());
        // Padding (u32) at 0x08C
        header[0x08C..0x090].copy_from_slice(&0u32.to_le_bytes());
        // NumberOfPages (u64) at 0x090
        header[0x090..0x098].copy_from_slice(&total_pages.to_le_bytes());
        // Runs[] starting at 0x098, each run is 16 bytes: base_page(u64) + page_count(u64)
        for (i, (base_page, data)) in self.runs.iter().enumerate() {
            let page_count = (data.len() / PAGE_SIZE) as u64;
            let off = 0x098 + i * 16;
            header[off..off + 8].copy_from_slice(&base_page.to_le_bytes());
            header[off + 8..off + 16].copy_from_slice(&page_count.to_le_bytes());
        }

        // 0xF98: DumpType
        header[0xF98..0xF9C].copy_from_slice(&self.dump_type.to_le_bytes());
        // 0xFA8: SystemTime
        header[0xFA8..0xFB0].copy_from_slice(&self.system_time.to_le_bytes());

        let is_bitmap = self.dump_type == 0x02 || self.dump_type == 0x05;

        if is_bitmap {
            self.build_bitmap(header)
        } else {
            self.build_run_based(header)
        }
    }

    /// Build run-based layout: data pages follow header sequentially at offset 0x2000.
    fn build_run_based(self, mut out: Vec<u8>) -> Vec<u8> {
        for (_, data) in &self.runs {
            out.extend_from_slice(data);
        }
        out
    }

    /// Build bitmap layout: summary header + bitmap + data pages at offset 0x2000.
    fn build_bitmap(self, mut out: Vec<u8>) -> Vec<u8> {
        const DUMP_VALID: u32 = 0x504D_5544; // "DUMP"
        const PAGE_SIZE: usize = 4096;

        // Find the highest PFN to determine bitmap size.
        let max_pfn: u64 = self
            .runs
            .iter()
            .map(|(base, data)| base + (data.len() / PAGE_SIZE) as u64)
            .max()
            .unwrap_or(0);

        // Bitmap: one bit per page up to max_pfn, rounded up to 8 bytes.
        let bitmap_bits = max_pfn as usize;
        let bitmap_bytes = bitmap_bits.div_ceil(8);
        // Align bitmap_bytes up to multiple of 8.
        let bitmap_bytes_aligned = (bitmap_bytes + 7) & !7;

        let mut bitmap = vec![0u8; bitmap_bytes_aligned];
        for (base_page, data) in &self.runs {
            let page_count = data.len() / PAGE_SIZE;
            for p in 0..page_count {
                let pfn = *base_page as usize + p;
                bitmap[pfn / 8] |= 1 << (pfn % 8);
            }
        }

        // Summary header at 0x2000:
        // ValidDump (u32) = "DUMP"
        // HeaderSize (u32) = offset from 0x2000 to start of page data
        // BitmapSize (u32) = bitmap size in bytes
        // Pages (u32) = total number of set bits
        let total_set_pages: u32 = self
            .runs
            .iter()
            .map(|(_, d)| (d.len() / PAGE_SIZE) as u32)
            .sum();
        let summary_header_size: u32 = 16; // 4 fields * 4 bytes
        let data_offset = summary_header_size as usize + bitmap_bytes_aligned;

        out.extend_from_slice(&DUMP_VALID.to_le_bytes());
        out.extend_from_slice(&(data_offset as u32).to_le_bytes());
        out.extend_from_slice(&(bitmap_bytes_aligned as u32).to_le_bytes());
        out.extend_from_slice(&total_set_pages.to_le_bytes());
        out.extend_from_slice(&bitmap);

        // Write page data in PFN order.
        // Build a map from PFN to page data for ordered output.
        let mut pfn_data: Vec<(u64, &[u8])> = Vec::new();
        for (base_page, data) in &self.runs {
            let page_count = data.len() / PAGE_SIZE;
            for p in 0..page_count {
                let pfn = base_page + p as u64;
                let start = p * PAGE_SIZE;
                pfn_data.push((pfn, &data[start..start + PAGE_SIZE]));
            }
        }
        pfn_data.sort_by_key(|(pfn, _)| *pfn);
        for (_, page) in &pfn_data {
            out.extend_from_slice(page);
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
    pub fn new() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

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
        let data_start = (ehdr_size + phdr_total).div_ceil(0x1000) * 0x1000;
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
            out[phdr_off + 8..phdr_off + 16]
                .copy_from_slice(&(current_offset as u64).to_le_bytes());
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

/// Build a synthetic VMware `.vmss`/`.vmsn` state file.
///
/// Produces the VMware group/tag binary format:
/// - 12-byte file header: magic(u32=0xBED2BED0) + unknown(u32=0) + group_count(u32)
/// - Group entries (80 bytes each): name(64 bytes null-terminated) + tags_offset(u64) + padding(8 bytes)
/// - "memory" group with region tags containing paddr(u64) + data
/// - Optional "cpu" group with CR3 tag
///
/// Tag format for memory regions:
/// - flags: u8 (0x06 = large data with explicit size)
/// - name_length: u8
/// - name: bytes ("regionPPN", "regionBytes")
/// - data_length: u32
/// - payload: depends on tag name
///
/// Tag format for CPU CR3:
/// - flags: u8 (0x46 = indexed + 8-byte data)
/// - name_length: u8
/// - name: "CR3"
/// - index0: u8 (0 = CPU 0)
/// - index1: u8 (3 = CR register 3)
/// - value: u64
///
/// Tag terminator: flags byte = 0
#[derive(Default)]
pub struct VmwareStateBuilder {
    memory_regions: Vec<(u64, Vec<u8>)>,
    cr3: Option<u64>,
}

impl VmwareStateBuilder {
    /// Create a new empty builder.
    pub fn new() -> Self {
        Self {
            memory_regions: Vec::new(),
            cr3: None,
        }
    }

    /// Add a physical memory region at the given physical address.
    pub fn add_region(mut self, paddr: u64, data: &[u8]) -> Self {
        self.memory_regions.push((paddr, data.to_vec()));
        self
    }

    /// Set the CR3 / DirectoryTableBase value (adds a "cpu" group).
    pub fn cr3(mut self, cr3: u64) -> Self {
        self.cr3 = Some(cr3);
        self
    }

    /// Build the complete VMware state file as a byte vector.
    pub fn build(self) -> Vec<u8> {
        let group_count: u32 = if self.cr3.is_some() { 2 } else { 1 };

        // Header: 12 bytes
        let header_size = 12usize;
        let group_entry_size = 80usize;
        let groups_size = group_count as usize * group_entry_size;

        let mut out = Vec::new();

        // File header
        out.extend_from_slice(&0xBED2BED0u32.to_le_bytes()); // magic
        out.extend_from_slice(&0u32.to_le_bytes()); // unknown
        out.extend_from_slice(&group_count.to_le_bytes()); // group_count

        // Reserve space for group entries — we'll fill tags_offset later
        let groups_start = out.len();
        out.resize(header_size + groups_size, 0);

        // --- "memory" group tags ---
        let memory_tags_offset = out.len() as u64;

        // Write region tags: for each region, emit regionPPN + regionBytes pair
        for (paddr, data) in &self.memory_regions {
            // regionPPN tag: flags=0x06, name="regionPPN", data=paddr as u64
            let name = b"regionPPN";
            out.push(0x06); // flags: large data with explicit size
            out.push(name.len() as u8);
            out.extend_from_slice(name);
            out.extend_from_slice(&8u32.to_le_bytes()); // data_length = 8
            out.extend_from_slice(&paddr.to_le_bytes());

            // regionBytes tag: flags=0x06, name="regionBytes", data=raw bytes
            let name = b"regionBytes";
            out.push(0x06); // flags: large data with explicit size
            out.push(name.len() as u8);
            out.extend_from_slice(name);
            let data_len = data.len() as u32;
            out.extend_from_slice(&data_len.to_le_bytes()); // data_length
            out.extend_from_slice(data);
        }

        // Tag terminator
        out.push(0x00);

        // Fill "memory" group entry
        {
            let entry_offset = groups_start;
            let name = b"memory";
            out[entry_offset..entry_offset + name.len()].copy_from_slice(name);
            // name is null-terminated, rest of 64 bytes is already zero
            let tags_off_pos = entry_offset + 64;
            out[tags_off_pos..tags_off_pos + 8].copy_from_slice(&memory_tags_offset.to_le_bytes());
            // padding 8 bytes already zero
        }

        // --- Optional "cpu" group ---
        if let Some(cr3_val) = self.cr3 {
            let cpu_tags_offset = out.len() as u64;

            // CR3 tag: flags=0x46 (indexed + 8-byte data)
            let name = b"CR3";
            out.push(0x46); // flags
            out.push(name.len() as u8);
            out.extend_from_slice(name);
            out.push(0x00); // index0 = CPU 0
            out.push(0x03); // index1 = CR register 3
            out.extend_from_slice(&cr3_val.to_le_bytes());

            // Tag terminator
            out.push(0x00);

            // Fill "cpu" group entry (second entry)
            let entry_offset = groups_start + group_entry_size;
            let name = b"cpu";
            out[entry_offset..entry_offset + name.len()].copy_from_slice(name);
            let tags_off_pos = entry_offset + 64;
            out[tags_off_pos..tags_off_pos + 8].copy_from_slice(&cpu_tags_offset.to_le_bytes());
        }

        out
    }
}

/// Compress data using `lzxpress::data::compress`, falling back to a
/// literal-only Xpress encoding if the library's round-trip is broken
/// for the given input.
///
/// The literal-only format is: every 32 bytes of input get a 4-byte flags
/// word (all zeros = all literals) followed by the 32 raw bytes.
fn xpress_compress_safe(data: &[u8]) -> Vec<u8> {
    // Try the library compressor first.
    if let Ok(compressed) = lzxpress::data::compress(data) {
        // Verify round-trip; the library has known issues with certain patterns.
        if let Ok(decompressed) = lzxpress::data::decompress(&compressed) {
            if decompressed == data {
                return compressed;
            }
        }
    }

    // Fallback: produce literal-only Xpress output.
    // Format: repeated blocks of [flags_u32_le=0x00000000][32 literal bytes].
    // A flags word of 0 means all 32 bits are 0, so all 32 symbols are literals.
    let mut out = Vec::with_capacity(data.len() + data.len() / 32 * 4 + 8);
    let mut pos = 0;
    while pos < data.len() {
        let chunk_len = (data.len() - pos).min(32);
        // flags = 0 means every bit is 0 = literal
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&data[pos..pos + chunk_len]);
        pos += chunk_len;
    }
    out
}

/// Build a synthetic Windows hibernation file (`hiberfil.sys`).
///
/// Produces a `PO_MEMORY_IMAGE` header with "hibr" magic, processor state
/// page with CR3, a page table page with PFN entries, and Xpress LZ77
/// compressed data blocks.
///
/// Layout:
/// - Page 0 (offset 0x0000): PO\_MEMORY\_IMAGE header with "hibr" magic at 0x00,
///   `LengthSelf` at 0x0C (256 = 64-bit), `FirstTablePage` at 0x68 (value 2).
/// - Page 1 (offset 0x1000): Processor state page with CR3 at offset 0x28.
/// - Page 2 (offset 0x2000): Page table -- array of PFN entries (u64),
///   terminated by `0xFFFF_FFFF_FFFF_FFFF`.
/// - After header pages: Xpress LZ77 compressed blocks.
///   Block header: sig(8) + num\_pages\_minus\_1(1) + compressed\_size\_field(3 bytes)
///   + padding to 0x20 + compressed data.
pub struct HiberfilBuilder {
    pages: Vec<(u64, [u8; 4096])>,
    cr3: u64,
}

impl Default for HiberfilBuilder {
    fn default() -> Self {
        Self {
            pages: Vec::new(),
            cr3: 0x1ab000,
        }
    }
}

impl HiberfilBuilder {
    /// Create a new builder with default CR3 (`0x1ab000`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the CR3 / `DirectoryTableBase` value stored in the processor state page.
    pub fn cr3(mut self, cr3: u64) -> Self {
        self.cr3 = cr3;
        self
    }

    /// Add a physical memory page at the given PFN.
    pub fn add_page(mut self, pfn: u64, data: &[u8; 4096]) -> Self {
        self.pages.push((pfn, *data));
        self
    }

    /// Build the complete hibernation file as a byte vector.
    pub fn build(self) -> Vec<u8> {
        const PAGE_SIZE: usize = 4096;
        const HIBR_MAGIC: u32 = 0x7262_6968; // "hibr" LE
        const LENGTH_SELF_64: u32 = 256;
        const XPRESS_SIG: [u8; 8] = [0x81, 0x81, b'x', b'p', b'r', b'e', b's', b's'];
        const BLOCK_HEADER_SIZE: usize = 0x20;

        let mut out = vec![0u8; 3 * PAGE_SIZE]; // pages 0, 1, 2

        // --- Page 0: PO_MEMORY_IMAGE header ---
        // Magic "hibr" at offset 0x00
        out[0x00..0x04].copy_from_slice(&HIBR_MAGIC.to_le_bytes());
        // LengthSelf at offset 0x0C: 256 indicates 64-bit
        out[0x0C..0x10].copy_from_slice(&LENGTH_SELF_64.to_le_bytes());
        // FirstTablePage at offset 0x68: page 2
        out[0x68..0x70].copy_from_slice(&2u64.to_le_bytes());

        // --- Page 1: Processor state ---
        // CR3 at offset 0x28 within page 1
        let cr3_offset = PAGE_SIZE + 0x28;
        out[cr3_offset..cr3_offset + 8].copy_from_slice(&self.cr3.to_le_bytes());

        // --- Page 2: Page table ---
        // Array of PFN entries (u64), terminated by sentinel 0xFFFFFFFFFFFFFFFF
        let table_base = 2 * PAGE_SIZE;
        let mut table_offset = 0usize;
        for (pfn, _) in &self.pages {
            out[table_base + table_offset..table_base + table_offset + 8]
                .copy_from_slice(&pfn.to_le_bytes());
            table_offset += 8;
        }
        // Sentinel terminator
        out[table_base + table_offset..table_base + table_offset + 8]
            .copy_from_slice(&u64::MAX.to_le_bytes());

        // --- Compressed data blocks ---
        // Each page gets its own Xpress block.
        for (_, page_data) in &self.pages {
            let compressed = xpress_compress_safe(page_data);

            // compressed_size_field = (compressed_len * 4) - 1, stored as 3 bytes LE
            let compressed_size_field = (compressed.len() * 4 - 1) as u32;
            let num_pages_minus_1: u8 = 0; // single page per block

            let mut block = Vec::new();
            // 8-byte signature
            block.extend_from_slice(&XPRESS_SIG);
            // 1 byte: num_pages_minus_1
            block.push(num_pages_minus_1);
            // 3 bytes: compressed_size_field (LE)
            block.push(compressed_size_field as u8);
            block.push((compressed_size_field >> 8) as u8);
            block.push((compressed_size_field >> 16) as u8);
            // Pad to BLOCK_HEADER_SIZE (0x20 = 32 bytes)
            block.resize(BLOCK_HEADER_SIZE, 0);
            // Compressed data
            block.extend_from_slice(&compressed);

            out.extend_from_slice(&block);
        }

        out
    }
}

/// Build a synthetic kdump (makedumpfile) dump for testing.
///
/// Produces the `disk_dump_header` + `kdump_sub_header` + bitmaps + page
/// descriptors + compressed page data layout used by makedumpfile and
/// crash-utility.
///
/// File layout (block_size = 4096 by default):
/// - Block 0: `disk_dump_header`
/// - Block 1: `kdump_sub_header` (mostly zeros for test)
/// - Blocks 2..2+N: 1st bitmap (valid PFNs)
/// - Blocks 2+N..2+2N: 2nd bitmap (dumped PFNs)
/// - After bitmaps: `page_desc[]` array (24 bytes each, block-aligned)
/// - After descs: compressed page data
///
/// `disk_dump_header` (Block 0):
/// - 0x00: signature "KDUMP   " (8 bytes, 3 trailing spaces)
/// - 0x08: header_version = 6 (i32)
/// - 0x0C: utsname (390 bytes = 6 fields * 65, zeros)
/// - Aligned to 4 after utsname: block_size(i32) + sub_hdr_size(i32=1) +
///   bitmap_blocks(u32) + max_mapnr(u32)
///
/// `page_desc` (24 bytes each):
/// - offset: i64 (file offset of compressed data)
/// - size: u32 (compressed size)
/// - flags: u32 (compression method)
/// - page_flags: u64 (kernel flags, 0 for test)
pub struct KdumpBuilder {
    pages: Vec<(u64, Vec<u8>)>,
    compression: u32,
    block_size: u32,
}

impl Default for KdumpBuilder {
    fn default() -> Self {
        Self {
            pages: Vec::new(),
            compression: 0x04, // snappy
            block_size: 4096,
        }
    }
}

impl KdumpBuilder {
    /// Create a new builder with defaults: block_size=4096, compression=snappy (0x04).
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the block size (must be a power of 2, typically 4096).
    pub fn block_size(mut self, bs: u32) -> Self {
        self.block_size = bs;
        self
    }

    /// Set the compression flags for page data.
    /// - 0x00: uncompressed
    /// - 0x01: zlib
    /// - 0x04: snappy
    /// - 0x20: zstd (stored as minimal zstd frame)
    pub fn compression(mut self, flags: u32) -> Self {
        self.compression = flags;
        self
    }

    /// Add a physical page at the given PFN with `data` (must be exactly block_size bytes).
    pub fn add_page(mut self, pfn: u64, data: &[u8]) -> Self {
        self.pages.push((pfn, data.to_vec()));
        self
    }

    /// Build the complete kdump file as a byte vector.
    pub fn build(self) -> Vec<u8> {
        let bs = self.block_size as usize;

        // Determine max PFN for bitmap sizing.
        let max_pfn = self
            .pages
            .iter()
            .map(|(pfn, _)| *pfn)
            .max()
            .map_or(0, |p| p + 1);

        // Bitmap: one bit per PFN up to max_pfn, padded to block_size.
        let bitmap_bits = max_pfn as usize;
        let bitmap_bytes_raw = bitmap_bits.div_ceil(8);
        let bitmap_blocks = bitmap_bytes_raw.div_ceil(bs);
        let bitmap_bytes = bitmap_blocks * bs;

        // Build bitmaps: both bitmaps are identical (valid == dumped).
        let mut bitmap = vec![0u8; bitmap_bytes];
        for (pfn, _) in &self.pages {
            let pfn = *pfn as usize;
            if pfn / 8 < bitmap.len() {
                bitmap[pfn / 8] |= 1 << (pfn % 8);
            }
        }

        // Compress each page.
        let mut compressed_pages: Vec<(u32, Vec<u8>)> = Vec::new(); // (flags, data)
        for (_, page_data) in &self.pages {
            let (flags, compressed) = self.compress_page(page_data);
            compressed_pages.push((flags, compressed));
        }

        // Layout calculation:
        // Block 0: disk_dump_header
        // Block 1: kdump_sub_header
        // Blocks 2..2+bitmap_blocks: 1st bitmap
        // Blocks 2+bitmap_blocks..2+2*bitmap_blocks: 2nd bitmap
        let desc_start_block = 2 + 2 * bitmap_blocks;
        let desc_start = desc_start_block * bs;

        // Sort pages by PFN for descriptor ordering.
        let mut indexed_pages: Vec<(usize, u64)> = self
            .pages
            .iter()
            .enumerate()
            .map(|(i, (pfn, _))| (i, *pfn))
            .collect();
        indexed_pages.sort_by_key(|(_, pfn)| *pfn);

        // page_desc array: 24 bytes each, block-aligned total.
        let num_descs = indexed_pages.len();
        let descs_raw_size = num_descs * 24;
        let descs_padded = descs_raw_size.div_ceil(bs) * bs;
        let data_start = desc_start + descs_padded;

        // Compute file offsets for each page's compressed data.
        let mut data_offsets: Vec<usize> = Vec::new();
        let mut cur_offset = data_start;
        for (orig_idx, _) in &indexed_pages {
            data_offsets.push(cur_offset);
            cur_offset += compressed_pages[*orig_idx].1.len();
        }

        // --- Assemble the file ---
        let total_size = cur_offset;
        let mut out = vec![0u8; total_size];

        // Block 0: disk_dump_header
        // Signature "KDUMP   " (8 bytes)
        out[0x00..0x08].copy_from_slice(b"KDUMP   ");
        // header_version = 6 (i32 LE)
        out[0x08..0x0C].copy_from_slice(&6i32.to_le_bytes());
        // utsname: 390 bytes of zeros (already zero)
        // Aligned offset after utsname: (0x0C + 390 + 3) & !3 = 0x19C
        let fields_off = (0x0C + 390 + 3) & !3; // 0x19C
                                                // block_size (i32)
        #[allow(clippy::cast_possible_wrap)]
        let block_size_i32 = self.block_size as i32;
        out[fields_off..fields_off + 4].copy_from_slice(&block_size_i32.to_le_bytes());
        // sub_hdr_size (i32) = 1
        out[fields_off + 4..fields_off + 8].copy_from_slice(&1i32.to_le_bytes());
        // bitmap_blocks (u32)
        out[fields_off + 8..fields_off + 12].copy_from_slice(&(bitmap_blocks as u32).to_le_bytes());
        // max_mapnr (u32)
        out[fields_off + 12..fields_off + 16].copy_from_slice(&(max_pfn as u32).to_le_bytes());

        // Block 1: kdump_sub_header (all zeros, already done)

        // Blocks 2..2+N: 1st bitmap
        let bm1_start = 2 * bs;
        out[bm1_start..bm1_start + bitmap.len()].copy_from_slice(&bitmap);

        // Blocks 2+N..2+2N: 2nd bitmap (same as 1st)
        let bm2_start = (2 + bitmap_blocks) * bs;
        out[bm2_start..bm2_start + bitmap.len()].copy_from_slice(&bitmap);

        // Page descriptors
        for (desc_idx, (orig_idx, _)) in indexed_pages.iter().enumerate() {
            let d_off = desc_start + desc_idx * 24;
            let (flags, ref compressed) = compressed_pages[*orig_idx];
            // offset: i64
            out[d_off..d_off + 8].copy_from_slice(
                &{
                    #[allow(clippy::cast_possible_wrap)]
                    let offset_i64 = data_offsets[desc_idx] as i64;
                    offset_i64
                }
                .to_le_bytes(),
            );
            // size: u32
            out[d_off + 8..d_off + 12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
            // flags: u32
            out[d_off + 12..d_off + 16].copy_from_slice(&flags.to_le_bytes());
            // page_flags: u64 = 0 (already zero)
        }

        // Compressed page data
        for (desc_idx, (orig_idx, _)) in indexed_pages.iter().enumerate() {
            let offset = data_offsets[desc_idx];
            let data = &compressed_pages[*orig_idx].1;
            out[offset..offset + data.len()].copy_from_slice(data);
        }

        out
    }

    /// Compress a single page based on the configured compression method.
    /// Returns (flags, compressed_data).
    fn compress_page(&self, data: &[u8]) -> (u32, Vec<u8>) {
        match self.compression {
            0x00 => {
                // Uncompressed: flags=0, data is raw
                (0x00, data.to_vec())
            }
            0x01 => {
                // Zlib
                use std::io::Write;
                let mut encoder =
                    flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(data).expect("zlib compress write");
                let compressed = encoder.finish().expect("zlib compress finish");
                (0x01, compressed)
            }
            0x04 => {
                // Snappy
                let mut encoder = snap::raw::Encoder::new();
                let compressed = encoder.compress_vec(data).expect("snappy compress");
                (0x04, compressed)
            }
            0x20 => {
                // Zstd: produce a minimal valid zstd frame.
                let compressed = Self::zstd_compress_minimal(data);
                (0x20, compressed)
            }
            _ => (0x00, data.to_vec()),
        }
    }

    /// Produce a minimal valid zstd frame that stores raw (uncompressed) data.
    ///
    /// Zstd frame format (minimal raw block):
    /// - 4-byte magic: 0xFD2FB528
    /// - Frame header descriptor byte
    /// - Window descriptor byte
    /// - Block header: 3 bytes (last_block=1, block_type=raw, block_size)
    /// - Raw data
    fn zstd_compress_minimal(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        // Magic number
        out.extend_from_slice(&0xFD2FB528u32.to_le_bytes());
        // Frame header descriptor: 0x00
        // single_segment=0, so window descriptor is present
        // no checksum, no dict_id, fcs_field_size=0
        out.push(0x00);
        // Window descriptor: exponent=0, mantissa=0 => window_size = 1 << 10 = 1024
        out.push(0x00);
        // Block header: 3 bytes LE
        // bit 0: last_block = 1
        // bits 2-1: block_type = 0 (raw)
        // bits 23-3: block_size = data.len()
        let block_header: u32 = 1 | ((data.len() as u32) << 3);
        let bh_bytes = block_header.to_le_bytes();
        out.extend_from_slice(&bh_bytes[..3]);
        // Raw data
        out.extend_from_slice(data);
        out
    }
}
