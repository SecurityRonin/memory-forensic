//! Shared synthetic in-memory registry-hive harness for tests.
//!
//! Builds a single-bin cell-map hive (cell index == byte offset within the bin,
//! so indices must be < 0x1000; cell data starts at `idx + 4`, past the size
//! header) plus a backing [`ObjectReader`], so registry-walker tests across
//! modules (registry, run_keys, amcache, …) construct nk/value cells without
//! duplicating the page-table + ISF scaffolding. Mirrors the in-memory
//! `_HHIVE.Storage[].Map` directory→table→bin layout that `cell_index_to_va`
//! walks.

use memf_core::object_reader::ObjectReader;
use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
use memf_core::vas::{TranslationMode, VirtualAddressSpace};
use memf_symbols::isf::IsfResolver;
use memf_symbols::test_builders::IsfBuilder;

fn cellmap_isf() -> serde_json::Value {
    IsfBuilder::new()
        .add_struct("_HHIVE", 0x800)
        .add_field("_HHIVE", "BaseBlock", 0x10, "pointer")
        .add_field("_HHIVE", "Storage", 0xb8, "char")
        .add_struct("_DUAL", 0x278)
        .add_field("_DUAL", "Map", 0x18, "pointer")
        .add_struct("_HMAP_ENTRY", 0x20)
        .add_field("_HMAP_ENTRY", "PermanentBinAddress", 0x0, "pointer")
        .add_field("_HMAP_ENTRY", "BlockOffset", 0x8, "unsigned long")
        .build_json()
}

pub(crate) struct CellHive {
    pub(crate) hhive_va: u64,
    pub(crate) bin_va: u64,
    bin: Vec<u8>,
}

impl CellHive {
    pub(crate) fn new(base: u64) -> Self {
        Self {
            hhive_va: base,
            bin_va: base + 0x4000,
            bin: vec![0u8; 0x1000],
        }
    }
    pub(crate) fn ao(idx: u32) -> usize {
        (idx + 4) as usize
    }
    /// Build a hive whose single 4 KiB bin IS the given buffer — cell index ==
    /// byte offset within `bin` (cells already laid out, e.g. from `build_cell`
    /// placed at their offsets). Lets a flat-fixture test reuse its `hbin_page`/
    /// `cell_page` directly as the HMAP bin. The root cell is the regf default 0x20.
    pub(crate) fn with_bin(base: u64, bin: Vec<u8>) -> Self {
        let mut h = Self::new(base);
        let n = bin.len().min(h.bin.len());
        h.bin[..n].copy_from_slice(&bin[..n]);
        h
    }
    /// `_CM_KEY_NODE` with CORRECT offsets: SubKeyCounts[Stable]@0x14,
    /// SubKeyLists[Stable]@0x1c, [Volatile]@0x20, NameLength@0x48, Name@0x4c.
    pub(crate) fn nk(
        &mut self,
        idx: u32,
        name: &[u8],
        stable_count: u32,
        stable_list: u32,
        volatile_list: u32,
    ) {
        let o = Self::ao(idx);
        self.bin[o + 0x14..o + 0x18].copy_from_slice(&stable_count.to_le_bytes());
        self.bin[o + 0x18..o + 0x1c].copy_from_slice(&1u32.to_le_bytes()); // volatile count
        self.bin[o + 0x1c..o + 0x20].copy_from_slice(&stable_list.to_le_bytes());
        self.bin[o + 0x20..o + 0x24].copy_from_slice(&volatile_list.to_le_bytes());
        self.bin[o + 0x48..o + 0x4a].copy_from_slice(&(name.len() as u16).to_le_bytes());
        self.bin[o + 0x4c..o + 0x4c + name.len()].copy_from_slice(name);
    }
    pub(crate) fn list(&mut self, idx: u32, sig: [u8; 2], entries: &[u32], stride: usize) {
        let o = Self::ao(idx);
        self.bin[o..o + 2].copy_from_slice(&sig);
        self.bin[o + 2..o + 4].copy_from_slice(&(entries.len() as u16).to_le_bytes());
        for (i, &e) in entries.iter().enumerate() {
            self.bin[o + 4 + i * stride..o + 4 + i * stride + 4].copy_from_slice(&e.to_le_bytes());
        }
    }
    pub(crate) fn lf(&mut self, idx: u32, children: &[u32]) {
        self.list(idx, *b"lf", children, 8);
    }
    pub(crate) fn li(&mut self, idx: u32, children: &[u32]) {
        self.list(idx, *b"li", children, 4);
    }
    pub(crate) fn ri(&mut self, idx: u32, sublists: &[u32]) {
        self.list(idx, *b"ri", sublists, 4);
    }
    /// Set `_CM_KEY_NODE` ValueCount@0x24 + ValueList@0x28 on cell `idx`.
    pub(crate) fn values(&mut self, idx: u32, count: u32, list_idx: u32) {
        let o = Self::ao(idx);
        self.bin[o + 0x24..o + 0x28].copy_from_slice(&count.to_le_bytes());
        self.bin[o + 0x28..o + 0x2c].copy_from_slice(&list_idx.to_le_bytes());
    }
    /// Write a value-list cell: a packed array of `_CM_KEY_VALUE` cell indices.
    pub(crate) fn value_list(&mut self, idx: u32, values: &[u32]) {
        let o = Self::ao(idx);
        for (i, &v) in values.iter().enumerate() {
            self.bin[o + i * 4..o + i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
    }
    /// `_CM_KEY_VALUE` with data stored in a separate (non-inline) data cell:
    /// "vk"@0, NameLength@0x02, DataLength@0x04, Data@0x08 (=data cell idx),
    /// Type@0x0C, Name@0x14.
    pub(crate) fn vk(&mut self, idx: u32, name: &[u8], kind: u32, data_len: u32, data_idx: u32) {
        let o = Self::ao(idx);
        self.bin[o..o + 2].copy_from_slice(b"vk");
        self.bin[o + 2..o + 4].copy_from_slice(&(name.len() as u16).to_le_bytes());
        self.bin[o + 4..o + 8].copy_from_slice(&data_len.to_le_bytes());
        self.bin[o + 8..o + 0xc].copy_from_slice(&data_idx.to_le_bytes());
        self.bin[o + 0xc..o + 0x10].copy_from_slice(&kind.to_le_bytes());
        self.bin[o + 0x14..o + 0x14 + name.len()].copy_from_slice(name);
    }
    /// Place raw bytes at cell `idx`'s data start (e.g. a value's data cell).
    pub(crate) fn data(&mut self, idx: u32, bytes: &[u8]) {
        let o = Self::ao(idx);
        self.bin[o..o + bytes.len()].copy_from_slice(bytes);
    }
    pub(crate) fn reader(&self) -> ObjectReader<SyntheticPhysMem> {
        let resolver = IsfResolver::from_value(&cellmap_isf()).unwrap();
        let bb_va = self.hhive_va + 0x1000;
        let dir_va = self.hhive_va + 0x2000;
        let table_va = self.hhive_va + 0x3000;
        let mut hh = vec![0u8; 0x1000];
        hh[0x10..0x18].copy_from_slice(&bb_va.to_le_bytes());
        hh[0xb8 + 0x18..0xb8 + 0x18 + 8].copy_from_slice(&dir_va.to_le_bytes());
        let mut dir = vec![0u8; 0x1000];
        dir[0..8].copy_from_slice(&table_va.to_le_bytes());
        let mut table = vec![0u8; 0x1000];
        table[0..8].copy_from_slice(&self.bin_va.to_le_bytes());
        // Map each page to a DISTINCT LOW physical address: identity (va==paddr)
        // would overflow SyntheticPhysMem for a high kernel-VA base, so callers
        // can use a real hive VA (e.g. 0xFFFF_8000_…) without lowering it.
        let (hh_pa, bb_pa, dir_pa, table_pa, bin_pa) =
            (0x20_0000u64, 0x20_1000, 0x20_2000, 0x20_3000, 0x20_4000);
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(self.hhive_va, hh_pa, flags::WRITABLE)
            .write_phys(hh_pa, &hh)
            .map_4k(bb_va, bb_pa, flags::WRITABLE)
            .write_phys(bb_pa, &vec![0u8; 0x1000])
            .map_4k(dir_va, dir_pa, flags::WRITABLE)
            .write_phys(dir_pa, &dir)
            .map_4k(table_va, table_pa, flags::WRITABLE)
            .write_phys(table_pa, &table)
            .map_4k(self.bin_va, bin_pa, flags::WRITABLE)
            .write_phys(bin_pa, &self.bin)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }
}
